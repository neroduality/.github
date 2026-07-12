#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Validate/format configured YAML manifests (yamllint schemas in lint-c-cpp.yaml).
Sorts spec_traceability by spec_prefix/symbol and lint_config keys recursively."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from consumer_manifest import manifest_path
from format_fail_on_change import apply_with_fail_on_change, formatter_ok_message
from policy_config import PolicyConfig

try:
    import yaml
except ImportError:
    print("error: PyYAML is required (install the python3-yaml package)", file=sys.stderr)
    sys.exit(2)

REQUIRED_FIELDS = ("spec_prefix", "symbol", "spec_value", "ref", "source")
OPTIONAL_FIELDS: tuple[str, ...] = ()
ENTRY_FIELD_ORDER = REQUIRED_FIELDS[:3] + OPTIONAL_FIELDS + REQUIRED_FIELDS[3:]
ENTRY_BLOCK_RE = re.compile(r"^  - spec_prefix:", re.MULTILINE)
SPEC_PREFIX_LINE_RE = re.compile(r"^  - spec_prefix: (?P<value>.+)$", re.MULTILINE)
FIELD_LINE_RE = re.compile(r"^    (?P<field>[a-z_]+): (?P<value>.+)$", re.MULTILINE)
TOP_LEVEL_KEY_RE = re.compile(r"^[a-z_][a-z0-9_]*:", re.MULTILINE)


def split_yaml_preamble(raw: str) -> tuple[str, str]:
    match = TOP_LEVEL_KEY_RE.search(raw)
    if match is None:
        return raw, ""
    return raw[: match.start()], raw[match.start() :]


def _list_sort_key(item: dict[str, Any]) -> tuple[str, ...]:
    for field in ("path", "name", "file", "id", "workflow", "label"):
        if field in item:
            value = item[field]
            if field == "workflow" and "job" in item:
                return (str(value), str(item["job"]))
            return (str(value),)
    return (json.dumps(item, sort_keys=True),)


def sort_list_node(items: list[Any], sort_by: Any) -> list[Any]:
    if not items:
        return items
    canonical = [canonicalize_lint_config(item, sort_by) for item in items]
    if all(isinstance(item, dict) for item in canonical):
        if isinstance(sort_by, list) and sort_by:
            return sorted(
                canonical,
                key=lambda entry: tuple(str(entry.get(field, "")).casefold() for field in sort_by),
            )
        return sorted(canonical, key=_list_sort_key)
    if all(isinstance(item, (str, int, float, bool)) or item is None for item in canonical):
        return sorted(canonical, key=lambda value: (value is None, str(value)))
    return canonical


def canonicalize_lint_config(value: Any, sort_by: Any = "key") -> Any:
    if isinstance(value, dict):
        return {key: canonicalize_lint_config(item, sort_by) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sort_list_node(value, sort_by)
    return value


LICENSE_HEADER_KEY = "license_header"


def _format_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    return yaml_scalar(str(value))


def _normalize_license_header(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("# "):
            lines.append(line)
        elif line == "#":
            lines.append("#")
        elif not line:
            if lines and lines[-1] != "":
                lines.append("")
        elif line.lstrip().startswith("#"):
            lines.append(line.lstrip())
        else:
            lines.append(line)
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _render_block_scalar(key: str, text: str, indent: int) -> list[str]:
    pad = " " * indent
    content = _normalize_license_header(text)
    out = [f"{pad}{key}: |"]
    out.extend(f"{pad}  {line}" for line in content)
    return out


def _render_mapping(data: dict[str, Any], indent: int) -> list[str]:
    lines: list[str] = []
    for key in sorted(data.keys()):
        lines.extend(_render_key_value(key, data[key], indent))
    return lines


def _render_list_item_fields(
    first_key: str,
    first_val: Any,
    rest: list[tuple[str, Any]],
    indent: int,
) -> list[str]:
    pad = " " * indent
    cont = " " * (indent + 2)
    lines: list[str] = []

    if isinstance(first_val, dict):
        lines.append(f"{pad}- {first_key}:")
        lines.extend(_render_mapping(first_val, indent + 4))
    elif isinstance(first_val, list):
        lines.append(f"{pad}- {first_key}:")
        lines.extend(_render_sequence(first_val, indent + 4))
    else:
        lines.append(f"{pad}- {first_key}: {_format_scalar(first_val)}")

    for key, value in rest:
        if isinstance(value, dict):
            lines.append(f"{cont}{key}:")
            lines.extend(_render_mapping(value, indent + 4))
        elif isinstance(value, list):
            lines.append(f"{cont}{key}:")
            lines.extend(_render_sequence(value, indent + 4))
        else:
            lines.append(f"{cont}{key}: {_format_scalar(value)}")
    return lines


def _render_sequence(items: list[Any], indent: int) -> list[str]:
    pad = " " * indent
    lines: list[str] = []
    for item in items:
        if isinstance(item, dict):
            sorted_items = sorted(item.items())
            first_key, first_val = sorted_items[0]
            lines.extend(_render_list_item_fields(first_key, first_val, sorted_items[1:], indent))
        else:
            lines.append(f"{pad}- {_format_scalar(item)}")
    return lines


def _render_key_value(key: str, value: Any, indent: int) -> list[str]:
    pad = " " * indent
    if key == LICENSE_HEADER_KEY and isinstance(value, str):
        return _render_block_scalar(key, value, indent)
    if isinstance(value, dict):
        lines = [f"{pad}{key}:"]
        lines.extend(_render_mapping(value, indent + 2))
        return lines
    if isinstance(value, list):
        if not value:
            return [f"{pad}{key}: []"]
        lines = [f"{pad}{key}:"]
        lines.extend(_render_sequence(value, indent + 2))
        return lines
    return [f"{pad}{key}: {_format_scalar(value)}"]


def render_lint_config(preamble: str, data: dict[str, Any]) -> str:
    sections = ["\n".join(_render_key_value(key, data[key], 0)) for key in sorted(data.keys())]
    body = "\n\n".join(sections) + "\n"
    if preamble and not preamble.endswith("\n"):
        preamble += "\n"
    if preamble and not preamble.endswith("\n\n"):
        preamble += "\n"
    return f"{preamble}{body}"


def lint_one_lint_config_manifest(manifest_path: Path, rule: dict[str, Any], args: argparse.Namespace) -> int:
    if not manifest_path.is_file():
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    raw = manifest_path.read_text(encoding="utf-8")
    preamble, body = split_yaml_preamble(raw)
    try:
        loaded = yaml.safe_load(body) or {}
    except yaml.YAMLError as exc:
        print(f"error: {manifest_path}: invalid YAML: {exc}", file=sys.stderr)
        return 2

    if not isinstance(loaded, dict):
        print(f"error: {manifest_path}: root must be a mapping", file=sys.stderr)
        return 1

    sort_by = rule.get("sort_by", "key")
    formatted = render_lint_config(preamble, canonicalize_lint_config(loaded, sort_by))
    if raw == formatted:
        return 0

    if args.check:
        print(f"error: {manifest_path} is not canonically sorted by key", file=sys.stderr)
        print("  run: python3 lib/policy/yaml_manifest.py --write", file=sys.stderr)
        return 1

    if args.fail_on_change:
        return apply_with_fail_on_change(
            [manifest_path],
            lambda: manifest_path.write_text(formatted, encoding="utf-8"),
            detail=f"rewrote {manifest_path} into canonical key order",
        )

    if args.write:
        manifest_path.write_text(formatted, encoding="utf-8")
        print(f"yamllint: rewrote {manifest_path}")
        return 0

    print(f"error: {manifest_path} is not canonical (pass --check, --write or --fail-on-change)", file=sys.stderr)
    return 1


def _parse_run_args(extras: list[str], repo_root: Path) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--fail-on-change", action="store_true")
    args = parser.parse_args(extras)
    args.manifest_was_explicit = args.manifest is not None
    if args.manifest is None:
        args.manifest = repo_root / "docs" / "spec-traceability.yaml"
    args.repo_root = repo_root
    return args


def run(config: PolicyConfig, paths: list[Path], extras: list[str]) -> int:
    args = _parse_run_args(extras, config.repo_root)
    if not args.manifest_was_explicit:
        configured_result = run_configured_yamllint(config, paths, args)
        if configured_result is not None:
            return configured_result

    result = lint_one_spec_manifest(args.manifest.resolve(), args)
    if result == 0 and (args.fail_on_change or args.write):
        print(yamllint_ok_message(1))
    return result


def sort_constants(constants: list[dict]) -> list[dict]:
    return sorted(
        constants,
        key=lambda entry: (
            str(entry["spec_prefix"]).casefold(),
            str(entry["symbol"]),
        ),
    )


def unquote_yaml_scalar(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        quote = value[0]
        inner = value[1:-1]
        if quote == '"':
            inner = inner.replace("\\\"", '"').replace("\\\\", "\\")
        return inner
    return value


def quoted_scalar(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def yaml_scalar(value: str) -> str:
    if not value:
        return '""'
    if re.fullmatch(r"\d+(\.\d+)+", value):
        return quoted_scalar(value)
    if any(ch in value for ch in ':#[]{},"\'&*!?|>@%`') or value != value.strip():
        return quoted_scalar(value)
    return value


def render_entry(entry: dict) -> str:
    lines = ["  - spec_prefix: " + yaml_scalar(str(entry["spec_prefix"]))]
    for field in ENTRY_FIELD_ORDER[1:]:
        if field not in entry:
            continue
        value = entry[field]
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        rendered = quoted_scalar(str(value)) if field in {"spec_value", "ref"} else yaml_scalar(str(value))
        lines.append(f"    {field}: {rendered}")
    return "\n".join(lines)


def render_manifest(preamble: str, constants: list[dict]) -> str:
    body = "\n\n".join(render_entry(entry) for entry in constants)
    if preamble and not preamble.endswith("\n"):
        preamble += "\n"
    return f"{preamble}constants:\n\n{body}\n"


def split_preamble(raw: str) -> tuple[str, str]:
    marker = "constants:"
    idx = raw.find(marker)
    if idx < 0:
        return raw, ""
    return raw[:idx], raw[idx:]


def parse_constants_body(body: str) -> list[dict]:
    matches = list(ENTRY_BLOCK_RE.finditer(body))
    constants: list[dict] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        block = body[start:end]
        entry: dict[str, str] = {}
        prefix_match = SPEC_PREFIX_LINE_RE.search(block)
        if prefix_match:
            entry["spec_prefix"] = unquote_yaml_scalar(prefix_match.group("value"))
        for field_match in FIELD_LINE_RE.finditer(block):
            field = field_match.group("field")
            if field not in ENTRY_FIELD_ORDER and field not in OPTIONAL_FIELDS:
                continue
            entry[field] = unquote_yaml_scalar(field_match.group("value"))
        if entry:
            constants.append(entry)
    return constants


def load_manifest(path: Path) -> tuple[str, dict]:
    raw = path.read_text(encoding="utf-8")
    preamble, body = split_preamble(raw)
    if not body.strip():
        raise ValueError("missing constants: section")

    constants = parse_constants_body(body)
    try:
        yaml_data = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc

    if not isinstance(yaml_data, dict):
        raise ValueError("manifest root must be a mapping")

    yaml_constants = yaml_data.get("constants")
    if not isinstance(yaml_constants, list) or not yaml_constants:
        raise ValueError("constants list is empty")

    if not constants:
        constants = [entry for entry in yaml_constants if isinstance(entry, dict)]

    if len(constants) != len(yaml_constants):
        raise ValueError("parsed entry count does not match YAML loader")

    return preamble, {"constants": constants}


def self_test() -> int:
    good = {
        "constants": [
            {
                "spec_prefix": "T2T-ISO14443-A",
                "symbol": "SAMPLE_X",
                "spec_value": "0x04",
                "ref": "section 1",
                "source": "a.h",
            },
        ]
    }
    assert validate_manifest(good) == [], validate_manifest(good)

    missing_field = {"constants": [{"spec_prefix": "P", "symbol": "SAMPLE_X", "source": "a.h"}]}
    assert any("spec_value" in e for e in validate_manifest(missing_field)), missing_field

    empty_field = {
        "constants": [
            {"spec_prefix": "P", "symbol": "  ", "spec_value": "1", "ref": "section 1", "source": "a.h"},
        ]
    }
    assert any("symbol" in e for e in validate_manifest(empty_field)), empty_field

    assert validate_manifest({"constants": []}) == ["constants must be a non-empty list"]
    assert validate_manifest({}) == ["constants must be a non-empty list"]

    unsorted = {
        "constants": [
            {"spec_prefix": "Z", "symbol": "B", "spec_value": "1", "ref": "section 1", "source": "a.h"},
            {"spec_prefix": "A", "symbol": "C", "spec_value": "2", "ref": "section 2", "source": "b.h"},
            {"spec_prefix": "A", "symbol": "A", "spec_value": "3", "ref": "section 3", "source": "c.h"},
        ]
    }
    sorted_entries = sort_constants(unsorted["constants"])
    assert [e["symbol"] for e in sorted_entries] == ["A", "C", "B"]
    rendered = render_manifest("", sorted_entries)
    assert "spec_value: \"1\"" in rendered
    assert rendered.index("spec_prefix: A") < rendered.index("spec_prefix: Z")

    raw_block = """
constants:

  - spec_prefix: CCID1.10
    symbol: SAMPLE_X
    spec_value: "0x61"
    ref: "section 6.1"
    source: firmware/x.h
"""
    parsed = parse_constants_body(raw_block)
    assert parsed[0]["spec_value"] == "0x61"
    roundtrip = render_manifest("", parsed)
    assert "spec_value: \"0x61\"" in roundtrip
    assert load_manifest_from_text(raw_block)[1]["constants"][0]["spec_value"] == "0x61"

    lint_cfg = {
        "z_section": {"b": 2, "a": 1},
        "a_section": {"y": 2, "x": 1},
        "items": [{"path": "b.yaml"}, {"path": "a.yaml"}],
    }
    canonical = canonicalize_lint_config(lint_cfg, "key")
    assert list(canonical.keys()) == ["a_section", "items", "z_section"]
    assert list(canonical["a_section"].keys()) == ["x", "y"]
    assert [item["path"] for item in canonical["items"]] == ["a.yaml", "b.yaml"]
    rendered = render_lint_config("# comment\n\n", canonical)
    assert rendered.startswith("# comment")
    assert rendered.index("a_section:") < rendered.index("z_section:")
    assert "\n\na_section:" in rendered

    license_cfg = canonicalize_lint_config(
        {
            "license_header": "# SPDX-License-Identifier: Apache-2.0\n#\n# Copyright (C) 2026 Example.\n",
            "scan": {"c_api_prefix": "x", "c_macro_prefix": "X"},
        },
        "key",
    )
    license_rendered = render_lint_config("", license_cfg)
    assert license_rendered.startswith("license_header:")
    assert "\n\nscan:\n" in license_rendered
    assert "  # SPDX-License-Identifier: Apache-2.0" in license_rendered

    print("yamllint self-test: OK")
    return 0


def load_manifest_from_text(raw: str) -> tuple[str, dict]:
    preamble, body = split_preamble(raw)
    constants = parse_constants_body(body)
    return preamble, {"constants": constants}


def validate_manifest(data: dict) -> list[str]:
    errors: list[str] = []
    constants = data.get("constants")
    if not isinstance(constants, list) or not constants:
        errors.append("constants must be a non-empty list")
        return errors

    for index, entry in enumerate(constants):
        if not isinstance(entry, dict):
            errors.append(f"constants[{index}]: expected mapping")
            continue
        for field in REQUIRED_FIELDS:
            value = entry.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                errors.append(f"constants[{index}]: missing or empty {field}")
    return errors


def canonical_text(preamble: str, data: dict) -> str:
    constants = sort_constants(list(data["constants"]))
    return render_manifest(preamble, constants)


def lint_one_spec_manifest(manifest_path: Path, args: argparse.Namespace) -> int:
    if not manifest_path.is_file():
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    try:
        preamble, data = load_manifest(manifest_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    errors = validate_manifest(data)
    if errors:
        print(f"error: {manifest_path} schema invalid", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    formatted = canonical_text(preamble, data)
    current = manifest_path.read_text(encoding="utf-8")
    if current == formatted:
        return 0

    if args.check:
        print(f"error: {manifest_path} is not canonically sorted/formatted", file=sys.stderr)
        print("  run: python3 .github/linters/policy/yaml_manifest.py --write", file=sys.stderr)
        return 1

    if args.fail_on_change:
        return apply_with_fail_on_change(
            [manifest_path],
            lambda: manifest_path.write_text(formatted, encoding="utf-8"),
            detail=(
                f"rewrote {manifest_path} into canonical sort/format "
                f"({len(data['constants'])} entries)"
            ),
        )

    if args.write:
        manifest_path.write_text(formatted, encoding="utf-8")
        print(f"yamllint: rewrote {manifest_path} ({len(data['constants'])} entries)")
        return 0

    print(f"error: {manifest_path} is not canonical (pass --check, --write or --fail-on-change)", file=sys.stderr)
    return 1


def configured_yaml_files(paths: list[Path]) -> list[Path]:
    return sorted(paths)


def yamllint_ok_message(checked: int, reformatted: int = 0) -> str:
    return formatter_ok_message("yamllint", checked, reformatted)


def run_configured_yamllint(config: PolicyConfig, paths: list[Path], args: argparse.Namespace) -> int | None:
    repo_root = config.repo_root.resolve()
    config_path = repo_root / ".github" / "lint-c-cpp.yaml"
    if not config_path.is_file():
        return None
    from consumer_manifest import yamllint_manifest_paths

    manifest_paths, missing = yamllint_manifest_paths(repo_root)
    if missing:
        for issue in missing:
            print(f"error: {issue}", file=sys.stderr)
        return 1
    yaml_paths = manifest_paths if manifest_paths else configured_yaml_files(paths)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    yamllint_cfg = config.get("yamllint") if isinstance(config.get("yamllint"), dict) else {}
    file_rules = yamllint_cfg.get("files", []) if isinstance(yamllint_cfg, dict) else []
    rule_paths = [
        str(rule.get("path"))
        for rule in file_rules
        if isinstance(rule, dict) and isinstance(rule.get("path"), str)
    ]
    if rule_paths != sorted(rule_paths):
        print("error: .github/lint-c-cpp.yaml yamllint.files must be sorted by path", file=sys.stderr)
        return 1
    by_path = {
        str(rule.get("path")): rule
        for rule in file_rules
        if isinstance(rule, dict) and isinstance(rule.get("path"), str)
    }
    failures = 0
    count = 0
    for yaml_path in yaml_paths:
        count += 1
        rel = yaml_path.relative_to(repo_root).as_posix()
        rule = by_path.get(rel, {})
        if rule.get("schema") == "spec_traceability":
            failures += int(lint_one_spec_manifest(yaml_path, args) != 0)
            continue
        if rule.get("schema") == "lint_config":
            failures += int(lint_one_lint_config_manifest(yaml_path, rule, args) != 0)
            continue
        try:
            yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            print(f"error: {rel}: invalid YAML: {exc}", file=sys.stderr)
            failures += 1
    if failures:
        return 1
    print(yamllint_ok_message(count))
    return 0

