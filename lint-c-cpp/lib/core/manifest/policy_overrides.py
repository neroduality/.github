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

"""policy.overrides: repo-wide add/remove plus optional by_compile_db dials."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

OVERRIDE_CONFIG_KEYS = (
    "clang-format",
    "clang-tidy-c",
    "clang-tidy-cxx",
    "clang-tidy-shared-c-cxx",
    "clang-tidy-unsafe-c",
    "clang-tidy-unsafe-cxx",
    "cppcheck",
    "openssf-hardening",
)
OVERRIDE_CONFIG_KEY_SET = frozenset(OVERRIDE_CONFIG_KEYS)
OVERRIDE_ENTRY_KEYS = frozenset({"add", "remove", "by_compile_db"})
OVERRIDE_BY_COMPILE_DB_ENTRY_KEYS = frozenset({"compile_commands_json", "add", "remove"})

_CLANG_TIDY_CONFIG_BY_OVERRIDE = {
    "clang-tidy-c": ".clang-tidy-c",
    "clang-tidy-cxx": ".clang-tidy-cxx",
    "clang-tidy-shared-c-cxx": ".clang-tidy-shared-c-cxx",
    "clang-tidy-unsafe-c": ".clang-tidy-unsafe-c",
    "clang-tidy-unsafe-cxx": ".clang-tidy-unsafe-cxx",
}
OVERRIDE_KEY_BY_CLANG_TIDY_CONFIG = {
    config: key for key, config in _CLANG_TIDY_CONFIG_BY_OVERRIDE.items()
}

_CHECKS_SPLIT_RE = re.compile(r"[\s,]+")


def _declared_compile_commands_json(repo_root: Path) -> frozenset[str]:
    from consumer_manifest import compile_db_firmware_entries, compile_db_userspace_entries

    paths: set[str] = set()
    for entry in compile_db_firmware_entries(repo_root):
        paths.add(str(entry["compile_commands_json"]))
    for entry in compile_db_userspace_entries(repo_root):
        paths.add(str(entry["compile_commands_json"]))
    return frozenset(paths)


def _validate_add_remove(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        return [f"{label} must be null or a non-empty list of non-empty strings"]
    if not all(isinstance(item, str) and item.strip() for item in value):
        return [f"{label} entries must be non-empty strings"]
    return []


def validate_policy_overrides(data: dict[str, Any], manifest_path: Path, repo_root: Path) -> list[str]:
    policy = data.get("policy")
    if not isinstance(policy, dict):
        return []
    block = policy.get("overrides")
    if block is None:
        return [f"{manifest_path}: policy.overrides is required"]
    if not isinstance(block, dict):
        return [f"{manifest_path}: policy.overrides must be a mapping"]

    issues: list[str] = []
    unknown = sorted(key for key in block if key not in OVERRIDE_CONFIG_KEY_SET)
    if unknown:
        issues.append(
            f"{manifest_path}: unknown policy.overrides keys: {', '.join(unknown)} "
            f"(allowed: {', '.join(OVERRIDE_CONFIG_KEYS)})"
        )
    missing = [key for key in OVERRIDE_CONFIG_KEYS if key not in block]
    if missing:
        issues.append(
            f"{manifest_path}: policy.overrides missing required keys: {', '.join(missing)}"
        )

    declared = _declared_compile_commands_json(repo_root)
    for key in OVERRIDE_CONFIG_KEYS:
        if key not in block:
            continue
        entry = block[key]
        label = f"policy.overrides.{key}"
        if not isinstance(entry, dict):
            issues.append(f"{manifest_path}: {label} must be a mapping")
            continue
        entry_unknown = sorted(k for k in entry if k not in OVERRIDE_ENTRY_KEYS)
        if entry_unknown:
            issues.append(
                f"{manifest_path}: unknown {label} fields: {', '.join(entry_unknown)} "
                "(allowed: add, remove, by_compile_db)"
            )
        missing_entry = sorted(k for k in OVERRIDE_ENTRY_KEYS if k not in entry)
        if missing_entry:
            issues.append(
                f"{manifest_path}: {label} missing required keys: {', '.join(missing_entry)} "
                "(use null if unused)"
            )
        issues.extend(
            f"{manifest_path}: {msg}"
            for msg in _validate_add_remove(entry.get("add"), f"{label}.add")
        )
        issues.extend(
            f"{manifest_path}: {msg}"
            for msg in _validate_add_remove(entry.get("remove"), f"{label}.remove")
        )
        if "by_compile_db" not in entry:
            continue
        by_db = entry.get("by_compile_db")
        if by_db is None:
            continue
        if not isinstance(by_db, list) or not by_db:
            issues.append(
                f"{manifest_path}: {label}.by_compile_db must be a non-empty list or null"
            )
            continue
        seen_json: set[str] = set()
        for index, item in enumerate(by_db):
            item_label = f"{label}.by_compile_db[{index}]"
            if not isinstance(item, dict):
                issues.append(f"{manifest_path}: {item_label} must be a mapping")
                continue
            item_unknown = sorted(k for k in item if k not in OVERRIDE_BY_COMPILE_DB_ENTRY_KEYS)
            if item_unknown:
                issues.append(
                    f"{manifest_path}: unknown {item_label} fields: {', '.join(item_unknown)}"
                )
            raw_json = item.get("compile_commands_json")
            if not isinstance(raw_json, str) or not raw_json.strip():
                issues.append(
                    f"{manifest_path}: {item_label}.compile_commands_json must be a non-empty string"
                )
            else:
                rel = Path(raw_json.strip()).as_posix()
                if rel in seen_json:
                    issues.append(
                        f"{manifest_path}: {item_label}.compile_commands_json duplicate {rel!r}"
                    )
                seen_json.add(rel)
                if rel not in declared:
                    issues.append(
                        f"{manifest_path}: {item_label}.compile_commands_json {rel!r} "
                        "is not declared under compile_db.firmware or compile_db.userspace"
                    )
            if "add" not in item:
                issues.append(f"{manifest_path}: {item_label}.add is required (use null if none)")
            else:
                issues.extend(
                    f"{manifest_path}: {msg}"
                    for msg in _validate_add_remove(item.get("add"), f"{item_label}.add")
                )
            if "remove" not in item:
                issues.append(f"{manifest_path}: {item_label}.remove is required (use null if none)")
            else:
                issues.extend(
                    f"{manifest_path}: {msg}"
                    for msg in _validate_add_remove(item.get("remove"), f"{item_label}.remove")
                )
    return issues


def policy_overrides(repo_root: Path) -> dict[str, Any]:
    from consumer_manifest import policy_block

    block = policy_block(repo_root).get("overrides")
    return block if isinstance(block, dict) else {}


def override_tokens(entry: dict[str, Any], key: str) -> tuple[str, ...] | None:
    raw = entry.get(key)
    if raw is None:
        return None
    if not isinstance(raw, list):
        return None
    return tuple(str(item).strip() for item in raw if isinstance(item, str) and item.strip())


def global_override_dials(repo_root: Path, config_key: str) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None]:
    entry = policy_overrides(repo_root).get(config_key)
    if not isinstance(entry, dict):
        return None, None
    return override_tokens(entry, "add"), override_tokens(entry, "remove")


def _merge_override_token_lists(
    *groups: tuple[str, ...] | None,
) -> tuple[str, ...] | None:
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        if not group:
            continue
        for token in group:
            if token in seen:
                continue
            seen.add(token)
            merged.append(token)
    return tuple(merged) if merged else None


def _by_compile_db_entries(repo_root: Path, config_key: str) -> list[dict[str, Any]]:
    entry = policy_overrides(repo_root).get(config_key)
    if not isinstance(entry, dict):
        return []
    block = entry.get("by_compile_db")
    if not isinstance(block, list):
        return []
    return [item for item in block if isinstance(item, dict)]


def config_has_by_compile_db(repo_root: Path, config_key: str) -> bool:
    return bool(_by_compile_db_entries(repo_root, config_key))


def _source_key_in_compile_db(repo_root: Path, compile_commands_json: str, lookup_key: str) -> bool:
    from repo_paths import source_key

    path = (repo_root.resolve() / compile_commands_json).resolve()
    if not path.is_file():
        return False
    try:
        rows = __import__("json").loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(rows, list):
        return False
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = source_key(row.get("file", ""), repo_root)
        if key == lookup_key:
            return True
    return False


def _declared_compile_db_kinds(repo_root: Path) -> list[tuple[str, str]]:
    """``(compile_commands_json, kind)`` with kind in ``firmware`` | ``userspace``."""
    from consumer_manifest import compile_db_firmware_entries, compile_db_userspace_entries

    rows: list[tuple[str, str]] = []
    for entry in compile_db_firmware_entries(repo_root):
        rows.append((str(entry["compile_commands_json"]), "firmware"))
    for entry in compile_db_userspace_entries(repo_root):
        rows.append((str(entry["compile_commands_json"]), "userspace"))
    return rows


def compile_commands_jsons_containing_source(
    repo_root: Path, lookup_key: str
) -> list[str]:
    """All declared ``compile_commands_json`` paths that list ``lookup_key``."""
    repo_root = repo_root.resolve()
    out: list[str] = []
    for rel, _kind in _declared_compile_db_kinds(repo_root):
        if _source_key_in_compile_db(repo_root, rel, lookup_key):
            out.append(Path(rel).as_posix())
    return out


def compile_commands_jsons_covering_source(
    repo_root: Path, lookup_key: str
) -> list[str]:
    """Declared databases containing a source or owning its manifest source root.

    Headers normally receive synthesized compile entries and therefore are not
    present in an original database. In that case every profile whose ``source``
    root covers the header is its provenance for per-database policy.
    """
    exact = compile_commands_jsons_containing_source(repo_root, lookup_key)
    if exact:
        return exact
    from consumer_manifest import compile_db_firmware_entries, compile_db_userspace_entries

    out: list[str] = []
    for entry in (*compile_db_firmware_entries(repo_root), *compile_db_userspace_entries(repo_root)):
        source = Path(str(entry.get("source", "")).strip()).as_posix().strip("/")
        if not source:
            continue
        if source == "." or lookup_key == source or lookup_key.startswith(f"{source}/"):
            rel = Path(str(entry["compile_commands_json"])).as_posix()
            if rel not in out:
                out.append(rel)
    return out


def owning_compile_commands_json(
    repo_root: Path,
    lookup_key: str,
    *,
    preferred_compile_db: str | None = None,
    provenance: list[str] | None = None,
) -> str | None:
    """Owning manifest ``compile_commands_json`` for a source key (plan merge rule).

    When ``preferred_compile_db`` is set (per-profile audit), that DB wins if it
    lists the source. When ``provenance`` lists DBs that contained the source,
    overrides are resolved against a provenance member rather than an arbitrary
    first match. Paths under ``firmware_compile_source_roots`` otherwise prefer a
    firmware DB that lists the key. ``tests/firmware/…`` stays on the
    tests/userspace DB. Otherwise prefer a userspace DB that lists the key.
    """
    from consumer_manifest import firmware_compile_source_roots

    repo_root = repo_root.resolve()
    if preferred_compile_db is not None:
        preferred = Path(preferred_compile_db).as_posix()
        if _source_key_in_compile_db(repo_root, preferred, lookup_key):
            return preferred
    containing: list[tuple[str, str]] = []
    for rel, kind in _declared_compile_db_kinds(repo_root):
        if _source_key_in_compile_db(repo_root, rel, lookup_key):
            containing.append((Path(rel).as_posix(), kind))
    if not containing:
        if provenance:
            declared = {
                Path(rel).as_posix() for rel, _kind in _declared_compile_db_kinds(repo_root)
            }
            for item in provenance:
                candidate = Path(item).as_posix()
                if candidate in declared:
                    return candidate
        return None
    if provenance:
        prov = {Path(item).as_posix() for item in provenance if item}
        for rel, _kind in containing:
            if rel in prov:
                # Prefer firmware provenance when the source is under firmware roots.
                roots = firmware_compile_source_roots(repo_root)
                prefer_firmware = any(
                    lookup_key == root or lookup_key.startswith(f"{root}/") for root in roots
                )
                if prefer_firmware:
                    for cand, kind in containing:
                        if cand in prov and kind == "firmware":
                            return cand
                for cand, kind in containing:
                    if cand in prov and kind == "userspace":
                        return cand
                return next(rel for rel, _ in containing if rel in prov)
    roots = firmware_compile_source_roots(repo_root)
    prefer_firmware = any(
        lookup_key == root or lookup_key.startswith(f"{root}/") for root in roots
    )
    if prefer_firmware:
        for rel, kind in containing:
            if kind == "firmware":
                return rel
    else:
        for rel, kind in containing:
            if kind == "userspace":
                return rel
    return containing[0][0]


def override_dials_for_source(
    repo_root: Path,
    config_key: str,
    lookup_key: str | None = None,
    *,
    preferred_compile_db: str | None = None,
    provenance: list[str] | None = None,
) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None]:
    """Global add/remove plus the ``by_compile_db`` entry for the owning compile DB."""
    owner = None
    if lookup_key is not None:
        owner = owning_compile_commands_json(
            repo_root,
            lookup_key,
            preferred_compile_db=preferred_compile_db,
            provenance=provenance,
        )
    return override_dials_for_compile_db(repo_root, config_key, owner)


def override_dials_for_compile_db(
    repo_root: Path,
    config_key: str,
    compile_commands_json: str | None,
) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None]:
    """Global add/remove plus ``by_compile_db`` dials for one compile DB path."""
    add, remove = global_override_dials(repo_root, config_key)
    if compile_commands_json is None:
        return add, remove
    owner = Path(compile_commands_json).as_posix()
    for item in _by_compile_db_entries(repo_root, config_key):
        raw_json = item.get("compile_commands_json")
        if not isinstance(raw_json, str) or not raw_json.strip():
            continue
        if Path(raw_json.strip()).as_posix() != owner:
            continue
        return (
            _merge_override_token_lists(add, override_tokens(item, "add")),
            _merge_override_token_lists(remove, override_tokens(item, "remove")),
        )
    return add, remove


def openssf_override_dials_for_source(
    repo_root: Path,
    lookup_key: str | None = None,
    *,
    preferred_compile_db: str | None = None,
    provenance: list[str] | None = None,
) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None]:
    """Global + owning-DB ``openssf-hardening`` dials (firmware-prefer ownership)."""
    return override_dials_for_source(
        repo_root,
        "openssf-hardening",
        lookup_key,
        preferred_compile_db=preferred_compile_db,
        provenance=provenance,
    )


def apply_openssf_coverage_flag_overrides(
    manifest: dict[str, Any],
    *,
    add: tuple[str, ...] | None,
    remove: tuple[str, ...] | None,
) -> dict[str, Any]:
    """Return a deep-copied manifest with coverage flag/definition dials applied.

    Audit / hardeninglint use this; dialed Hardening.cmake generate also filters emit
    lists to the same coverage set (build ground truth). Kit undialed cmake/ stays FULL.
    """
    import copy

    if not add and not remove:
        return manifest
    out = copy.deepcopy(manifest)
    coverage = out.get("coverage")
    if not isinstance(coverage, dict):
        return out
    flags = coverage.get("flags")
    if not isinstance(flags, list):
        return out
    flag_strs = [str(item) for item in flags]
    definitions = coverage.get("definitions")
    definition_strs = (
        [str(item) for item in definitions] if isinstance(definitions, list) else []
    )
    if remove:
        drop = set(remove)
        flag_strs = [item for item in flag_strs if item not in drop]
        definition_strs = [item for item in definition_strs if item not in drop]
    if add:
        for item in add:
            if item.startswith("-") or item.startswith("LINKER:"):
                if item not in flag_strs:
                    flag_strs.append(item)
            elif item not in definition_strs:
                definition_strs.append(item)
    coverage["definitions"] = definition_strs
    coverage["flags"] = flag_strs
    return out


def openssf_manifest_for_audit(
    repo_root: Path,
    kit_manifest: dict[str, Any],
    *,
    lookup_key: str | None = None,
    preferred_compile_db: str | None = None,
    provenance: list[str] | None = None,
) -> dict[str, Any]:
    """Kit OpenSSF manifest with consumer ``policy.overrides.openssf-hardening`` applied."""
    add, remove = openssf_override_dials_for_source(
        repo_root,
        lookup_key,
        preferred_compile_db=preferred_compile_db,
        provenance=provenance,
    )
    return apply_openssf_coverage_flag_overrides(kit_manifest, add=add, remove=remove)


def compile_db_override_slug(compile_commands_json: str) -> str:
    """Filesystem-safe slug for a ``compile_commands_json`` path."""
    return Path(compile_commands_json).as_posix().replace("/", "__").replace(".", "_")


def materialize_clang_tidy_config_for_compile_db(
    repo_root: Path,
    *,
    base_config_name: str,
    base_text: str,
    out_path: Path,
    compile_commands_json: str | None,
) -> Path:
    """Write a clang-tidy config with global + owning-DB Checks dials applied."""
    override_key = OVERRIDE_KEY_BY_CLANG_TIDY_CONFIG.get(base_config_name)
    if override_key is None:
        out_path.write_text(base_text, encoding="utf-8")
        return out_path
    add, remove = override_dials_for_compile_db(
        repo_root, override_key, compile_commands_json
    )
    text = apply_clang_tidy_checks_overrides(base_text, add=add, remove=remove)
    out_path.write_text(text, encoding="utf-8")
    return out_path


def apply_cppcheck_cli_dials(
    enable: list[str],
    suppressions: list[str],
    *,
    add: tuple[str, ...] | None,
    remove: tuple[str, ...] | None,
) -> tuple[list[str], list[str]]:
    """Apply cppcheck override tokens to enable/suppress lists."""
    enable = list(enable)
    suppressions = list(suppressions)
    if remove:
        drop = set(remove)
        enable = [item for item in enable if item not in drop]
        suppressions = [item for item in suppressions if item not in drop] + [
            item for item in remove if item not in enable and item not in suppressions
        ]
    if add:
        for item in add:
            if item.startswith("--enable="):
                name = item.split("=", 1)[-1]
                if name not in enable:
                    enable.append(name)
            elif item in enable:
                continue
            elif item not in suppressions:
                if item not in enable:
                    enable.append(item)
    return enable, suppressions


def _normalize_check_token(token: str, *, disable: bool) -> str:
    name = token.strip()
    if not name:
        return name
    if disable:
        return name if name.startswith("-") else f"-{name}"
    return name[1:] if name.startswith("-") else name


def apply_clang_tidy_checks_overrides(text: str, *, add: tuple[str, ...] | None, remove: tuple[str, ...] | None) -> str:
    if not add and not remove:
        return text
    match = re.search(r"(?ms)^(Checks:\s*>\s*\n)(.*?)(\n\n|\nWarningsAsErrors:)", text)
    if match is None:
        match = re.search(r"(?ms)^(Checks:\s*)(.*?)(\n\n|\nWarningsAsErrors:)", text)
    if match is None:
        return text
    prefix, body, suffix = match.group(1), match.group(2), match.group(3)
    tokens = [part for part in _CHECKS_SPLIT_RE.split(body) if part]
    normalized: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        key = token.lstrip("-")
        if key in seen:
            continue
        seen.add(key)
        normalized.append(token)
    if remove:
        drop = {tok.lstrip("-") for tok in remove}
        normalized = [tok for tok in normalized if tok.lstrip("-") not in drop]
        for tok in remove:
            name = _normalize_check_token(tok, disable=True)
            key = name.lstrip("-")
            if key not in {t.lstrip("-") for t in normalized}:
                normalized.append(name)
                seen.add(key)
    if add:
        for tok in add:
            name = _normalize_check_token(tok, disable=False)
            key = name.lstrip("-")
            normalized = [t for t in normalized if t.lstrip("-") != key]
            normalized.append(name)
            seen.add(key)
    rendered = ",\n  ".join(normalized)
    if prefix.rstrip().endswith(">"):
        new_body = f"  {rendered},\n"
    else:
        new_body = rendered
    return text[: match.start()] + prefix + new_body + suffix + text[match.end() :]


def apply_clang_format_style_overrides(
    text: str,
    *,
    add: tuple[str, ...] | None,
    remove: tuple[str, ...] | None,
) -> str:
    """Apply style-option add/remove to a ``.clang-format`` body."""
    if not add and not remove:
        return text
    lines = text.splitlines(keepends=True)
    if remove:
        drop_keys = {tok.split(":", 1)[0].strip() for tok in remove}
        lines = [
            line
            for line in lines
            if not (
                ":" in line
                and not line.lstrip().startswith("#")
                and line.split(":", 1)[0].strip() in drop_keys
            )
        ]
    if add:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] = lines[-1] + "\n"
        for tok in add:
            lines.append(tok if tok.endswith("\n") else f"{tok}\n")
    return "".join(lines)


def materialize_override_configs(repo_root: Path, lint_kit: Path, out_dir: Path) -> Path:
    """Copy kit configs into out_dir applying global policy.overrides add/remove.

    Per-``by_compile_db`` dials are applied when clang-tidy/cppcheck/OpenSSF select the
    owning compile DB (firmware-prefer merge ownership). Global dials are always applied
    here. For clang-format, global lands in ``.clang-format`` and each ``by_compile_db``
    entry also gets ``.clang-format.by-<slug>`` (global + that DB's dials).
    """
    from consumer_manifest import clang_tidy_header_filter_regex

    repo_root = repo_root.resolve()
    lint_kit = lint_kit.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # clang-format
    fmt_src = lint_kit / "config" / ".clang-format"
    kit_fmt = fmt_src.read_text(encoding="utf-8")
    add, remove = global_override_dials(repo_root, "clang-format")
    (out_dir / ".clang-format").write_text(
        apply_clang_format_style_overrides(kit_fmt, add=add, remove=remove),
        encoding="utf-8",
    )
    for item in _by_compile_db_entries(repo_root, "clang-format"):
        raw_json = item.get("compile_commands_json")
        if not isinstance(raw_json, str) or not raw_json.strip():
            continue
        owner = Path(raw_json.strip()).as_posix()
        db_add, db_remove = override_dials_for_compile_db(repo_root, "clang-format", owner)
        slug = compile_db_override_slug(owner)
        (out_dir / f".clang-format.by-{slug}").write_text(
            apply_clang_format_style_overrides(kit_fmt, add=db_add, remove=db_remove),
            encoding="utf-8",
        )

    # clang-tidy overlays (HeaderFilter applied by compile_db_lint; Checks here)
    for override_key, config_name in _CLANG_TIDY_CONFIG_BY_OVERRIDE.items():
        add, remove = global_override_dials(repo_root, override_key)
        text = (lint_kit / "config" / config_name).read_text(encoding="utf-8")
        text = apply_clang_tidy_checks_overrides(text, add=add, remove=remove)
        (out_dir / config_name).write_text(text, encoding="utf-8")

    # cppcheck: write a small overlay sidecar for enable/suppress tokens (consumed by runner)
    add, remove = global_override_dials(repo_root, "cppcheck")
    cppcheck_overlay = {
        "add": list(add) if add else None,
        "remove": list(remove) if remove else None,
    }
    import json

    (out_dir / "cppcheck-overrides.json").write_text(
        json.dumps(cppcheck_overlay, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # openssf-hardening: copy kit manifest then strip/add coverage.flags (global dials).
    # Per-``by_compile_db`` dials are applied at compile-DB audit time (like tidy).
    add, remove = global_override_dials(repo_root, "openssf-hardening")
    import yaml

    openssf_path = lint_kit / "config" / "openssf-hardening-manifest.yaml"
    openssf_data = yaml.safe_load(openssf_path.read_text(encoding="utf-8")) or {}
    if isinstance(openssf_data, dict):
        openssf_data = apply_openssf_coverage_flag_overrides(
            openssf_data, add=add, remove=remove
        )
    if add or remove:
        (out_dir / "openssf-hardening-manifest.yaml").write_text(
            yaml.safe_dump(openssf_data, sort_keys=False),
            encoding="utf-8",
        )
    else:
        (out_dir / "openssf-hardening-manifest.yaml").write_text(
            openssf_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    # Keep a note for HeaderFilter consumers (unused here; compile_db_lint rewrites).
    _ = clang_tidy_header_filter_regex
    return out_dir


def lint_overrides_dir(repo_root: Path) -> Path:
    return repo_root.resolve() / "build" / "lint-overrides"
