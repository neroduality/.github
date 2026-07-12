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

"""Ensure source files carry the repository license header from the consumer manifest."""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from consumer_manifest import manifest_path
from format_fail_on_change import fail_if_repaired, formatter_ok_message
from policy_config import PolicyConfig
from scan_policy import license_header_classify

_LICENSE_LINES: list[str] | None = None
_HOLDER: str | None = None
_LAST_LINE: str | None = None
_SPDX_LINE: str | None = None

_SELF_TEST_LICENSE_BLOB = """\
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
"""


def _year() -> int:
    return datetime.now(UTC).year


def _require_configured() -> None:
    if _LICENSE_LINES is None:
        print(
            "error: license_header is not configured (set it in .github/lint-c-cpp.yaml)",
            file=sys.stderr,
        )
        raise SystemExit(2)


def _md_header_rx() -> re.Pattern[str]:
    _require_configured()
    spdx = re.escape(_SPDX_LINE or "SPDX-License-Identifier:")
    return re.compile(rf"^<!-- {spdx} -->\s*\r?\n<!--\r?\n(.*?)\r?\n-->\s*", re.DOTALL)


def _strip_config_comment_marker(line: str) -> str:
    stripped = line.lstrip()
    for marker in ("#", "//"):
        if stripped == marker:
            return ""
        if stripped.startswith(marker + " "):
            return stripped[len(marker) + 1 :]
        if stripped.startswith(marker):
            return stripped[len(marker) :]
    return line.rstrip()


def _extract_holder(lines: list[str]) -> str | None:
    """Copyright holder from the configured license blob's Copyright line."""
    for line in lines:
        match = re.search(r"Copyright \(C\)\s+(?:\{year\}|\d{4})\s+(.+)", line)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return None


def _apply_license_blob(license_blob: str) -> None:
    lines = [_strip_config_comment_marker(line) for line in license_blob.splitlines()]
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        print("error: license_header must contain at least one line", file=sys.stderr)
        raise SystemExit(2)
    global _LICENSE_LINES, _HOLDER, _LAST_LINE, _SPDX_LINE
    _LICENSE_LINES = lines
    _SPDX_LINE = next(
        (line for line in lines if line.startswith("SPDX-License-Identifier:")),
        None,
    )
    holder = _extract_holder(lines)
    _HOLDER = holder
    nonempty = [line for line in lines if line.strip()]
    _LAST_LINE = nonempty[-1] if nonempty else None


def _load_yaml_mapping(path: Path) -> dict:
    try:
        import yaml
    except ImportError:
        print(f"error: PyYAML is required to read {path}", file=sys.stderr)
        raise SystemExit(2)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def configure_from_manifest(repo_root: Path) -> None:
    """Load license text from .github/lint-c-cpp.yaml (required for consumer repos)."""
    manifest = repo_root / ".github" / "lint-c-cpp.yaml"
    if not manifest.is_file():
        print(f"error: missing {manifest_path(repo_root)}", file=sys.stderr)
        raise SystemExit(2)
    data = _load_yaml_mapping(manifest)
    license_blob = data.get("license_header")
    if not isinstance(license_blob, str) or not license_blob.strip():
        print(
            f"error: {manifest_path(repo_root)} license_header must be a non-empty string",
            file=sys.stderr,
        )
        raise SystemExit(2)
    _apply_license_blob(license_blob)
    scan = data.get("scan") if isinstance(data.get("scan"), dict) else {}
    if scan.get("exclude_dirs") or scan.get("exclude_files"):
        unknown = []
        if scan.get("exclude_dirs"):
            unknown.append("exclude_dirs")
        if scan.get("exclude_files"):
            unknown.append("exclude_files")
        print(
            f"error: {manifest_path(repo_root)} unknown scan fields: {', '.join(unknown)} "
            f"(allowed: {', '.join(sorted(['c_api_prefix', 'c_macro_prefix', 'exclude_gitignore', 'public_headers_dir', 'source_roots']))})",
            file=sys.stderr,
        )
        raise SystemExit(2)


def _configured_lines(year: int) -> list[str]:
    _require_configured()
    return [line.format(year=year) for line in _LICENSE_LINES or []]


def _prefixed_header_text(year: int, prefix: str) -> str:
    rendered = []
    for line in _configured_lines(year):
        rendered.append(prefix if line == "" else f"{prefix} {line}")
    rendered.extend(["", ""])
    return "\n".join(rendered)


def hash_header_text(year: int) -> str:
    return _prefixed_header_text(year, "#")


def cpp_header_text(year: int) -> str:
    return _prefixed_header_text(year, "//")


def md_header_text(year: int) -> str:
    lines = _configured_lines(year)
    spdx = (
        lines[0]
        if lines and lines[0].startswith("SPDX-License-Identifier:")
        else (_SPDX_LINE or "")
    )
    inner_lines = lines[1:] if lines and lines[0].startswith("SPDX-License-Identifier:") else lines
    while inner_lines and inner_lines[0] == "":
        inner_lines = inner_lines[1:]
    inner = "\n".join(inner_lines)
    return f"<!-- {spdx} -->\n<!--\n{inner}\n-->\n\n"


@dataclass(frozen=True)
class FileKind:
    style: str


def classify(path: Path) -> FileKind | None:
    kind = license_header_classify(path)
    return FileKind(kind.style) if kind is not None else None


def _strip_comment_content(ln: str, prefix: str) -> str | None:
    if prefix == "#":
        if not ln.startswith("#"):
            return None
        if ln == "#":
            return ""
        return ln[2:] if ln.startswith("# ") else ln[1:]
    stripped = ln.strip()
    if not stripped.startswith("//"):
        return None
    if stripped == "//":
        return ""
    return stripped[3:] if stripped.startswith("// ") else stripped[2:]


def _line_present(line: str, text: str) -> bool:
    if line in text:
        return True
    stripped = line.strip()
    return bool(stripped and stripped in text)


def _markers_ok(text: str, *, require_spdx: bool = True, skip_spdx: bool = False) -> bool:
    _require_configured()
    year_match = re.search(r"Copyright \(C\)\s+(\d{4})", text)
    year = int(year_match.group(1)) if year_match else _year()
    for line in _configured_lines(year):
        if not line.strip():
            continue
        if skip_spdx and line.startswith("SPDX-License-Identifier:"):
            continue
        if not _line_present(line, text):
            return False
    if require_spdx and _SPDX_LINE and _SPDX_LINE not in text:
        return False
    return True


def _markers_ok_md_inner(text: str) -> bool:
    return _markers_ok(text, require_spdx=False, skip_spdx=True)


def _markers_ok_plain(text: str) -> bool:
    return _markers_ok(text)


def _is_license_inner(inner: str) -> bool:
    _require_configured()
    s = inner.strip()
    if s == "":
        return True
    for line in _LICENSE_LINES or []:
        stripped = line.strip()
        if not stripped:
            continue
        pattern = "^" + re.escape(stripped).replace(re.escape("{year}"), r"\d{4}") + "$"
        if re.match(pattern, s):
            return True
    if _LAST_LINE:
        formatted_last = _LAST_LINE.format(year=_year())
        if formatted_last in s or _LAST_LINE in s:
            return True
    return False


def _last_line_in_raw(raw: str, year: int) -> bool:
    if not _LAST_LINE:
        return False
    formatted = _LAST_LINE.format(year=year)
    return formatted in raw or _LAST_LINE in raw


def _comment_inner_ok(block: list[str], prefix: str) -> bool:
    parts: list[str] = []
    for ln in block:
        inner = _strip_comment_content(ln, prefix)
        if inner is None:
            return False
        parts.append(inner)
    return _markers_ok_plain("\n".join(parts))


def _scan_comment_license_extent(
    lines: list[str], spdx_idx: int, prefix: str, year: int
) -> tuple[int, bool]:
    k = spdx_idx
    while k < len(lines):
        raw = lines[k]
        if prefix != "#" and raw.strip() == "":
            break
        if prefix == "#":
            if not raw.startswith("#"):
                break
            inner = _strip_comment_content(raw, prefix)
        else:
            if not raw.lstrip().startswith("//"):
                break
            inner = _strip_comment_content(raw, prefix)
        if inner is None:
            break
        if _last_line_in_raw(raw, year):
            return k + 1, True
        if _is_license_inner(inner):
            k += 1
            continue
        break
    return k, False


def _repair_line_comment(
    content: str, year: int, *, prefix: str, shebang: bool = False
) -> tuple[str, bool]:
    lines = content.splitlines()
    trailing_nl = content.endswith("\n") if content else True
    out_prefix: list[str] = []
    i = 0
    if shebang and lines and lines[0].startswith("#!"):
        out_prefix.append(lines[0])
        i = 1
    while i < len(lines) and lines[i].strip() == "":
        i += 1

    spdx_idx = None
    for j in range(i, min(len(lines), i + 40)):
        line = lines[j]
        if prefix == "#":
            if line.startswith("# SPDX-License-Identifier:"):
                spdx_idx = j
                break
        elif line.lstrip().startswith("// SPDX-License-Identifier:"):
            spdx_idx = j
            break

    header_lines = (hash_header_text if prefix == "#" else cpp_header_text)(year).splitlines()
    if spdx_idx is None:
        merged = out_prefix + header_lines + lines[i:]
    else:
        end_exclusive, complete = _scan_comment_license_extent(lines, spdx_idx, prefix, year)
        if complete and _comment_inner_ok(lines[spdx_idx:end_exclusive], prefix):
            return content, False
        merged = out_prefix + header_lines + lines[end_exclusive:]

    text = "\n".join(merged)
    if trailing_nl or text == "":
        text += "\n"
    return text, True


def repair_hash(content: str, year: int) -> tuple[str, bool]:
    return _repair_line_comment(content, year, prefix="#", shebang=True)


def repair_cpp(content: str, year: int) -> tuple[str, bool]:
    return _repair_line_comment(content, year, prefix="//")


def repair_md(content: str, year: int) -> tuple[str, bool]:
    bom = ""
    if content.startswith("\ufeff"):
        bom = "\ufeff"
    body = content[len(bom) :]

    m = _md_header_rx().match(body)
    if m is not None and _markers_ok_md_inner(m.group(1)):
        return content, False

    fresh = md_header_text(year)
    if m is not None:
        new_body = fresh + body[m.end() :].lstrip("\n")
    else:
        new_body = fresh + body.lstrip("\n")

    out = bom + new_body
    if content.endswith("\n") or not content:
        if not out.endswith("\n"):
            out += "\n"
    return out, True


def process_file(path: Path, year: int, dry_run: bool) -> bool:
    kind = classify(path)
    if kind is None:
        return False
    text = path.read_text(encoding="utf-8")
    if kind.style == "hash":
        new_text, changed = repair_hash(text, year)
    elif kind.style == "cpp":
        new_text, changed = repair_cpp(text, year)
    else:
        new_text, changed = repair_md(text, year)

    if not changed:
        return False
    if dry_run:
        print(f"would update: {path}", file=sys.stderr)
        return True
    path.write_text(new_text, encoding="utf-8", newline="\n")
    print(f"updated: {path}", file=sys.stderr)
    return True


def iter_targets(paths: list[Path]) -> list[Path]:
    return [path for path in paths if classify(path) is not None]


def run(config: PolicyConfig, paths: list[Path], extras: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--fail-on-change", action="store_true")
    args = parser.parse_args(extras)
    if args.check and args.fail_on_change:
        print("error: --check and --fail-on-change are mutually exclusive", file=sys.stderr)
        return 2

    if not config.license_header:
        print(
            "error: license_header is not configured (set it in .github/lint-c-cpp.yaml)",
            file=sys.stderr,
        )
        return 2
    _apply_license_blob(config.license_header)
    year = _year()
    dry_run = args.dry_run or args.check
    targets = iter_targets(paths)
    scanned = len(targets)
    changed_count = 0
    for path in targets:
        if process_file(path, year, dry_run):
            changed_count += 1
    if args.check and changed_count > 0:
        print(
            f"error: {changed_count} file(s) missing or incomplete SPDX header "
            "(run without --check to fix)",
            file=sys.stderr,
        )
        return 1
    if args.fail_on_change and changed_count > 0:
        return fail_if_repaired(
            detail=f"repaired SPDX headers in {changed_count} file(s)",
            changed_count=changed_count,
        )
    print(formatter_ok_message("license headers", scanned, 0))
    return 0


def run_self_test() -> int:
    _apply_license_blob(_SELF_TEST_LICENSE_BLOB)
    year = 2026
    failures: list[str] = []

    repaired, changed = repair_hash("#!/usr/bin/env bash\necho ok\n", year)
    if not changed or not repaired.startswith("#!/usr/bin/env bash\n# SPDX-License-Identifier:"):
        failures.append("hash repair must preserve shebang and insert header")
    same, changed = repair_hash(repaired, year)
    if changed or same != repaired:
        failures.append("hash repair must be idempotent")

    repaired_cpp, changed = repair_cpp("int main(void) { return 0; }\n", year)
    if not changed or not repaired_cpp.startswith("// SPDX-License-Identifier:"):
        failures.append("C/C++ repair must insert // header")
    _, changed = repair_cpp(repaired_cpp, year)
    if changed:
        failures.append("C/C++ repair must be idempotent")

    repaired_md, changed = repair_md("# Title\n", year)
    if not changed or not repaired_md.startswith("<!-- SPDX-License-Identifier: Apache-2.0 -->"):
        failures.append("Markdown repair must insert HTML-comment header")
    _, changed = repair_md(repaired_md, year)
    if changed:
        failures.append("Markdown repair must be idempotent")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".gitignore").write_text("third-party/\n", encoding="utf-8")
        keep = root / "third-party" / "vendor.c"
        scan = root / "src.c"
        keep.parent.mkdir(parents=True)
        keep.write_text("int vendor;\n", encoding="utf-8")
        scan.write_text("int project;\n", encoding="utf-8")

        targets = {
            path.name
            for path in iter_targets([scan])
        }
        if "vendor.c" in targets:
            failures.append("target walk must honor .gitignore directory pruning")
        if "src.c" not in targets:
            failures.append("target walk must include project source")

    if failures:
        print("license-headers self-test failures:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("license-headers self-test: OK")
    return 0

