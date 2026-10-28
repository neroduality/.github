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

"""Ensure source files carry the full license_header corpus from the consumer manifest.

The manifest ``license_header`` block is the sole corpus. Comment markers (``#`` /
``//``) in that blob are stripped; the checker re-applies the style for each file
kind and requires a contiguous exact match of every configured line -- not merely
an SPDX identifier.
"""

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

# Comment lines that only work at the very top of a file, so the header goes
# below them the way it goes below a shebang: Dockerfile parser directives, a
# PEP 263 encoding cookie, and Emacs / Vim modelines.
_TOP_DIRECTIVE_BODY = re.compile(
    r"(?:syntax|escape|check)\s*=|.*?coding[:=]|.*-\*-.*-\*-|(?:.*\s)?(?:vim?|ex):"
)


def _is_top_directive(line: str, prefix: str) -> bool:
    stripped = line.lstrip(" \t\f")
    if not stripped.startswith(prefix):
        return False
    body = stripped[len(prefix) :].lstrip()
    if body.startswith("SPDX-License-Identifier:"):
        return False
    return _TOP_DIRECTIVE_BODY.match(body) is not None


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
    except ImportError as err:
        print(f"error: PyYAML is required to read {path}", file=sys.stderr)
        raise SystemExit(2) from err
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
    raw_scan = data.get("scan")
    scan = raw_scan if isinstance(raw_scan, dict) else {}
    if scan.get("exclude_dirs") or scan.get("exclude_files"):
        unknown = []
        if scan.get("exclude_dirs"):
            unknown.append("exclude_dirs")
        if scan.get("exclude_files"):
            unknown.append("exclude_files")
        print(
            f"error: {manifest_path(repo_root)} unknown scan fields: {', '.join(unknown)} "
            "(allowed: c_api_prefix, c_macro_prefix, exclude_gitignore, public_headers_dir, "
            "source_roots)",
            file=sys.stderr,
        )
        raise SystemExit(2)


def _configured_lines(year: int) -> list[str]:
    _require_configured()
    return [line.format(year=year) for line in _LICENSE_LINES or []]


def _expected_comment_lines(year: int, prefix: str) -> list[str]:
    """Full license_header corpus rendered as line comments (no trailing blanks)."""
    rendered: list[str] = []
    for line in _configured_lines(year):
        rendered.append(prefix if line == "" else f"{prefix} {line}")
    return rendered


def _prefixed_header_text(year: int, prefix: str) -> str:
    # One blank line after the full corpus separates it from file body.
    return "\n".join([*_expected_comment_lines(year, prefix), "", ""])


def hash_header_text(year: int) -> str:
    return _prefixed_header_text(year, "#")


def cpp_header_text(year: int) -> str:
    return _prefixed_header_text(year, "//")


def _md_inner_lines(year: int) -> list[str]:
    lines = _configured_lines(year)
    if lines and lines[0].startswith("SPDX-License-Identifier:"):
        lines = lines[1:]
    while lines and lines[0] == "":
        lines = lines[1:]
    return lines


def md_header_text(year: int) -> str:
    lines = _configured_lines(year)
    spdx = (
        lines[0]
        if lines and lines[0].startswith("SPDX-License-Identifier:")
        else (_SPDX_LINE or "")
    )
    inner = "\n".join(_md_inner_lines(year))
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


def _md_inner_matches_corpus(inner: str, year: int) -> bool:
    """Markdown body comment must be the full configured corpus (minus SPDX line)."""
    expected = "\n".join(_md_inner_lines(year))
    return inner.strip("\n") == expected


def _is_license_inner(inner: str) -> bool:
    """True when a comment line still looks like part of a (possibly broken) header."""
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


def _scan_comment_license_extent(lines: list[str], spdx_idx: int, prefix: str) -> int:
    """End index of a SPDX-started line-comment run (for replacement)."""
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
        if inner is None or not _is_license_inner(inner):
            break
        k += 1
    return k


def _is_exact_license_line(inner: str) -> bool:
    """True only for a blank or a full corpus line. Unlike ``_is_license_inner``,
    a comment that merely contains the last corpus sentence does not match."""
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
    return False


def _license_block_qualifies(inners: list[str]) -> bool:
    """A comment run/block is a redundant license header when every line is an
    exact corpus line and it carries the SPDX tag, a Copyright line, or at least
    two corpus lines. A comment that only mentions the license stays."""
    nonblank = [s.strip() for s in inners if s.strip()]
    if not nonblank or not all(_is_exact_license_line(s) for s in nonblank):
        return False
    if any(s.startswith("SPDX-License-Identifier:") for s in nonblank):
        return True
    if any(re.match(r"Copyright \(C\)\s+\d{4}", s) for s in nonblank):
        return True
    return len(nonblank) >= 2


def _consume_line_comment_license_run(lines: list[str], start: int, marker: str) -> int | None:
    """End index (exclusive) of a license-only ``marker`` comment run at ``start``."""
    inners: list[str] = []
    k = start
    while k < len(lines):
        inner = _strip_comment_content(lines[k], marker)
        if inner is None or not _is_license_inner(inner):
            break
        inners.append(inner)
        k += 1
    return k if k > start and _license_block_qualifies(inners) else None


def _block_comment_inner(line: str) -> str:
    s = line.strip()
    if s.startswith("/*"):
        s = s[2:]
    if s.endswith("*/"):
        s = s[:-2]
    s = s.strip()
    if s.startswith("*"):
        s = s[1:].strip()
    return s


def _consume_block_comment_license(lines: list[str], start: int) -> int | None:
    """End index (exclusive) of a ``/* ... */`` block at ``start`` that is a license header."""
    if not lines[start].lstrip().startswith("/*"):
        return None
    inners: list[str] = []
    k = start
    while k < len(lines):
        raw = lines[k]
        inners.append(_block_comment_inner(raw))
        k += 1
        if "*/" in raw:
            break
    else:
        return None  # unterminated block comment: leave untouched
    return k if _license_block_qualifies(inners) else None


def _strip_duplicate_license_blocks(rest: list[str], prefix: str) -> tuple[list[str], bool]:
    """Drop redundant license headers at the head of ``rest`` (the file body after
    the canonical header). Handles a second ``//``/``#`` run and, for C/C++, one or
    more ``/* ... */`` blocks (``/* SPDX */`` followed by ``/* Copyright ... */``).
    Exactly one blank line then separates header and body."""
    j = 0
    stripped_any = False
    while True:
        while j < len(rest) and rest[j].strip() == "":
            j += 1
        if j >= len(rest):
            break
        end = _consume_line_comment_license_run(rest, j, prefix)
        if end is None and prefix != "#":
            end = _consume_block_comment_license(rest, j)
        if end is None:
            break
        j = end
        stripped_any = True
    if not stripped_any:
        return rest, False
    return rest[j:], True


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
    while i < len(lines) and _is_top_directive(lines[i], prefix):
        out_prefix.append(lines[i])
        i += 1
    while i < len(lines) and lines[i].strip() == "":
        i += 1

    expected = _expected_comment_lines(year, prefix)
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
    # The header must be the first thing after the shebang. Source found above a
    # misplaced SPDX tag is real code: the rewrite moves it below the header.
    preamble = [] if spdx_idx is None else lines[i:spdx_idx]
    while preamble and preamble[-1].strip() == "":
        preamble.pop()
    if spdx_idx is None:
        # No line-comment header: replace any block-comment header instead of
        # stacking the corpus in front of it.
        rest, _ = _strip_duplicate_license_blocks(lines[i:], prefix)
    elif lines[spdx_idx : spdx_idx + len(expected)] == expected:
        # Contiguous block equals the entire corpus; only a misplaced header or a
        # trailing duplicate header (any comment style) still needs repair.
        rest, stripped = _strip_duplicate_license_blocks(lines[spdx_idx + len(expected) :], prefix)
        if not stripped and not preamble:
            return content, False
    else:
        end_exclusive = _scan_comment_license_extent(lines, spdx_idx, prefix)
        rest, _ = _strip_duplicate_license_blocks(lines[end_exclusive:], prefix)
    if preamble:
        while rest and rest[0].strip() == "":
            rest = rest[1:]
        preamble = preamble + ([""] if rest else [])
    merged = out_prefix + header_lines + preamble + rest

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
    rest = body[m.end() :] if m is not None else body
    # Drop any further SPDX HTML-comment headers stacked after the first.
    duplicates = 0
    while True:
        dup = _md_header_rx().match(rest.lstrip("\n"))
        if dup is None:
            break
        rest = rest.lstrip("\n")[dup.end() :]
        duplicates += 1
    if m is not None and duplicates == 0 and _md_inner_matches_corpus(m.group(1), year):
        return content, False

    fresh = md_header_text(year)
    new_body = fresh + rest.lstrip("\n")

    out = bom + new_body
    if (content.endswith("\n") or not content) and not out.endswith("\n"):
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
            f"error: {changed_count} file(s) with a missing, incomplete, "
            "or duplicated license_header corpus (run without --check to fix)",
            file=sys.stderr,
        )
        return 1
    if args.fail_on_change and changed_count > 0:
        return fail_if_repaired(
            detail=f"repaired license_header corpus in {changed_count} file(s)",
            changed_count=changed_count,
        )
    print(formatter_ok_message("license headers", scanned, 0))
    return 0


def run_self_test() -> int:
    _apply_license_blob(_SELF_TEST_LICENSE_BLOB)
    year = 2026
    failures: list[str] = []
    expected_cpp = _expected_comment_lines(year, "//")
    expected_hash = _expected_comment_lines(year, "#")

    repaired, changed = repair_hash("#!/usr/bin/env bash\necho ok\n", year)
    if not changed or not repaired.startswith("#!/usr/bin/env bash\n# SPDX-License-Identifier:"):
        failures.append("hash repair must preserve shebang and insert header")
    if not all(line in repaired for line in expected_hash):
        failures.append("hash repair must insert the full license_header corpus")
    same, changed = repair_hash(repaired, year)
    if changed or same != repaired:
        failures.append("hash repair must be idempotent")

    repaired_cpp, changed = repair_cpp("int main(void) { return 0; }\n", year)
    if not changed or not repaired_cpp.startswith("// SPDX-License-Identifier:"):
        failures.append("C/C++ repair must insert // header")
    if repaired_cpp.splitlines()[: len(expected_cpp)] != expected_cpp:
        failures.append("C/C++ repair must insert the full license_header corpus")
    _, changed = repair_cpp(repaired_cpp, year)
    if changed:
        failures.append("C/C++ repair must be idempotent")

    spdx_only = "// SPDX-License-Identifier: Apache-2.0\n\nint x;\n"
    fixed_spdx_only, changed = repair_cpp(spdx_only, year)
    if not changed or fixed_spdx_only.splitlines()[: len(expected_cpp)] != expected_cpp:
        failures.append("SPDX-only header must be rejected; full corpus required")

    partial = "\n".join([*expected_cpp[:3], "", "int x;"]) + "\n"
    fixed_partial, changed = repair_cpp(partial, year)
    if not changed or fixed_partial.splitlines()[: len(expected_cpp)] != expected_cpp:
        failures.append("partial license_header corpus must be rejected")

    good_cpp = "\n".join([*expected_cpp, "", "int x;"]) + "\n"
    block_header = (
        "/* SPDX-License-Identifier: Apache-2.0 */\n"
        "/*\n"
        " * Copyright (C) 2026 Nero Duality, LLC.\n"
        " *\n"
        ' * Licensed under the Apache License, Version 2.0 (the "License");\n'
        " * limitations under the License.\n"
        " */\n"
    )
    stacked = "\n".join(expected_cpp) + "\n\n" + block_header + "\nint x;\n"
    fixed_stacked, changed = repair_cpp(stacked, year)
    if not changed or fixed_stacked != good_cpp:
        failures.append("// corpus followed by a /* */ license block must drop the duplicate")
    fixed_block_only, changed = repair_cpp(block_header + "\nint x;\n", year)
    if not changed or fixed_block_only != good_cpp:
        failures.append("/* */ license header must be replaced, not stacked under the // corpus")
    twice = "\n".join(expected_cpp) + "\n\n" + "\n".join(expected_cpp) + "\n\nint x;\n"
    fixed_twice, changed = repair_cpp(twice, year)
    if not changed or fixed_twice != good_cpp:
        failures.append("a second // license run must be dropped")
    kept = (
        "\n".join(expected_cpp)
        + "\n\n/* Harness notes: see limitations under the License. */\nint x;\n"
    )
    _, changed = repair_cpp(kept, year)
    if changed:
        failures.append("a single non-license comment echoing one corpus line must be kept")
    _, changed = repair_cpp(good_cpp, year)
    if changed:
        failures.append("duplicate-header repair must be idempotent")

    lead = '#include "cbmc.h"\n\n'
    good_lead = "\n".join([*expected_cpp, "", '#include "cbmc.h"', "", "int x;"]) + "\n"
    lead_dup = lead + "\n".join(expected_cpp) + "\n\n" + block_header + "\nint x;\n"
    fixed_lead, changed = repair_cpp(lead_dup, year)
    if not changed or fixed_lead != good_lead:
        failures.append("code before a duplicated header must move below the header")
    fixed_moved, changed = repair_cpp(lead + good_cpp, year)
    if not changed or fixed_moved != good_lead:
        failures.append("code before a correct header must move below the header")
    _, changed = repair_cpp(good_lead, year)
    if changed:
        failures.append("moved-header repair must be idempotent")
    partial_lead = lead + "// SPDX-License-Identifier: Apache-2.0\n\nint x;\n"
    fixed_partial_lead, changed = repair_cpp(partial_lead, year)
    if not changed or fixed_partial_lead != good_lead:
        failures.append("code before an incomplete header must move below the header")
    chatter = (
        "\n".join(expected_cpp)
        + "\n\n/* See limitations under the License.\n"
        + " * Also limitations under the License.\n */\nint x;\n"
    )
    _, changed = repair_cpp(chatter, year)
    if changed:
        failures.append("a comment that only contains the last corpus sentence must be kept")

    good_hash = "#!/usr/bin/env bash\n" + "\n".join(expected_hash) + "\n\necho ok\n"
    hash_twice = (
        "#!/usr/bin/env bash\n"
        + "\n".join(expected_hash)
        + "\n\n"
        + "\n".join(expected_hash)
        + "\n\necho ok\n"
    )
    fixed_hash_twice, changed = repair_hash(hash_twice, year)
    if not changed or fixed_hash_twice != good_hash:
        failures.append("a second # license run must be dropped")
    hash_kept = (
        "#!/usr/bin/env bash\n"
        + "\n".join(expected_hash)
        + "\n\n# Env overrides: FOO, BAR\necho ok\n"
    )
    _, changed = repair_hash(hash_kept, year)
    if changed:
        failures.append("ordinary # comments after the corpus must be kept")

    docker_good = "# syntax=docker/dockerfile:1.7\n" + "\n".join(expected_hash) + "\n\nFROM x\n"
    _, changed = repair_hash(docker_good, year)
    if changed:
        failures.append("a Dockerfile parser directive above the header must stay first")
    fixed_docker, changed = repair_hash("# syntax=docker/dockerfile:1.7\nFROM x\n", year)
    if not changed or fixed_docker != docker_good:
        failures.append("the header must go below a Dockerfile parser directive")
    cookie = "#!/usr/bin/env python3\n# -*- coding: latin-1 -*-\n"
    _, changed = repair_hash(cookie + "\n".join(expected_hash) + "\n\nx = 1\n", year)
    if changed:
        failures.append("a PEP 263 encoding cookie above the header must stay on line 2")
    fixed_include, _ = repair_cpp('#include "x.h"\n' + good_cpp, year)
    if not fixed_include.startswith("// SPDX-License-Identifier:"):
        failures.append("a C #include is code, not a top-of-file directive")

    md_good = md_header_text(year) + "# Title\n"
    fixed_md_twice, changed = repair_md(md_header_text(year) + md_good, year)
    if not changed or fixed_md_twice != md_good:
        failures.append("a second Markdown SPDX comment header must be dropped")

    repaired_md, changed = repair_md("# Title\n", year)
    if not changed or not repaired_md.startswith("<!-- SPDX-License-Identifier: Apache-2.0 -->"):
        failures.append("Markdown repair must insert HTML-comment header")
    for line in _md_inner_lines(year):
        if line.strip() and line not in repaired_md:
            failures.append("Markdown repair must insert the full license_header corpus")
            break
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

        targets = {path.name for path in iter_targets([scan])}
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
