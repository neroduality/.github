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

"""``#pragma once``, mixed-angle/quote dupes, and macro ``#include`` dupes."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from policy_config import K_HEADER, PolicyConfig
from scan_policy import strip_comments_only

LINT_TITLE = "duplicate includes"
LINT_FIX_HINT = "Remove mixed-angle/quote or macro #include dupes; exact repeats are clang-tidy."

INCLUDE_LITERAL = re.compile(r'^\s*#\s*include\s+(?:"([^"]+)"|<([^>]+)>)')
INCLUDE_MACRO = re.compile(r'^\s*#\s*include\s+([A-Za-z_][A-Za-z0-9_]*)')
PRAGMA_ONCE = re.compile(r"^\s*#\s*pragma\s+once\b")

_SELF_TEST_CASES: dict[str, tuple[str, set[str]]] = {
    "unique_ok.c": ('#include "a.h"\n#include "b.h"\n', set()),
    "pragma_once_ok.h": ('// license comment\n\n#pragma once\n#include "a.h"\n', set()),
    "pragma_once_after_include_bad.h": ('#include "a.h"\n#pragma once\n', {"pragma_once_after_include_bad.h"}),
    "pragma_once_missing_bad.hpp": ("// license comment\nint f(void);\n", {"pragma_once_missing_bad.hpp"}),
    "pragma_once_in_block_comment_bad.h": ("/* #pragma once */\nint f(void);\n", {"pragma_once_in_block_comment_bad.h"}),
    "dup_literal.c": ('#include "foo.h"\n#include "foo.h"\n', set()),
    "dup_mixed.c": ('#include <foo.h>\n#include "foo.h"\n', {"dup_mixed.c"}),
    "dup_macro.c": ("#include CONFIG_HEADER\n#include CONFIG_HEADER\n", set()),
    "comment_ok.c": ('/* duplicate mention: #include "foo.h" */\n#include "foo.h"\n', set()),
    "string_ok.c": ('const char *s = "#include \\"foo.h\\"";\n#include "foo.h"\n', set()),
    "string_slash_star_mixed_bad.c": (
        'const char *a = "/*";\n#include "x.h"\n#include <x.h>\nconst char *b = "*/";\n',
        {"string_slash_star_mixed_bad.c"},
    ),
    "multiline_comment_mixed_bad.c": (
        '#include "x.h"\n/* multi\nline */\n#include <x.h>\n',
        {"multiline_comment_mixed_bad.c"},
    ),
}
_SELF_TEST_LINES = {"multiline_comment_mixed_bad.c": 4}


def parse_include(code_line: str) -> tuple[str, str] | None:
    m = INCLUDE_LITERAL.match(code_line)
    if m:
        return ("path", m.group(1) or m.group(2))
    m = INCLUDE_MACRO.match(code_line)
    if m:
        return ("macro", m.group(1))
    return None


def _include_style(code_line: str) -> str:
    return "angle" if "<" in code_line.split("//", 1)[0] else "quote"


def scan_header_pragma_once(path: Path, code_lines: list[str]) -> list[str]:
    for line_no, code_line in enumerate(code_lines, 1):
        if not code_line.strip():
            continue
        if PRAGMA_ONCE.match(code_line):
            return []
        return [
            f"{path}:{line_no}: header must start with #pragma once "
            "(first non-comment, non-blank directive/code line)"
        ]
    return [f"{path}:1: header must start with #pragma once"]


def scan_file(path: Path, config: PolicyConfig) -> list[str]:
    code_lines = strip_comments_only(
        path.read_text(encoding="utf-8", errors="replace")
    ).splitlines()
    seen_paths: dict[str, tuple[int, str]] = {}
    seen_macros: dict[str, int] = {}
    issues: list[str] = []

    if config.has(path, K_HEADER):
        issues.extend(scan_header_pragma_once(path, code_lines))

    for line_no, code_line in enumerate(code_lines, 1):
        parsed = parse_include(code_line)
        if parsed is None:
            continue
        kind, key = parsed
        if kind == "path":
            style = _include_style(code_line)
            first = seen_paths.get(key)
            if first is not None:
                first_line, first_style = first
                if first_style != style:
                    issues.append(
                        f"{path}:{line_no}: duplicate #include for {key} "
                        f'(mixed <...> and "..."; first at line {first_line})'
                    )
                continue
            seen_paths[key] = (line_no, style)
            continue
        first_macro = seen_macros.get(key)
        if first_macro is not None:
            continue
        seen_macros[key] = line_no
    return issues


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    return [issue for path in paths for issue in scan_file(path, config)]


def prepare_self_test_repo(root: Path) -> None:
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
        "  source_roots: [core]\n",
        encoding="utf-8",
    )
    core = root / "core"
    core.mkdir(parents=True)
    for name, (content, _) in _SELF_TEST_CASES.items():
        (core / name).write_text(content, encoding="utf-8")


def verify_self_test(errors: list[str]) -> int:
    reported = {Path(err.split(":", 2)[0]).name for err in errors}
    reported_lines = {Path(err.split(":", 2)[0]).name: int(err.split(":", 2)[1]) for err in errors}
    for name, (_, expected) in _SELF_TEST_CASES.items():
        if (expected and name not in reported) or (not expected and name in reported):
            print(f"self-test {'miss' if expected else 'false positive'}: {name}", file=sys.stderr)
            return 1
    for name, line in _SELF_TEST_LINES.items():
        if reported_lines.get(name) != line:
            print(f"self-test line mismatch: {name}", file=sys.stderr)
            return 1
    print("duplicate-includes self-test: OK")
    return 0
