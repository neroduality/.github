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

"""Reject Google/cpplint/clang-tidy NOLINT and cppcheck inline suppressions."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from policy_config import PolicyConfig

LINT_TITLE = "nolint-audit"

_SUPPRESSION_TOKEN = re.compile(
    r"\bNOLINT(?:NEXTLINE|BEGIN|END)?\b(?:\s*\([^)]*\))?"
    r"|\bcppcheck-suppress(?:-begin|-end|-file|-macro)?\b(?:\s*\[[^\]]*\])?"
)

_SELF_TEST_CASES: dict[str, tuple[str, bool]] = {
    "clean.c": ("int ok(void) { return 0; }\n", False),
    "bad_nextline.c": ("// NOLINTNEXTLINE(clang-analyzer-valist.Uninitialized)\nint bad(void) { return 1; }\n", True),
    "bad_block_nextline.c": ("/* NOLINTNEXTLINE(example) */\nint fine(void) { return 0; }\n", True),
    "bad_nolint.c": ("int x; // NOLINT(readability)\n", True),
    "bad_nolint_bare.c": ("// NOLINT\nint y;\n", True),
    "bad_begin_end.c": (
        "// NOLINTBEGIN(readability-magic-numbers)\nint a = 42;\n// NOLINTEND(readability-magic-numbers)\n",
        True,
    ),
    "bad_inline.c": ("int z = 0; /* NOLINTNEXTLINE */ int w = 1;\n", True),
    "bad_cppcheck.c": ("int x; // cppcheck-suppress constParameterPointer\n", True),
    "bad_cppcheck_bracket.c": ("// cppcheck-suppress[uninitvar]\nint y;\n", True),
    "bad_cppcheck_begin.c": (
        "// cppcheck-suppress-begin knownConditionTrueFalse\nint a = 0;\n// cppcheck-suppress-end knownConditionTrueFalse\n",
        True,
    ),
    "bad_cppcheck_file.c": ("// cppcheck-suppress-file uninitvar\nint z;\n", True),
    "bad_cppcheck_macro.c": ("// cppcheck-suppress-macro constVariable\n#define M 1\n", True),
    "string_literal.c": ('const char *msg = "NOLINT";\n', False),
    "string_cppcheck.c": ('const char *m = "cppcheck-suppress foo";\n', False),
    "string_line_comment.c": ('const char *url = "see http://x NOLINT";\n', False),
    "multiline_block.c": (
        "/* start of a block\n NOLINTNEXTLINE(readability)\n end */\nint m(void){return 0;}\n",
        True,
    ),
}


def scan_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    raw_lines = text.splitlines()
    findings: list[str] = []
    from scan_policy import comment_view

    for line_no, comment_line in enumerate(comment_view(text).splitlines(), 1):
        match = _SUPPRESSION_TOKEN.search(comment_line)
        if match is not None:
            raw = raw_lines[line_no - 1].strip() if line_no - 1 < len(raw_lines) else ""
            findings.append(f"{path}:{line_no}: {match.group(0)} -- {raw}")
    return findings


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    del config
    return [finding for path in paths for finding in scan_file(path)]


def run(config: PolicyConfig, paths: list[Path], extras: list[str]) -> int:
    del extras
    findings = lint(paths, config)
    if not findings:
        print("nolint-audit: OK (0 inline suppressions)")
        return 0
    print(f"nolint-audit: found {len(findings)} inline suppression(s)")
    for item in findings:
        print(item)
    return 1


def prepare_self_test_repo(root: Path) -> None:
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
        "  public_headers_dir: include/sample\n  source_roots: [core]\n"
        "policy:\n  nolint_allowed:\n    - core/allowed.c\n",
        encoding="utf-8",
    )
    core = root / "core"
    core.mkdir(parents=True)
    for name, (content, _) in _SELF_TEST_CASES.items():
        (core / name).write_text(content, encoding="utf-8")
    (core / "allowed.c").write_text("// NOLINTNEXTLINE(foo)\nint allowed(void) { return 0; }\n", encoding="utf-8")


def verify_self_test(errors: list[str]) -> int:
    reported = {Path(item.split(":", 2)[0]).name for item in errors}
    expected = {name for name, (_, flagged) in _SELF_TEST_CASES.items() if flagged}
    if reported != expected:
        print(f"nolint-audit self-test failed: got {sorted(reported)} expected {sorted(expected)}", file=sys.stderr)
        return 1
    print("nolint-audit self-test: OK")
    return 0
