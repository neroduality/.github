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

"""Reject parent-directory traversals in C/C++ include directives."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from policy_config import PolicyConfig
from scan_policy import strip_comments_only

LINT_TITLE = "relative includes"
LINT_FIX_HINT = "Use include path basenames; no ../ in #include."

INCLUDE_LITERAL = re.compile(r'^\s*#\s*include\s+(?:"([^"]+)"|<([^>]+)>)')

_SELF_TEST_CASES: dict[str, tuple[str, set[str]]] = {
    "ok.c": ('#include "sample_frame.h"\n', set()),
    "bad.c": ('#include "../common/foo.h"\n', {"bad.c"}),
    "angle_bad.cpp": ("#include <../foo.h>\n", {"angle_bad.cpp"}),
    "comment_ok.c": ('/* #include "../bad.h" */\n#include "ok.h"\n', set()),
    "parent_include_bad.c": ('#include "../generated.h"\n', {"parent_include_bad.c"}),
    "string_slash_star_bad.c": (
        'const char *a = "/*";\n#include "../evil.h"\nconst char *b = "*/";\n',
        {"string_slash_star_bad.c"},
    ),
    "multiline_comment_bad.c": (
        'int x;\n/* multi\nline\ncomment */\n#include "../evil.h"\n',
        {"multiline_comment_bad.c"},
    ),
}
_SELF_TEST_LINES = {"string_slash_star_bad.c": 2, "multiline_comment_bad.c": 5}


def scan_file(path: Path) -> list[str]:
    code_lines = strip_comments_only(path.read_text(encoding="utf-8", errors="replace")).splitlines()
    issues: list[str] = []
    for line_no, code_line in enumerate(code_lines, 1):
        match = INCLUDE_LITERAL.match(code_line)
        if not match:
            continue
        include_path = match.group(1) or match.group(2)
        if "../" in include_path:
            issues.append(f"{path}:{line_no}: relative parent include banned: {include_path}")
    return issues


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    del config
    return [issue for path in paths for issue in scan_file(path)]


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
    expected = {name for name, (_, names) in _SELF_TEST_CASES.items() if names}
    if reported != expected:
        print(f"relative-includes self-test failed: got {reported}, expected {expected}", file=sys.stderr)
        return 1
    for name, line in _SELF_TEST_LINES.items():
        if reported_lines.get(name) != line:
            print(f"relative-includes line mismatch: {name}", file=sys.stderr)
            return 1
    print("relative-includes self-test: OK")
    return 0
