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

"""Banned upstream libc APIs and raw terminal I/O (unsafe_api scan job).
See scan_policy.BANNED_C_API_NAMES and project ``{prefix}_*`` output wrappers."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from policy_config import PolicyConfig
from scan_policy import (
    BANNED_C_API_CALL,
    BANNED_C_API_NAMES,
    BANNED_OUTPUT_C_API_NAMES,
    blank_comments_and_strings,
    is_preprocessor_at,
    line_number_at,
)

LINT_TITLE = "unsafe API policy"
LINT_FIX_HINT = (
    "Use bounded project helpers and project_* output wrappers. "
    "Full banned set: scan_policy.BANNED_C_API_NAMES (complements clang-tidy unsafe)."
)
LINT_OK_DETAIL = (
    "  (wrapper_files exempt; complements clang-tidy unsafe — "
    "libc bans from scan_policy.BANNED_C_API_NAMES; also C++ streams and fd stdout/stderr)"
)

_PREFIX = "sample"

_SELF_TEST_CASES: dict[str, tuple[str, set[str]]] = {
    "good.c": ("void f(void){}\n", set()),
    "comment_ok.c": ("/* strcpy(d,s) */ void f(void){}\n", set()),
    "string_slash_star_bad.c": (
        'const char *o = "/*";\n'
        "void f(void){ system(a); }\n"
        'const char *c = "*/";\n',
        {"string_slash_star_bad.c"},
    ),
    "good_io.cpp": (f"void f(){{ {_PREFIX}::{_PREFIX}_stderr_line(\"x\"); }}\n", set()),
    "good_format.h": (
        f"int {_PREFIX}_snprintf(char *buf, size_t cap, const char *fmt, ...);\n",
        set(),
    ),
    "good_fd_write.cpp": ("void f(){ write(fd, buf, n); }\n", set()),
    f"{_PREFIX}_format.c": (
        f"int {_PREFIX}_vsnprintf(char *buf, size_t cap, const char *fmt, va_list args) {{\n"
        "  return vsnprintf(buf, cap, fmt, args);\n"
        "}\n",
        set(),
    ),
    f"{_PREFIX}_io.c": (
        f"void {_PREFIX}_emit_line(const char *s) {{\n"
        "  fputs(s, stdout);\n"
        "  fflush(stdout);\n"
        "}\n",
        set(),
    ),
    "bad_println.cpp": ('void f(){ std::println("x"); }\n', {"bad_println.cpp"}),
    "bad_raw_fd.cpp": ("void f(){ write(1, buf, n); }\n", {"bad_raw_fd.cpp"}),
}
for _api in BANNED_C_API_NAMES:
    _SELF_TEST_CASES[f"bad_{_api}.c"] = (f"void f(void){{{_api}(a,b);}}\n", {f"bad_{_api}.c"})

UPSTREAM_PATTERN_RES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            "|".join(
                (
                    r"std::println\s*\(",
                    r"std::print\s*\(",
                    r"std::cout\s*<<",
                    r"std::cerr\s*<<",
                    r"std::clog\s*<<",
                    r"std::wcout\s*<<",
                    r"std::wcerr\s*<<",
                    r"std::wclog\s*<<",
                    r"\bSerial\.(?:print|println|write)\s*\(",
                )
            )
        ),
        "raw stream/terminal output",
    ),
    (
        re.compile(r"\bwrite\s*\(\s*(?:1|2|STDOUT_FILENO|STDERR_FILENO)\b"),
        "raw stream/terminal output",
    ),
)


def scan_banned_c_api(path: Path, blanked: str, text: str, prefix: str) -> list[str]:
    issues: list[str] = []
    for match in BANNED_C_API_CALL.finditer(blanked):
        if is_preprocessor_at(blanked, match.start()):
            continue
        api = match.group(1)
        line_no = line_number_at(text, match.start())
        if api in BANNED_OUTPUT_C_API_NAMES:
            hint = f"use {prefix}_* output wrappers"
        else:
            hint = "use bounded helpers"
        issues.append(
            f"{path}:{line_no}: banned C API {api}() "
            f"({hint}; see scan_policy.BANNED_C_API_NAMES / .clang-tidy)"
        )
    return issues


def scan_raw_terminal_output(path: Path, blanked: str, text: str, prefix: str) -> list[str]:
    issues: list[str] = []
    for pattern, detail in UPSTREAM_PATTERN_RES:
        for match in pattern.finditer(blanked):
            if is_preprocessor_at(blanked, match.start()):
                continue
            line_no = line_number_at(text, match.start())
            issues.append(
                f"{path}:{line_no}: output must use {prefix}_* wrappers ({detail})"
            )
    return issues


def scan_file(path: Path, prefix: str) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    blanked = blank_comments_and_strings(text)
    issues = scan_banned_c_api(path, blanked, text, prefix)
    issues.extend(scan_raw_terminal_output(path, blanked, text, prefix))
    return sorted(set(issues))


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    prefix = config.c_api_prefix
    return sorted({issue for path in paths for issue in scan_file(path, prefix)})


def prepare_self_test_repo(root: Path) -> None:
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
        "  source_roots: [core]\n"
        "policy:\n  unsafe_api:\n    wrapper_files:\n"
        f"      - core/app/{_PREFIX}_format.c\n"
        f"      - core/app/{_PREFIX}_format.h\n"
        f"      - core/app/{_PREFIX}_io.c\n"
        f"      - core/app/{_PREFIX}_parse.c\n"
        f"      - core/app/{_PREFIX}_parse.h\n",
        encoding="utf-8",
    )
    app_dir = root / "core" / "app"
    app_dir.mkdir(parents=True)
    for name, (content, _) in _SELF_TEST_CASES.items():
        (app_dir / name).write_text(content, encoding="utf-8")


def verify_self_test(errors: list[str]) -> int:
    reported = {Path(err.split(":", 2)[0]).name for err in errors}
    for name, (_, expected) in _SELF_TEST_CASES.items():
        if expected and name not in reported:
            print(f"self-test miss: expected violation in {name}", file=sys.stderr)
            return 1
        if not expected and name in reported:
            print(f"self-test false positive: {name}", file=sys.stderr)
            return 1
    print("unsafe API self-test: OK")
    return 0
