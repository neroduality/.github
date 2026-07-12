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

"""No C++ new/delete (unsafe_api scan job)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from policy_config import PolicyConfig
from scan_policy import blank_comments_and_strings, is_preprocessor_at, line_number_at

LINT_TITLE = "C++ heap policy"
LINT_FIX_HINT = "Use stack/static buffers only; no C++ new/delete in project code."
LINT_OK_DETAIL = (
    "  (wrapper_files exempt; complements clang-tidy unsafe — "
    "C++ new/delete only; malloc/free via banned_libc_io)"
)

HEAP_CXX_DELETE = re.compile(r"\bdelete\b\s*(?:\[\s*\])?\s*[\w(:~*&]")
HEAP_CXX_NEW = re.compile(
    r"(?<![A-Za-z0-9_])new\s*[\[(]|"
    r"(?<![A-Za-z0-9_])new\s+"
    r"(?:const\s+|volatile\s+|unsigned\s+|signed\s+|auto\s+|std::[\w:]+\s*|\[\[nodiscard\]\]\s*)?"
    r"(?:[A-Za-z_][\w:]*|\*)"
)

_SELF_TEST_CASES: dict[str, tuple[str, set[str]]] = {
    "heap_new.cpp": ("struct S{}; void f(){auto*p=new S; delete p;}\n", {"heap_new.cpp"}),
    "heap_new_array.cpp": ("void f(){auto*p=new int[4]; delete[] p;}\n", {"heap_new_array.cpp"}),
    "heap_placement_new.cpp": ("struct S{}; void f(void* a){auto*p=new (a) S; (void)p;}\n", {"heap_placement_new.cpp"}),
    "heap_delete_paren.cpp": ("struct S{}; void f(S* p){ delete (p); }\n", {"heap_delete_paren.cpp"}),
    "not_delete_ident_ok.cpp": ("int deleteEntry(int x){ return x; }\n", set()),
    "malloc_ok.c": ("void f(void){void*p=malloc(16); free(p);}\n", set()),
    "brace_init_ok.cpp": ("struct S{int x;}; void f(){S s{}; (void)s;}\n", set()),
    "param_new_mode.cpp": ("enum E{A,B}; void f(E new_mode){(void)new_mode; g_mode=new_mode;}\n", set()),
    "split_new.cpp": ("struct S{}; void f(){auto*p=new\n S; delete p;}\n", {"split_new.cpp"}),
    "st25_new_bad.cpp": ("struct S{}; void f(){auto*p=new S; delete p;}\n", {"st25_new_bad.cpp"}),
}


def scan_match(path: Path, text: str, match: re.Match[str], message: str) -> str | None:
    if is_preprocessor_at(text, match.start()):
        return None
    return f"{path}:{line_number_at(text, match.start())}: {message}"


def scan_file(path: Path) -> list[str]:
    issues: list[str] = []
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    text = blank_comments_and_strings(raw_text)
    for regex, message in (
        (HEAP_CXX_NEW, "C++ heap allocation (use stack/static buffers; new is forbidden in project code)"),
        (HEAP_CXX_DELETE, "C++ heap delete (use stack/static buffers; delete is forbidden in project code)"),
    ):
        for match in regex.finditer(text):
            issue = scan_match(path, text, match, message)
            if issue is not None:
                issues.append(issue)
    return sorted(set(issues))


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    del config
    return sorted({issue for path in paths for issue in scan_file(path)})


def prepare_self_test_repo(root: Path) -> None:
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
        "  source_roots: [core, include]\n"
        "policy:\n  unsafe_api:\n    header: sample_null.h\n"
        "    include_headers: [attrs.h]\n    wrapper_files:\n      - include/sample/cxx_heap_sink.cpp\n",
        encoding="utf-8",
    )
    core = root / "core"
    frontends = core / "frontends" / "st25r3916"
    wrapper = root / "include" / "sample" / "cxx_heap_sink.cpp"
    core.mkdir(parents=True)
    frontends.mkdir(parents=True)
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("struct S{}; void sink(){auto*p=new S; delete p;}\n", encoding="utf-8")
    for name, (content, _) in _SELF_TEST_CASES.items():
        dest = frontends if name == "st25_new_bad.cpp" else core
        (dest / name).write_text(content, encoding="utf-8")


def verify_self_test(errors: list[str]) -> int:
    reported = {Path(err.split(":", 2)[0]).name for err in errors}
    failed = False
    for name, (_, expected) in _SELF_TEST_CASES.items():
        if expected and name not in reported:
            print(f"self-test miss: expected violation in {name}", file=sys.stderr)
            failed = True
        if not expected and name in reported:
            print(f"self-test false positive: {name}", file=sys.stderr)
            failed = True
    if "cxx_heap_sink.cpp" in reported:
        print("self-test false positive in cxx_heap_sink.cpp", file=sys.stderr)
        failed = True
    if failed:
        print("reported:", sorted(reported), file=sys.stderr)
        return 1
    print("C++ heap policy self-test: OK")
    return 0
