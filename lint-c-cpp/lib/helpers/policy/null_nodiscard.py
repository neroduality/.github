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

"""Project NULL macro and NODISCARD on fallible bool APIs (unsafe_api scan job).
Raw NULL/nullptr tokens forbidden outside the canonical null header."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from policy_config import K_CANONICAL_NULL, K_HEADER, NullPolicy, PolicyConfig
from scan_policy import strip_comments_and_strings as strip_code

LINT_TITLE = "null/nodiscard policy"
LINT_FIX_HINT = "Use project NULL and NODISCARD macros."

RAW_NULL = re.compile(r"\bNULL\b")
LEGACY_NULL_TOKEN = re.compile(r"(?<![A-Z_])OLD_NULL\b")
CAST_NULL = re.compile(r"\(\s*[\w:][^)]*\*+\s*\)\s*0\b")
STANDALONE_NULLPTR = re.compile(r"\bnullptr\b")

_SELF_TEST_CASES: dict[str, tuple[str, set[str]]] = {
    "missing_nodiscard.h": (
        "#pragma once\nbool probe_no_nodiscard(void);\n",
        {"missing_nodiscard.h"},
    ),
    "multiline_nodiscard_ok.h": (
        "#pragma once\nSAMPLE_NODISCARD bool\nprobe_ok(void);\n",
        set(),
    ),
    "multiline_nodiscard_bad.h": (
        "#pragma once\nbool\nprobe_bad(void);\n",
        {"multiline_nodiscard_bad.h"},
    ),
    "trailing_bool_bad.h": (
        "#pragma once\nauto probe_trailing(void) -> bool;\n",
        {"trailing_bool_bad.h"},
    ),
    "trailing_bool_ok.h": (
        "#pragma once\nSAMPLE_NODISCARD auto probe_trailing_ok(void) -> bool;\n",
        set(),
    ),
    "raw_null.c": ("void f(void* p) { if (p == NULL) {} }\n", {"raw_null.c"}),
    "legacy_old_null.c": ("void f(void* p) { if (p == OLD_NULL) {} }\n", {"legacy_old_null.c"}),
    "cast_null.c": ("const void* p = (const uint8_t*)0;\n", {"cast_null.c"}),
    "cast_null_nonconst.c": ("void* p = (uint8_t*)0;\n", {"cast_null_nonconst.c"}),
    "cast_null_void.c": ("void* p = (void*)0;\n", {"cast_null_void.c"}),
    "header_nullptr.h": (
        "#pragma once\nvoid f(const char* s) { if (s == nullptr) {} }\n",
        {"header_nullptr.h"},
    ),
    "source_nullptr.cpp": (
        "void f(const char* s) { if (s == nullptr) {} }\n",
        {"source_nullptr.cpp"},
    ),
    "header_default_nullptr_bad.h": (
        "#pragma once\nvoid f(uint8_t* p = nullptr);\n",
        {"header_default_nullptr_bad.h"},
    ),
    "nodiscard_field.h": (
        "struct S { SAMPLE_NODISCARD bool flag{}; };\n",
        {"nodiscard_field.h"},
    ),
    "struct_field_ok.h": ("struct S { bool flag{}; };\n", set()),
    "static_internal_ok.h": ("static bool helper(void) { return false; }\n", set()),
    "comment_null.c": ("/* NULL is bad in code */ void f(void) {}\n", set()),
    "multiline_comment_null.c": (
        "/* canonical docs mention\n * nullptr and NULL here.\n */\nvoid f(void) {}\n",
        set(),
    ),
    "comment_nullptr.c": ("/* nullptr is bad in code */ void f(void) {}\n", set()),
    "comment_sample_null.c": ("/* SAMPLE_NULL is the canonical token. */ void f(void) {}\n", set()),
    "sample_null_define_ok.h": ("#define SAMPLE_NULL nullptr\n", {"sample_null_define_ok.h"}),
    "missing_null_include.c": (
        "void f(void* p) { if (p == SAMPLE_NULL) {} }\n",
        {"missing_null_include.c"},
    ),
    "null_include_ok.c": (
        '#include "sample_null.h"\nvoid f(void* p) { if (p == SAMPLE_NULL) {} }\n',
        set(),
    ),
}


def strip_comments_and_strings(line: str) -> str:
    line = re.sub(r"//.*", "", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
    return line


def canonical_null_define_allowed(path: Path, line: str, policy: NullPolicy, config: PolicyConfig) -> bool:
    if not config.has(path, K_CANONICAL_NULL):
        return False
    stripped = strip_comments_and_strings(line)
    return bool(
        policy.null_define.search(stripped)
        or policy.null_define_null.search(stripped)
    )


def merge_bool_decl_lines(lines: list[str], policy: NullPolicy) -> list[tuple[int, str]]:
    merged: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if policy.bool_head.match(line.rstrip()):
            start = i + 1
            parts = [line.strip()]
            j = i + 1
            while j < len(lines):
                parts.append(lines[j].strip())
                if ";" in lines[j] or "{" in lines[j]:
                    break
                j += 1
            merged.append((start, " ".join(parts)))
            i = j + 1
            continue
        merged.append((i + 1, line))
        i += 1
    return merged


def is_struct_or_field(decl: str) -> bool:
    if "(" not in decl and ";" in decl:
        return True
    if re.search(r"\bbool\s+\w+\s*\{", decl):
        return True
    return False


def has_nodiscard(decl: str, policy: NullPolicy) -> bool:
    return policy.nodiscard_macro in decl or "[[nodiscard]]" in decl


def is_bool_function_decl(decl: str) -> bool:
    return bool(
        re.search(r"\bbool\s+\w+\s*\(", decl)
        or re.search(r"\bauto\s+\w+\s*\([^;{}]*\)\s*->\s*bool\b", decl)
    )


def scan_nodiscard_header(path: Path, policy: NullPolicy) -> list[str]:
    issues: list[str] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for start_line, decl in merge_bool_decl_lines(lines, policy):
        if re.search(r"\bstatic\s+bool\s+\w+\s*\(", decl) and "inline" not in decl:
            continue
        if not is_bool_function_decl(decl):
            continue
        if is_struct_or_field(decl):
            continue
        if "operator" in decl:
            continue
        if not has_nodiscard(decl, policy):
            issues.append(
                f"{path}:{start_line}: fallible bool API missing {policy.nodiscard_macro}"
            )
    return issues


def scan_null_tokens(path: Path, policy: NullPolicy, config: PolicyConfig) -> list[str]:
    issues: list[str] = []
    raw = path.read_text(encoding="utf-8", errors="replace")
    raw_lines = raw.splitlines()
    code_lines = strip_code(raw).splitlines()
    for i, (line, code) in enumerate(zip(raw_lines, code_lines), 1):
        if canonical_null_define_allowed(path, line, policy, config):
            continue
        if RAW_NULL.search(code):
            issues.append(f"{path}:{i}: raw NULL (use {policy.null_macro})")
        if LEGACY_NULL_TOKEN.search(code):
            issues.append(f"{path}:{i}: legacy OLD_NULL (use {policy.null_macro})")
        if CAST_NULL.search(code):
            issues.append(f"{path}:{i}: (T*)0 cast (use {policy.null_macro})")
    return issues


def has_null_include(text: str, policy: NullPolicy) -> bool:
    if f'#include "{policy.include_dir_prefix}/' in text:
        return True
    return any(f'#include "{header}"' in text for header in policy.null_includes)


def scan_null_include(path: Path, policy: NullPolicy, config: PolicyConfig) -> list[str]:
    if config.has(path, K_CANONICAL_NULL):
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    code = strip_code(text)
    if not policy.null_token.search(code):
        return []
    if has_null_include(text, policy):
        return []
    alt_headers = ", ".join(
        sorted(h for h in policy.null_includes if h != policy.canonical_header)[:3]
    )
    return [
        f"{path}: missing #include \"{policy.canonical_header}\" "
        f"(or {alt_headers}) for {policy.null_macro}"
    ]


def scan_standalone_nullptr(path: Path, policy: NullPolicy, config: PolicyConfig) -> list[str]:
    issues: list[str] = []
    raw = path.read_text(encoding="utf-8", errors="replace")
    raw_lines = raw.splitlines()
    code_lines = strip_code(raw).splitlines()
    for i, (line, code) in enumerate(zip(raw_lines, code_lines), 1):
        if canonical_null_define_allowed(path, line, policy, config):
            continue
        if STANDALONE_NULLPTR.search(code):
            issues.append(f"{path}:{i}: standalone nullptr (use {policy.null_macro})")
    return issues


def scan_nodiscard_on_fields(path: Path, policy: NullPolicy, config: PolicyConfig) -> list[str]:
    if not config.has(path, K_HEADER):
        return []
    issues: list[str] = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if policy.nodiscard_on_field.search(line):
            issues.append(
                f"{path}:{i}: {policy.nodiscard_macro} on data member (functions only)"
            )
    return issues


def scan_file(path: Path, config: PolicyConfig) -> list[str]:
    policy = config.null_policy
    issues: list[str] = []
    if config.has(path, K_HEADER):
        issues.extend(scan_nodiscard_header(path, policy))
        issues.extend(scan_nodiscard_on_fields(path, policy, config))
    issues.extend(scan_null_tokens(path, policy, config))
    issues.extend(scan_standalone_nullptr(path, policy, config))
    issues.extend(scan_null_include(path, policy, config))
    return issues


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    return [issue for path in paths for issue in scan_file(path, config)]


def prepare_self_test_repo(root: Path) -> None:
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
        "  public_headers_dir: include/sample\n  source_roots: [core, include]\n"
        "policy:\n  unsafe_api:\n    header: sample_null.h\n"
        "    include_headers: [attrs.h, mem_util.h]\n"
        "    wrapper_files:\n      - include/sample/sample_null.h\n",
        encoding="utf-8",
    )
    core = root / "core"
    core.mkdir(parents=True)
    st25_root = core / "frontends" / "st25r3916"
    st25_root.mkdir(parents=True)
    canonical = root / "include" / "sample"
    canonical.mkdir(parents=True)
    (canonical / "sample_null.h").write_text(
        "#if defined(__cplusplus)\n"
        "#define SAMPLE_NULL nullptr\n"
        "#else\n"
        "#define SAMPLE_NULL NULL\n"
        "#endif\n",
        encoding="utf-8",
    )
    for name, (content, _) in _SELF_TEST_CASES.items():
        (core / name).write_text(content, encoding="utf-8")
    (st25_root / "raw_null_st25.c").write_text(
        "void f(void* p) { if (p == NULL) {} }\n",
        encoding="utf-8",
    )


def verify_self_test(errors: list[str]) -> int:
    reported = {Path(item.split(":", 2)[0]).name for item in errors}
    failed = False
    for name, (_, expected) in _SELF_TEST_CASES.items():
        if expected and name not in reported:
            print(f"self-test miss: expected violation in {name}", file=sys.stderr)
            failed = True
        if not expected and name in reported:
            print(f"self-test false positive: {name}", file=sys.stderr)
            failed = True
    canonical_errors = [err for err in errors if "sample_null.h" in err.split(":", 1)[0]]
    if canonical_errors:
        print(f"self-test false positive in canonical header: {canonical_errors}", file=sys.stderr)
        failed = True
    if "raw_null_st25.c" not in reported:
        print("self-test miss: expected violation in st25r3916 tree", file=sys.stderr)
        failed = True
    if failed:
        print("reported:", sorted(reported), file=sys.stderr)
        return 1
    print("null/nodiscard self-test: OK")
    return 0
