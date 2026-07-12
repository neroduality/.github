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

"""Constant placement/bounds policy (complements clang-tidy magic-number checks).
Enforces caps, stack arrays, recursion, printf-index gaps."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

from policy_config import K_HEADER, K_MAGIC_SHARED, K_STACK_ARRAY, K_TU, PolicyConfig
from scan_policy import strip_comments_and_strings

LINT_TITLE = "constant placement/bounds policy"
LINT_FIX_HINT = (
    "General magic numbers are enforced by clang-tidy; fix placement/bounds issues "
    "here (shared caps in canonical headers, file-local caps at the top of the .c/.cpp)."
)

STACK_ARRAY_DECL_RE = re.compile(
    r"\b(?:char|uint8_t|unsigned char)\s+(\w+)\s*\[\s*(\d+)u?\s*\]"
)
CONTROL_CALL_NAMES = frozenset(
    {
        "catch",
        "for",
        "if",
        "return",
        "sizeof",
        "switch",
        "while",
    }
)
CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

IDENTITY_LITERAL_VALUES = frozenset({0, 1})
INT_LITERAL_RE = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)([uUlLzZ]*)\b")
NUMERIC_LITERAL_RE = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)[uUlLzZ]*\b")
HEADER_DEFINE_LITERAL_RE = re.compile(r"^\s*#\s*define\s+([A-Z_][A-Z0-9_]*)\b")
ENUM_MEMBER_LITERAL_RE = re.compile(
    r"\b([A-Z_][A-Z0-9_]*)\s*=\s*(?:0[xX][0-9a-fA-F]+|\d+)[uUlLzZ]*"
)
HEADER_CONST_LITERAL_RE = re.compile(
    r"^\s*(?:static\s+)?(?:inline\s+)?constexpr\s+[\w:<>,\s*&]+\s+([A-Z_][A-Z0-9_]*)\s*="
)
ENUM_OPEN_LITERAL_RE = re.compile(r"\benum\b(?:\s+(?:class|struct)\b)?[^{};(]*\{")
# clang-tidy gap: format/printf attribute macros often take numeric arg indices.
FORMAT_MACRO_LITERAL_RE = re.compile(
    r"\b[A-Z_][A-Z0-9_]*PRINTF\s*\(|__attribute__\s*\(\s*\(\s*format\s*\(",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LiteralHit:
    label: str
    lineno: int
    token: str
    value: int
    raw: str
    lit_end: int


@dataclass(frozen=True)
class HeaderConstant:
    label: str
    lineno: int
    name: str


def _blank_all_comments(text: str) -> str:
    def _blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"/\*.*?\*/", _blank, text, flags=re.DOTALL)
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        body = line[: len(line) - len(newline)]
        body = re.sub(r"//.*", lambda m: " " * len(m.group(0)), body)
        body = re.sub(
            r'"([^"\\]|\\.)*"',
            lambda m: '"' + " " * (len(m.group(0)) - 2) + '"',
            body,
        )
        body = re.sub(
            r"'([^'\\]|\\.)*'",
            lambda m: "'" + " " * (len(m.group(0)) - 2) + "'",
            body,
        )
        out.append(body + newline)
    return "".join(out)


def _brace_spans(blanked: str, open_re: re.Pattern[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in open_re.finditer(blanked):
        brace = blanked.find("{", match.start())
        if brace < 0:
            continue
        depth = 0
        i = brace
        while i < len(blanked):
            ch = blanked[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        spans.append((match.start(), i))
    return spans


def _enum_body_line_set(text: str) -> frozenset[int]:
    blanked = _blank_all_comments(text)
    lines: set[int] = set()
    for start, end in _brace_spans(blanked, ENUM_OPEN_LITERAL_RE):
        first = text.count("\n", 0, start) + 1
        last = text.count("\n", 0, end) + 1
        lines.update(range(first, last + 1))
    return frozenset(lines)


# Anonymous, non-typedef enum bodies only: their members are plain constants that
# can be relocated. Members of a NAMED or typedef'd enum define a type and must
# never be "moved to a .c/.cpp" — doing so would break the enum type.
_ANON_ENUM_OPEN_RE = re.compile(r"(?<![A-Za-z0-9_])enum\s*\{")


def _anonymous_enum_body_line_set(text: str) -> frozenset[int]:
    blanked = _blank_all_comments(text)
    lines: set[int] = set()
    for start, end in _brace_spans(blanked, _ANON_ENUM_OPEN_RE):
        prefix = blanked[:start]
        stmt_start = max(prefix.rfind(";"), prefix.rfind("}"), prefix.rfind("{"))
        if re.search(r"\btypedef\b", prefix[stmt_start + 1 :]):
            continue
        first = text.count("\n", 0, start) + 1
        last = text.count("\n", 0, end) + 1
        lines.update(range(first, last + 1))
    return frozenset(lines)


def _literal_value(token: str) -> int:
    base = token.rstrip("uUlLzZ")
    return int(base, 16) if base[:2].lower() == "0x" else int(base)


def _strip_for_literal_scan(raw: str) -> str:
    line = re.sub(r"/\*.*?\*/", "", raw, flags=re.DOTALL)
    line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
    line = re.sub(r"//.*", "", line)
    return line


def _is_function_macro(line: str) -> bool:
    return bool(re.match(r"^\s*#\s*define\s+[A-Za-z_]\w*\s*\(", line))


def _line_has_numeric_value(line: str) -> bool:
    return bool(NUMERIC_LITERAL_RE.search(_strip_for_literal_scan(line)))


def _format_macro_literal_issue(hit: LiteralHit) -> str:
    return (
        f"{hit.label}:{hit.lineno}: numeric literal {hit.token} in format/printf macro "
        f"(use a named enum/constexpr index; clang-tidy may not diagnose attribute "
        f"arguments in all header contexts)"
    )


def scan_clang_tidy_gap_literals(text: str, label: str) -> list[str]:
    """Flag numeric literals in format/printf attribute macro arguments only."""
    blanked = _blank_all_comments(text)
    raw_lines = text.splitlines()
    code_lines = blanked.splitlines()
    if len(code_lines) < len(raw_lines):
        code_lines.extend([""] * (len(raw_lines) - len(code_lines)))
    enum_lines = _enum_body_line_set(text)
    issues: list[str] = []
    for lineno, raw in enumerate(raw_lines, 1):
        code = code_lines[lineno - 1] if lineno <= len(code_lines) else ""
        if lineno in enum_lines:
            continue
        if code.lstrip().startswith("#"):
            continue
        if not FORMAT_MACRO_LITERAL_RE.search(code):
            continue
        for match in INT_LITERAL_RE.finditer(code):
            value = _literal_value(match.group(0))
            if value in IDENTITY_LITERAL_VALUES:
                continue
            hit = LiteralHit(label, lineno, match.group(0), value, raw, match.end())
            issues.append(_format_macro_literal_issue(hit))
    return issues


def extract_header_constants(text: str, label: str) -> list[HeaderConstant]:
    constants: list[HeaderConstant] = []
    enum_lines = _anonymous_enum_body_line_set(text)
    for lineno, raw in enumerate(text.splitlines(), 1):
        if lineno not in enum_lines:
            continue
        for match in ENUM_MEMBER_LITERAL_RE.finditer(raw):
            constants.append(HeaderConstant(label, lineno, match.group(1)))

    for lineno, raw in enumerate(text.splitlines(), 1):
        if lineno in enum_lines:
            continue
        if _is_function_macro(raw):
            continue
        define_match = HEADER_DEFINE_LITERAL_RE.match(raw)
        if define_match and _line_has_numeric_value(raw):
            constants.append(HeaderConstant(label, lineno, define_match.group(1)))
            continue
        const_match = HEADER_CONST_LITERAL_RE.match(raw.strip())
        if const_match and _line_has_numeric_value(raw):
            constants.append(HeaderConstant(label, lineno, const_match.group(1)))
    return constants


def translation_units_referencing(symbol: str, tu_texts: dict[Path, str]) -> set[Path]:
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\b")
    return {path for path, text in tu_texts.items() if pattern.search(text)}


def scan_header_constant_placement(
    header_constants: list[HeaderConstant],
    header_paths: dict[str, Path],
    tu_texts: dict[Path, str],
    config: PolicyConfig,
    header_texts: dict[Path, str],
) -> list[str]:
    issues: list[str] = []
    spec_tracked = config.spec_tracked_symbols
    for constant in header_constants:
        path = header_paths.get(constant.label)
        if path is None or config.has(path, K_MAGIC_SHARED):
            continue
        if constant.name in spec_tracked:
            continue
        if _referenced_in_headers(constant.name, path, header_texts):
            continue
        users = translation_units_referencing(constant.name, tu_texts)
        if len(users) != 1:
            continue
        only_tu = config.label(next(iter(users)))
        issues.append(
            f"{constant.label}:{constant.lineno}: header constant {constant.name} is only "
            f"referenced from {only_tu} (move to that .c/.cpp as static/file-local constexpr "
            f"instead of exposing it in a header)"
        )
    return issues


def _referenced_in_headers(symbol: str, defining: Path, header_texts: dict[Path, str]) -> bool:
    """True if the symbol is used in any header beyond its single definition site."""
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\b")
    for path, text in header_texts.items():
        count = len(pattern.findall(text))
        if path == defining:
            if count > 1:  # definition + at least one in-header use
                return True
        elif count > 0:
            return True
    return False


def scan_constant_placement(config: PolicyConfig, paths: list[Path]) -> list[str]:
    texts: dict[Path, str] = {}
    labels: dict[Path, str] = {}
    for path in paths:
        texts[path] = path.read_text(encoding="utf-8", errors="replace")
        labels[path] = config.label(path)

    tu_texts = {path: text for path, text in texts.items() if config.has(path, K_TU)}
    header_texts = {
        path: _blank_all_comments(text)
        for path, text in texts.items()
        if config.has(path, K_HEADER)
    }

    header_constants: list[HeaderConstant] = []
    header_paths: dict[str, Path] = {}

    errors: list[str] = []
    for path in paths:
        label = labels.get(path)
        if label is None:
            continue
        errors.extend(scan_clang_tidy_gap_literals(texts[path], label))
        if config.has(path, K_HEADER):
            header_paths[label] = path
            header_constants.extend(extract_header_constants(texts[path], label))

    errors.extend(
        scan_header_constant_placement(
            header_constants, header_paths, tu_texts, config, header_texts
        )
    )
    return errors


def strip_comments_and_strings(line: str) -> str:
    line = re.sub(r"//.*", "", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r'"([^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'([^'\\]|\\.)*'", "''", line)
    return line


def strip_block_comments_preserve_lines(text: str) -> str:
    return re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )


def paren_content(text: str, open_pos: int) -> str | None:
    depth = 0
    start = open_pos + 1
    for pos in range(open_pos, len(text)):
        char = text[pos]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:pos]
    return None


def count_call_args(args: str) -> int:
    stripped = args.strip()
    if not stripped or stripped == "void":
        return 0
    depth = 0
    count = 1
    for char in stripped:
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(depth - 1, 0)
        elif char == "," and depth == 0:
            count += 1
    return count


def scan_naked_stack_arrays(path: Path, config: PolicyConfig) -> list[str]:
    """Flag char/uint8_t stack arrays with numeric bounds >= configured minimum."""
    if not config.has(path, K_STACK_ARRAY):
        return []

    issues: list[str] = []
    stack_min = config.stack_array_min
    text = path.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        code = strip_comments_and_strings(line)
        for _name, size_s in STACK_ARRAY_DECL_RE.findall(code):
            size = int(size_s)
            if size < stack_min:
                continue
            issues.append(
                f"{path}:{i}: naked stack array bound {size} "
                f"(use a named #define/enum cap from shared bounds headers)"
            )
    return issues


def function_info_from_signature(signature: str) -> tuple[str, int] | None:
    """Best-effort C/C++ function name extraction for lint, not compilation."""
    before_body = signature.split("{", 1)[0]
    if before_body.lstrip().startswith("#") or ";" in before_body:
        return None
    match = CALL_NAME_RE.search(before_body)
    if match is None:
        return None
    name = match.group(1)
    if name in CONTROL_CALL_NAMES:
        return None
    args = paren_content(before_body, match.end() - 1)
    if args is None:
        return None
    return name, count_call_args(args)


def scan_direct_recursion(path: Path, config: PolicyConfig) -> list[str]:
    """Flag direct self-calls unless bounded recursion is explicitly annotated."""
    if not config.has(path, K_TU):
        return []

    bounded_annotation = config.bounded_recursion_annotation
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    raw_lines = raw_text.splitlines()
    code_text = strip_block_comments_preserve_lines(raw_text)
    code_lines = [strip_comments_and_strings(line) for line in code_text.splitlines()]
    issues: list[str] = []
    index = 0
    signature_parts: list[str] = []

    while index < len(code_lines):
        code = code_lines[index]
        stripped = code.strip()
        if not stripped or stripped.startswith("#"):
            signature_parts.clear()
            index += 1
            continue

        signature_parts.append(code)
        signature = " ".join(signature_parts)
        open_pos = signature.find("{")
        semicolon_pos = signature.find(";")
        if semicolon_pos != -1 and (open_pos == -1 or semicolon_pos < open_pos):
            signature_parts.clear()
            index += 1
            continue
        if open_pos == -1:
            if len(signature_parts) > 8:
                signature_parts.clear()
            index += 1
            continue

        function_info = function_info_from_signature(signature)
        signature_parts.clear()
        if function_info is None:
            index += 1
            continue
        name, param_count = function_info

        depth = 0
        body_code: list[tuple[int, str]] = []
        body_raw: list[str] = []
        first_body_line = True
        while index < len(code_lines):
            code_line = code_lines[index]
            raw_line = raw_lines[index]
            if first_body_line:
                fragment = code_line.split("{", 1)[1]
                raw_fragment = raw_line.split("{", 1)[1] if "{" in raw_line else raw_line
                first_body_line = False
            else:
                fragment = code_line
                raw_fragment = raw_line
            depth += code_line.count("{")
            depth -= code_line.count("}")
            body_code.append((index + 1, fragment))
            body_raw.append(raw_fragment)
            index += 1
            if depth <= 0:
                break

        if bounded_annotation in "\n".join(body_raw):
            continue
        call_re = re.compile(rf"\b{re.escape(name)}\s*\(")
        for line_no, body_line in body_code:
            for match in call_re.finditer(body_line):
                args = paren_content(body_line, match.end() - 1)
                if args is None or count_call_args(args) != param_count:
                    continue
                issues.append(
                    f"{path}:{line_no}: direct recursion in {name}() "
                    f"(replace with an iterative bounded loop or annotate "
                    f"{bounded_annotation} with the maximum depth)"
                )
                break
            else:
                continue
            break

    return issues


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    errors: list[str] = []
    errors.extend(scan_constant_placement(config, paths))
    for path in paths:
        errors.extend(scan_naked_stack_arrays(path, config))
        errors.extend(scan_direct_recursion(path, config))
    return sorted(set(errors))


_SELF_TEST_CASES: dict[str, tuple[str, set[str]]] = {
        "bad_type4.cpp": (
            "void f(){ uint16_t c = 240; (void)c; }\n",
            set(),
        ),
        "good_type4.cpp": (
            '#include "sample/limits.h"\n'
            "void f(){ uint16_t c = SAMPLE_PAYLOAD_MAX; (void)c; }\n",
            set(),
        ),
        "local_define.cpp": (
            "#define CHUNK_MAX 240u\nvoid f(){ uint8_t n = CHUNK_MAX; (void)n; }\n",
            set(),
        ),
        "limit_test.c": (
            "void t(void){ (void)SAMPLE_PAYLOAD_MAX; }\n",
            set(),
        ),
        "bad_test_literal.c": (
            "void t(void){ unsigned sentinel = 0xAAu; (void)sentinel; }\n",
            set(),
        ),
        "bad_stack.cpp": (
            "void f(){ char vcard[400]; vcard[0]=0; (void)vcard; }\n",
            {"bad_stack.cpp"},
        ),
        "good_stack.cpp": (
            '#include "sample/limits.h"\n'
            "void f(){ char line[SAMPLE_JSONL_LINE_MAX]; line[0]=0; (void)line; }\n",
            set(),
        ),
        "bad_recursion.cpp": (
            "static bool walk(unsigned depth) { return depth == 0u ? true : walk(depth - 1u); }\n",
            {"bad_recursion.cpp"},
        ),
        "good_loop.cpp": (
            "void loop(void) { poll_one_cycle(); }\n",
            set(),
        ),
        "bad_loop_bound.cpp": (
            "void scan(void) { for (int depth = 0; depth < 8; ++depth) { step(); } }\n",
            set(),
        ),
        "good_loop_bound.cpp": (
            "enum { SCAN_DEPTH_MAX = 8u }; void scan(void) { for (int depth = 0; depth < SCAN_DEPTH_MAX; ++depth) { step(); } }\n",
            set(),
        ),
        "good_bounded_recursion.cpp": (
            "static bool walk(unsigned depth) { /* SAMPLE_BOUNDED_RECURSION max depth: 2 */ return depth == 0u ? true : walk(depth - 1u); }\n",
            set(),
        ),
        "bad_plain_decimal.cpp": (
            "int f(int x){ if (x <= 225) { return 42; } return 0; }\n",
            set(),
        ),
        "bad_hex.cpp": (
            "void g(void){ uint8_t c = 0xFFu; (void)c; }\n",
            set(),
        ),
        "good_constexpr.cpp": (
            "static constexpr unsigned kValue = 0x22u;\nvoid f(void){ (void)kValue; }\n",
            set(),
        ),
        "identity_literals_ok.cpp": (
            "void f(int x){ if (x <= 0) { (void)x; } if (x == 1u) { return; } }\n",
            set(),
        ),
        "comments_strings_ok.cpp": (
            'void f(void){ const char *s = "240 0xFF"; /* 400 */ (void)s; }\n',
            set(),
        ),
        "single_use_header_cap.h": (
            "#define SAMPLE_LOCAL_HEADER_CAP 7u\n",
            {"single_use_header_cap.h"},
        ),
        "uses_single_header.cpp": (
            '#include "single_use_header_cap.h"\nint f(void){ return SAMPLE_LOCAL_HEADER_CAP; }\n',
            set(),
        ),
        "shared_header_cap.h": (
            "#define SAMPLE_SHARED_HEADER_CAP 8u\n",
            set(),
        ),
        "uses_shared_header_a.cpp": (
            '#include "shared_header_cap.h"\nint a(void){ return SAMPLE_SHARED_HEADER_CAP; }\n',
            set(),
        ),
        "uses_shared_header_b.cpp": (
            '#include "shared_header_cap.h"\nint b(void){ return SAMPLE_SHARED_HEADER_CAP; }\n',
            set(),
        ),
        "bad_printf_indices.h": (
            "SAMPLE_PRINTF(4, 5)\nbool sample_appendf(char *buf, size_t cap, size_t *off, const char *fmt, ...);\n",
            {"bad_printf_indices.h"},
        ),
}


def prepare_self_test_repo(root: Path) -> None:
    core = root / "core"
    core.mkdir(parents=True)
    tests = root / "tests"
    tests.mkdir(parents=True)
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
        "  source_roots: [core, include, userspace, tests]\n"
        "policy:\n  unsafe_api:\n    header: sample_null.h\n    include_headers: [attrs.h, mem_util.h]\n"
        "  constants_headers: [limits.h, board_config.h, config.h]\n",
        encoding="utf-8",
    )
    canon = root / "include" / "sample"
    canon.mkdir(parents=True)
    (canon / "limits.h").write_text(
        "enum { SAMPLE_PAYLOAD_MAX = 32u, SAMPLE_JSONL_LINE_MAX = 512u };\n",
        encoding="utf-8",
    )
    for name, (content, _) in _SELF_TEST_CASES.items():
        if name in {"limit_test.c", "bad_test_literal.c"}:
            continue
        if name.endswith(".h"):
            target = root / "include" / "sample" / name
        else:
            target = core / name
        target.write_text(content, encoding="utf-8")
    (tests / "test_limits.c").write_text(_SELF_TEST_CASES["limit_test.c"][0], encoding="utf-8")
    (tests / "bad_test_literal.c").write_text(_SELF_TEST_CASES["bad_test_literal.c"][0], encoding="utf-8")


def verify_self_test(errors: list[str]) -> int:
    reported = {Path(err.split(":", 2)[0]).name for err in errors}
    failed = False
    for name, (_, expected) in _SELF_TEST_CASES.items():
        probe_name = "test_limits.c" if name == "limit_test.c" else name
        if expected and probe_name not in reported and name not in reported:
            print(f"self-test miss: expected violation in {name}", file=sys.stderr)
            failed = True
        if not expected and (probe_name in reported or name in reported):
            print(f"self-test false positive: {name}", file=sys.stderr)
            failed = True
    if failed:
        print("reported:", sorted(reported), file=sys.stderr)
        return 1
    print("constant placement self-test: OK")
    return 0

