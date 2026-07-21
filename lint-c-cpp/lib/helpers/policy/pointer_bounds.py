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

"""Safe indexing for pointer-parameter buffers (defense-in-depth; not flow-sensitive).
Requires guards or canonical span/copy helpers before subscripts."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from policy_config import PolicyConfig
from scan_policy import strip_comments_and_strings

LINT_TITLE = "safe-indexing policy"
LINT_FIX_HINT = "Use project span/copy helpers or add explicit bounds guards before indexing."
LINT_OK_DETAIL = (
    "  (supplementary anti-drift gate; bounds safety is enforced by helpers, "
    "sanitizer/Valgrind profiles, and clang-tidy/cppcheck)"
)

GUARD_REGEXES = (
    re.compile(r"\b(?:\w*len|\w*cap|\w*bytes|nbytes|rlen|count|size|total|need|end_offset|declared_total|"
               r"response_len|max_storage_len|pos|nstd|hdr_skip|nad_idx)\s*(?:<=|>=|==|!=|[<>])\s*"),
    re.compile(r"\b\w+\s*(?:<=|>=|==|!=|[<>])\s*\d+[uU]?\b"),
    re.compile(r"for\s*\([^;]*;\s*[^;]*<\s*(?:len|n|cap|\w+_len|\w+_cap|sizeof\s*\()"),
    re.compile(r"while\s*\(\s*\w+\s*<\s*(?:len|cap|\w+_len|\w+_cap|sizeof\s*\()"),
    # Null-terminated (sentinel) C-string scan. Char literals are blanked to '<spaces>'
    # by strip_comments_and_strings, so match `s[i] != '...'` and `s[i] != 0` too.
    re.compile(r"\w+\[\s*\w+\s*\]\s*!=\s*(?:'[^']*'|0[uU]?)"),
    re.compile(r"for\s*\([^;]*;\s*\w+\[\s*\w+\s*\]\s*;"),
    re.compile(r"\bstd::min\s*\("),
    re.compile(r"\b(?:sizeof|static_cast<unsigned>\(sizeof)\s*\("),
    re.compile(r"\.size\s*\(\s*\)"),
)

POINTER_PARAM_RE = re.compile(
    r"\b(?:const\s+)?(?:(?:unsigned\s+)?(?:u?int(?:8|16|32|64)_t|char|byte|std::byte|void)"
    r"|unsigned\s+char)\s*\*+\s*(\w+)\b"
)

LOCAL_ARRAY_DECL = re.compile(
    r"\b(?:static\s+)?(?:const\s+)?(?:unsigned\s+)?(?:u?int(?:8|16|32|64)_t|char)\s+"
    r"(\w+)\s*\[[^\]]+\]"
)

SUBSCRIPT = re.compile(r"\b(\w+)\[([^\]]+)\]")
DATA_PTR = re.compile(r"(?:&(\w+)\[(\d+[uU]?)\]|(\w+)\s*\+\s*(\d+[uU]?))")
WRITE_SUBSCRIPT = re.compile(r"\b(\w+)\[([^\]]+)\]\s*(?:\+\+|--)?\s*=(?!=)")
LITERAL_INDEX = re.compile(r"^(\d+)[uU]?$")
LOOP_INDEX = re.compile(r"for\s*\(\s*(?:uint\d+_t\s+)?(\w+)\s*=")
BOUNDED_LOOP = re.compile(
    r"for\s*\(\s*(?:uint\d+_t\s+)?(\w+)\s*=\s*[^;]*;\s*\1\s*<\s*([^;)]+)"
)
PARAM_ARRAY_BOUND_RE = re.compile(r"\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]\s*[,);]")
_SAFE_HELPER_PARTS = ("copy_", "try_", "span_ok", "parse_", "bounded_")


def _safe_helper_call_in_body(
    body: str, config: PolicyConfig, index_expr: str
) -> bool:
    prefix = config.c_api_prefix
    part_alt = "|".join(re.escape(part) for part in _SAFE_HELPER_PARTS)
    expr = re.sub(r"\s+", "", index_expr).rstrip("+")
    helper_names = [re.escape(token) for token in config.safe_indexing_helpers]
    helper_name = (
        rf"(?:{'|'.join(helper_names)}|{re.escape(prefix)}_\w*(?:{part_alt})\w*)"
        if helper_names
        else rf"{re.escape(prefix)}_\w*(?:{part_alt})\w*"
    )
    for match in re.finditer(rf"\b{helper_name}\s*\(([^;]*)\)", body):
        args = re.sub(r"\s+", "", match.group(1))
        if re.search(rf"(?<!\w){re.escape(expr)}(?:[uU])?(?!\w)", args):
            return True
    return False


def function_has_guard_for_index(
    lines: list[str], line_idx: int, index_expr: str, config: PolicyConfig
) -> bool:
    body = function_body(lines, line_idx)
    expr = re.sub(r"\s+", "", index_expr).rstrip("+")
    if _safe_helper_call_in_body(body, config, expr):
        return True
    if not re.fullmatch(r"\w+", expr):
        return False
    bound = r"(?:\w*(?:len|cap|size|count|bytes)\w*|\w+\.size\s*\(\s*\))"
    return bool(
        re.search(rf"\b{re.escape(expr)}\s*(?:<|<=|>=|>)\s*{bound}", body)
        or re.search(rf"{bound}\s*(?:<|<=|>=|>)\s*\b{re.escape(expr)}\b", body)
    )


def function_bounds(lines: list[str], line_idx: int) -> tuple[int, int]:
    depth = 0
    func_start = 0
    for i in range(line_idx, -1, -1):
        opens = lines[i].count("{")
        closes = lines[i].count("}")
        if i == line_idx:
            net = closes - opens
            depth += max(net, 0)
        else:
            depth += closes - opens
        if depth < 0:
            func_start = i
            break
    else:
        func_start = 0

    while func_start > 0:
        prev = lines[func_start - 1].strip()
        if not prev or prev.startswith("#") or prev.endswith((";", "{", "}", ":")):
            break
        func_start -= 1

    depth = 0
    func_end = len(lines) - 1
    started = False
    for i in range(func_start, len(lines)):
        depth += lines[i].count("{")
        depth -= lines[i].count("}")
        if depth > 0:
            started = True
        if started and depth <= 0:
            func_end = i
            break
    return func_start, func_end


def function_body(lines: list[str], line_idx: int) -> str:
    start, end = function_bounds(lines, line_idx)
    return "\n".join(lines[start : end + 1])


def function_header(body: str) -> str:
    brace = body.find("{")
    return body if brace < 0 else body[:brace]


def pointer_params(body: str) -> frozenset[str]:
    return frozenset(POINTER_PARAM_RE.findall(function_header(body)))


def local_array_names(body: str) -> frozenset[str]:
    return frozenset(LOCAL_ARRAY_DECL.findall(body))


def external_buffer_names(body: str) -> frozenset[str]:
    return pointer_params(body) - local_array_names(body)


def literal_index_value(index_expr: str) -> int | None:
    match = LITERAL_INDEX.match(index_expr.strip())
    if not match:
        return None
    return int(match.group(1))


def function_has_output_cap_for_literal(lines: list[str], line_idx: int, lit: int) -> bool:
    body = function_body(lines, line_idx)
    need = lit + 1
    size_name = r"(?:n|rlen|count|bytes|\w*(?:cap|len|size))"
    for match in re.finditer(
        rf"\b{size_name}\s*(<=|>=|<|>)\s*(\d+)[uU]?\b", body
    ):
        operator, raw_value = match.groups()
        value = int(raw_value)
        if operator in {"<", ">="} and value >= need:
            return True
        if operator in {"<=", ">"} and value >= lit:
            return True
    return False


def function_has_loop_bound_for_index(lines: list[str], line_idx: int, index_expr: str) -> bool:
    body = function_body(lines, line_idx)
    idx = index_expr.strip()
    if idx in {"i", "n", "pos"}:
        for match in BOUNDED_LOOP.finditer(body):
            if match.group(1) == idx:
                return True
    for match in LOOP_INDEX.finditer(body):
        if match.group(1) == idx:
            if re.search(rf"for\s*\([^;]*;\s*{re.escape(idx)}\s*<\s*", body):
                return True
    return False


def function_has_length_guard_for_expr(lines: list[str], line_idx: int, index_expr: str) -> bool:
    body = function_body(lines, line_idx)
    expr = index_expr.strip()

    def len_minus_guard(var: str, minus_lit: int) -> bool:
        need = minus_lit + 1
        return bool(
            re.search(rf"\b{re.escape(var)}\s*(?:<=|>=|[<>])\s*{need}[uU]?\b", body)
            or re.search(rf"\b{re.escape(var)}\s*>=\s*{need}[uU]?\b", body)
        )

    match = re.fullmatch(r"(\w+)\s*-\s*(\d+)[uU]?", expr)
    if match:
        return len_minus_guard(match.group(1), int(match.group(2)))
    return False


def subscript_allowed(
    lines: list[str],
    line_idx: int,
    index_expr: str,
    *,
    is_write: bool,
    config: PolicyConfig,
) -> bool:
    lit = literal_index_value(index_expr)
    if lit is not None and function_has_output_cap_for_literal(lines, line_idx, lit):
        return True
    if function_has_loop_bound_for_index(lines, line_idx, index_expr):
        return True
    if function_has_length_guard_for_expr(lines, line_idx, index_expr):
        return True
    if function_has_guard_for_index(lines, line_idx, index_expr, config):
        return True
    return False


def scan_subscripts(path: Path, lines: list[str], config: PolicyConfig) -> list[str]:
    issues: list[str] = []
    prefix = config.c_api_prefix
    for i, line in enumerate(lines):
        if "(" in line and PARAM_ARRAY_BOUND_RE.search(line) and "{" not in line:
            continue
        body = function_body(lines, i)
        names = external_buffer_names(body)
        if not names:
            continue
        write_match = WRITE_SUBSCRIPT.search(line)
        is_write = write_match is not None and write_match.group(1) in names
        for match in SUBSCRIPT.finditer(line):
            name, idx_expr = match.group(1), match.group(2).strip()
            if name not in names:
                continue
            if LOCAL_ARRAY_DECL.search(line) and name in local_array_names(body):
                continue
            if subscript_allowed(lines, i, idx_expr, is_write=is_write, config=config):
                continue
            kind = "write to" if is_write else "unchecked subscript"
            issues.append(
                f"{path}:{i + 1}: {kind} [{idx_expr}] on pointer buffer '{name}' "
                f"(use {prefix}_* span/copy helpers or an explicit bounds guard)"
            )
    return issues


def scan_data_ptrs(path: Path, lines: list[str], config: PolicyConfig) -> list[str]:
    issues: list[str] = []
    for i, line in enumerate(lines):
        match = DATA_PTR.search(line)
        if not match:
            continue
        name = match.group(1) or match.group(3)
        off = match.group(2) or match.group(4)
        if not name:
            continue
        body = function_body(lines, i)
        if name not in external_buffer_names(body):
            continue
        if function_has_guard_for_index(lines, i, off or "", config):
            continue
        literal_off = literal_index_value(off or "")
        if literal_off is not None and function_has_output_cap_for_literal(lines, i, literal_off):
            continue
        if function_has_length_guard_for_expr(lines, i, off or ""):
            continue
        issues.append(
            f"{path}:{i + 1}: unchecked buffer data pointer '{name}' at offset {off} "
            f"(use approved span/copy helpers or an explicit bounds guard)"
        )
    return issues


def scan_file(path: Path, config: PolicyConfig) -> list[str]:
    text = strip_comments_and_strings(path.read_text(encoding="utf-8", errors="replace"))
    lines = text.splitlines()
    issues: list[str] = []
    issues.extend(scan_subscripts(path, lines, config))
    issues.extend(scan_data_ptrs(path, lines, config))
    return issues


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    return [issue for path in paths for issue in scan_file(path, config)]


_SELF_TEST_CASES: dict[str, tuple[str, set[str]]] = {
        "safe_copy_ok.c": (
            '#include "sample/mem_util.h"\n'
            "bool g(uint8_t *d, const uint8_t *s) { return sample_copy_bytes(d, 8, 0, s, 4); }\n",
            set(),
        ),
        "literal_header_ok.c": (
            "bool h(const uint8_t *payload, uint16_t n) {\n"
            "  if (n < 5u) return false;\n"
            "  return payload[0] == 0x00u && payload[4] == 3u;\n"
            "}\n",
            set(),
        ),
        "deep_literal_bad.c": (
            "bool h(const uint8_t *resp, int n) {\n"
            "  (void)n;\n"
            "  return resp[14] == 0;\n"
            "}\n",
            {"deep_literal_bad.c"},
        ),
        "inline_deep_literal_bad.c": (
            "bool h(const uint8_t *payload) { return payload[5] == 0; }\n",
            {"inline_deep_literal_bad.c"},
        ),
        "multiline_sig_deep_literal_bad.c": (
            "bool h(const uint8_t *payload,\n"
            "       uint16_t n) {\n"
            "  (void)n;\n"
            "  return payload[7] == 0;\n"
            "}\n",
            {"multiline_sig_deep_literal_bad.c"},
        ),
        "multiline_sig_guarded_ok.c": (
            "bool h(const uint8_t *payload,\n"
            "       uint16_t n) {\n"
            "  if (n < 8u) return false;\n"
            "  return payload[7] == 0;\n"
            "}\n",
            set(),
        ),
        "local_array_decl_ok.c": (
            "void h(void) { uint8_t scratch[5]; scratch[4] = 0; (void)scratch; }\n",
            set(),
        ),
        "switch_size_guard_ok.cpp": (
            "void f(std::vector<uint8_t> resp) {\n"
            "  size_t pos = 0;\n"
            "  if (pos + 2u >= resp.size()) { return; }\n"
            "  switch (resp[pos]) {\n"
            "  default: break;\n"
            "  }\n"
            "}\n",
            set(),
        ),
        "switch_noguard_bad.cpp": (
            "void f(const uint8_t *resp, int n) {\n"
            "  (void)n;\n"
            "  switch (resp[7]) {\n"
            "  default: break;\n"
            "  }\n"
            "}\n",
            {"switch_noguard_bad.cpp"},
        ),
        "guarded_var_ok.c": (
            "bool h(const uint8_t *payload, uint16_t payload_len, uint8_t lc) {\n"
            "  if (!sample_span_ok(5u, lc, payload_len)) return false;\n"
            "  return payload[5] == 0;\n"
            "}\n",
            set(),
        ),
        "loop_bound_ok.c": (
            "uint16_t crc(const uint8_t *buf, uint16_t len) {\n"
            "  uint16_t c = 0;\n"
            "  for (uint16_t i = 0u; i < len; i++) { c ^= buf[i]; }\n"
            "  return c;\n"
            "}\n",
            set(),
        ),
        "len_minus_ok.c": (
            "bool ok(const uint8_t *frame, uint16_t len) {\n"
            "  if (len < 3u) return false;\n"
            "  return frame[len - 2u] == 0;\n"
            "}\n",
            set(),
        ),
        "cap_literal_ok.c": (
            "bool fill(uint8_t *out, unsigned cap) {\n"
            "  if (cap < 5u) return false;\n"
            "  out[4] = 0;\n"
            "  return true;\n"
            "}\n",
            set(),
        ),
        "data_ptr_bad.c": (
            "bool w(const uint8_t *payload, uint16_t payload_len) {\n"
            "  (void)payload_len;\n"
            "  return write_slot(4, &payload[5]);\n"
            "}\n",
            {"data_ptr_bad.c"},
        ),
        "pos_write_bad.c": (
            "bool w(uint8_t *buf, size_t cap) {\n"
            "  size_t pos = 0;\n"
            "  buf[pos++] = 1;\n"
            "  return true;\n"
            "}\n",
            {"pos_write_bad.c"},
        ),
        "unrelated_guard_bad.c": (
            "bool h(const uint8_t *payload, uint16_t payload_len, unsigned retries) {\n"
            "  if (retries > 3u) return false;\n"
            "  return payload[5] == 0;\n"
            "}\n",
            {"unrelated_guard_bad.c"},
        ),
        "non_pointer_ok.c": (
            "struct S { uint8_t data[8]; };\n"
            "uint8_t f(S *s) { return s->data[5]; }\n",
            set(),
        ),
}


def prepare_self_test_repo(root: Path) -> None:
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
        "  source_roots: [core, port, include, userspace, tests]\n"
        "policy:\n  unsafe_api:\n    header: sample_null.h\n    include_headers: [attrs.h, mem_util.h]\n"
        "  constants_headers: [limits.h, board_config.h, config.h]\n",
        encoding="utf-8",
    )
    include = root / "include" / "sample"
    include.mkdir(parents=True)
    (include / "mem_util.h").write_text(
        "bool sample_copy_bytes(void *d, size_t dc, size_t off, const void *s, size_t n);\n"
        "bool sample_span_ok(size_t base, size_t extent, size_t cap);\n",
        encoding="utf-8",
    )
    probe = root / "core" / "probe"
    probe.mkdir(parents=True)
    for name, (content, _) in _SELF_TEST_CASES.items():
        (probe / name).write_text(content, encoding="utf-8")


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
    if failed:
        print("reported:", sorted(reported), file=sys.stderr)
        return 1
    print("safe-indexing self-test: OK")
    return 0

