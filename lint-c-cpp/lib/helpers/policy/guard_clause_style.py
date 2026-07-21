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

"""Early-return guard style for fallible bool functions (source scan job).
Rejects positive if/return-true wrappers; dispatch/classification chains are OK."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from policy_config import PolicyConfig
from scan_policy import strip_comments_and_strings

LINT_TITLE = "early-return style"
LINT_FIX_HINT = "Prefer guard clauses over positive if/return-true wrappers."

IF_POSITIVE = re.compile(r"^\s*if\s*\((.+)\)\s*\{?\s*$")
RETURN_TRUE = re.compile(r"^\s*return\s+true\s*;\s*$")
RETURN_FALSE = re.compile(r"^\s*return\s+false\s*;\s*$")
ELSE_FALSE = re.compile(r"^\s*\}\s*else\s*\{\s*$")
CLOSE_BRACE = re.compile(r"^\s*\}\s*$")
ELSE_IF = re.compile(r"^\s*\}\s*else\s+if\s*\(")

_SELF_TEST_CASES: dict[str, tuple[str, set[str]]] = {
    "wrapped_bad.c": (
        "static bool wrapped_bad(int x) {\n"
        "  if (x > 0) {\n"
        "    do_work();\n"
        "    return true;\n"
        "  }\n"
        "  return false;\n"
        "}\n",
        {"wrapped_bad.c"},
    ),
    "wrapped_unspaced_bad.c": (
        "static bool wrapped_unspaced_bad(int x) {\n"
        "  if (x>0) {\n"
        "    do_work();\n"
        "    return true;\n"
        "  }\n"
        "  return false;\n"
        "}\n",
        {"wrapped_unspaced_bad.c"},
    ),
    "wrapped_one_line_bad.c": (
        "static bool wrapped_one_line_bad(int x) { if (x > 0) { do_work(); return true; } return false; }\n",
        {"wrapped_one_line_bad.c"},
    ),
    "guard_ok.c": (
        "static bool guard_ok(int x) {\n"
        "  if (x <= 0) {\n"
        "    return false;\n"
        "  }\n"
        "  do_work();\n"
        "  return true;\n"
        "}\n",
        set(),
    ),
    "dispatch_ok.c": (
        "static bool dispatch_ok(int k) {\n"
        "  if (k == 1) {\n"
        "    return true;\n"
        "  }\n"
        "  if (k == 2) {\n"
        "    return true;\n"
        "  }\n"
        "  return false;\n"
        "}\n",
        set(),
    ),
    "classify_ok.c": (
        "static bool classify_ok(char c) {\n"
        "  if (c >= '0' && c <= '9') {\n"
        "    return true;\n"
        "  }\n"
        "  if (c >= 'a' && c <= 'f') {\n"
        "    return true;\n"
        "  }\n"
        "  return false;\n"
        "}\n",
        set(),
    ),
    "else_bad.c": (
        "static bool else_bad(int x) {\n"
        "  if (x > 0) {\n"
        "    return true;\n"
        "  } else {\n"
        "    return false;\n"
        "  }\n"
        "}\n",
        {"else_bad.c"},
    ),
    "else_if_dispatch_ok.c": (
        "static bool chain_ok(int k) {\n"
        "  if (k == 1) {\n"
        "    return true;\n"
        "  } else if (k == 2) {\n"
        "    return true;\n"
        "  } else {\n"
        "    return false;\n"
        "  }\n"
        "}\n",
        set(),
    ),
}


def find_matching_brace(lines: list[str], open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(lines)):
        depth += lines[i].count("{")
        depth -= lines[i].count("}")
        if depth == 0 and i > open_idx:
            return i
    return -1


def condition_looks_inverted(cond: str) -> bool:
    stripped = cond.strip()
    if stripped.startswith("!"):
        return True
    if "||" in stripped:
        return True
    return False


def find_block_open_for_close(lines: list[str], close_idx: int) -> int:
    depth = 0
    for i in range(close_idx, -1, -1):
        depth -= lines[i].count("{")
        depth += lines[i].count("}")
        if depth == 0 and i < close_idx:
            return i
    return -1


def preceding_if_sibling(lines: list[str], if_idx: int) -> bool:
    j = if_idx - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    if j < 0 or not CLOSE_BRACE.match(lines[j]):
        return False
    prev_open = find_block_open_for_close(lines, j)
    if prev_open < 0:
        return False
    if j <= prev_open:
        return False
    if not RETURN_TRUE.match(lines[j - 1]):
        return False
    return IF_POSITIVE.match(lines[prev_open]) is not None


def is_dispatch_or_classification(lines: list[str], if_idx: int, close_idx: int) -> bool:
    if if_idx > 0 and ELSE_IF.match(lines[if_idx - 1]):
        return True
    if preceding_if_sibling(lines, if_idx):
        return True
    j = close_idx + 1
    while j < len(lines):
        line = lines[j]
        if not line.strip():
            j += 1
            continue
        if ELSE_IF.match(line) or IF_POSITIVE.match(line):
            return True
        if RETURN_FALSE.match(line):
            return False
        break
    body = lines[if_idx + 1 : close_idx]
    positive_if_returns = 0
    for k, body_line in enumerate(body):
        if IF_POSITIVE.match(body_line):
            sub_close = find_matching_brace(lines, if_idx + 1 + k)
            if sub_close >= 0:
                for inner in lines[if_idx + 2 + k : sub_close]:
                    if RETURN_TRUE.match(inner):
                        positive_if_returns += 1
                        break
    return positive_if_returns >= 1


def _func_start_pattern(config: PolicyConfig) -> re.Pattern[str]:
    nodiscard = re.escape(f"{config.c_macro_prefix}_NODISCARD")
    return re.compile(
        rf"^(?:static\s+)?(?:inline\s+)?(?:{nodiscard}\s+)?bool\s+\w+\s*\("
    )


def iter_bool_function_bodies(lines: list[str], config: PolicyConfig) -> list[tuple[int, int]]:
    func_start = _func_start_pattern(config)
    bodies: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if func_start.match(stripped) or (stripped.startswith("bool ") and "(" in stripped):
            j = i
            while j < len(lines) and "{" not in lines[j]:
                j += 1
            if j >= len(lines):
                break
            end = find_matching_brace(lines, j)
            if end >= 0:
                bodies.append((j, end))
                i = end + 1
                continue
        i += 1
    return bodies


def scan_wrapped_success_in_body(
    lines: list[str], path: Path, open_idx: int, close_idx: int
) -> list[str]:
    issues: list[str] = []
    for i in range(open_idx + 1, close_idx):
        m = IF_POSITIVE.match(lines[i])
        if not m:
            continue
        cond = m.group(1)
        if condition_looks_inverted(cond):
            continue
        block_close = find_matching_brace(lines, i)
        if block_close < 0 or block_close > close_idx:
            continue
        if not RETURN_TRUE.match(lines[block_close - 1]):
            continue
        if block_close + 1 >= len(lines):
            continue
        if not RETURN_FALSE.match(lines[block_close + 1]):
            continue
        if is_dispatch_or_classification(lines, i, block_close):
            continue
        issues.append(
            f"{path}:{i + 1}: wrap happy path in positive if/return-true; "
            f"use guard clause and fall-through return true"
        )
    return issues


def scan_else_return_false(lines: list[str], path: Path) -> list[str]:
    issues: list[str] = []
    for i in range(len(lines) - 2):
        if not RETURN_TRUE.match(lines[i]):
            continue
        if not ELSE_FALSE.match(lines[i + 1]):
            continue
        if i + 2 >= len(lines):
            continue
        if not RETURN_FALSE.match(lines[i + 2]):
            continue
        if i > 0 and ELSE_IF.match(lines[i - 1]):
            continue
        issues.append(
            f"{path}:{i + 2}: if/else return true/false; invert guard and early-return false"
        )
    return issues


def scan_inline_wrapped_success(text: str, path: Path) -> list[str]:
    issues: list[str] = []
    pattern = re.compile(
        r"if\s*\(([^)]*)\)\s*\{[^{}]*\breturn\s+true\s*;\s*\}"
        r"\s*return\s+false\s*;"
    )
    for match in pattern.finditer(text):
        if condition_looks_inverted(match.group(1)):
            continue
        if re.search(
            r"if\s*\([^)]*\)\s*\{[^{}]*\breturn\s+true\s*;\s*\}\s*$",
            text[: match.start()],
        ):
            continue
        line_no = text.count("\n", 0, match.start()) + 1
        issues.append(
            f"{path}:{line_no}: wrap happy path in positive if/return-true; "
            "use guard clause and fall-through return true"
        )
    return issues


def scan_file(path: Path, config: PolicyConfig) -> list[str]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    text = strip_comments_and_strings(raw)
    lines = text.splitlines()
    issues: list[str] = []
    issues.extend(scan_else_return_false(lines, path))
    issues.extend(scan_inline_wrapped_success(text, path))
    seen: set[str] = set()
    for open_idx, close_idx in iter_bool_function_bodies(lines, config):
        for issue in scan_wrapped_success_in_body(lines, path, open_idx, close_idx):
            if issue not in seen:
                seen.add(issue)
                issues.append(issue)
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
    print("early-return style self-test: OK")
    return 0
