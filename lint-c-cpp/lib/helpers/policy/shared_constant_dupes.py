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

"""One authoritative numeric ``{PREFIX}_*`` definition per constant (source scan job).
Flags duplicate #define, enum, or constexpr/const values across production files."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

from policy_config import PolicyConfig
from scan_policy import strip_comments_only

LINT_TITLE = "duplicate definitions"
LINT_FIX_HINT = (
    "Each shared spec constant must have exactly one authoritative definition. "
    "Remove shadow copies and include the canonical header."
)
DEFINE_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+(.+?)[ \t]*(?:/\*|//|$)",
    re.MULTILINE,
)
CONST_RE = re.compile(
    r"^\s*(?:static\s+)?(?:inline\s+)?(?:constexpr|const)\s+"
    r"[\w:<>,\s*&]+?\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]*\])?\s*=\s*(.+?)(?:\s*/\*|\s*//|\s*;)",
    re.MULTILINE,
)
ENUM_OPEN_RE = re.compile(r"\benum\b(?:\s+(?:class|struct)\b)?[^{};(]*\{")
NUMERIC_RE = re.compile(r"^(0[xX][0-9A-Fa-f]+|\d+)[uUlL]*$")


def is_numeric(token: str) -> bool:
    return bool(NUMERIC_RE.match(token.strip()))


def wanted(symbol: str, config: PolicyConfig) -> bool:
    return symbol.startswith(f"{config.c_macro_prefix}_")


def _iter_enum_members(code: str):
    for match in ENUM_OPEN_RE.finditer(code):
        brace = code.find("{", match.start())
        if brace < 0:
            continue
        depth = 0
        i = brace
        while i < len(code):
            ch = code[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = code[brace + 1 : i]
        seg_start = 0
        pdepth = 0
        segments: list[str] = []
        for idx, ch in enumerate(body):
            if ch in "([":
                pdepth += 1
            elif ch in ")]":
                pdepth -= 1
            elif ch == "," and pdepth == 0:
                segments.append(body[seg_start:idx])
                seg_start = idx + 1
        segments.append(body[seg_start:])
        for seg in segments:
            m = re.match(r"\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+)\s*$", seg, re.DOTALL)
            if m:
                yield m.group(1), m.group(2).strip()


def collect_definitions(text: str, config: PolicyConfig) -> dict[str, str]:
    code = strip_comments_only(text)
    out: dict[str, str] = {}
    for match in DEFINE_RE.finditer(code):
        name, value = match.group(1), match.group(2).strip()
        if wanted(name, config) and is_numeric(value):
            out[name] = value
    for name, value in _iter_enum_members(code):
        if wanted(name, config) and is_numeric(value):
            out.setdefault(name, value)
    for match in CONST_RE.finditer(code):
        name, value = match.group(1), match.group(2).strip()
        if wanted(name, config) and is_numeric(value):
            out.setdefault(name, value)
    return out


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    sites: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = config.label(path)
        for symbol in collect_definitions(text, config):
            sites[symbol].add(rel)

    errors: list[str] = []
    for symbol, files_for_symbol in sorted(sites.items()):
        files = sorted(files_for_symbol)
        if len(files) < 2:
            continue
        errors.append(f"{symbol}: defined in {len(files)} files: {', '.join(files)}")
    return errors


def prepare_self_test_repo(root: Path) -> None:
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
        "  source_roots: [core, port, userspace, tests]\n",
        encoding="utf-8",
    )
    common = root / "core"
    reader = root / "port"
    userspace = root / "userspace"
    tests = root / "tests"
    for directory in (common, reader, userspace, tests):
        directory.mkdir(parents=True)
    (common / "canonical.h").write_text("enum { SAMPLE_DUP = 0x23u };\n", encoding="utf-8")
    (reader / "shadow.h").write_text("#define SAMPLE_DUP 0x23u\n", encoding="utf-8")
    (tests / "mirror.h").write_text("#define SAMPLE_DUP 0x23u\n", encoding="utf-8")
    (reader / "local_a.cpp").write_text("#define SAMPLE_LOCAL_ONLY 7u\n", encoding="utf-8")
    (userspace / "local_b.cpp").write_text("#define SAMPLE_LOCAL_ONLY 7u\n", encoding="utf-8")
    (common / "doc_only.h").write_text(
        "/* #define SAMPLE_COMMENTED 9u */\n// #define SAMPLE_COMMENTED 9u\n",
        encoding="utf-8",
    )
    (reader / "real_commented.cpp").write_text("#define SAMPLE_COMMENTED 9u\n", encoding="utf-8")


def verify_self_test(errors: list[str]) -> int:
    if not any("SAMPLE_DUP" in err for err in errors):
        print("self-test miss: expected SAMPLE_DUP duplicate", file=sys.stderr)
        return 1
    if not any("SAMPLE_LOCAL_ONLY" in err for err in errors):
        print("self-test miss: expected SAMPLE_LOCAL_ONLY duplicate", file=sys.stderr)
        return 1
    if any("SAMPLE_COMMENTED" in err for err in errors):
        print("self-test false positive: SAMPLE_COMMENTED", file=sys.stderr)
        return 1
    print("duplicate-definitions self-test: OK")
    return 0
