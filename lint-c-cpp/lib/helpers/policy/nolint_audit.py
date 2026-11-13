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

"""Reject every way of switching a check off from inside a consumer repository.

The kit owns all tool configuration, and there is no waiver list. Repo-wide, this
rejects:

* suppression comments for every tool the kit or the build runs (clang-tidy,
  cppcheck, clang-format, shellcheck, ruff, mypy, markdownlint, yamllint, zizmor,
  codespell, coverage exclusions, and the common Python linters);
* compiler and analyzer escapes in C/C++: diagnostic pragmas that ignore or
  downgrade warnings (GCC/clang, MSVC, IAR/TI/NVCC ``diag_*``), ``system_header``
  pragmas, ``[[clang::suppress]]``, ``no_sanitize`` attributes, per-function
  hardening overrides (``optimize`` pragmas and attributes, ``no_stack_protector``,
  ``nocf_check``), and ``__clang_analyzer__`` / ``__CPPCHECK__`` branches that hide
  code from the analyzers;
* compiler flags that switch warnings off (``-Wno-*`` outside comments in any
  build, CI, script or preset file; ``-w`` / ``--no-warnings`` in build files and
  as the value of a compiler-flag variable anywhere);
  hardening_verify checks the same on the real compile commands, plus project
  directories passed as system include directories;
* repo-local tool config files and pyproject/setup.cfg/tox.ini tool sections,
  except zizmor.yml / zizmor.yaml (zizmor is run by the consumer, not the kit).
"""

from __future__ import annotations

import io
import re
import sys
import tokenize
from pathlib import Path

from policy_config import PolicyConfig
from policy_overrides import lint_overrides_dir
from scan_policy import INO_SUFFIX, SOURCE_SUFFIXES, comment_view, strip_comments_only

LINT_TITLE = "nolint-audit"

# Included fragments, template bodies and module units carry C/C++ comments too.
_C_SUFFIXES = SOURCE_SUFFIXES | {
    INO_SUFFIX,
    ".cppm",
    ".inc",
    ".inl",
    ".ipp",
    ".ixx",
    ".tcc",
    ".tpp",
}

_CODESPELL = r"\bcodespell:\s*ignore"
_COMMON = rf"\b(?:LCOV|GCOVR)_EXCL\w*|{_CODESPELL}"
_CODESPELL_ANYWHERE = re.compile(_CODESPELL)

_C_COMMENT = re.compile(
    r"\bNOLINT(?:NEXTLINE|BEGIN|END)?\b(?:\s*\([^)]*\))?"
    r"|\bcppcheck-suppress(?:-begin|-end|-file|-macro)?\b(?:\s*\[[^\]]*\])?"
    r"|\bclang-format\s+off\b"
    rf"|{_COMMON}"
)

# Matched against comment text that starts at its '#'.
_HASH_COMMENT = re.compile(
    r"#\s*shellcheck\s[^#\n]*?\bdisable="
    r"|#\s*(?:(?:ruff|flake8):\s*)?noqa\b"
    r"|#\s*type:\s*ignore\b"
    r"|#\s*(?:mypy|pyright):"
    r"|#\s*pylint:\s*(?:disable|skip-file)"
    r"|#\s*fmt:\s*(?:off|skip)\b"
    r"|#\s*isort:\s*(?:skip\w*|off)\b"
    r"|#\s*pragma:\s*no\s*(?:cover|branch)\b"
    r"|#\s*nosec\b"
    r"|#\s*yamllint\s+disable"
    r"|#\s*zizmor:\s*ignore"
    rf"|{_COMMON}"
)

_MARKDOWN_COMMENT = re.compile(
    rf"\bmarkdownlint-(?:disable|capture|configure-file)|\bprettier-ignore\b|{_COMMON}"
)

# Matched against C/C++ text with comments removed (string contents kept, so
# _Pragma("...") arguments stay visible).
_C_CODE = re.compile(
    r"^[ \t]*#[ \t]*pragma[ \t]+(?:GCC|clang)[ \t]+diagnostic[ \t]+(?:ignored|warning)\b"
    r"|^[ \t]*#[ \t]*pragma[ \t]+(?:(?:GCC|clang)[ \t]+)?system_header\b"
    r"|^[ \t]*#[ \t]*pragma[ \t]+warning[ \t]*\([ \t]*(?:disable|push[ \t]*,[ \t]*0)"
    # IAR, TI, Keil armcc and NVCC diagnostic control.
    r"|^[ \t]*#[ \t]*pragma[ \t]+(?:nv_)?diag_(?:suppress|remark|warning)\b"
    # Per-function overrides of the hardening flags (stack protector, CET,
    # -fno-strict-overflow and friends).
    r"|^[ \t]*#[ \t]*pragma[ \t]+GCC[ \t]+optimize\b"
    r"|\b_Pragma\s*\(\s*\"[^\"\n]*"
    r"(?:diagnostic\s+(?:ignored|warning)|system_header|diag_(?:suppress|remark|warning)"
    r"|GCC\s+optimize)"
    r"|\bgnu\s*::\s*_*optimize_*\s*\("
    r"|\b__attribute__\s*\(\([^;{}]*?\b_*optimize_*\s*\("
    r"|\b_*(?:no_stack_protector|nocf_check)_*\b"
    # [[clang::suppress]] and __attribute__((suppress)) hide analyzer findings.
    r"|\bclang\s*::\s*suppress\b"
    r"|\b__attribute__\s*\(\([^;{}]*?\b_*suppress_*\b"
    # Code the analyzers would not see: clang's analyzer and cppcheck define these.
    r"|\b(?:__clang_analyzer__|__CPPCHECK__|__cppcheck__)\b"
    r"|\b_*(?:no_sanitize|disable_sanitizer_instrumentation)\w*",
    re.MULTILINE,
)

# Tools would read these on their own; the kit passes its own config instead.
_TOOL_CONFIG_FILES = frozenset(
    {
        ".clang-format",
        "_clang-format",
        ".clang-format-ignore",
        ".clang-tidy",
        ".codespellrc",
        ".flake8",
        ".markdownlint-cli2.cjs",
        ".markdownlint-cli2.jsonc",
        ".markdownlint-cli2.mjs",
        ".markdownlint-cli2.yaml",
        ".markdownlint.json",
        ".markdownlint.jsonc",
        ".markdownlint.yaml",
        ".markdownlint.yml",
        ".markdownlintignore",
        ".markdownlintrc",
        ".mypy.ini",
        ".pylintrc",
        ".ruff.toml",
        ".shellcheckrc",
        ".yamllint",
        ".yamllint.yaml",
        ".yamllint.yml",
        "mypy.ini",
        "pylintrc",
        "ruff.toml",
        "shellcheckrc",
    }
)
# zizmor.yml / zizmor.yaml are deliberately absent: the kit never runs zizmor, so
# it has no config to pass; the consumer's workflow audit reads the repo's own.
_TOOL_SECTION_FILES = frozenset({"pyproject.toml", "setup.cfg", "tox.ini"})

# Compiler flags that switch warnings off, wherever a build or CI file sets them.
_WARNING_OFF_FLAG = re.compile(r"(?<![\w-])-Wno-(?:[\w+=,.-]*[\w+=])?")
# -w is only unambiguous in build files (elsewhere it is e.g. docker's workdir flag).
_BUILD_WARNING_OFF_FLAG = re.compile(r"(?<![\w-])(?:-w|--no-warnings)(?![\w=-])")
# Inside build files -w is also make's own --print-directory: make invocations and
# MAKEFLAGS/MFLAGS are dropped before looking for the compiler's -w.
_MAKE_OWN_FLAGS = re.compile(
    r"^[ \t]*(?:(?:export|override)[ \t]+)*(?:MAKE|M)FLAGS\b.*"
    r"|(?:\$[({]MAKE[)}]|(?<![\w.-])(?:\S*/)?make\b)[^;&|\n]*",
    re.MULTILINE,
)
# Outside build files, -w still counts when it is the value of a compiler-flag
# variable: CFLAGS=-w, -DCMAKE_C_FLAGS="-O2 -w", "CMAKE_CXX_FLAGS": "-w".
_COMPILER_FLAG_VALUE = re.compile(
    r"(?i)(?<![a-z0-9])(?:[a-z0-9_]*_)?(?:c|cc|cxx|cpp|objc|objcxx)_?flags(?:_[a-z0-9_]+)?"
    r"[\"']?\s*(?:\+?=|:=|\?=|:)\s*"
    r"(?:\"(?P<dq>[^\"\n]*)\"|'(?P<sq>[^'\n]*)'|(?P<bare>[^\s;&|,}\]]*))"
)
# Arduino reads compiler flags from build_opt.h and *.local.txt; they are not C.
_FLAG_FILE_NAMES = frozenset({"boards.local.txt", "build_opt.h", "platform.local.txt"})
_BUILD_FILE_NAMES = _FLAG_FILE_NAMES | {
    "CMakeLists.txt",
    "CMakePresets.json",
    "CMakeUserPresets.json",
    "GNUmakefile",
    "Makefile",
    "makefile",
    "meson.build",
    "meson.options",
}
_BUILD_FILE_SUFFIXES = frozenset({".cmake", ".mk"})
_TOOL_SECTION = re.compile(
    r"^[ \t]*\[(?:tool\.(?:codespell|mypy|pylint|pyright|ruff)\b"
    r"|codespell\]|flake8\]|mypy\b|pylint\b)",
    re.MULTILINE,
)

_SELF_TEST_CASES: dict[str, tuple[str, bool]] = {
    "core/clean.c": ("int ok(void) { return 0; }\n", False),
    "core/bad_nextline.c": ("// NOLINTNEXTLINE(foo)\nint bad(void) { return 1; }\n", True),
    "core/bad_block_nextline.c": ("/* NOLINTNEXTLINE(example) */\nint f(void);\n", True),
    "core/bad_nolint.c": ("int x; // NOLINT(readability)\n", True),
    "core/bad_nolint_bare.c": ("// NOLINT\nint y;\n", True),
    "core/bad_begin_end.c": ("// NOLINTBEGIN(x)\nint a = 42;\n// NOLINTEND(x)\n", True),
    "core/bad_inline.c": ("int z = 0; /* NOLINTNEXTLINE */ int w = 1;\n", True),
    "core/bad_cppcheck.c": ("int x; // cppcheck-suppress constParameterPointer\n", True),
    "core/bad_cppcheck_bracket.c": ("// cppcheck-suppress[uninitvar]\nint y;\n", True),
    "core/bad_cppcheck_file.c": ("// cppcheck-suppress-file uninitvar\nint z;\n", True),
    "core/bad_clang_format.c": ("// clang-format off\nint  a;\n// clang-format on\n", True),
    "core/bad_lcov.c": ("int f(void) { return 0; } // LCOV_EXCL_LINE\n", True),
    "core/bad_codespell.c": ("int teh; // codespell:ignore teh\n", True),
    "core/bad_pragma.c": (
        '#pragma clang diagnostic push\n#pragma clang diagnostic ignored "-Wformat"\n',
        True,
    ),
    "core/bad_pragma_gcc_warning.c": ('#  pragma GCC diagnostic warning "-Wconversion"\n', True),
    "core/bad_underscore_pragma.c": (
        '#define QUIET _Pragma("GCC diagnostic ignored \\"-Wshadow\\"")\n',
        True,
    ),
    "core/bad_system_header.h": ("#pragma GCC system_header\n", True),
    "core/bad_analyzer.c": ("#ifndef __clang_analyzer__\nint a;\n#endif\n", True),
    "core/bad_no_sanitize.c": ('__attribute__((no_sanitize("address"))) void f(void);\n', True),
    "core/bad_no_sanitize_reserved.c": (
        '__attribute__((__no_sanitize__("address"))) void f(void);\n',
        True,
    ),
    "core/bad_no_sanitize_address.c": (
        "__attribute__((__no_sanitize_address__)) void f(void);\n",
        True,
    ),
    "core/bad_no_instrument.c": (
        "__attribute__((__disable_sanitizer_instrumentation__)) void f(void);\n",
        True,
    ),
    "core/bad_clang_suppress.cpp": ("void f() { [[clang::suppress]] g(); }\n", True),
    "core/bad_gnu_suppress.c": ("void f(void) { __attribute__((suppress)) g(); }\n", True),
    "core/bad_cppcheck_guard.c": ("#ifndef __CPPCHECK__\nint a;\n#endif\n", True),
    "core/bad_diag_suppress.c": ("#pragma diag_suppress 177\n", True),
    "core/bad_msvc_level0.c": ("#pragma warning(push, 0)\n", True),
    "core/bad_gcc_optimize.c": ('#pragma GCC optimize("no-stack-protector")\n', True),
    "core/bad_optimize_attr.c": (
        '__attribute__((hot, optimize("no-strict-overflow"))) void f(void);\n',
        True,
    ),
    "core/bad_no_stack_protector.c": ("__attribute__((no_stack_protector)) void f(void);\n", True),
    "core/bad_nocf.c": ("__attribute__((nocf_check)) void f(void);\n", True),
    "core/bad_fragment.inc": ("// NOLINTNEXTLINE\nint x;\n", True),
    "core/bad_template.ipp": ("int y; // NOLINT\n", True),
    "core/ok_names.c": ("int suppress_count;\nvoid optimize(int no_stack_protector_x);\n", False),
    "core/ok_pragma_push.c": ("#pragma once\n#pragma clang diagnostic push\n", False),
    "core/string_literal.c": ('const char *msg = "NOLINT";\n', False),
    "core/string_cppcheck.c": ('const char *m = "cppcheck-suppress foo";\n', False),
    "core/comment_pragma.c": ("/* never #pragma GCC diagnostic ignored */\nint q;\n", False),
    "core/multiline_block.c": ("/* a\n NOLINTNEXTLINE(readability)\n end */\nint m;\n", True),
    "scripts/clean.sh": ("#!/usr/bin/env bash\n# shellcheck source=lib.sh\necho '#'\n", False),
    "scripts/bad_shellcheck.sh": ("#!/usr/bin/env bash\n# shellcheck disable=SC2086\n", True),
    "scripts/bad_shellcheck_combo.sh": (
        "#!/usr/bin/env bash\nx=1 # shellcheck source=a.sh disable=SC1091\n",
        True,
    ),
    "tools/clean.py": ('MSG = "# noqa is a string"\n', False),
    "tools/bad_noqa.py": ("import os  # noqa: F401\n", True),
    "tools/bad_ruff_file.py": ("# ruff: noqa\nimport os\n", True),
    "tools/bad_type_ignore.py": ("x: int = 'a'  # type: ignore[assignment]\n", True),
    "tools/bad_mypy_inline.py": ("# mypy: ignore-errors\nx = 1\n", True),
    "tools/bad_fmt.py": ("# fmt: off\nx = [1,2]\n", True),
    "tools/bad_cover.py": ("def f():  # pragma: no cover\n    return 1\n", True),
    "tools/bad_isort_file.py": ("# isort: skip_file\nimport os\n", True),
    "tools/bad_pylint_file.py": ("# pylint: skip-file\nimport os\n", True),
    "tools/bad_cflags.py": ('ENV = {"CFLAGS": "-O2 -w"}\n', True),
    "docs/clean.md": ("# Title\n\nWe forbid `# noqa` and NOLINT in prose.\n", False),
    "docs/bad_markdownlint.md": ("<!-- markdownlint-disable MD013 -->\n# T\n", True),
    "docs/bad_markdownlint_line.md": ("# T\n\nlong <!-- markdownlint-disable-line -->\n", True),
    "config/clean.yaml": ("key: value  # plain comment\n", False),
    "config/bad_yamllint.yaml": ("key: value  # yamllint disable-line rule:line-length\n", True),
    "config/bad_zizmor.yml": ("on: push  # zizmor: ignore[artipacked]\n", True),
    "CMakeLists.txt": ("add_compile_options(-Wall)\n# never -Wno-unused here\n", False),
    "build/bad.cmake": ("target_compile_options(app PRIVATE -Wno-unused-parameter)\n", True),
    "build/bad_w.cmake": ("set_source_files_properties(a.c PROPERTIES COMPILE_OPTIONS -w)\n", True),
    "build/ok_sanitize.cmake": ("add_compile_options(-fno-sanitize-recover=all)\n", False),
    "build/bad.mk": ("CFLAGS += -O2 -Wno-error\n", True),
    "build/ok_make_w.mk": ("MAKEFLAGS += -w\nall:\n\t$(MAKE) -w -C sub\n\tmake -w\n", False),
    "build/bad_recipe_w.mk": ("all:\n\t$(MAKE) -C sub && $(CC) -w -c a.c\n", True),
    "sub/Makefile": ("export MFLAGS = -w\nall:\n\t${MAKE} -w -C lib\n", False),
    "build/CMakePresets.json": ('{"cacheVariables": {"CMAKE_C_FLAGS": "-Wno-format"}}\n', True),
    "CMakePresets.json": ('{"cacheVariables": {"CMAKE_CXX_FLAGS": "-w"}}\n', True),
    "scripts/bad_cflags.sh": ("#!/bin/sh\nCFLAGS=-Wno-shadow cmake -B build\n", True),
    "scripts/bad_cflags_w.sh": ("#!/bin/sh\nexport CFLAGS='-O2 -w'\n", True),
    "scripts/bad_cmake_w.sh": ('#!/bin/sh\ncmake -DCMAKE_C_FLAGS="-w" -B build\n', True),
    "scripts/ok_docker_w.sh": ("#!/bin/sh\ndocker run -w /src img\n", False),
    "scripts/ok_flags_then_make.sh": ("#!/bin/sh\nCFLAGS=-O2 make -w\nMAKEFLAGS=-w\n", False),
    ".github/workflows/bad_ci.yml": ("env:\n  CXXFLAGS: -w\n", True),
    ".github/zizmor.yml": ("rules:\n  artipacked:\n    disable: true\n", False),
    "zizmor.yaml": ("rules: {}\n", False),
    "tools/bad_flags.py": ('FLAGS = ["-Wall", "-Wno-unused"]\n', True),
    "sketch/build_opt.h": ("-DFOO=1 -Wno-unused-variable\n", True),
    "sketch/ok/build_opt.h": ("-DFOO=1 -Wall\n", False),
    "hw/platform.local.txt": ("compiler.c.extra_flags=-w\n", True),
    "config/bad_codespell.xml": ("<a>teh</a> <!-- codespell:ignore teh -->\n", True),
    ".shellcheckrc": ("disable=all\n", True),
    "sub/.clang-tidy": ("Checks: '-*'\n", True),
    ".markdownlintignore": ("docs/\n", True),
    "pyproject.toml": ('[project]\nname = "x"\n\n[tool.ruff.lint]\nignore = ["E"]\n', True),
    "setup.cfg": ("[codespell]\nskip = *\n", True),
    "tox.ini": ("[tox]\nenvlist = py3\n", False),
}


def _comment_findings(pattern: re.Pattern[str], view: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for line_no, line in enumerate(view.splitlines(), 1):
        match = pattern.search(line)
        if match is not None:
            found.append((line_no, match.group(0)))
    return found


def _hash_comment_view(text: str) -> str:
    """Each line's text from its first '#' that starts a comment (line start or after space)."""
    out: list[str] = []
    for line in text.splitlines():
        match = re.search(r"(?:^|(?<=\s))#", line)
        out.append(line[match.start() :] if match else "")
    return "\n".join(out)


def _hash_code_view(text: str) -> str:
    """Each line with its '#' comment (line start or after space) removed."""
    out: list[str] = []
    for line in text.splitlines():
        match = re.search(r"(?:^|(?<=\s))#", line)
        out.append(line[: match.start()] if match else line)
    return "\n".join(out)


def _warning_flag_findings(path: Path, text: str) -> list[tuple[int, str]]:
    code = _hash_code_view(text)
    hits = _comment_findings(_WARNING_OFF_FLAG, code)
    if path.name in _BUILD_FILE_NAMES or path.suffix.lower() in _BUILD_FILE_SUFFIXES:
        hits += _comment_findings(_BUILD_WARNING_OFF_FLAG, _MAKE_OWN_FLAGS.sub("", code))
    for match in _COMPILER_FLAG_VALUE.finditer(code):
        value = match.group("dq") or match.group("sq") or match.group("bare") or ""
        flag = _BUILD_WARNING_OFF_FLAG.search(value)
        if flag is not None:
            hits.append((code.count("\n", 0, match.start()) + 1, flag.group(0)))
    return [(line_no, f"warning switched off by {flag}") for line_no, flag in sorted(set(hits))]


def _python_comment_view(text: str) -> str:
    lines = [""] * (text.count("\n") + 1)
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                lines[token.start[0] - 1] = token.string
    except (tokenize.TokenError, SyntaxError):
        return _hash_comment_view(text)
    return "\n".join(lines)


def _markdown_comment_view(text: str) -> str:
    out = [" " * len(line) for line in text.splitlines()]
    for match in re.finditer(r"<!--.*?-->", text, re.DOTALL):
        first = text.count("\n", 0, match.start())
        for offset, chunk in enumerate(match.group(0).split("\n")):
            out[first + offset] = chunk
    return "\n".join(out)


def scan_text(path: Path, text: str) -> list[tuple[int, str]]:
    name = path.name
    suffix = path.suffix.lower()
    if name in _TOOL_CONFIG_FILES:
        return [(1, f"repo-local tool config {name}")]
    findings: list[tuple[int, str]] = []
    if name in _TOOL_SECTION_FILES:
        for match in _TOOL_SECTION.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            findings.append((line_no, f"tool config section {match.group(0).strip()}"))
    if name in _FLAG_FILE_NAMES:
        findings += _warning_flag_findings(path, text)
    elif suffix in _C_SUFFIXES:
        findings += _comment_findings(_C_COMMENT, comment_view(text))
        code = strip_comments_only(text)
        for match in _C_CODE.finditer(code):
            line_no = code.count("\n", 0, match.start()) + 1
            findings.append((line_no, match.group(0).strip()))
    elif suffix == ".py":
        findings += _comment_findings(_HASH_COMMENT, _python_comment_view(text))
        findings += _warning_flag_findings(path, text)
    elif suffix == ".md":
        findings += _comment_findings(_MARKDOWN_COMMENT, _markdown_comment_view(text))
    else:
        findings += _comment_findings(_HASH_COMMENT, _hash_comment_view(text))
        findings += _warning_flag_findings(path, text)
        # codespell honours its inline ignore in any comment syntax, not just #.
        findings += [
            hit for hit in _comment_findings(_CODESPELL_ANYWHERE, text) if hit not in findings
        ]
    return sorted(findings)


def scan_file(path: Path) -> list[str]:
    try:
        blob = path.read_bytes()
    except OSError:
        return []
    if b"\0" in blob[:8192] and path.name not in _TOOL_CONFIG_FILES:
        return []
    text = blob.decode("utf-8", errors="replace")
    raw_lines = text.splitlines()
    findings: list[str] = []
    for line_no, token in scan_text(path, text):
        raw = raw_lines[line_no - 1].strip() if line_no - 1 < len(raw_lines) else ""
        findings.append(f"{path}:{line_no}: {token} -- {raw}")
    return findings


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    generated = lint_overrides_dir(config.repo_root)
    return [
        finding
        for path in paths
        if not path.resolve().is_relative_to(generated)
        for finding in scan_file(path)
    ]


def run(config: PolicyConfig, paths: list[Path], extras: list[str]) -> int:
    del extras
    findings = lint(paths, config)
    if not findings:
        print(f"nolint-audit: OK (0 suppressions in {len(paths)} files)")
        return 0
    print(f"nolint-audit: found {len(findings)} suppression(s); fix the finding instead")
    for item in findings:
        print(item)
    return 1


def prepare_self_test_repo(root: Path) -> None:
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
        "  public_headers_dir: include/sample\n  source_roots: [core]\n",
        encoding="utf-8",
    )
    for rel, (content, _) in _SELF_TEST_CASES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def verify_self_test(errors: list[str]) -> int:
    reported = {item.split(":", 1)[0] for item in errors}
    expected = {rel for rel, (_, flagged) in _SELF_TEST_CASES.items() if flagged}
    reported_rel = {
        rel for rel in _SELF_TEST_CASES if any(path.endswith("/" + rel) for path in reported)
    }
    if reported_rel != expected:
        print(
            "nolint-audit self-test failed: "
            f"missed {sorted(expected - reported_rel)} "
            f"false positives {sorted(reported_rel - expected)}",
            file=sys.stderr,
        )
        return 1
    print("nolint-audit self-test: OK")
    return 0
