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

"""Verify consumer cmake/ hardening against the kit OpenSSF flag manifest."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

_LINT_LIB = Path(__file__).resolve().parents[2]
_DEFAULT_LINT_KIT = _LINT_LIB.parent
if str(_LINT_LIB) not in sys.path:
    sys.path.insert(0, str(_LINT_LIB))
from lint_pythonpath import bootstrap as _bootstrap_lint_pythonpath

_bootstrap_lint_pythonpath()
_POLICY_DIR = Path(__file__).resolve().parent
if str(_POLICY_DIR) not in sys.path:
    sys.path.insert(0, str(_POLICY_DIR))
from compile_db_util import (
    cmake_generator,
    entry_command,
    is_cross_compile_command,
    storage_key_prefers_firmware_compile,
)
from repo_paths import source_key
from consumer_manifest import discover_hardening_cmake_roots
from policy_paths import add_hardening_path_args, central_scan_paths, load_cmake_paths, load_paths
from scan_policy import JOB_CMAKE, JOB_SOURCE

DEFAULT_REQUIRED_MODULES = (
    "Hardening.cmake",
    "CompilerHardeningProbes.cmake",
)

FORBIDDEN_CMAKE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\badd_compile_options\s*\([^)]*-fPIE\b"), "raw -fPIE in CMakeLists"),
    (re.compile(r"\badd_compile_options\s*\([^)]*-fPIC\b"), "raw -fPIC in CMakeLists"),
    (re.compile(r"\badd_link_options\s*\([^)]*-pie\b"), "raw -pie in CMakeLists"),
    (re.compile(r"\badd_link_options\s*\([^)]*-shared\b"), "raw -shared in CMakeLists"),
    (re.compile(r"\badd_(compile|link)_options\s*\([^)]*-D_FORTIFY_SOURCE\b"), "raw _FORTIFY_SOURCE"),
    (re.compile(r"\badd_link_options\s*\([^)]*LINKER:-z,relro\b"), "raw relro link flag"),
    (re.compile(r"\badd_link_options\s*\([^)]*LINKER:-z,now\b"), "raw now link flag"),
    (re.compile(r"\badd_link_options\s*\([^)]*LINKER:-z,nodlopen\b"), "raw nodlopen link flag"),
    (re.compile(r"\badd_link_options\s*\([^)]*LINKER:-z,noexecstack\b"), "raw noexecstack link flag"),
    (re.compile(r"\binclude\s*\([^)]*HostHardening\.cmake"), "legacy HostHardening.cmake include"),
    (re.compile(r"\binclude\s*\([^)]*CompilerHardeningProbes\.cmake"), "legacy CompilerHardeningProbes.cmake include"),
    (re.compile(r"\bdefine_host_hardening\s*\("), "legacy define_host_hardening() call"),
    (re.compile(r"\bhost_hardening\b"), "legacy host_hardening target name"),
)

SUPPORTED_STANDARDS = frozenset({"17", "20", "23"})
LINKER_FLAG_RE = re.compile(r'"(LINKER:[^"]+)"')
GENEX_GATE_ALIASES: dict[str, list[str]] = {
    "_hardening_host": ["CMAKE_CROSSCOMPILING"],
    "_hardening_host_exe": ["CMAKE_CROSSCOMPILING", "TARGET_PROPERTY:TYPE", "EXECUTABLE"],
    "_hardening_consumer_exe": ["TARGET_PROPERTY:TYPE", "EXECUTABLE"],
    "_hardening_consumer_shared": ["TARGET_PROPERTY:TYPE", "SHARED_LIBRARY"],
    "_hardening_fortify_cfg": ["CONFIG:Release", "CONFIG:RelWithDebInfo", "CONFIG:MinSizeRel"],
    "_hardening_production_cfg": ["CONFIG:Production"],
    "_hardening_relwithdebinfo_cfg": ["CONFIG:RelWithDebInfo"],
    "_hardening_debug_cfg": ["CONFIG:Debug"],
}
CONFIGURE_TIME_PROBES = frozenset({"HAVE_INSTRUMENTED_SANITIZER"})
MANIFEST_TOP_LEVEL_KEYS = frozenset({"cmake", "consumer", "coverage", "guide"})
GUIDE_ALLOWED_KEYS = frozenset({"date", "normative_tables", "url"})
COVERAGE_ALLOWED_KEYS = frozenset({"definitions", "flags"})
CONSUMER_ALLOWED_KEYS = frozenset({"cmake_dir", "required_modules"})
CMAKE_BLOCK_KEYS = frozenset({"C", "CXX", "common"})
KNOWN_GATE_MARKERS = frozenset(
    {
        "CMAKE_CROSSCOMPILING",
        "CONFIG:Release",
        "CONFIG:RelWithDebInfo",
        "CONFIG:MinSizeRel",
        "CONFIG:Production",
        "CONFIG:Debug",
        "NOT_INSTRUMENTED_SANITIZER",
        "NOT_FHARDENED",
        "TARGET_PROPERTY:TYPE",
        "EXECUTABLE",
        "SHARED_LIBRARY",
    }
)
OPENSSF_TABLE1_FLAGS = frozenset(
    {
        "-Wall",
        "-Wextra",
        "-Wformat",
        "-Wformat=2",
        "-Wconversion",
        "-Wsign-conversion",
        "-Wtrampolines",
        "-Wimplicit-fallthrough",
        "-Wbidi-chars=any",
        "-Werror",
        "-Werror=format-security",
        "-Werror=implicit",
        "-Werror=incompatible-pointer-types",
        "-Werror=int-conversion",
    }
)
OPENSSF_TABLE2_FLAGS = frozenset(
    {
        "-O2",
        "-U_FORTIFY_SOURCE",
        "-D_FORTIFY_SOURCE=3",
        "-fstrict-flex-arrays=3",
        "-fstack-clash-protection",
        "-fstack-protector-strong",
        "-fcf-protection=full",
        "-mbranch-protection=standard",
        "LINKER:-z,nodlopen",
        "LINKER:-z,noexecstack",
        "LINKER:-z,relro",
        "LINKER:-z,now",
        "-fPIE",
        "-pie",
        "-fPIC",
        "-shared",
        "-fno-delete-null-pointer-checks",
        "-fno-strict-overflow",
        "-fno-strict-aliasing",
        "-ftrivial-auto-var-init=zero",
        "-fexceptions",
        "-fhardened",
        "LINKER:--as-needed",
        "LINKER:--no-copy-dt-needed-entries",
        "-fzero-init-padding-bits=all",
    }
)
OPENSSF_TABLE2_DEFINITIONS = frozenset(
    {
        "_GLIBCXX_ASSERTIONS",
        "_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
        "_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE",
        "_GLIBCXX_DEBUG",
        "_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG",
    }
)
OPENSSF_PROSE_FLAGS = frozenset(
    {
        "-Whardened",
        "-Werror=trampolines",
        "-fzero-init-padding-bits=union",
    }
)
FORBIDDEN_ENVIRONMENT_PROBES = frozenset({"HAVE_NATIVE_USERSPACE", "HAVE_SHARED_LIBRARY"})
BIDI_POLICY_FLAGS = {"any": "-Wbidi-chars=any", "unpaired": "-Wbidi-chars=unpaired"}
THIRD_PARTY_INCLUDE_RE = re.compile(r"(?i)(?:third[-_]?party|/vendor/|/external/)")
INCLUDE_DIR_STMT_RE = re.compile(
    r"(?:target_include_directories|include_directories)\s*\([^)]*\)",
    re.IGNORECASE,
)
HARDENING_INCLUDE_RE = re.compile(r"include\s*\([^)]*Hardening\.cmake", re.IGNORECASE)
SANITIZER_ADD_COMPILE_RE = re.compile(r"add_compile_options\s*\([^)]*-fsanitize", re.IGNORECASE)
CMAKE_SANITIZER_FLAGS_RE = re.compile(
    r"(?:string\s*\(\s*APPEND\s+CMAKE_(?:C|CXX)_(?:FLAGS|EXE_LINKER_FLAGS)"
    r"|set\s*\(\s*CMAKE_(?:C|CXX)_(?:FLAGS|EXE_LINKER_FLAGS))"
    r"[^;\n]*-fsanitize",
    re.IGNORECASE,
)
PROBE_VERIFY_BUILD_DIR = "build/lint/openssf-probe-verify"
GENEX_FLAG_RE = re.compile(r":((?:LINKER:[^>]+)|(?:-[\w=+\-./]+(?:,[\w=+\-./]+)*))>")
STANDALONE_LINK_FLAG_RE = re.compile(r"(?:^|\s)(-pie|-shared)(?:\s|$)", re.MULTILINE)
BUILD_OPT_RE = re.compile(r"-O[123s]\b")
BLANKET_WERROR_RE = re.compile(r"\badd_compile_options\s*\(")
ADD_TARGET_RE = re.compile(r"\badd_(?:executable|library)\s*\(\s*([^\s)]+)")
INTERFACE_LIBRARY_RE = re.compile(r"\badd_library\s*\(\s*([^\s)]+)\s+INTERFACE\b")
TARGET_LINK_RE = re.compile(r"\btarget_link_libraries\s*\(")
PROJECT_CXX_RE = re.compile(r"\bproject\s*\([^)]*\bCXX\b")


def _has_blanket_werror(text: str) -> bool:
    for match in BLANKET_WERROR_RE.finditer(text):
        start = match.end()
        depth = 1
        index = start
        while index < len(text) and depth:
            ch = text[index]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            index += 1
        inner = text[start : index - 1] if depth == 0 else ""
        if re.search(r"(?:^|[,\s])-Werror(?:\)|\s|,|$)", inner):
            return True
    return False


def _load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required (install the python3-yaml package)")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected mapping at top level")
    return data


def _guide_block(manifest: dict[str, Any]) -> dict[str, Any]:
    block = manifest.get("guide", {})
    return block if isinstance(block, dict) else {}


def _coverage_block(manifest: dict[str, Any]) -> dict[str, Any]:
    block = manifest.get("coverage", {})
    return block if isinstance(block, dict) else {}


def _consumer_block(manifest: dict[str, Any]) -> dict[str, Any]:
    block = manifest.get("consumer", {})
    return block if isinstance(block, dict) else {}


def _cmake_block(manifest: dict[str, Any]) -> dict[str, Any]:
    block = manifest.get("cmake", {})
    return block if isinstance(block, dict) else {}


def load_hardening_manifest(lint_kit: Path) -> dict[str, Any]:
    manifest_path = lint_kit / "config" / "openssf-hardening-manifest.yaml"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"missing kit hardening manifest: {manifest_path}")
    manifest = _load_yaml(manifest_path)
    top_level_issues = verify_manifest_top_level_schema(manifest)
    if top_level_issues:
        raise ValueError("\n".join(top_level_issues))
    anchor_issues = verify_coverage_cmake_parity(manifest)
    if anchor_issues:
        raise ValueError("\n".join(anchor_issues))
    schema_issues = verify_guide_schema(manifest) + verify_coverage_schema(manifest)
    if schema_issues:
        raise ValueError("\n".join(schema_issues))
    consumer_issues = verify_consumer_schema(manifest)
    if consumer_issues:
        raise ValueError("\n".join(consumer_issues))
    cmake_issues = verify_cmake_schema(manifest)
    if cmake_issues:
        raise ValueError("\n".join(cmake_issues))
    gate_issues = verify_manifest_gate_markers(manifest)
    if gate_issues:
        raise ValueError("\n".join(gate_issues))
    guide_issues = verify_guide_table_coverage(manifest)
    if guide_issues:
        raise ValueError("\n".join(guide_issues))
    extra_issues = verify_manifest_no_unlisted_flags(manifest)
    if extra_issues:
        raise ValueError("\n".join(extra_issues))
    return manifest


def _allowed_coverage_tokens(manifest: dict[str, Any]) -> set[str]:
    """Positive allowlist: flags/defs declared under coverage."""
    coverage = _coverage_block(manifest)
    allowed: set[str] = set()
    flags = coverage.get("flags", [])
    if isinstance(flags, list):
        allowed.update(str(item) for item in flags)
    definitions = coverage.get("definitions", [])
    if isinstance(definitions, list):
        allowed.update(str(item) for item in definitions)
    return allowed


def verify_manifest_no_unlisted_flags(manifest: dict[str, Any]) -> list[str]:
    """cmake must contain only coverage.flags + coverage.definitions."""
    issues: list[str] = []
    allowed = _allowed_coverage_tokens(manifest)
    manifest_tokens = _collect_manifest_flag_tokens(manifest)
    extras = sorted(manifest_tokens - allowed)
    for token in extras:
        issues.append(
            f"openssf-hardening-manifest.yaml: cmake contains unlisted entry {token!r} "
            "not listed in coverage.flags or coverage.definitions"
        )
    return issues


def _collect_manifest_flag_tokens(manifest: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for language in ("C", "CXX"):
        required, probe_gated, genex_gated, definitions_genex_gated = _resolve_flag_requirements(
            manifest, language
        )
        tokens.update(required)
        tokens.update(flag for flag, _ in probe_gated if flag)
        tokens.update(flag for flag, _ in genex_gated if flag)
        tokens.update(definition for definition, _ in definitions_genex_gated if definition)
    return tokens


def verify_coverage_cmake_parity(manifest: dict[str, Any]) -> list[str]:
    """Ensure coverage lists are satisfied by cmake templates."""
    issues: list[str] = []
    coverage = _coverage_block(manifest)
    if not coverage:
        issues.append("openssf-hardening-manifest.yaml: coverage must be a mapping")
        return issues

    manifest_tokens = _collect_manifest_flag_tokens(manifest)
    values = coverage.get("flags", [])
    if not isinstance(values, list):
        issues.append("openssf-hardening-manifest.yaml: coverage.flags must be a list")
    else:
        for flag in values:
            label = str(flag)
            if label not in manifest_tokens:
                issues.append(
                    f"openssf-hardening-manifest.yaml: coverage.flags entry {label!r} "
                    "missing from cmake"
                )

    definitions = coverage.get("definitions", [])
    if not isinstance(definitions, list):
        issues.append("openssf-hardening-manifest.yaml: coverage.definitions must be a list")
    else:
        for definition in definitions:
            label = str(definition)
            if label not in manifest_tokens:
                issues.append(
                    f"openssf-hardening-manifest.yaml: coverage.definitions entry "
                    f"{label!r} missing from cmake"
                )

    return issues


def verify_manifest_top_level_schema(manifest: dict[str, Any]) -> list[str]:
    """Top-level manifest keys are positive-only."""
    issues: list[str] = []
    if not isinstance(manifest, dict):
        issues.append("openssf-hardening-manifest.yaml: expected mapping at top level")
        return issues
    for key in sorted(manifest):
        if key not in MANIFEST_TOP_LEVEL_KEYS:
            issues.append(
                f"openssf-hardening-manifest.yaml: unknown top-level key {key!r} "
                f"(allowed: {', '.join(sorted(MANIFEST_TOP_LEVEL_KEYS))})"
            )
    return issues


def _unknown_section_keys(block: dict[str, Any], allowed: frozenset[str], label: str) -> list[str]:
    issues: list[str] = []
    for key in sorted(block):
        if key not in allowed:
            issues.append(
                f"openssf-hardening-manifest.yaml: unknown {label}.{key} "
                f"(allowed: {', '.join(sorted(allowed))})"
            )
    return issues


def verify_consumer_schema(manifest: dict[str, Any]) -> list[str]:
    consumer = _consumer_block(manifest)
    if not consumer:
        return []
    return _unknown_section_keys(consumer, CONSUMER_ALLOWED_KEYS, "consumer")


def verify_cmake_schema(manifest: dict[str, Any]) -> list[str]:
    cmake = _cmake_block(manifest)
    if not cmake:
        return ["openssf-hardening-manifest.yaml: cmake must be a mapping"]
    return _unknown_section_keys(cmake, CMAKE_BLOCK_KEYS, "cmake")


def verify_guide_schema(manifest: dict[str, Any]) -> list[str]:
    guide = _guide_block(manifest)
    if not guide:
        return ["openssf-hardening-manifest.yaml: guide must be a mapping"]
    return _unknown_section_keys(guide, GUIDE_ALLOWED_KEYS, "guide")


def verify_coverage_schema(manifest: dict[str, Any]) -> list[str]:
    coverage = _coverage_block(manifest)
    if not coverage:
        return ["openssf-hardening-manifest.yaml: coverage must be a mapping"]
    return _unknown_section_keys(coverage, COVERAGE_ALLOWED_KEYS, "coverage")


def verify_manifest_gate_markers(manifest: dict[str, Any]) -> list[str]:
    """Every compile_genex_gated gate_requires marker must be a known auto-discovered gate."""
    issues: list[str] = []
    cmake = _cmake_block(manifest)
    if not cmake:
        return issues
    for block_name in ("common", "C", "CXX"):
        block = cmake.get(block_name, {})
        if not isinstance(block, dict):
            continue
        for section in ("compile_genex_gated", "link_genex_gated", "definitions_genex_gated"):
            items = block.get(section, [])
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                raw_gate = item.get("gate_requires", [])
                if not isinstance(raw_gate, list):
                    continue
                label = str(item.get("flag") or item.get("definition") or "")
                for marker in raw_gate:
                    token = str(marker)
                    if token not in KNOWN_GATE_MARKERS:
                        issues.append(
                            f"openssf-hardening-manifest.yaml: cmake.{block_name}.{section} "
                            f"entry {label!r} uses unknown gate marker {token!r}"
                        )
    return issues


def verify_guide_table_coverage(manifest: dict[str, Any]) -> list[str]:
    """Ensure Tables 1–2 + guide prose flags are fully listed in coverage.flags."""
    issues: list[str] = []
    coverage = _coverage_block(manifest)
    required = {str(flag) for flag in coverage.get("flags", []) if flag}
    definitions = {str(item) for item in coverage.get("definitions", []) if item}

    for flag in sorted(OPENSSF_TABLE1_FLAGS - required):
        issues.append(
            f"openssf-hardening-manifest.yaml: Table 1 flag {flag!r} missing from coverage.flags"
        )
    for flag in sorted(OPENSSF_TABLE2_FLAGS - required):
        issues.append(
            f"openssf-hardening-manifest.yaml: Table 2 flag {flag!r} missing from coverage.flags"
        )
    for definition in sorted(OPENSSF_TABLE2_DEFINITIONS - definitions):
        issues.append(
            f"openssf-hardening-manifest.yaml: Table 2 definition {definition!r} "
            "missing from coverage.definitions"
        )
    for flag in sorted(OPENSSF_PROSE_FLAGS - required):
        issues.append(
            f"openssf-hardening-manifest.yaml: guide prose flag {flag!r} missing from coverage.flags"
        )
    return issues


def _discover_bidi_policy(manifest: dict[str, Any]) -> tuple[str, str]:
    """Discover bidi flag from cmake (coverage.flags drives the probe-gated entry)."""
    common = _cmake_block(manifest).get("common", {})
    if isinstance(common, dict):
        items = common.get("compile_probe_gated", [])
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                flag = str(item.get("flag", ""))
                for policy, label in BIDI_POLICY_FLAGS.items():
                    if flag == label:
                        return policy, label
    return "any", BIDI_POLICY_FLAGS["any"]


def _required_modules(manifest: dict[str, Any]) -> tuple[str, ...]:
    consumer = _consumer_block(manifest)
    modules = consumer.get("required_modules")
    if isinstance(modules, list) and modules:
        return tuple(str(item) for item in modules)
    return DEFAULT_REQUIRED_MODULES


def _consumer_cmake_dir(manifest: dict[str, Any]) -> str:
    consumer = _consumer_block(manifest)
    cmake_dir = consumer.get("cmake_dir")
    if isinstance(cmake_dir, str) and cmake_dir.strip():
        return cmake_dir.strip()
    return "cmake"


def _validate_standard(language: str, standard: str) -> str | None:
    if standard not in SUPPORTED_STANDARDS:
        return f"unsupported {language} standard {standard} (supported: 17, 20, 23)"
    return None


def _standard_label(language: str, standard: str) -> str:
    return f"{language}{standard}"


def _cmake_root_standard_summary(root: dict[str, str]) -> str:
    labels: list[str] = []
    c_std = str(root.get("c_standard", "")).strip()
    cxx_std = str(root.get("cxx_standard", "")).strip()
    if c_std:
        labels.append(_standard_label("C", c_std))
    if cxx_std:
        labels.append(_standard_label("CXX", cxx_std))
    return ", ".join(labels) if labels else "(no standard declared)"


def _print_hardeninglint_cmake_ok(config: dict[str, object]) -> None:
    roots = config.get("cmake_roots", [])
    print(f"hardeninglint (cmake): OK — {len(roots)} CMake project root(s)")
    print("  role: OpenSSF flags in CMakeLists (define_hardening); not compile_db JSON inputs")
    for root in roots:
        if not isinstance(root, dict):
            continue
        print(f"  {root['file']}: {_cmake_root_standard_summary(root)}")


def hardening_config(repo_root: Path) -> dict[str, object]:
    return {
        "interface_target": "hardening",
        "cmake_roots": discover_hardening_cmake_roots(repo_root),
    }


def _flag_pattern(label: str) -> re.Pattern[str]:
    if label.startswith("LINKER:"):
        return re.compile(re.escape(label))
    if label.startswith("-D") or label.startswith("-U"):
        return re.compile(re.escape(label))
    token = re.escape(label)
    return re.compile(rf"(?:^|[\s:>]){token}(?:[\s\"<,]|$)")


def extract_hardening_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for match in LINKER_FLAG_RE.finditer(text):
        tokens.add(match.group(1))
    for match in GENEX_FLAG_RE.finditer(text):
        tokens.add(match.group(1))
    for match in STANDALONE_LINK_FLAG_RE.finditer(text):
        tokens.add(match.group(1))
    return tokens


_LIST_MERGE_KEYS = (
    "compile",
    "compile_gnu",
    "compile_clang",
)
_PROBE_GATED_KEYS = ("compile_probe_gated", "link_probe_gated")
_GENEX_GATED_KEYS = ("compile_genex_gated", "link_genex_gated")
_DEFINITIONS_GENEX_GATED_KEY = "definitions_genex_gated"
_VALID_FLAG_LANGUAGES = frozenset({"C", "CXX"})


def _substitute_language_probe(probe: str, language: str) -> str:
    return probe.replace("{LANG}", language)


def _merge_flag_list_blocks(blocks: tuple[dict[str, Any], ...], key: str) -> list[str]:
    merged: list[str] = []
    for block in blocks:
        values = block.get(key, [])
        if isinstance(values, list):
            merged.extend(str(item) for item in values)
    return merged


def _merge_probe_gated_blocks(
    blocks: tuple[dict[str, Any], ...],
    key: str,
    language: str,
) -> list[tuple[str, str]]:
    merged: list[tuple[str, str]] = []
    for block in blocks:
        values = block.get(key, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            flag = str(item.get("flag", ""))
            probe = str(item.get("probe", ""))
            if probe:
                probe = _substitute_language_probe(probe, language)
            merged.append((flag, probe))
    return merged


def _merge_compile_arch_blocks(blocks: tuple[dict[str, Any], ...]) -> list[str]:
    merged: list[str] = []
    for block in blocks:
        compile_arch = block.get("compile_arch", {})
        if not isinstance(compile_arch, dict):
            continue
        for values in compile_arch.values():
            if isinstance(values, list):
                merged.extend(str(item) for item in values)
    return merged


# compile_arch keys → CMAKE_SYSTEM_PROCESSOR genex (host-only; matches audit arch filter).
_COMPILE_ARCH_PROCESSOR_GENEX: dict[str, str] = {
    "x86_64_native": (
        "$<OR:$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>,"
        "$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},AMD64>>"
    ),
}


def _compile_arch_keyed_flags(manifest: dict[str, Any]) -> dict[str, list[str]]:
    """``cmake.common.compile_arch`` keyed flag lists (preserve arch identity for emit)."""
    common = _cmake_block(manifest).get("common", {})
    if not isinstance(common, dict):
        return {}
    compile_arch = common.get("compile_arch", {})
    if not isinstance(compile_arch, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key, values in compile_arch.items():
        if not isinstance(values, list):
            continue
        flags = [str(item) for item in values if item]
        if flags:
            out[str(key)] = flags
    return out


def _arch_gated_compile_genex(arch_key: str, flag: str) -> str:
    """Host + arch-gated genex for one ``compile_arch`` flag (never emit ungated on cross)."""
    host = "${_hardening_host}"
    proc = _COMPILE_ARCH_PROCESSOR_GENEX.get(arch_key)
    if proc is None:
        # Unknown arch key: still host-only so cross toolchains never see it.
        return f"$<$<AND:{host}>:{flag}>"
    return f"$<$<AND:{host},{proc}>:{flag}>"


def _usable_openssf_probe_cache(
    cache: dict[str, bool],
    manifest: dict[str, Any],
) -> dict[str, bool]:
    """Return ``cache`` only when it contains at least one known OpenSSF probe key.

    Arduino / out-of-tree firmware DBs often sit next to unrelated or empty
    ``CMakeCache.txt`` files. Those must not fail-closed on missing probes.
    """
    if not cache:
        return {}
    known = _collect_manifest_probes(manifest)
    if not known:
        return {}
    if not any(key in cache for key in known):
        return {}
    return cache


def _merge_gated_item_blocks(
    blocks: tuple[dict[str, Any], ...],
    list_key: str,
    item_key: str,
) -> list[tuple[str, list[str]]]:
    merged: list[tuple[str, list[str]]] = []
    for block in blocks:
        values = block.get(list_key, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            value = str(item.get(item_key, ""))
            raw_gate = item.get("gate_requires", [])
            if not isinstance(raw_gate, list):
                continue
            gate_requires = [str(marker) for marker in raw_gate if marker]
            if value and gate_requires:
                merged.append((value, gate_requires))
    return merged


def _merge_genex_gated_blocks(
    blocks: tuple[dict[str, Any], ...],
    key: str,
) -> list[tuple[str, list[str]]]:
    return _merge_gated_item_blocks(blocks, key, "flag")


def _merge_definitions_genex_gated_blocks(
    blocks: tuple[dict[str, Any], ...],
) -> list[tuple[str, list[str]]]:
    return _merge_gated_item_blocks(blocks, _DEFINITIONS_GENEX_GATED_KEY, "definition")


def _flag_set_block(manifest: dict[str, Any], language: str) -> dict[str, Any]:
    """Merge cmake.common with cmake.C or cmake.CXX for one language."""
    if language not in _VALID_FLAG_LANGUAGES:
        return {}

    cmake = _cmake_block(manifest)
    if not cmake:
        return {}

    common = cmake.get("common", {})
    lang = cmake.get(language, {})
    if not isinstance(common, dict):
        common = {}
    if not isinstance(lang, dict):
        lang = {}

    if not common:
        return {}

    blocks = (common, lang)
    merged: dict[str, Any] = {}
    for key in _LIST_MERGE_KEYS:
        values = _merge_flag_list_blocks(blocks, key)
        if values:
            merged[key] = values

    compile_arch_flags = _merge_compile_arch_blocks(blocks)
    if compile_arch_flags:
        merged["compile_arch"] = {"merged": compile_arch_flags}

    for key in _PROBE_GATED_KEYS:
        entries = _merge_probe_gated_blocks(blocks, key, language)
        if entries:
            merged[key] = [{"flag": flag, "probe": probe} for flag, probe in entries]

    for key in _GENEX_GATED_KEYS:
        entries = _merge_genex_gated_blocks(blocks, key)
        if entries:
            merged[key] = [{"flag": flag, "gate_requires": gate} for flag, gate in entries]

    def_entries = _merge_definitions_genex_gated_blocks(blocks)
    if def_entries:
        merged[_DEFINITIONS_GENEX_GATED_KEY] = [
            {"definition": definition, "gate_requires": gate} for definition, gate in def_entries
        ]

    return merged


def _resolve_flag_requirements(
    manifest: dict[str, Any],
    language: str,
) -> tuple[
    list[str],
    list[tuple[str, str]],
    list[tuple[str, list[str]]],
    list[tuple[str, list[str]]],
]:
    cmake = _cmake_block(manifest)
    if not isinstance(cmake.get("common"), dict):
        raise ValueError("openssf-hardening-manifest.yaml: missing cmake.common")
    if language not in _VALID_FLAG_LANGUAGES:
        raise ValueError(f"openssf-hardening-manifest.yaml: unsupported language {language!r}")
    if not isinstance(cmake.get(language), dict):
        raise ValueError(f"openssf-hardening-manifest.yaml: missing cmake.{language}")

    block = _flag_set_block(manifest, language)
    if not block:
        raise ValueError(f"openssf-hardening-manifest.yaml: empty merged flag set for {language}")

    required: list[str] = []
    probe_gated: list[tuple[str, str]] = []
    genex_gated: list[tuple[str, list[str]]] = []
    definitions_genex_gated: list[tuple[str, list[str]]] = []

    for key in ("compile", "compile_gnu", "compile_clang"):
        values = block.get(key, [])
        if isinstance(values, list):
            required.extend(str(item) for item in values)

    compile_arch = block.get("compile_arch", {})
    if isinstance(compile_arch, dict):
        for values in compile_arch.values():
            if isinstance(values, list):
                required.extend(str(item) for item in values)

    for key in _PROBE_GATED_KEYS:
        values = block.get(key, [])
        if isinstance(values, list):
            for item in values:
                if isinstance(item, dict):
                    probe_gated.append((str(item.get("flag", "")), str(item.get("probe", ""))))

    for key in _GENEX_GATED_KEYS:
        values = block.get(key, [])
        if isinstance(values, list):
            for item in values:
                if isinstance(item, dict):
                    raw_gate = item.get("gate_requires", [])
                    if isinstance(raw_gate, list):
                        gate_requires = [str(marker) for marker in raw_gate if marker]
                        if gate_requires:
                            genex_gated.append((str(item.get("flag", "")), gate_requires))

    def_values = block.get(_DEFINITIONS_GENEX_GATED_KEY, [])
    if isinstance(def_values, list):
        for item in def_values:
            if isinstance(item, dict):
                raw_gate = item.get("gate_requires", [])
                if isinstance(raw_gate, list):
                    gate_requires = [str(marker) for marker in raw_gate if marker]
                    definition = str(item.get("definition", ""))
                    if definition and gate_requires:
                        definitions_genex_gated.append((definition, gate_requires))

    return required, probe_gated, genex_gated, definitions_genex_gated


def _collect_manifest_probes(manifest: dict[str, Any]) -> set[str]:
    probes: set[str] = set()
    for language in ("C", "CXX"):
        _, probe_gated, _, _ = _resolve_flag_requirements(manifest, language)
        for _, probe in probe_gated:
            if probe:
                probes.add(probe)
    return probes


def _probe_defined_by_check_module(probes_text: str, probe: str) -> bool:
    if probe in CONFIGURE_TIME_PROBES:
        return probe in probes_text
    if probe not in probes_text:
        return False
    for match in re.finditer(
        rf"check_(?:c|cxx)_compiler_flag\s*\([^)]*\b{re.escape(probe)}\b|"
        rf"check_linker_flag\s*\([^)]*\b{re.escape(probe)}\b",
        probes_text,
        flags=re.IGNORECASE,
    ):
        return True
    return False


def verify_consumer_cmake_modules(repo_root: Path, manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    cmake_dir = repo_root / _consumer_cmake_dir(manifest)
    hardening_path = cmake_dir / "Hardening.cmake"
    if not hardening_path.is_file():
        issues.append(f"missing consumer {hardening_path}")
        return issues

    hardening_text = hardening_path.read_text(encoding="utf-8", errors="replace")
    if "function(define_hardening" not in hardening_text:
        issues.append(f"{hardening_path}: must define function(define_hardening)")
    if "CompilerHardeningProbes.cmake" not in hardening_text:
        issues.append(f"{hardening_path}: must include CompilerHardeningProbes.cmake")

    for name in _required_modules(manifest):
        path = cmake_dir / name
        if not path.is_file():
            issues.append(f"missing consumer cmake module: {path}")

    probes_path = cmake_dir / "CompilerHardeningProbes.cmake"
    if probes_path.is_file():
        probes_text = probes_path.read_text(encoding="utf-8", errors="replace")
        for probe in sorted(_collect_manifest_probes(manifest)):
            if not _probe_defined_by_check_module(probes_text, probe):
                issues.append(
                    f"{probes_path}: probe {probe!r} must be set by "
                    "check_c_compiler_flag, check_cxx_compiler_flag, or check_linker_flag"
                )
        for probe in sorted(FORBIDDEN_ENVIRONMENT_PROBES):
            if probe in probes_text:
                issues.append(
                    f"{probes_path}: forbidden custom environment probe {probe!r}; "
                    "gate with CMAKE_CROSSCOMPILING or $<TARGET_PROPERTY:TYPE> only"
                )

    return issues


def _strip_cmake_comments(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        if "#" in line:
            line = line[: line.index("#")]
        lines.append(line)
    return "\n".join(lines)


def _split_cmake_call_args(inner: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in inner:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch in " \t\n\r" and depth == 0:
            if current:
                args.append("".join(current).strip())
                current = []
        else:
            current.append(ch)
    if current:
        args.append("".join(current).strip())
    return [arg for arg in args if arg]


def _extract_cmake_call_inner(text: str, open_paren_index: int) -> str:
    depth = 1
    index = open_paren_index
    while index < len(text) and depth:
        ch = text[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        index += 1
    if depth != 0:
        return ""
    return text[open_paren_index:index - 1]


def _parse_target_link_libraries(text: str) -> dict[str, list[tuple[str, str]]]:
    links: dict[str, list[tuple[str, str]]] = {}
    cleaned = _strip_cmake_comments(text)
    for match in TARGET_LINK_RE.finditer(cleaned):
        inner = _extract_cmake_call_inner(cleaned, match.end())
        if not inner:
            continue
        parts = _split_cmake_call_args(inner)
        if len(parts) < 2:
            continue
        target = parts[0]
        visibility = "PRIVATE"
        start = 1
        if parts[1] in ("PUBLIC", "PRIVATE", "INTERFACE"):
            visibility = parts[1]
            start = 2
        for lib in parts[start:]:
            lib = lib.strip()
            if not lib:
                continue
            links.setdefault(target, []).append((lib, visibility))
    return links


def _parse_defined_targets(text: str) -> set[str]:
    cleaned = _strip_cmake_comments(text)
    # Aliases and imported targets are not compiled here. OBJECT libraries are
    # compiled independently and therefore must consume hardening requirements.
    excluded: set[str] = set()
    for match in re.finditer(r"\badd_library\s*\(\s*([^\s)]+)([^)]*)\)", cleaned, re.DOTALL):
        if re.search(r"\b(?:ALIAS|IMPORTED)\b", match.group(2)):
            excluded.add(match.group(1))
    targets = {match.group(1) for match in ADD_TARGET_RE.finditer(cleaned)}
    targets.update(match.group(1) for match in INTERFACE_LIBRARY_RE.finditer(cleaned))
    return targets - excluded


def _target_reaches_hardening(
    target: str,
    links: dict[str, list[tuple[str, str]]],
    hardening_target: str,
    visiting: set[str] | None = None,
) -> bool:
    if target == hardening_target:
        return True
    if visiting is None:
        visiting = set()
    if target in visiting:
        return False
    visiting.add(target)
    for lib, _visibility in links.get(target, []):
        if lib == hardening_target:
            return True
        if _target_reaches_hardening(lib, links, hardening_target, visiting):
            return True
    return False


_COMPILE_SUFFIXES = frozenset({".c", ".cpp", ".cc", ".cxx"})


def repo_uses_cxx(
    repo_root: Path,
    *,
    source_paths: list[Path],
    cmake_paths: list[Path],
) -> bool:
    for path in source_paths:
        if path.suffix.lower() in {".cpp", ".cxx", ".cc"}:
            return True
    for cmake_path in cmake_paths:
        text = cmake_path.read_text(encoding="utf-8", errors="replace")
        if PROJECT_CXX_RE.search(text):
            return True
    return False


def verify_cxx_hardening_adoption(
    repo_root: Path,
    config: dict[str, object],
    *,
    source_paths: list[Path],
    cmake_paths: list[Path],
) -> list[str]:
    if not repo_uses_cxx(repo_root, source_paths=source_paths, cmake_paths=cmake_paths):
        return []
    issues: list[str] = []
    for root in config["cmake_roots"]:
        if str(root.get("cxx_standard") or ""):
            return issues
    issues.append(
        "project uses C++ (.cpp sources or project(... CXX)) but no define_hardening() root sets CXX_STANDARD"
    )
    return issues


def verify_target_hardening_links(
    repo_root: Path,
    config: dict[str, object],
    *,
    cmake_paths: list[Path],
) -> list[str]:
    """Every add_executable/add_library under scan.source_roots must transitively link hardening."""
    issues: list[str] = []
    hardening_target = str(config.get("interface_target") or "hardening")
    interface_targets: set[str] = {hardening_target}
    all_links: dict[str, list[tuple[str, str]]] = {}
    all_targets: set[str] = set()

    for cmake_path in cmake_paths:
        text = cmake_path.read_text(encoding="utf-8", errors="replace")
        cleaned = _strip_cmake_comments(text)
        interface_targets.update(INTERFACE_LIBRARY_RE.findall(cleaned))
        all_targets.update(_parse_defined_targets(text))
        for target, entries in _parse_target_link_libraries(text).items():
            all_targets.add(target)
            all_links.setdefault(target, []).extend(entries)

    for cmake_path in cmake_paths:
        rel = cmake_path.relative_to(repo_root).as_posix()
        text = cmake_path.read_text(encoding="utf-8", errors="replace")
        cleaned = _strip_cmake_comments(text)
        file_targets = _parse_defined_targets(text) | set(_parse_target_link_libraries(text))
        for target in sorted(file_targets):
            if target in interface_targets:
                continue
            if not _target_reaches_hardening(target, all_links, hardening_target):
                issues.append(
                    f"{rel}: target {target!r} must transitively link {hardening_target!r} "
                    "(target_link_libraries PUBLIC or PRIVATE chain)"
                )
    return issues


def verify_hardening_flags(
    repo_root: Path,
    manifest: dict[str, Any],
    config: dict[str, object],
) -> list[str]:
    issues: list[str] = []
    hardening_path = repo_root / _consumer_cmake_dir(manifest) / "Hardening.cmake"
    if not hardening_path.is_file():
        return issues

    hardening_text = _strip_cmake_comments(
        hardening_path.read_text(encoding="utf-8", errors="replace")
    )
    tokens = extract_hardening_tokens(hardening_text)

    seen_checks: set[tuple[str, str]] = set()
    for root in config["cmake_roots"]:
        rel = str(root["file"])
        c_standard = str(root.get("c_standard") or "")
        cxx_standard = str(root.get("cxx_standard") or "")

        if not c_standard and not cxx_standard:
            issues.append(f"{rel}: define_hardening() must set C_STANDARD and/or CXX_STANDARD")
            continue

        language_specs: list[tuple[str, str]] = []
        if c_standard:
            language_specs.append(("C", c_standard))
        if cxx_standard:
            language_specs.append(("CXX", cxx_standard))

        for language, standard in language_specs:
            standard_issue = _validate_standard(language, standard)
            if standard_issue:
                issues.append(f"{rel}: {standard_issue}")
                continue

            dedupe_key = (language, standard)
            if dedupe_key in seen_checks:
                continue
            seen_checks.add(dedupe_key)

            label = _standard_label(language, standard)
            try:
                required, probe_gated, genex_gated, definitions_genex_gated = (
                    _resolve_flag_requirements(manifest, language)
                )
            except ValueError as exc:
                issues.append(str(exc))
                continue

            covered_flags = _required_flag_names(manifest)
            covered_defs = {
                str(item) for item in _coverage_block(manifest).get("definitions", []) if item
            }

            rel_path = hardening_path.relative_to(repo_root)
            for flag in required:
                if flag not in covered_flags:
                    continue
                if flag not in tokens:
                    issues.append(f"{rel_path} missing OpenSSF flag {flag!r} ({label})")

            for flag, probe in probe_gated:
                if not flag or not probe or flag not in covered_flags:
                    continue
                if flag not in tokens:
                    issues.append(f"{rel_path} missing probe-gated flag {flag!r} ({label})")
                elif probe not in hardening_text:
                    issues.append(f"{rel_path} missing probe gate {probe!r} for flag {flag!r}")

            for flag, gate_requires in genex_gated:
                if not flag or not gate_requires or flag not in covered_flags:
                    continue
                if flag not in tokens:
                    issues.append(f"{rel_path} missing genex-gated flag {flag!r} ({label})")

            for definition, gate_requires in definitions_genex_gated:
                if not definition or not gate_requires or definition not in covered_defs:
                    continue
                if definition not in hardening_text:
                    issues.append(
                        f"{rel_path} missing genex-gated definition {definition!r} ({label})"
                    )

    return issues


FORTIFY_RELEASE_CONFIG_GATE_RE = re.compile(
    r"_hardening_fortify_cfg|_FORTIFY_SOURCE[^\n]*\$<OR:\s*\$<CONFIG:Release>"
)
FEXCEPTIONS_RE = re.compile(r"\badd_compile_options\s*\([^)]*-fexceptions\b")
FHARDENED_RE = re.compile(r"-fhardened\b")


def _line_is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return not stripped or stripped.startswith("#")


def _line_satisfies_genex_gate(line: str, gate_requires: list[str]) -> bool:
    for marker in gate_requires:
        if marker == "SHARED_LIBRARY":
            if any(
                token in line
                for token in ("SHARED_LIBRARY", "MODULE_LIBRARY", "_hardening_consumer_shared")
            ):
                continue
            return False
        if marker == "CONFIG:Release":
            if "CONFIG:Release" in line or "_hardening_fortify_cfg" in line:
                continue
            return False
        if marker == "CONFIG:MinSizeRel":
            if "CONFIG:MinSizeRel" in line or "_hardening_fortify_cfg" in line:
                continue
            return False
        if marker == "CONFIG:Production":
            if "_hardening_production_cfg" in line:
                continue
            return False
        if marker == "CONFIG:RelWithDebInfo":
            if (
                "CONFIG:RelWithDebInfo" in line
                or "_hardening_relwithdebinfo_cfg" in line
                or "_hardening_fortify_cfg" in line
            ):
                continue
            return False
        if marker == "CONFIG:Debug":
            if "CONFIG:Debug" in line or "_hardening_debug_cfg" in line:
                continue
            return False
        if marker == "NOT_INSTRUMENTED_SANITIZER":
            if (
                "HAVE_INSTRUMENTED_SANITIZER" in line
                and ("$<NOT:" in line or "NOT:$<BOOL" in line)
            ):
                continue
            return False
        if marker == "NOT_FHARDENED":
            if (
                ("HAVE_C_FHARDENED" in line or "HAVE_CXX_FHARDENED" in line)
                and ("$<NOT:" in line or "NOT:$<BOOL" in line)
            ):
                continue
            return False
        if marker in line:
            continue
        if any(
            alias in line and marker in GENEX_GATE_ALIASES.get(alias, [])
            for alias in GENEX_GATE_ALIASES
        ):
            continue
        return False
    return True


def _lines_with_flag(text: str, flag: str) -> list[str]:
    pattern = _flag_pattern(flag)
    return [line for line in text.splitlines() if pattern.search(line)]


def verify_genex_gating(
    repo_root: Path,
    manifest: dict[str, Any],
) -> list[str]:
    issues: list[str] = []
    hardening_path = repo_root / _consumer_cmake_dir(manifest) / "Hardening.cmake"
    if not hardening_path.is_file():
        return issues

    text = _strip_cmake_comments(
        hardening_path.read_text(encoding="utf-8", errors="replace")
    )
    rel_path = hardening_path.relative_to(repo_root)
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for language in ("C", "CXX"):
        _, _, genex_gated, definitions_genex_gated = _resolve_flag_requirements(manifest, language)
        for flag, gate_requires in genex_gated:
            key = (flag, tuple(gate_requires))
            if key in seen:
                continue
            seen.add(key)
            lines = _lines_with_flag(text, flag)
            if not lines:
                continue
            if not any(_line_satisfies_genex_gate(line, gate_requires) for line in lines):
                issues.append(
                    f"{rel_path}: {flag} must use upstream CMake generator gating "
                    f"({', '.join(gate_requires)})"
                )
        for definition, gate_requires in definitions_genex_gated:
            key = (definition, tuple(gate_requires))
            if key in seen:
                continue
            seen.add(key)
            lines = [line for line in text.splitlines() if definition in line]
            if not lines:
                issues.append(f"{rel_path} missing genex-gated definition {definition!r}")
                continue
            if not any(_line_satisfies_genex_gate(line, gate_requires) for line in lines):
                issues.append(
                    f"{rel_path}: {definition} must use upstream CMake generator gating "
                    f"({', '.join(gate_requires)})"
                )

    return issues


def verify_hardening_uniformity(
    repo_root: Path,
    manifest: dict[str, Any],
    config: dict[str, object],
) -> list[str]:
    """Ensure hardening flags live on the interface target, not duplicated in CMake roots."""
    issues: list[str] = []
    hardening_path = repo_root / _consumer_cmake_dir(manifest) / "Hardening.cmake"
    hardening_text = (
        hardening_path.read_text(encoding="utf-8", errors="replace") if hardening_path.is_file() else ""
    )

    if hardening_text and not FORTIFY_RELEASE_CONFIG_GATE_RE.search(hardening_text):
        if "-D_FORTIFY_SOURCE=3" in hardening_text or "_FORTIFY_SOURCE=3" in hardening_text:
            issues.append(
                "cmake/Hardening.cmake must gate _FORTIFY_SOURCE=3 on Release/RelWithDebInfo/MinSizeRel"
            )

    if hardening_text and re.search(r"-Wno-", hardening_text):
        issues.append(
            "cmake/Hardening.cmake must not use -Wno-* waivers; "
            "gate flags via openssf-hardening-manifest.yaml compile_genex_gated instead"
        )

    for root in config["cmake_roots"]:
        path = repo_root / str(root["file"])
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")

        if _has_blanket_werror(text):
            issues.append(f"{path}: blanket -Werror must be on cmake/Hardening.cmake, not CMakeLists")
        if BUILD_OPT_RE.search(text):
            issues.append(f"{path}: -O1/-O2/-O3/-Os optimization flags must be on cmake/Hardening.cmake, not CMakeLists")
        if FHARDENED_RE.search(text):
            issues.append(f"{path}: -fhardened must be on cmake/Hardening.cmake, not CMakeLists")
        if FEXCEPTIONS_RE.search(text):
            issues.append(f"{path}: -fexceptions must be on cmake/Hardening.cmake, not CMakeLists")

    return issues


def verify_cmake_roots(repo_root: Path, config: dict[str, object]) -> list[str]:
    issues: list[str] = []
    if not config["cmake_roots"]:
        issues.append(
            "no CMakeLists.txt found that include cmake/Hardening.cmake "
            "(or Hardening.by-<slug>.cmake)"
        )
        return issues

    for root in config["cmake_roots"]:
        rel = str(root["file"])
        path = repo_root / rel
        target = str(root.get("interface_target") or config.get("interface_target") or "hardening")
        if not path.is_file():
            issues.append(f"missing CMake hardening root: {path}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if not HARDENING_MODULE_INCLUDE_RE.search(text):
            issues.append(
                f"{path}: must include cmake/Hardening.cmake "
                "(or Hardening.by-<slug>.cmake for dialed compile_db)"
            )
        if "define_hardening(" not in text:
            issues.append(f"{path}: must call define_hardening()")
        elif target not in text:
            issues.append(f"{path}: must link the {target} interface target")

        c_standard = str(root.get("c_standard") or "")
        cxx_standard = str(root.get("cxx_standard") or "")
        if not c_standard and not cxx_standard:
            issues.append(f"{path}: define_hardening() must set C_STANDARD and/or CXX_STANDARD")

        for pattern, detail in FORBIDDEN_CMAKE_PATTERNS:
            if pattern.search(text):
                issues.append(f"{path}: {detail}")
    return issues


def verify_consumer_hardening_no_unlisted_flags(
    repo_root: Path,
    manifest: dict[str, Any],
    *,
    kit_manifest: dict[str, Any] | None = None,
) -> list[str]:
    """Hardening.cmake may only contain kit coverage tokens (FULL allowlist).

    Dial-removed tokens remain legal in generated FULL CMake; dials waive presence
    checks, not the allowlist for unlisted extras.
    """
    issues: list[str] = []
    cmake_dir = repo_root / _consumer_cmake_dir(manifest)
    hardening_path = cmake_dir / "Hardening.cmake"
    if not hardening_path.is_file():
        return issues
    allow_src = kit_manifest if kit_manifest is not None else manifest
    allowed = _allowed_coverage_tokens(allow_src)
    tokens = extract_hardening_tokens(
        _strip_cmake_comments(hardening_path.read_text(encoding="utf-8", errors="replace"))
    )
    extras = sorted(tokens - allowed)
    rel = hardening_path.relative_to(repo_root)
    for token in extras:
        issues.append(
            f"{rel}: flag {token!r} is not listed in coverage.flags or coverage.definitions"
        )
    return issues


def verify_system_include_policy(
    repo_root: Path,
    *,
    cmake_paths: list[Path],
) -> list[str]:
    """Third-party/vendor include paths must use SYSTEM (OpenSSF -isystem guidance)."""
    issues: list[str] = []
    for cmake_path in cmake_paths:
        text = _strip_cmake_comments(cmake_path.read_text(encoding="utf-8", errors="replace"))
        rel = cmake_path.relative_to(repo_root).as_posix()
        for match in INCLUDE_DIR_STMT_RE.finditer(text):
            block = match.group(0)
            if not THIRD_PARTY_INCLUDE_RE.search(block):
                continue
            if re.search(r"\bSYSTEM\b", block, re.IGNORECASE):
                continue
            issues.append(
                f"{rel}: third-party include must use SYSTEM (OpenSSF -isystem guidance): {block[:80]!r}..."
            )
    return issues


def verify_sanitizer_before_hardening(
    repo_root: Path,
    *,
    cmake_paths: list[Path],
) -> list[str]:
    """Sanitizer flags must be on CMAKE_*_FLAGS before Hardening.cmake include (fortify probe)."""
    issues: list[str] = []
    for cmake_path in cmake_paths:
        text = _strip_cmake_comments(cmake_path.read_text(encoding="utf-8", errors="replace"))
        include_match = HARDENING_MODULE_INCLUDE_RE.search(text)
        if not include_match:
            continue
        rel = cmake_path.relative_to(repo_root).as_posix()
        before = text[: include_match.start()]
        after = text[include_match.end() :]
        if not SANITIZER_ADD_COMPILE_RE.search(after):
            continue
        if CMAKE_SANITIZER_FLAGS_RE.search(before):
            continue
        issues.append(
            f"{rel}: add_compile_options(-fsanitize) after Hardening include without prior "
            "CMAKE_C/CXX_FLAGS sanitizer setup breaks HAVE_INSTRUMENTED_SANITIZER / fortify gating"
        )
    return issues


def _required_flag_names(manifest: dict[str, Any]) -> set[str]:
    return {str(flag) for flag in _coverage_block(manifest).get("flags", []) if flag}


# Mutually exclusive OpenSSF alternatives: prefer the first token whose probe is true.
_EXCLUSIVE_PROBE_FLAG_GROUPS: tuple[tuple[str, ...], ...] = (
    ("-fzero-init-padding-bits=all", "-fzero-init-padding-bits=union"),
)


def _exclusive_probe_mates(flag: str) -> tuple[str, ...] | None:
    for group in _EXCLUSIVE_PROBE_FLAG_GROUPS:
        if flag in group:
            return group
    return None


def _select_exclusive_probe_flag(
    group: tuple[str, ...],
    *,
    covered_flags: set[str],
    probe_by_flag: dict[str, str],
    probe_cache: dict[str, bool],
) -> str | None:
    """Return the preferred dialed flag in an exclusive group with a true probe."""
    for flag in group:
        if flag not in covered_flags:
            continue
        probe = probe_by_flag.get(flag)
        if probe and probe_cache.get(probe):
            return flag
    return None


def _collect_required_native_probes(manifest: dict[str, Any], config: dict[str, object]) -> set[str]:
    """Probe vars for required_flags only; auto-discovered from flag_sets.

    Exclusive alternatives (e.g. zero-init padding all vs union) are handled in
    ``verify_native_toolchain_probes`` (at least one must succeed).
    """
    required_flags = _required_flag_names(manifest)
    uses_c = any(root.get("c_standard") for root in config["cmake_roots"])
    uses_cxx = any(root.get("cxx_standard") for root in config["cmake_roots"])
    probes: set[str] = set()
    for language, enabled in (("C", uses_c), ("CXX", uses_cxx)):
        if not enabled:
            continue
        _, probe_gated, _, _ = _resolve_flag_requirements(manifest, language)
        for flag, probe in probe_gated:
            if flag not in required_flags or not probe:
                continue
            if _exclusive_probe_mates(flag):
                continue
            probes.add(probe)
    return probes


def _exclusive_group_probe_issues(
    manifest: dict[str, Any],
    config: dict[str, object],
    cache: dict[str, bool],
    *,
    source_dir: Path,
) -> list[str]:
    required_flags = _required_flag_names(manifest)
    uses_c = any(root.get("c_standard") for root in config["cmake_roots"])
    uses_cxx = any(root.get("cxx_standard") for root in config["cmake_roots"])
    probe_by_flag: dict[str, str] = {}
    for language, enabled in (("C", uses_c), ("CXX", uses_cxx)):
        if not enabled:
            continue
        _, probe_gated, _, _ = _resolve_flag_requirements(manifest, language)
        for flag, probe in probe_gated:
            if flag in required_flags and probe:
                probe_by_flag.setdefault(flag, probe)
    issues: list[str] = []
    for group in _EXCLUSIVE_PROBE_FLAG_GROUPS:
        dialed = [flag for flag in group if flag in required_flags]
        if not dialed:
            continue
        probes = [probe_by_flag[flag] for flag in dialed if flag in probe_by_flag]
        if not probes:
            continue
        if any(cache.get(probe) for probe in probes):
            continue
        issues.append(
            f"native toolchain exclusive OpenSSF probes all false for {dialed!r} "
            f"on CI host; dial-remove or fix toolchain ({source_dir})"
        )
    return issues


def _host_inapplicable_probes(manifest: dict[str, Any], probes: set[str]) -> set[str]:
    """Drop probes that flag_sets gate to a different host ISA/OS than the CI runner."""
    inapplicable: set[str] = set()
    machine = platform.machine().lower()
    if machine not in ("aarch64", "arm64") and "HAVE_ARM_BRANCH_PROTECTION_STANDARD" in probes:
        inapplicable.add("HAVE_ARM_BRANCH_PROTECTION_STANDARD")
    if platform.system() != "Linux":
        inapplicable.update(
            probe
            for probe in probes
            if probe.startswith("HAVE_LINK_")
        )
    return inapplicable


def _parse_cmake_cache_bools(cache_path: Path) -> dict[str, bool]:
    values: dict[str, bool] = {}
    for line in cache_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("//"):
            continue
        if ":BOOL=" not in line and ":INTERNAL=" not in line:
            continue
        name, _, rest = line.partition(":")
        _kind, _, raw = rest.partition("=")
        if not name.startswith("HAVE_"):
            continue
        values[name] = raw.strip().upper() in {"1", "ON", "TRUE", "YES"}
    return values


def _select_probe_configure_source(repo_root: Path, config: dict[str, object]) -> Path | None:
    candidates: list[tuple[int, Path]] = []
    for root in config.get("cmake_roots", []):
        cmake_lists = repo_root / str(root["file"])
        if not cmake_lists.is_file():
            continue
        text = cmake_lists.read_text(encoding="utf-8", errors="replace")
        if "project(" not in text:
            continue
        rel = cmake_lists.relative_to(repo_root).as_posix()
        priority = 1
        if rel.startswith("tests/"):
            priority = 3
        elif rel.startswith("userspace/"):
            priority = 2
        candidates.append((priority, cmake_lists.parent))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def verify_native_toolchain_probes(
    repo_root: Path,
    manifest: dict[str, Any],
    config: dict[str, object],
) -> list[str]:
    """Fail when CI host toolchain cannot satisfy manifest probe-gated OpenSSF flags."""
    if not shutil.which("cmake"):
        return ["native toolchain probe check: cmake not found"]
    roots = config.get("cmake_roots", [])
    if not roots:
        return []

    source_dir = _select_probe_configure_source(repo_root, config)
    if source_dir is None:
        return []

    build_dir = repo_root / PROBE_VERIFY_BUILD_DIR
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "cmake",
        "-S",
        str(source_dir),
        "-B",
        str(build_dir),
        "-G",
        cmake_generator(),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ]
    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit {proc.returncode}"
        return [f"native toolchain probe configure failed for {source_dir}: {tail}"]

    cache_path = build_dir / "CMakeCache.txt"
    if not cache_path.is_file():
        return ["native toolchain probe check: CMakeCache.txt missing after configure"]

    cache = _parse_cmake_cache_bools(cache_path)
    required = _collect_required_native_probes(manifest, config)
    required -= _host_inapplicable_probes(manifest, required)
    issues: list[str] = []
    for probe in sorted(required):
        if cache.get(probe):
            continue
        issues.append(
            f"native toolchain probe {probe}=0 on CI host; dial-remove the flag or fix the toolchain "
            f"({source_dir})"
        )
    issues.extend(_exclusive_group_probe_issues(manifest, config, cache, source_dir=source_dir))
    return issues


def _host_applicable_audit_flag(flag: str) -> bool:
    machine = platform.machine().lower()
    if flag == "-mbranch-protection=standard":
        return machine in ("aarch64", "arm64")
    if flag == "-fcf-protection=full":
        return machine in ("x86_64", "amd64")
    return True


def compile_db_host_probe_cache(
    repo_root: Path,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """Merge ``HAVE_*`` probe results from host ``compile_db.userspace`` configure trees."""
    from consumer_manifest import compile_db_userspace_entries

    caches: list[dict[str, bool]] = []
    for project in compile_db_userspace_entries(repo_root):
        cache_path = (repo_root / str(project["build_dir"]) / "CMakeCache.txt").resolve()
        if cache_path.is_file():
            caches.append(_parse_cmake_cache_bools(cache_path))
    merged: dict[str, bool] = {}
    for cache in caches:
        merged.update(cache)
    if manifest is None:
        return merged
    return _usable_openssf_probe_cache(merged, manifest)


def compile_db_cross_probe_cache_for_db(
    repo_root: Path,
    compile_commands_json: str,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """``HAVE_*`` probes from one firmware ``compile_commands_json`` build tree."""
    repo_root = repo_root.resolve()
    rel = Path(compile_commands_json).as_posix()
    cache_path = (repo_root / rel).parent / "CMakeCache.txt"
    raw: dict[str, bool] = {}
    if cache_path.is_file():
        raw = _parse_cmake_cache_bools(cache_path)
    if manifest is None:
        return raw
    return _usable_openssf_probe_cache(raw, manifest)


def compile_db_cross_probe_caches(
    repo_root: Path,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, dict[str, bool]]:
    """Per-firmware-DB probe caches (UNO vs WBA must not merge)."""
    from consumer_manifest import compile_db_firmware_entries

    out: dict[str, dict[str, bool]] = {}
    for entry in compile_db_firmware_entries(repo_root):
        rel = Path(str(entry["compile_commands_json"])).as_posix()
        out[rel] = compile_db_cross_probe_cache_for_db(
            repo_root, rel, manifest=manifest
        )
    return out


def compile_db_cross_probe_cache(
    repo_root: Path,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """Merged firmware probe cache (legacy helper; prefer per-DB caches for audit)."""
    merged: dict[str, bool] = {}
    for cache in compile_db_cross_probe_caches(repo_root, manifest=None).values():
        merged.update(cache)
    if manifest is None:
        return merged
    return _usable_openssf_probe_cache(merged, manifest)



def _compile_language_for_source(source: Path) -> str:
    if source.suffix.lower() in {".cpp", ".cxx", ".cc", ".hpp"}:
        return "CXX"
    return "C"


def _is_link_or_type_only_flag(flag: str) -> bool:
    """Link / target-type flags are enforced via CMake regen + link.txt, not compile DB."""
    return flag in {"-pie", "-shared", "-fPIE", "-fPIC"} or flag.startswith("LINKER:")


def _compile_db_gate_applies(
    gate_requires: list[str],
    *,
    cross_compile: bool,
    command: str,
    build_type: str | None,
    probe_cache: dict[str, bool],
    language: str,
) -> bool | None:
    """Return True/False if gates are decidable; None means skip (TYPE-only / unknown)."""
    markers = [str(m) for m in gate_requires]
    if "TARGET_PROPERTY:TYPE" in markers:
        return None
    if "CMAKE_CROSSCOMPILING" in markers and cross_compile:
        return False
    config_markers = [m for m in markers if m.startswith("CONFIG:")]
    if config_markers:
        if not build_type:
            return None
        wanted = {m.split(":", 1)[1].lower() for m in config_markers}
        # Production maps to Release/MinSizeRel in synthetic CMake helpers.
        if "production" in wanted:
            wanted.update({"release", "minsizerel"})
        if build_type.lower() not in wanted:
            return False
    if "NOT_INSTRUMENTED_SANITIZER" in markers and "-fsanitize" in command:
        return False
    if "NOT_FHARDENED" in markers:
        probe = f"HAVE_{language}_FHARDENED"
        if probe_cache.get(probe, False):
            return False
    return True


def _definition_present_in_command(definition: str, command: str) -> bool:
    if f"-D{definition}" in command:
        return True
    # Bare token match for already-expanded forms.
    return definition in command


def compile_db_audit_flags_for_context(
    manifest: dict[str, Any],
    *,
    cross_compile: bool,
    probe_cache: dict[str, bool],
    language: str = "C",
    command: str = "",
    build_type: str | None = None,
) -> tuple[list[str], list[str]]:
    """Full OpenSSF compile/def anchors for one TU.

    Returns ``(required_flags_or_defs, probe_issues)``. Probe-gated dialed flags are
    always required when context applies (fail-closed); missing/false probes are reported
    separately rather than silently shrinking the required set.
    Link / TYPE-only tokens are omitted (link.txt + CMake regen).
    """
    covered_flags = _required_flag_names(manifest)
    covered_defs = {
        str(item) for item in _coverage_block(manifest).get("definitions", []) if item
    }
    try:
        required, probe_gated, genex_gated, definitions_genex_gated = _resolve_flag_requirements(
            manifest, language
        )
    except ValueError:
        return [], []

    flags: list[str] = []
    probe_issues: list[str] = []
    seen: set[str] = set()

    arch_flags = set(
        _merge_compile_arch_blocks((_cmake_block(manifest).get("common", {}),))
    )

    def _add(token: str) -> None:
        if token in seen or token not in covered_flags:
            return
        if _is_link_or_type_only_flag(token):
            return
        seen.add(token)
        flags.append(token)

    for flag in required:
        if flag in arch_flags:
            if cross_compile or not _host_applicable_audit_flag(flag):
                continue
        elif not cross_compile and not _host_applicable_audit_flag(flag):
            continue
        _add(flag)

    for flag, probe in probe_gated:
        if not flag or flag not in covered_flags or _is_link_or_type_only_flag(flag):
            continue
        if flag.startswith("LINKER:"):
            continue
        if not cross_compile and not _host_applicable_audit_flag(flag):
            continue
        mates = _exclusive_probe_mates(flag)
        if mates:
            # Handle once per group (prefer first dialed flag with a true probe).
            if flag != mates[0] and mates[0] in covered_flags:
                continue
            if not probe_cache:
                continue
            probe_by_flag = {f: p for f, p in probe_gated if f in mates}
            chosen = _select_exclusive_probe_flag(
                mates,
                covered_flags=covered_flags,
                probe_by_flag=probe_by_flag,
                probe_cache=probe_cache,
            )
            if chosen:
                _add(chosen)
            else:
                dialed = [item for item in mates if item in covered_flags]
                probe_issues.append(
                    f"OpenSSF exclusive probes all false/missing for {dialed!r} "
                    "(dial-remove or fix toolchain probes)"
                )
            continue
        if not probe_cache:
            # Unconfigured tree: cmake regen still enforces templates; skip command anchors.
            continue
        if not probe:
            probe_issues.append(f"missing probe name for OpenSSF flag {flag!r}")
            continue
        if probe not in probe_cache:
            probe_issues.append(
                f"OpenSSF probe {probe!r} missing from CMakeCache for flag {flag!r} "
                "(dial-remove the flag or reconfigure probes)"
            )
            continue
        if not probe_cache[probe]:
            probe_issues.append(
                f"OpenSSF probe {probe!r} is false for flag {flag!r} "
                "(dial-remove the flag or fix the toolchain probe)"
            )
            continue
        _add(flag)

    for flag, gate_requires in genex_gated:
        if not flag or flag not in covered_flags or _is_link_or_type_only_flag(flag):
            continue
        applies = _compile_db_gate_applies(
            gate_requires,
            cross_compile=cross_compile,
            command=command,
            build_type=build_type,
            probe_cache=probe_cache,
            language=language,
        )
        if applies is True:
            _add(flag)

    for definition, gate_requires in definitions_genex_gated:
        if not definition or definition not in covered_defs:
            continue
        applies = _compile_db_gate_applies(
            gate_requires,
            cross_compile=cross_compile,
            command=command,
            build_type=build_type,
            probe_cache=probe_cache,
            language=language,
        )
        if applies is True and definition not in seen:
            seen.add(definition)
            flags.append(definition)

    return flags, probe_issues


def compile_db_audit_flags(manifest: dict[str, Any]) -> list[str]:
    """Host-native audit anchors with all probe-gated flags (legacy helper)."""
    flags, _ = compile_db_audit_flags_for_context(
        manifest,
        cross_compile=False,
        probe_cache={probe: True for probe in _collect_manifest_probes(manifest)},
        language="C",
        command="",
        build_type="Release",
    )
    return flags


def _compile_db_audit_cross_context(
    lookup_key: str,
    command: str,
    *,
    repo_root: Path | None = None,
) -> bool:
    if storage_key_prefers_firmware_compile(lookup_key, repo_root):
        return True
    return is_cross_compile_command(command)


def _build_type_from_cache(cache_path: Path) -> str | None:
    if not cache_path.is_file():
        return None
    for line in cache_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("CMAKE_BUILD_TYPE:"):
            _kind, _, raw = line.partition("=")
            value = raw.strip()
            return value or None
    return None


def _owning_build_dir_for_lookup(
    repo_root: Path,
    lookup_key: str,
    *,
    preferred_compile_db: str | None = None,
    provenance: list[str] | None = None,
) -> Path | None:
    from policy_overrides import owning_compile_commands_json

    rel = owning_compile_commands_json(
        repo_root,
        lookup_key,
        preferred_compile_db=preferred_compile_db,
        provenance=provenance,
    )
    if not rel:
        return None
    return (repo_root / rel).parent


def verify_compile_commands_openssf(
    repo_root: Path,
    lint_kit: Path,
    *,
    merged_json: Path | None = None,
    entries_by_key: dict[str, dict] | None = None,
    source_paths: list[Path],
) -> list[str]:
    """Per-TU audit: every scan C/C++ file must carry full OpenSSF compile/def anchors.

    Each ``compile_db.firmware[]`` database is audited independently (UNO vs WBA must
    not share one merged command or probe cache). Host/userspace sources are audited
    once via the richest/merged map.
    """
    try:
        kit_manifest = load_hardening_manifest(lint_kit)
    except (FileNotFoundError, ValueError) as exc:
        return [str(exc)]

    from policy_overrides import openssf_manifest_for_audit
    from consumer_manifest import compile_db_firmware_entries
    from compile_db_util import (
        entry_compile_db_provenance,
        load_compile_entries_by_db,
        storage_key_prefers_firmware_compile,
    )

    repo_root = repo_root.resolve()
    manifest = openssf_manifest_for_audit(repo_root, kit_manifest, lookup_key=None)
    host_probes = compile_db_host_probe_cache(repo_root, manifest=kit_manifest)
    cross_probes_by_db = compile_db_cross_probe_caches(repo_root, manifest=kit_manifest)
    entries_by_db = load_compile_entries_by_db(repo_root)
    if entries_by_key is not None:
        from policy_overrides import _source_key_in_compile_db

        for fw_entry in compile_db_firmware_entries(repo_root):
            db_rel = Path(str(fw_entry["compile_commands_json"])).as_posix()
            bucket = entries_by_db.setdefault(db_rel, {})
            for lookup_key, entry in entries_by_key.items():
                if not storage_key_prefers_firmware_compile(lookup_key, repo_root):
                    continue
                provenance = entry_compile_db_provenance(entry)
                if provenance:
                    if db_rel in provenance:
                        bucket[lookup_key] = entry
                elif _source_key_in_compile_db(repo_root, db_rel, lookup_key):
                    bucket[lookup_key] = entry
    if entries_by_key is not None:
        by_key = entries_by_key
    else:
        from compile_db_util import MergedCompileDatabase

        if merged_json is None:
            from consumer_manifest import clang_tidy_merge_build_dir

            merge_dir = repo_root / clang_tidy_merge_build_dir(repo_root)
            merged_json = merge_dir / "compile_commands.json"
        if not merged_json.is_file():
            return [f"compile_commands OpenSSF audit: missing merged database {merged_json}"]
        by_key = MergedCompileDatabase.from_json(merged_json, repo_root).by_key
    host_flag_sample, _ = compile_db_audit_flags_for_context(
        manifest,
        cross_compile=False,
        probe_cache=host_probes,
        language="C",
        command="",
        build_type="Release",
    )
    any_cross_sample = False
    for probes in cross_probes_by_db.values():
        sample, _ = compile_db_audit_flags_for_context(
            manifest,
            cross_compile=True,
            probe_cache=probes,
            language="C",
            command="",
            build_type=None,
        )
        if sample:
            any_cross_sample = True
            break
    if not cross_probes_by_db:
        # No firmware DBs: allow host-only sample check.
        legacy_cross = compile_db_cross_probe_cache(repo_root, manifest=kit_manifest)
        sample, _ = compile_db_audit_flags_for_context(
            manifest,
            cross_compile=True,
            probe_cache=legacy_cross,
            language="C",
            command="",
            build_type=None,
        )
        any_cross_sample = bool(sample)
    if not host_flag_sample and not any_cross_sample:
        return ["compile_commands OpenSSF audit: no coverage.flags anchors in cmake"]

    issues: list[str] = []
    deferred_missing_entry: list[tuple[str, str]] = []
    hardened_hosts: list[tuple[Path, str]] = []
    firmware_audited: set[str] = set()

    def _audit_one(
        *,
        source: Path,
        lookup_key: str,
        rel: str,
        entry: dict,
        preferred_compile_db: str | None,
        probe_cache: dict[str, bool],
        build_dir: Path | None,
        label_prefix: str,
    ) -> None:
        command = entry_command(entry)
        cross = _compile_db_audit_cross_context(lookup_key, command, repo_root=repo_root)
        language = _compile_language_for_source(source)
        provenance = entry_compile_db_provenance(entry)
        tu_manifest = openssf_manifest_for_audit(
            repo_root,
            kit_manifest,
            lookup_key=lookup_key,
            preferred_compile_db=preferred_compile_db,
            provenance=provenance or None,
        )
        build_type = (
            _build_type_from_cache(build_dir / "CMakeCache.txt") if build_dir else None
        )
        cache = dict(probe_cache)
        if build_dir is not None:
            local_cache = build_dir / "CMakeCache.txt"
            if local_cache.is_file():
                local = _usable_openssf_probe_cache(
                    _parse_cmake_cache_bools(local_cache), kit_manifest
                )
                if local:
                    cache.update(local)
        flags, probe_issues = compile_db_audit_flags_for_context(
            tu_manifest,
            cross_compile=cross,
            probe_cache=cache,
            language=language,
            command=command,
            build_type=build_type,
        )
        for msg in probe_issues:
            issues.append(f"compile_commands OpenSSF audit: {label_prefix}{rel}: {msg}")
        covered_defs = {
            str(item) for item in _coverage_block(tu_manifest).get("definitions", []) if item
        }
        missing: list[str] = []
        for flag in flags:
            if flag in covered_defs:
                if not _definition_present_in_command(flag, command):
                    missing.append(flag)
            elif flag not in command:
                missing.append(flag)
        if missing:
            kind = "cross-compile" if cross else "host-native"
            issues.append(
                f"compile_commands OpenSSF audit: {label_prefix}{rel} ({kind}) "
                f"missing {', '.join(missing)}"
            )
            return
        hardened_hosts.append((source.resolve(), command))

    # Firmware profiles: one independent audit per declared compile database.
    for fw_entry in compile_db_firmware_entries(repo_root):
        db_rel = Path(str(fw_entry["compile_commands_json"])).as_posix()
        db_entries = entries_by_db.get(db_rel, {})
        probe_cache = cross_probes_by_db.get(db_rel, {})
        build_dir = (repo_root / db_rel).parent
        label = f"[{db_rel}] "
        for source in source_paths:
            if source.suffix.lower() not in _COMPILE_SUFFIXES:
                continue
            lookup_key = source_key(source, repo_root)
            if lookup_key is None:
                lookup_key = str(source.resolve())
            entry = db_entries.get(lookup_key)
            # Test / caller overrides: prefer entries_by_key when provenance matches.
            if entries_by_key is not None and lookup_key in entries_by_key:
                override = entries_by_key[lookup_key]
                prov = entry_compile_db_provenance(override)
                if not prov or db_rel in prov:
                    entry = override
            if entry is None:
                continue
            rel = source.relative_to(repo_root).as_posix()
            _audit_one(
                source=source,
                lookup_key=lookup_key,
                rel=rel,
                entry=entry,
                preferred_compile_db=db_rel,
                probe_cache=probe_cache,
                build_dir=build_dir,
                label_prefix=label,
            )
            firmware_audited.add(lookup_key)

    # Host / userspace: audit once via richest/merged map (not firmware-preferring keys
    # already covered above).
    for source in source_paths:
        if source.suffix.lower() not in _COMPILE_SUFFIXES:
            continue
        lookup_key = source_key(source, repo_root)
        if lookup_key is None:
            lookup_key = str(source.resolve())
        rel = source.relative_to(repo_root).as_posix()
        if storage_key_prefers_firmware_compile(lookup_key, repo_root):
            if lookup_key not in firmware_audited:
                deferred_missing_entry.append(
                    (
                        lookup_key,
                        f"compile_commands OpenSSF audit: missing firmware entry for {rel}",
                    )
                )
            continue
        entry = by_key.get(lookup_key)
        if entry is None:
            deferred_missing_entry.append(
                (lookup_key, f"compile_commands OpenSSF audit: missing entry for {rel}")
            )
            continue
        provenance = entry_compile_db_provenance(entry)
        preferred = provenance[0] if len(provenance) == 1 else None
        build_dir = None
        if preferred:
            build_dir = (repo_root / preferred).parent
        elif provenance:
            build_dir = (repo_root / provenance[0]).parent
        else:
            build_dir = _owning_build_dir_for_lookup(repo_root, lookup_key)
        _audit_one(
            source=source,
            lookup_key=lookup_key,
            rel=rel,
            entry=entry,
            preferred_compile_db=preferred,
            probe_cache=host_probes,
            build_dir=build_dir,
            label_prefix="",
        )

    from compile_db_util import amalgamation_included_source_keys

    covered = amalgamation_included_source_keys(repo_root, iter(hardened_hosts))
    for lookup_key, message in deferred_missing_entry:
        if lookup_key in covered:
            continue
        issues.append(message)
    return issues


@dataclass(frozen=True)
class CompileDbOpenssfAuditScope:
    audited_cc_files: int
    host_native_files: int
    cross_compile_files: int
    host_audit_flag_count: int
    cross_audit_flag_count: int


def compile_db_openssf_audit_scope(
    repo_root: Path,
    lint_kit: Path,
    *,
    source_paths: list[Path],
    entries_by_key: dict[str, dict],
) -> CompileDbOpenssfAuditScope:
    """Describe which scan C/C++ files ``verify_compile_commands_openssf`` audits."""
    repo_root = repo_root.resolve()
    try:
        kit_manifest = load_hardening_manifest(lint_kit)
        from policy_overrides import openssf_manifest_for_audit

        manifest = openssf_manifest_for_audit(repo_root, kit_manifest, lookup_key=None)
    except (FileNotFoundError, ValueError):
        manifest = {}
    host_probes = compile_db_host_probe_cache(repo_root)
    cross_probes_by_db = compile_db_cross_probe_caches(repo_root)
    cross_probe_union: dict[str, bool] = {}
    for cache in cross_probes_by_db.values():
        cross_probe_union.update(cache)
    audited = 0
    host_native = 0
    cross_compile = 0
    for source in source_paths:
        if source.suffix.lower() not in _COMPILE_SUFFIXES:
            continue
        lookup_key = source_key(source, repo_root)
        if lookup_key is None:
            lookup_key = str(source.resolve())
        entry = entries_by_key.get(lookup_key)
        if entry is None:
            continue
        audited += 1
        if _compile_db_audit_cross_context(lookup_key, entry_command(entry), repo_root=repo_root):
            cross_compile += 1
        else:
            host_native += 1
    return CompileDbOpenssfAuditScope(
        audited_cc_files=audited,
        host_native_files=host_native,
        cross_compile_files=cross_compile,
        host_audit_flag_count=len(
            compile_db_audit_flags_for_context(
                manifest,
                cross_compile=False,
                probe_cache=host_probes,
                language="C",
                command="",
                build_type="Release",
            )[0]
        ),
        cross_audit_flag_count=len(
            compile_db_audit_flags_for_context(
                manifest,
                cross_compile=True,
                probe_cache=cross_probe_union,
                language="C",
                command="",
                build_type=None,
            )[0]
        ),
    )


def format_compile_db_openssf_audit_ok(scope: CompileDbOpenssfAuditScope) -> list[str]:
    return [
        f"OK — {scope.audited_cc_files} scan C/C++ file(s) "
        f"({scope.host_native_files} host-native, {scope.cross_compile_files} cross-compile)",
        "scope: all scan.source_roots; probe-gated anchors from host/firmware CMakeCache",
        f"flag anchors: up to {scope.host_audit_flag_count} (host-native) / "
        f"{scope.cross_audit_flag_count} (cross-compile) per entry",
    ]


def scan_repo(
    repo_root: Path,
    lint_kit: Path,
    *,
    source_paths: list[Path],
    cmake_paths: list[Path],
    audit_links: bool = True,
) -> list[str]:
    config = hardening_config(repo_root)
    try:
        kit_manifest = load_hardening_manifest(lint_kit)
        from policy_overrides import openssf_manifest_for_audit

        # Global openssf-hardening dials apply to coverage-driven cmake checks too.
        manifest = openssf_manifest_for_audit(repo_root, kit_manifest, lookup_key=None)
    except FileNotFoundError as exc:
        return [str(exc)]

    issues: list[str] = []
    issues.extend(verify_consumer_cmake_modules(repo_root, manifest))
    issues.extend(
        verify_hardening_include_wiring(
            repo_root, kit_manifest, cmake_paths=cmake_paths
        )
    )
    issues.extend(verify_cmake_roots(repo_root, config))
    issues.extend(
        verify_cxx_hardening_adoption(
            repo_root,
            config,
            source_paths=source_paths,
            cmake_paths=cmake_paths,
        )
    )
    issues.extend(verify_target_hardening_links(repo_root, config, cmake_paths=cmake_paths))
    issues.extend(verify_genex_gating(repo_root, manifest))
    issues.extend(verify_hardening_flags(repo_root, manifest, config))
    issues.extend(verify_hardening_uniformity(repo_root, manifest, config))
    issues.extend(
        verify_consumer_hardening_no_unlisted_flags(
            repo_root, manifest, kit_manifest=kit_manifest
        )
    )
    issues.extend(verify_system_include_policy(repo_root, cmake_paths=cmake_paths))
    issues.extend(verify_sanitizer_before_hardening(repo_root, cmake_paths=cmake_paths))
    if audit_links:
        issues.extend(verify_userspace_link_txt_openssf(repo_root, lint_kit, kit_manifest))
    return issues


def _synthetic_genex_for_flag(flag: str, gate_requires: list[str]) -> str:
    conditions: list[str] = []
    markers = set(gate_requires)
    if "CMAKE_CROSSCOMPILING" in markers:
        conditions.append("$<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>")
    fortify_cfgs = {"CONFIG:Release", "CONFIG:RelWithDebInfo", "CONFIG:MinSizeRel"}
    if len(fortify_cfgs & markers) >= 2 or fortify_cfgs <= markers:
        conditions.append("${_hardening_fortify_cfg}")
    elif "CONFIG:RelWithDebInfo" in markers:
        conditions.append("${_hardening_relwithdebinfo_cfg}")
    elif "CONFIG:Release" in markers or "CONFIG:MinSizeRel" in markers:
        conditions.append("${_hardening_fortify_cfg}")
    if "CONFIG:Production" in markers:
        conditions.append("${_hardening_production_cfg}")
    if "CONFIG:Debug" in markers:
        conditions.append("${_hardening_debug_cfg}")
    if "NOT_INSTRUMENTED_SANITIZER" in markers:
        conditions.append("$<NOT:$<BOOL:${HAVE_INSTRUMENTED_SANITIZER}>>")
    if "NOT_FHARDENED" in markers:
        conditions.append("$<NOT:$<BOOL:${HAVE_C_FHARDENED}>>")
    if "TARGET_PROPERTY:TYPE" in markers and "EXECUTABLE" in markers:
        conditions.append("$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>")
    if "TARGET_PROPERTY:TYPE" in markers and "SHARED_LIBRARY" in markers:
        conditions.append(
            "$<OR:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>,"
            "$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>>"
        )
    if not conditions:
        return flag
    if len(conditions) == 1:
        condition = conditions[0]
    else:
        condition = "$<AND:" + ",".join(conditions) + ">"
    return f"$<{condition}:{flag}>"


_O2_PROBE_FLAGS = frozenset(
    {
        "-fzero-init-padding-bits=all",
        "-fzero-init-padding-bits=union",
        "-fhardened",
        "-Whardened",
    }
)

_KIT_GENERATED_CMAKE_FILES = ("Hardening.cmake", "CompilerHardeningProbes.cmake")

# Matches Hardening.cmake and Hardening.by-<slug>.cmake includes.
HARDENING_MODULE_INCLUDE_RE = re.compile(
    r"include\s*\([^)\n]*?(?P<name>Hardening(?:\.by-[A-Za-z0-9_.-]+)?\.cmake)",
    re.IGNORECASE,
)


def _coverage_flag_list(manifest: dict[str, Any]) -> list[str]:
    """Dialed coverage flags in manifest order (not sorted)."""
    return [str(flag) for flag in _coverage_block(manifest).get("flags", []) if flag]


def _coverage_definition_list(manifest: dict[str, Any]) -> list[str]:
    """Dialed coverage definitions in manifest order (not sorted)."""
    return [str(item) for item in _coverage_block(manifest).get("definitions", []) if item]


def _coverage_flag_set(manifest: dict[str, Any]) -> set[str]:
    return set(_coverage_flag_list(manifest))


def _coverage_definition_set(manifest: dict[str, Any]) -> set[str]:
    return set(_coverage_definition_list(manifest))


# Mutually exclusive libc++ hardening modes — never emit more than one in flat Make.
_LIBCPP_HARDENING_MODE_DEFS = frozenset(
    {
        "_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
        "_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE",
        "_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG",
    }
)


def _language_compile_flag_names(manifest: dict[str, Any], language: str) -> set[str]:
    """Bare compile flag names from cmake.common + cmake.<language> (no link tokens)."""
    required, probe_gated, genex_gated, _defs = _resolve_flag_requirements(manifest, language)
    names: set[str] = set()
    for flag in required:
        if flag in ("-pie", "-shared") or flag.startswith("LINKER:"):
            continue
        names.add(flag)
    for flag, _probe in probe_gated:
        if flag in ("-pie", "-shared") or flag.startswith("LINKER:"):
            continue
        names.add(flag)
    for flag, _gate in genex_gated:
        if flag in ("-pie", "-shared") or flag.startswith("LINKER:"):
            continue
        names.add(flag)
    return names


def _ordered_language_coverage_flags(manifest: dict[str, Any], language: str) -> list[str]:
    """Coverage flags for one language, preserving coverage.flags order.

    Flags declared by the kit keep their C/CXX scope. Consumer-added flags that
    have no kit language metadata apply to both languages.
    """
    lang_flags = _language_compile_flag_names(manifest, language)
    known_flags = _language_compile_flag_names(
        manifest, "C"
    ) | _language_compile_flag_names(manifest, "CXX")
    return [
        flag
        for flag in _coverage_flag_list(manifest)
        if (flag in lang_flags or flag not in known_flags)
        and flag not in {"-pie", "-shared"}
        and not flag.startswith("LINKER:")
    ]


def _ordered_make_definitions(manifest: dict[str, Any]) -> list[str]:
    """Flat Make definitions; omit exclusive ``_LIBCPP_HARDENING_MODE`` (CONFIG genex only)."""
    out: list[str] = []
    for definition in _coverage_definition_list(manifest):
        if definition in _LIBCPP_HARDENING_MODE_DEFS:
            continue
        out.append(definition)
    return out


def _hash_license_comment_lines(repo_root: Path) -> list[str]:
    """``#``-comment license lines from consumer ``license_header`` (required)."""
    import spdx_headers as spdx

    spdx.configure_from_manifest(repo_root)
    return spdx._expected_comment_lines(spdx._year(), "#")


def _openssf_generated_preamble(repo_root: Path, note_lines: list[str]) -> str:
    """Consumer ``license_header`` (hash comments) + generation notes for cmake/mk emits."""
    parts = list(_hash_license_comment_lines(repo_root))
    parts.append("#")
    for line in note_lines:
        parts.append("#" if line == "" else f"# {line}")
    parts.append("#")
    return "\n".join(parts) + "\n"


def _dial_note_lines(dial_note: str | None, default_lines: list[str]) -> list[str]:
    if dial_note is None:
        return list(default_lines)
    lines: list[str] = []
    for index, raw in enumerate(dial_note.split("\n")):
        if index > 0 and raw.startswith("# "):
            lines.append(raw[2:])
        elif index > 0 and raw == "#":
            lines.append("")
        else:
            lines.append(raw)
    return lines


def generate_hardening_cmake(
    manifest: dict[str, Any],
    *,
    repo_root: Path,
    dial_note: str | None = None,
) -> str:
    """Synthesize ``Hardening.cmake`` emitting only dialed ``coverage`` tokens.

    ``manifest`` must already have ``coverage.flags`` / ``definitions`` dialed (global
    and/or by_compile_db). Kit undialed manifest ⇒ FULL emit.

    C compile options come from cmake.C (+ common); CXX from cmake.CXX (+ common).
    Preamble is the consumer ``license_header`` from ``repo_root``.
    """
    covered_flags = _coverage_flag_set(manifest)
    covered_defs = _coverage_definition_set(manifest)
    arch_keyed = _compile_arch_keyed_flags(manifest)
    arch_flag_set = {flag for flags in arch_keyed.values() for flag in flags}
    note_lines = _dial_note_lines(
        dial_note,
        [
            "Generated from config/openssf-hardening-manifest.yaml — do not hand-edit.",
            "Sync via policy.overrides.openssf-hardening (fail-on-change rewrite).",
        ],
    )
    lines = [
        _openssf_generated_preamble(repo_root, note_lines),
        "include(${CMAKE_CURRENT_LIST_DIR}/CompilerHardeningProbes.cmake)\n",
        "include(CMakeParseArguments)\n",
        "function(define_hardening)\n",
        '  cmake_parse_arguments(HARDENING "" "TARGET;C_STANDARD;CXX_STANDARD" "" ${ARGN})\n',
        "  if(NOT HARDENING_TARGET)\n",
        '    message(FATAL_ERROR "define_hardening requires TARGET")\n',
        "  endif()\n",
        '  if(TARGET "${HARDENING_TARGET}")\n',
        "    return()\n",
        "  endif()\n",
        '  add_library("${HARDENING_TARGET}" INTERFACE)\n',
        "  set(_hardening_host $<NOT:$<BOOL:${CMAKE_CROSSCOMPILING}>>)\n",
        "  set(_hardening_fortify_cfg $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>)\n",
        "  set(_hardening_production_cfg $<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>)\n",
        "  set(_hardening_relwithdebinfo_cfg $<CONFIG:RelWithDebInfo>)\n",
        "  set(_hardening_debug_cfg $<CONFIG:Debug>)\n",
    ]
    compile_by_lang: dict[str, set[str]] = {"C": set(), "CXX": set()}
    link_flags: set[str] = set()
    definitions: set[str] = set()

    for language in ("C", "CXX"):
        required, probe_gated, genex_gated, definitions_genex_gated = _resolve_flag_requirements(
            manifest, language
        )
        for flag in required:
            if flag not in covered_flags:
                continue
            # compile_arch flags are emitted host+arch-gated below (not ungated on cross).
            if flag in arch_flag_set:
                continue
            if flag in ("-pie", "-shared") or flag.startswith("LINKER:"):
                link_flags.add(flag)
            else:
                compile_by_lang[language].add(flag)
        for flag, probe in probe_gated:
            if flag not in covered_flags:
                continue
            gated = f"$<$<BOOL:${{{probe}}}>:{flag}>"
            if flag in ("-pie", "-shared") or flag.startswith("LINKER:"):
                link_flags.add(gated)
            else:
                compile_by_lang[language].add(gated)
        for flag, gate_requires in genex_gated:
            if flag not in covered_flags:
                continue
            gated = _synthetic_genex_for_flag(flag, gate_requires)
            if flag in ("-pie", "-shared") or flag.startswith("LINKER:"):
                link_flags.add(gated)
            else:
                compile_by_lang[language].add(gated)
        for definition, gate_requires in definitions_genex_gated:
            if definition not in covered_defs:
                continue
            definitions.add(_synthetic_genex_for_flag(definition, gate_requires))

        for arch_key, flags in arch_keyed.items():
            for flag in flags:
                if flag not in covered_flags:
                    continue
                if flag in ("-pie", "-shared") or flag.startswith("LINKER:"):
                    continue
                compile_by_lang[language].add(_arch_gated_compile_genex(arch_key, flag))

    known_compile_flags = _language_compile_flag_names(
        manifest, "C"
    ) | _language_compile_flag_names(manifest, "CXX")
    consumer_added_compile_flags = [
        flag
        for flag in _coverage_flag_list(manifest)
        if flag not in known_compile_flags
        and flag not in {"-pie", "-shared"}
        and not flag.startswith("LINKER:")
    ]
    for language in ("C", "CXX"):
        compile_by_lang[language].update(consumer_added_compile_flags)

    known_definitions: set[str] = set()
    for language in ("C", "CXX"):
        _required, _probe_gated, _genex_gated, language_definitions = (
            _resolve_flag_requirements(manifest, language)
        )
        known_definitions.update(
            definition for definition, _gate in language_definitions if definition
        )
    definitions.update(
        definition
        for definition in _coverage_definition_list(manifest)
        if definition not in known_definitions
        and definition not in _LIBCPP_HARDENING_MODE_DEFS
    )

    for language in ("C", "CXX"):
        compile_flags = compile_by_lang[language]
        if not compile_flags:
            continue
        lines.append('  target_compile_options("${HARDENING_TARGET}" INTERFACE\n')
        for flag in sorted(compile_flags):
            lines.append(f"    $<$<COMPILE_LANGUAGE:{language}>:{flag}>\n")
        lines.append("  )\n")

    if link_flags:
        lines.append('  target_link_options("${HARDENING_TARGET}" INTERFACE\n')
        for flag in sorted(link_flags):
            if flag.startswith("$<") or flag in ("-pie", "-shared"):
                lines.append(f"    {flag}\n")
            else:
                lines.append(f'    "{flag}"\n')
        lines.append("  )\n")

    if definitions:
        lines.append('  target_compile_definitions("${HARDENING_TARGET}" INTERFACE\n')
        for definition in sorted(definitions):
            lines.append(f"    {definition}\n")
        lines.append("  )\n")

    lines.append("endfunction()\n")
    return "".join(lines)


def generate_hardening_flags_mk(
    manifest: dict[str, Any],
    *,
    repo_root: Path,
    dial_note: str | None = None,
    compile_commands_json: str | None = None,
) -> str:
    """Flat Make fragment of dialed OpenSSF compile flags for Arduino / non-CMake firmware.

    Preserves ``coverage.flags`` / ``definitions`` order. CFLAGS come from cmake.C
    (+ common); CXXFLAGS from cmake.CXX (+ common). Mutually exclusive
    ``_LIBCPP_HARDENING_MODE`` definitions are omitted (CONFIG genex only works in CMake).
    Preamble is the consumer ``license_header`` from ``repo_root``.
    """
    c_flags = _ordered_language_coverage_flags(manifest, "C")
    cxx_flags = _ordered_language_coverage_flags(manifest, "CXX")
    covered_defs = _ordered_make_definitions(manifest)
    cppflags = []
    for definition in covered_defs:
        if definition.startswith("-D"):
            cppflags.append(definition)
        else:
            cppflags.append(f"-D{definition}")
    default_notes = [
        "Generated from kit openssf-hardening-manifest + dials — do not hand-edit.",
        "Arduino / Make consumers: include this file and append to build.extra_flags",
        "(or equivalent), e.g. NFC_BUILD_EXTRA_FLAGS += $(NERO_OPENSSF_CFLAGS)",
    ]
    if compile_commands_json and dial_note is None:
        default_notes[0] = (
            "Generated from kit openssf-hardening-manifest + dials for "
            f"{compile_commands_json} — do not hand-edit."
        )
    note_lines = _dial_note_lines(dial_note, default_notes)
    cflags = " ".join(c_flags)
    cxxflags = " ".join(cxx_flags)
    defs = " ".join(cppflags)
    return (
        _openssf_generated_preamble(repo_root, note_lines)
        + f"NERO_OPENSSF_CFLAGS := {cflags}\n"
        + f"NERO_OPENSSF_CXXFLAGS := {cxxflags}\n"
        + f"NERO_OPENSSF_CPPFLAGS := {defs}\n"
    )


def generate_probes_cmake(manifest: dict[str, Any], *, repo_root: Path) -> str:
    """FULL OpenSSF ``CompilerHardeningProbes.cmake`` body from the kit manifest."""
    c_probes, cxx_probes, link_probes, arm_flag = _collect_synthetic_probe_groups(manifest)
    all_probes = sorted(_collect_manifest_probes(manifest))

    lines = [
        _openssf_generated_preamble(
            repo_root,
            [
                "Generated from config/openssf-hardening-manifest.yaml — do not hand-edit.",
                "Copy from .github/lint-c-cpp/cmake/; relax via policy.overrides.openssf-hardening.",
            ],
        ),
        "include(CheckCCompilerFlag)\n",
        "include(CheckCXXCompilerFlag)\n",
        "include(CheckLinkerFlag)\n",
        "\n",
        "set(HAVE_INSTRUMENTED_SANITIZER 0)\n",
        "foreach(_sanitizer_var IN ITEMS\n",
        "    CMAKE_C_FLAGS\n",
        "    CMAKE_CXX_FLAGS\n",
        "    CMAKE_C_FLAGS_DEBUG\n",
        "    CMAKE_CXX_FLAGS_DEBUG\n",
        "    CMAKE_C_FLAGS_RELWITHDEBINFO\n",
        "    CMAKE_CXX_FLAGS_RELWITHDEBINFO)\n",
        '  if(${_sanitizer_var} MATCHES "-fsanitize")\n',
        "    set(HAVE_INSTRUMENTED_SANITIZER 1)\n",
        "  endif()\n",
        "endforeach()\n\n",
    ]

    _append_compiler_probe_checks(lines, language="C", probes=c_probes)
    _append_compiler_probe_checks(lines, language="CXX", probes=cxx_probes)

    lines.extend(
        [
            "set(HAVE_ARM_BRANCH_PROTECTION_STANDARD 0)\n",
            "if(UNIX\n",
            "   AND NOT APPLE\n",
            '   AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|AArch64|arm64|ARM64)$")\n',
            "  if(CMAKE_C_COMPILER)\n",
            f"    check_c_compiler_flag({arm_flag} HAVE_ARM_BRANCH_PROTECTION_STANDARD)\n",
            "  elseif(CMAKE_CXX_COMPILER)\n",
            f"    check_cxx_compiler_flag({arm_flag} HAVE_ARM_BRANCH_PROTECTION_STANDARD)\n",
            "  endif()\n",
            "endif()\n\n",
        ]
    )

    lines.append("if(UNIX AND NOT APPLE)\n")
    for flag, probe in link_probes:
        lines.append(f'  check_linker_flag(C "{flag}" {probe})\n')
    if link_probes:
        lines.append("else()\n")
        for _, probe in link_probes:
            lines.append(f"  set({probe} 0)\n")
    lines.append("endif()\n\n")

    lines.append("mark_as_advanced(\n")
    for probe in all_probes:
        lines.append(f"  {probe}\n")
    lines.append("  HAVE_INSTRUMENTED_SANITIZER)\n")
    return "".join(lines)


def write_generated_hardening_cmake(
    path: Path,
    manifest: dict[str, Any],
    *,
    repo_root: Path,
    dial_note: str | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        generate_hardening_cmake(manifest, repo_root=repo_root, dial_note=dial_note),
        encoding="utf-8",
    )


def write_generated_probes_cmake(path: Path, manifest: dict[str, Any], *, repo_root: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_probes_cmake(manifest, repo_root=repo_root), encoding="utf-8")


def _normalize_generated_cmake(text: str) -> str:
    return text.replace("\r\n", "\n").strip() + "\n"


def _hardening_module_name_for_compile_json(repo_root: Path, compile_commands_json: str) -> str:
    """``Hardening.cmake`` or ``Hardening.by-<slug>.cmake`` for one compile DB path."""
    from policy_overrides import _by_compile_db_entries, compile_db_override_slug

    owner = Path(compile_commands_json).as_posix()
    for item in _by_compile_db_entries(repo_root, "openssf-hardening"):
        raw = item.get("compile_commands_json")
        if not isinstance(raw, str) or not raw.strip():
            continue
        if Path(raw.strip()).as_posix() == owner:
            return f"Hardening.by-{compile_db_override_slug(owner)}.cmake"
    return "Hardening.cmake"


def _expected_consumer_hardening_modules(
    repo_root: Path,
    kit_manifest: dict[str, Any],
) -> dict[str, str]:
    """Map consumer cmake basename → expected file body (dialed generate)."""
    from policy_overrides import (
        _by_compile_db_entries,
        apply_openssf_coverage_flag_overrides,
        compile_db_override_slug,
        global_override_dials,
        openssf_manifest_for_audit,
        override_dials_for_compile_db,
    )

    expected: dict[str, str] = {}
    global_add, global_remove = global_override_dials(repo_root, "openssf-hardening")
    if not global_add and not global_remove:
        expected["Hardening.cmake"] = generate_hardening_cmake(
            kit_manifest, repo_root=repo_root
        )
    else:
        global_manifest = openssf_manifest_for_audit(
            repo_root, kit_manifest, lookup_key=None
        )
        expected["Hardening.cmake"] = generate_hardening_cmake(
            global_manifest,
            repo_root=repo_root,
            dial_note=(
                "Generated from kit openssf-hardening-manifest + global "
                "policy.overrides.openssf-hardening — do not hand-edit."
            ),
        )
    expected["CompilerHardeningProbes.cmake"] = generate_probes_cmake(
        kit_manifest, repo_root=repo_root
    )

    for item in _by_compile_db_entries(repo_root, "openssf-hardening"):
        raw = item.get("compile_commands_json")
        if not isinstance(raw, str) or not raw.strip():
            continue
        compile_json = Path(raw.strip()).as_posix()
        add, remove = override_dials_for_compile_db(
            repo_root, "openssf-hardening", compile_json
        )
        dialed = apply_openssf_coverage_flag_overrides(
            kit_manifest, add=add, remove=remove
        )
        name = f"Hardening.by-{compile_db_override_slug(compile_json)}.cmake"
        expected[name] = generate_hardening_cmake(
            dialed,
            repo_root=repo_root,
            dial_note=(
                f"Generated from kit openssf-hardening-manifest + dials for "
                f"{compile_json} — do not hand-edit."
            ),
        )
        flags_name = f"Hardening.flags.by-{compile_db_override_slug(compile_json)}.mk"
        expected[flags_name] = generate_hardening_flags_mk(
            dialed,
            repo_root=repo_root,
            compile_commands_json=compile_json,
        )
    return expected


def _compile_json_for_cmake_root(repo_root: Path, cmake_rel: str) -> str | None:
    """Best-effort owning ``compile_commands_json`` for a Hardening-adopting CMakeLists."""
    from consumer_manifest import (
        compile_db_firmware_entries,
        compile_db_userspace_entries,
        firmware_compile_source_roots,
    )

    cmake_rel = Path(cmake_rel).as_posix()
    for entry in compile_db_userspace_entries(repo_root):
        source = str(entry.get("source") or "").strip().strip("/")
        if not source:
            continue
        if cmake_rel == f"{source}/CMakeLists.txt" or cmake_rel.startswith(f"{source}/"):
            return str(entry["compile_commands_json"])
    for entry in compile_db_firmware_entries(repo_root):
        source = str(entry.get("source") or "").strip().strip("/")
        if not source:
            continue
        if cmake_rel == f"{source}/CMakeLists.txt" or cmake_rel.startswith(f"{source}/"):
            return str(entry["compile_commands_json"])
    for root in firmware_compile_source_roots(repo_root):
        if cmake_rel == f"{root}/CMakeLists.txt" or cmake_rel.startswith(f"{root}/"):
            for entry in compile_db_firmware_entries(repo_root):
                entry_source = str(entry.get("source") or "").strip().strip("/")
                if entry_source == root:
                    return str(entry["compile_commands_json"])
            firmware = compile_db_firmware_entries(repo_root)
            if firmware:
                return str(firmware[0]["compile_commands_json"])
            break
    # Fallback: first userspace entry if any.
    userspace = compile_db_userspace_entries(repo_root)
    if userspace:
        return str(userspace[0]["compile_commands_json"])
    firmware = compile_db_firmware_entries(repo_root)
    if firmware:
        return str(firmware[0]["compile_commands_json"])
    return None


def _included_hardening_module_names(text: str) -> list[str]:
    return [match.group("name") for match in HARDENING_MODULE_INCLUDE_RE.finditer(text)]


def sync_kit_cmake_regen(
    repo_root: Path,
    lint_kit: Path,
    kit_manifest: dict[str, Any],
) -> list[str]:
    """Rewrite consumer OpenSSF cmake to dialed generate; fail-on-change if dirty.

    Same gate as license/yamllint/markdownlint: write in place, then ask to commit
    and re-run. Does not leave stale files as soft policy-only findings.

    Never rewrites ``lint_kit/cmake`` — the kit install is shared read-only for
    consumers; kit templates are updated only in the lint-c-cpp repo itself.
    """
    from format_fail_on_change import fail_on_change_error

    _ = lint_kit  # call-site compatibility; kit install is never mutated
    rewritten: list[str] = []
    consumer_dir = repo_root / _consumer_cmake_dir(kit_manifest)

    expected = _expected_consumer_hardening_modules(repo_root, kit_manifest)
    consumer_dir.mkdir(parents=True, exist_ok=True)
    for name, body in expected.items():
        consumer_path = consumer_dir / name
        expected_text = _normalize_generated_cmake(body)
        if not consumer_path.is_file() or _normalize_generated_cmake(
            consumer_path.read_text(encoding="utf-8")
        ) != expected_text:
            consumer_path.write_text(expected_text, encoding="utf-8")
            rewritten.append(consumer_path.relative_to(repo_root).as_posix())

    allowed = set(expected)
    if consumer_dir.is_dir():
        for path in sorted(consumer_dir.glob("Hardening.by-*.cmake")):
            if path.name not in allowed:
                rel = path.relative_to(repo_root).as_posix()
                path.unlink()
                rewritten.append(f"{rel} (removed)")
        for path in sorted(consumer_dir.glob("Hardening.flags.by-*.mk")):
            if path.name not in allowed:
                rel = path.relative_to(repo_root).as_posix()
                path.unlink()
                rewritten.append(f"{rel} (removed)")

    if not rewritten:
        return []
    detail = "rewrote OpenSSF cmake modules: " + ", ".join(rewritten)
    return [fail_on_change_error(detail)]


def verify_kit_cmake_regen(
    repo_root: Path,
    lint_kit: Path,
    kit_manifest: dict[str, Any],
) -> list[str]:
    """Compat alias: sync + fail-on-change (see ``sync_kit_cmake_regen``)."""
    return sync_kit_cmake_regen(repo_root, lint_kit, kit_manifest)


def _make_includes_hardening_flags_mk(repo_root: Path, flags_mk_name: str) -> bool:
    """True if Makefile or make/*.mk includes ``cmake/<flags_mk_name>``."""
    needles = (
        flags_mk_name,
        f"cmake/{flags_mk_name}",
        f"$(CURDIR)/cmake/{flags_mk_name}",
        f"${{CURDIR}}/cmake/{flags_mk_name}",
    )
    candidates: list[Path] = []
    makefile = repo_root / "Makefile"
    if makefile.is_file():
        candidates.append(makefile)
    make_dir = repo_root / "make"
    if make_dir.is_dir():
        candidates.extend(sorted(make_dir.glob("*.mk")))
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(needle in text for needle in needles):
            return True
    return False


def verify_hardening_include_wiring(
    repo_root: Path,
    kit_manifest: dict[str, Any],
    *,
    cmake_paths: list[Path],
) -> list[str]:
    """Fail closed: each Hardening adopter must include the dial module for its compile DB.

    Without this, dialed ``Hardening.by-<slug>.cmake`` files can exist while firmware/host
    still ``include(Hardening.cmake)`` — lint/files look correct, binaries keep wrong flags.

    Firmware ``by_compile_db`` entries may wire via CMake (``Hardening.by-*.cmake``) **or**
    Make (``Hardening.flags.by-*.mk``) for Arduino-style toolchains.
    """
    del kit_manifest
    from consumer_manifest import compile_db_firmware_entries, compile_db_userspace_entries
    from policy_overrides import _by_compile_db_entries, compile_db_override_slug

    if not compile_db_firmware_entries(repo_root) and not compile_db_userspace_entries(
        repo_root
    ):
        return []

    issues: list[str] = []
    repo_root = repo_root.resolve()
    cmake_included_by_db: dict[str, set[str]] = {}
    for cmake_path in cmake_paths:
        if not cmake_path.is_file():
            continue
        text = _strip_cmake_comments(
            cmake_path.read_text(encoding="utf-8", errors="replace")
        )
        included = _included_hardening_module_names(text)
        if not included and "define_hardening(" not in text:
            continue
        rel = cmake_path.relative_to(repo_root).as_posix()
        if "define_hardening(" in text and not included:
            issues.append(
                f"{rel}: define_hardening() without include of Hardening.cmake / "
                "Hardening.by-<slug>.cmake"
            )
            continue
        if not included:
            continue
        compile_json = _compile_json_for_cmake_root(repo_root, rel)
        if compile_json is None:
            issues.append(
                f"{rel}: cannot map CMakeLists to compile_db for Hardening include wiring"
            )
            continue
        expected = _hardening_module_name_for_compile_json(repo_root, compile_json)
        cmake_included_by_db.setdefault(Path(compile_json).as_posix(), set()).update(
            included
        )
        if expected not in included:
            issues.append(
                f"{rel}: must include cmake/{expected} for compile_db {compile_json} "
                f"(found {included!r}) — dialed Hardening modules are build ground truth, "
                "not lint-only"
            )
        # Using both plain + by-slug is ambiguous.
        if len(set(included)) > 1:
            issues.append(
                f"{rel}: include exactly one Hardening module (found {included!r})"
            )

    firmware_jsons = {
        Path(str(entry["compile_commands_json"])).as_posix()
        for entry in compile_db_firmware_entries(repo_root)
    }
    for item in _by_compile_db_entries(repo_root, "openssf-hardening"):
        raw = item.get("compile_commands_json")
        if not isinstance(raw, str) or not raw.strip():
            continue
        compile_json = Path(raw.strip()).as_posix()
        if compile_json not in firmware_jsons:
            continue
        slug = compile_db_override_slug(compile_json)
        by_cmake = f"Hardening.by-{slug}.cmake"
        by_mk = f"Hardening.flags.by-{slug}.mk"
        cmake_wired = by_cmake in cmake_included_by_db.get(compile_json, set())
        # Also accept any cmake path that included by_cmake even if mapped to another key
        # (multi-firmware DB edge); scan all collected includes.
        if not cmake_wired:
            cmake_wired = any(
                by_cmake in names for names in cmake_included_by_db.values()
            )
        make_wired = _make_includes_hardening_flags_mk(repo_root, by_mk)
        if not cmake_wired and not make_wired:
            issues.append(
                f"openssf-hardening.by_compile_db {compile_json}: wire build ground truth "
                f"via cmake/{by_cmake} (CMake/ESP-IDF) or include cmake/{by_mk} from "
                "Makefile/make/*.mk (Arduino)"
            )
    return issues


def _link_txt_needles(token: str) -> tuple[str, ...]:
    if token.startswith("LINKER:"):
        rest = token[len("LINKER:") :]
        return (token, f"-Wl,{rest}", rest)
    if token == "-pie":
        return ("-pie", "-Wl,-pie")
    if token == "-shared":
        return ("-shared",)
    return (token,)


def _link_txt_has_token(text: str, token: str) -> bool:
    return any(needle in text for needle in _link_txt_needles(token))


def _userspace_link_texts(build_dir: Path) -> list[tuple[str, str]]:
    """Return ``(label, text)`` link surfaces: Make ``link.txt`` and/or Ninja ``build.ninja``."""
    found: list[tuple[str, str]] = []
    for link_path in sorted(build_dir.glob("**/CMakeFiles/**/*.dir/link.txt")):
        try:
            found.append(
                (
                    link_path.relative_to(build_dir).as_posix(),
                    link_path.read_text(encoding="utf-8", errors="replace"),
                )
            )
        except OSError:
            continue
    if found:
        return found
    ninja = build_dir / "build.ninja"
    if ninja.is_file():
        try:
            found.append(
                (
                    "build.ninja",
                    ninja.read_text(encoding="utf-8", errors="replace"),
                )
            )
        except OSError:
            pass
    return found


def verify_userspace_link_txt_openssf(
    repo_root: Path,
    lint_kit: Path,
    kit_manifest: dict[str, Any],
) -> list[str]:
    """Require dialed link OpenSSF tokens in userspace link lines (Make or Ninja)."""
    del lint_kit
    from consumer_manifest import compile_db_userspace_entries
    from policy_overrides import override_dials_for_compile_db

    issues: list[str] = []
    entries = compile_db_userspace_entries(repo_root)
    if not entries:
        return issues

    for project in entries:
        build_dir = (repo_root / str(project["build_dir"])).resolve()
        compile_json = str(project.get("compile_commands_json") or "")
        add, remove = override_dials_for_compile_db(
            repo_root, "openssf-hardening", compile_json or None
        )
        dialed = apply_openssf_coverage_flag_overrides_local(
            kit_manifest, add=add, remove=remove
        )
        covered = _required_flag_names(dialed)
        link_tokens = sorted(
            token
            for token in covered
            if token.startswith("LINKER:") or token in {"-pie", "-shared"}
        )
        if not link_tokens:
            continue
        cache = build_dir / "CMakeCache.txt"
        if not cache.is_file():
            issues.append(
                f"OpenSSF link audit: configured userspace build "
                f"{build_dir.relative_to(repo_root)} has no CMakeCache.txt "
                "(configure the declared userspace project before auditing)"
            )
            continue
        link_texts = _userspace_link_texts(build_dir)
        if not link_texts:
            issues.append(
                f"OpenSSF link audit: configured userspace build "
                f"{build_dir.relative_to(repo_root)} has no CMakeFiles/**/link.txt "
                "or build.ninja (configure/build the userspace targets)"
            )
            continue
        for label, text in link_texts:
            shared = "-shared" in text
            missing: list[str] = []
            for token in link_tokens:
                if token == "-pie" and shared and label != "build.ninja":
                    continue
                if token == "-shared" and not shared:
                    continue
                if not _link_txt_has_token(text, token):
                    missing.append(token)
            if missing:
                rel = f"{build_dir.relative_to(repo_root).as_posix()}/{label}"
                issues.append(
                    f"OpenSSF link audit: {rel} missing {', '.join(missing)}"
                )
    return issues


def apply_openssf_coverage_flag_overrides_local(
    manifest: dict[str, Any],
    *,
    add: tuple[str, ...] | None,
    remove: tuple[str, ...] | None,
) -> dict[str, Any]:
    from policy_overrides import apply_openssf_coverage_flag_overrides

    return apply_openssf_coverage_flag_overrides(manifest, add=add, remove=remove)


def _write_synthetic_hardening_fixture(
    path: Path, manifest: dict[str, Any], *, repo_root: Path
) -> None:
    write_generated_hardening_cmake(path, manifest, repo_root=repo_root)


def _write_synthetic_probes_fixture(
    path: Path, manifest: dict[str, Any], *, repo_root: Path
) -> None:
    write_generated_probes_cmake(path, manifest, repo_root=repo_root)


def _collect_synthetic_probe_groups(
    manifest: dict[str, Any],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]], str]:
    c_probes: list[tuple[str, str]] = []
    cxx_probes: list[tuple[str, str]] = []
    link_probes: list[tuple[str, str]] = []
    arm_flag = "-mbranch-protection=standard"
    seen: set[str] = set()

    for language in ("C", "CXX"):
        _, probe_gated, _, _ = _resolve_flag_requirements(manifest, language)
        for flag, probe in probe_gated:
            if not probe or probe in seen:
                continue
            seen.add(probe)
            if probe == "HAVE_ARM_BRANCH_PROTECTION_STANDARD":
                arm_flag = flag
            elif probe.startswith("HAVE_LINK_"):
                link_probes.append((flag, probe))
            elif probe.startswith("HAVE_CXX_"):
                cxx_probes.append((flag, probe))
            else:
                c_probes.append((flag, probe))

    return c_probes, cxx_probes, link_probes, arm_flag


def _append_compiler_probe_checks(
    lines: list[str],
    *,
    language: str,
    probes: list[tuple[str, str]],
) -> None:
    check_fn = "check_c_compiler_flag" if language == "C" else "check_cxx_compiler_flag"
    fallback_assignments: list[str] = []

    lines.append(f"if(CMAKE_{language}_COMPILER)\n")
    for flag, probe in probes:
        if flag in _O2_PROBE_FLAGS:
            continue
        lines.append(f"  {check_fn}({flag} {probe})\n")

    o2_probes = [(flag, probe) for flag, probe in probes if flag in _O2_PROBE_FLAGS]
    if o2_probes:
        lines.append('  set(_lint_probe_save_flags "${CMAKE_REQUIRED_FLAGS}")\n')
        lines.append('  set(CMAKE_REQUIRED_FLAGS "-O2")\n')
        for flag, probe in o2_probes:
            lines.append(f"  {check_fn}({flag} {probe})\n")
        lines.append('  set(CMAKE_REQUIRED_FLAGS "${_lint_probe_save_flags}")\n')

    lines.append("else()\n")
    for _, probe in probes:
        fallback_assignments.append(f"  set({probe} 0)\n")
    lines.extend(fallback_assignments)
    lines.append("endif()\n\n")


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        kit = root / "kit"
        repo = root / "repo"
        kit.mkdir(parents=True)
        (repo / "cmake").mkdir(parents=True)
        (repo / "userspace").mkdir(parents=True)
        (repo / ".github").mkdir(parents=True)

        canonical = _DEFAULT_LINT_KIT
        manifest_src = canonical / "config" / "openssf-hardening-manifest.yaml"
        if not manifest_src.is_file():
            print(f"self-test miss: missing {manifest_src}", file=sys.stderr)
            return 1
        (kit / "config").mkdir(parents=True)
        (kit / "config" / "openssf-hardening-manifest.yaml").write_bytes(manifest_src.read_bytes())
        manifest = _load_yaml(manifest_src)

        good_cmake = """cmake_minimum_required(VERSION 3.20)
project(sample C)
include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Hardening.cmake")
define_hardening(
  TARGET hardening
  C_STANDARD 23)
add_library(core STATIC core.c)
target_link_libraries(core PUBLIC hardening)
"""
        (repo / "userspace" / "CMakeLists.txt").write_text(good_cmake, encoding="utf-8")
        (repo / ".github" / "lint-c-cpp.yaml").write_text(
            "license_header: |\n  # SPDX\n"
            "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
            "  public_headers_dir: include/sample\n"
            "  source_roots: [core, port, include, userspace, tests, esp-idf]\n"
            "compile_db:\n  firmware: []\n  userspace:\n"
            "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
            "      source: userspace\n"
            "policy:\n  constants_headers: [limits.h]\n"
            "  nolint_allowed: null\n"
            "  resource_lifetime: null\n"
            "  shared_c_cxx_source_roots: null\n"
            "  overrides:\n"
            "    clang-format: {add: null, remove: null, by_compile_db: null}\n"
            "    clang-tidy-c: {add: null, remove: null, by_compile_db: null}\n"
            "    clang-tidy-cxx: {add: null, remove: null, by_compile_db: null}\n"
            "    clang-tidy-shared-c-cxx: {add: null, remove: null, by_compile_db: null}\n"
            "    clang-tidy-unsafe-c: {add: null, remove: null, by_compile_db: null}\n"
            "    clang-tidy-unsafe-cxx: {add: null, remove: null, by_compile_db: null}\n"
            "    cppcheck: {add: null, remove: null, by_compile_db: null}\n"
            "    openssf-hardening: {add: null, remove: null, by_compile_db: null}\n"
            "enabled_lint_jobs:\n"
            "  - license\n"
            "  - yamllint\n"
            "  - markdownlint\n"
            "  - format\n"
            "  - openssf\n"
            "  - compile_db\n"
            "  - clang_tidy\n"
            "  - banned_cxx_heap\n"
            "  - banned_libc_io\n"
            "  - null_nodiscard\n"
            "  - relative_includes\n"
            "  - duplicate_includes\n"
            "  - shared_constant_dupes\n"
            "  - magic_literals\n"
            "  - guard_clause_style\n"
            "  - pointer_bounds\n"
            "  - raii_lifetime\n"
            "  - nolint_audit\n"
            "  - spec_traceability\n"
            "  - cppcheck\n"
            "  - firmware_compile_db\n"
            "firmware_build: null\n"
            "spec_traceability: null\n"
            "toolchain: null\n"
            "workflow: null\n"
            "yamllint: null\n",
            encoding="utf-8",
        )
        (kit / "cmake").mkdir(parents=True)
        write_generated_hardening_cmake(
            kit / "cmake" / "Hardening.cmake", manifest, repo_root=repo
        )
        write_generated_probes_cmake(
            kit / "cmake" / "CompilerHardeningProbes.cmake", manifest, repo_root=repo
        )
        write_generated_hardening_cmake(
            repo / "cmake" / "Hardening.cmake", manifest, repo_root=repo
        )
        write_generated_probes_cmake(
            repo / "cmake" / "CompilerHardeningProbes.cmake", manifest, repo_root=repo
        )
        synthetic_build = repo / "build" / "lint" / "userspace"
        synthetic_build.mkdir(parents=True)
        (synthetic_build / "CMakeCache.txt").write_text(
            "CMAKE_BUILD_TYPE:STRING=Release\n", encoding="utf-8"
        )
        synthetic_link_tokens = [
            token
            for token in _required_flag_names(manifest)
            if token.startswith("LINKER:") or token == "-pie"
        ]
        (synthetic_build / "build.ninja").write_text(
            "command = cc " + " ".join(synthetic_link_tokens) + "\n",
            encoding="utf-8",
        )

        def paths_for() -> tuple[list[Path], list[Path]]:
            return (
                central_scan_paths(JOB_SOURCE, repo_root=repo),
                central_scan_paths(JOB_CMAKE, repo_root=repo),
            )

        source_paths, cmake_paths = paths_for()
        if scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths):
            print("self-test miss: expected good repo to pass", file=sys.stderr)
            return 1

        bad = repo / "userspace" / "CMakeLists.txt"
        bad.write_text(good_cmake + "\nadd_library(obj OBJECT obj.c)\n", encoding="utf-8")
        if not any(
            "target 'obj' must transitively link 'hardening'" in issue
            for issue in scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths)
        ):
            print("self-test miss: expected unhardened OBJECT library rejection", file=sys.stderr)
            return 1

        bad.write_text(good_cmake + '\nadd_link_options(-pie "LINKER:-z,relro")\n', encoding="utf-8")
        if not any("raw -pie" in issue for issue in scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths)):
            print("self-test miss: expected duplicate -pie detection", file=sys.stderr)
            return 1

        legacy = bad.read_text(encoding="utf-8").replace("define_hardening", "define_host_hardening")
        bad.write_text(legacy, encoding="utf-8")
        if not any("define_host_hardening" in issue for issue in scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths)):
            print("self-test miss: expected legacy define_host_hardening rejection", file=sys.stderr)
            return 1

        (repo / "userspace" / "CMakeLists.txt").write_text(good_cmake, encoding="utf-8")
        stripped = (repo / "cmake" / "Hardening.cmake").read_text(encoding="utf-8").replace("-Wall", "")
        (repo / "cmake" / "Hardening.cmake").write_text(stripped, encoding="utf-8")
        if not any("missing OpenSSF flag '-Wall'" in issue for issue in scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths)):
            print("self-test miss: expected missing template flag detection", file=sys.stderr)
            return 1

        (repo / "userspace" / "CMakeLists.txt").write_text(good_cmake, encoding="utf-8")
        _write_synthetic_hardening_fixture(
            repo / "cmake" / "Hardening.cmake", manifest, repo_root=repo
        )

        bad_werror = good_cmake + "\nadd_compile_options(-Werror)\n"
        (repo / "userspace" / "CMakeLists.txt").write_text(bad_werror, encoding="utf-8")
        if not any("blanket -Werror must be on cmake/Hardening.cmake" in issue for issue in scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths)):
            print("self-test miss: expected duplicate blanket -Werror detection", file=sys.stderr)
            return 1

        (repo / "userspace" / "CMakeLists.txt").write_text(good_cmake, encoding="utf-8")

        (repo / "esp-idf" / "main").mkdir(parents=True)
        embedded_cmake = """cmake_minimum_required(VERSION 3.20)
idf_component_register(SRCS core.c)
include("${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Hardening.cmake")
define_hardening(
  TARGET hardening
  C_STANDARD 17)
target_link_libraries(${COMPONENT_LIB} PUBLIC hardening)
"""
        (repo / "esp-idf" / "main" / "CMakeLists.txt").write_text(embedded_cmake, encoding="utf-8")
        source_paths, cmake_paths = paths_for()
        if scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths):
            print("self-test miss: expected embedded + userspace roots to pass with probe-gated Hardening.cmake", file=sys.stderr)
            return 1

        ungated = (repo / "cmake" / "Hardening.cmake").read_text(encoding="utf-8") + "\n  -fPIE\n"
        (repo / "cmake" / "Hardening.cmake").write_text(ungated, encoding="utf-8")
        if not any("must use upstream CMake generator gating" in issue for issue in scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths)):
            print("self-test miss: expected ungated genex flag rejection", file=sys.stderr)
            return 1

        _write_synthetic_hardening_fixture(
            repo / "cmake" / "Hardening.cmake", manifest, repo_root=repo
        )
        embedded_bad = repo / "esp-idf" / "main" / "CMakeLists.txt"
        embedded_bad.write_text(embedded_cmake + '\nadd_compile_options(-fPIE)\n', encoding="utf-8")
        if not any("raw -fPIE in CMakeLists" in issue for issue in scan_repo(repo, kit, source_paths=source_paths, cmake_paths=cmake_paths)):
            print("self-test miss: expected raw -fPIE rejection in CMakeLists", file=sys.stderr)
            return 1

    print("hardeninglint self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_hardening_path_args(parser)
    parser.add_argument("--lint-kit", type=Path, dest="lint_kit")
    parser.add_argument(
        "--skip-link-audit",
        action="store_true",
        help="Run source/config checks without requiring configured link surfaces",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if args.paths_file is None or args.cmake_paths_file is None:
        parser.error("--paths-file and --cmake-paths-file are required (omit only for --self-test)")

    repo_root = args.repo_root.resolve()
    lint_kit = args.lint_kit
    if lint_kit is None:
        env_lint_kit = Path(str(__import__("os").environ.get("LINT_KIT", ""))).resolve()
        lint_kit = env_lint_kit if env_lint_kit.is_dir() else _DEFAULT_LINT_KIT
    lint_kit = lint_kit.resolve()

    source_paths = load_paths(args)
    cmake_paths = load_cmake_paths(args)
    try:
        kit_manifest = load_hardening_manifest(lint_kit)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Fail-on-change: rewrite dialed/kit OpenSSF cmake, then require commit + re-run.
    regen_issues = sync_kit_cmake_regen(repo_root, lint_kit, kit_manifest)
    if regen_issues:
        for issue in regen_issues:
            print(issue, file=sys.stderr)
        return 1

    issues = scan_repo(
        repo_root,
        lint_kit,
        source_paths=source_paths,
        cmake_paths=cmake_paths,
        audit_links=not args.skip_link_audit,
    )
    if not issues:
        try:
            from policy_overrides import openssf_manifest_for_audit

            manifest = openssf_manifest_for_audit(repo_root, kit_manifest, lookup_key=None)
            config = hardening_config(repo_root)
            issues.extend(verify_native_toolchain_probes(repo_root, manifest, config))
        except ValueError as exc:
            issues.append(str(exc))
    if issues:
        print("error: hardeninglint cmake policy violations:", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        return 1

    config = hardening_config(repo_root)
    _print_hardeninglint_cmake_ok(config)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
