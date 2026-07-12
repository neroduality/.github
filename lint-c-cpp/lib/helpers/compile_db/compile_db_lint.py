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
#
# Manifest-driven compile DB, cppcheck, and clang-tidy orchestration for lint.sh.

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_LINT_LIB = Path(__file__).resolve().parents[2]
_DEFAULT_LINT_KIT = _LINT_LIB.parent
if str(_LINT_LIB) not in sys.path:
    sys.path.insert(0, str(_LINT_LIB))
from lint_pythonpath import bootstrap as _bootstrap_lint_pythonpath

_bootstrap_lint_pythonpath()
from consumer_manifest import (
    clang_tidy_header_filter_regex,
    clang_tidy_header_filter_regex_for_overlay,
    clang_tidy_merge_build_dir,
    clang_tidy_overlays,
    clang_tidy_unsafe_overlays,
    compile_db_is_configured,
    compile_db_userspace_entries,
    cppcheck_cli_common_args,
    cppcheck_config,
    cxx_in_c_compatible_header_violations,
    iter_headers_for_role,
    load,
    resolve_scan_paths,
    verify_compile_db_cmake_coverage,
)
from scan_policy import (
    JOB_SOURCE,
    JOB_UNSAFE_API,
    SOURCE_SUFFIXES,
    bootstrap_scan_manifest,
    path_in_scan_scope,
    read_paths_file,
)
from compile_db_util import (
    MergedCompileDatabase,
    assert_compile_db_entries_in_scan_scope,
    cmake_generator,
    clang_target_for_command,
    compile_db_index_keys,
    compile_db_input_stats,
    compile_driver_path,
    compile_entry_preference,
    compile_file_repo_rel,
    compiler_target_triple,
    count_cc_paths_by_scan_source_root,
    entry_command,
    format_source_root_entry_counts,
    host_target_triple,
    is_cross_compile_command,
    load_richest_compile_entries,
    verify_required_compile_commands,
)
from repo_paths import source_key


_CONTAINER_PATH_PREFIXES = ("/src/", "/workspace/")
_FIRMWARE_COMPILE_DB_LABEL = "firmware compile"
_CPPCHECK_COMPILE_COMMANDS = "cppcheck.compile_commands.json"


def repo_relative_source(src: Path, repo_root: Path) -> Path | None:
    """Map an absolute compile-db path to a repo-relative path in scan scope."""
    rel = source_key(src, repo_root)
    if rel is None:
        return None
    rel_path = Path(rel)
    if not path_in_scan_scope(rel_path, repo_root):
        return None
    return rel_path


def clang_tidy_scan_targets(scan_paths: list[Path]) -> list[Path]:
    """Sorted C/C++ scan paths that must have compile-DB coverage (TUs + headers)."""
    return sorted(scan_paths)


# Direct clang-tidy inputs are real translation units only. Headers are still in
# compile-DB / OpenSSF scope and are reported via HeaderFilterRegex when a TU
# includes them. Analyzing ``.h`` as ``-x c-header`` breaks C++-in-``.h`` firmware
# headers and includer-macro APIs (``#error`` without the including TU's defines).
CLANG_TIDY_INPUT_SUFFIXES = frozenset({".c", ".cpp", ".cc", ".cxx"})


def clang_tidy_input_targets(scan_paths: list[Path]) -> list[Path]:
    """Sorted paths passed as clang-tidy argv (TUs only; headers via HeaderFilterRegex)."""
    return sorted(path for path in scan_paths if path.suffix in CLANG_TIDY_INPUT_SUFFIXES)


def _rewrite_missing_abs_path(path_str: str, response_file: Path) -> str:
    """Map a missing foreign absolute path onto the tree that owns ``response_file``.

    Bind-mounted CI often rebases ``@cflags`` to ``/src/...`` while the file body
    still embeds the host checkout prefix (``-specs=/home/.../picolibc.specs``).
    Without repair, ``gcc -E -v -specs=...`` fails and cross scrub drops picolibc
    ``-isystem`` order — clang then parses newlib ``stdio.h`` and breaks ``_REENT``.
    """
    path = Path(path_str)
    if not path.is_absolute() or path.exists():
        return path_str
    parts = path.parts
    # Skip the root component (``/`` or ``C:\\``) when building suffixes.
    for start in range(1, len(parts)):
        suffix = parts[start:]
        if not suffix:
            continue
        for parent in response_file.resolve().parents:
            candidate = parent.joinpath(*suffix)
            if candidate.exists():
                return str(candidate)
    return path_str


def _repair_response_token(token: str, response_file: Path) -> str:
    """Rewrite missing absolute paths inside one expanded response-file token."""
    # Longest joined prefixes first so ``-isystem/path`` wins over ``-I``.
    for prefix in (
        "-isystem",
        "-idirafter",
        "-iquote",
        "-imacros",
        "-include",
        "-specs=",
        "--sysroot=",
        "-isysroot=",
        "-I",
    ):
        if not token.startswith(prefix):
            continue
        value = token[len(prefix) :]
        if not value or not value.startswith("/"):
            return token
        repaired = _rewrite_missing_abs_path(value, response_file)
        return prefix + repaired if repaired != value else token
    if token.startswith("/") and not Path(token).exists():
        return _rewrite_missing_abs_path(token, response_file)
    return token


def _expand_at_response_tokens(tokens: list[str]) -> list[str]:
    """Expand GCC/arduino ``@file`` response files into the token stream.

    Arduino Renesas (and similar) platforms put FSP/BSP ``-iwithprefixbefore``
    include paths and variant ``-D`` defines in ``@includes.txt`` / ``@defines.txt``.
    Those must be expanded before clang-tidy scrubbing — dropping ``@file`` leaves
    headers like ``bsp_api.h`` unresolved.

    Absolute paths inside the response body are repaired against the response
    file's real tree when the embedded prefix is stale (host path under ``/src``).
    """
    out: list[str] = []
    for token in tokens:
        if not (token.startswith("@") and len(token) > 1):
            out.append(token)
            continue
        path = Path(token[1:])
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        nested: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            nested.extend(
                _repair_response_token(part, path) for part in shlex.split(stripped)
            )
        out.extend(_expand_at_response_tokens(nested))
    return out


def _materialize_iprefix_flags(tokens: list[str]) -> list[str]:
    """Resolve ``-iprefix`` + ``-iwithprefix{,before}`` into plain ``-I`` paths.

    clang understands these flags, but materializing to ``-I`` keeps synthesis /
    scrub output uniform with the rest of the compile DB and avoids depending on
    ``-iprefix`` state surviving across token filters.
    """
    prefix = ""
    out: list[str] = []
    skip_next = False

    def _take_joined_or_next(flag: str, token: str, index: int) -> tuple[str, bool]:
        if token == flag:
            if index + 1 < len(tokens):
                return tokens[index + 1], True
            return "", True
        return token[len(flag) :], False

    for index, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if token == "-iprefix" or token.startswith("-iprefix"):
            value, skip_next = _take_joined_or_next("-iprefix", token, index)
            prefix = value
            continue
        if token == "-iwithprefixbefore" or token.startswith("-iwithprefixbefore"):
            rel, skip_next = _take_joined_or_next("-iwithprefixbefore", token, index)
            if prefix and rel:
                out.append(f"-I{prefix}{rel}" if rel.startswith("/") else f"-I{prefix}/{rel}")
            continue
        if token == "-iwithprefix" or token.startswith("-iwithprefix"):
            # Must check after -iwithprefixbefore (prefix of this name).
            rel, skip_next = _take_joined_or_next("-iwithprefix", token, index)
            if prefix and rel:
                out.append(f"-I{prefix}{rel}" if rel.startswith("/") else f"-I{prefix}/{rel}")
            continue
        out.append(token)
    return out


def _normalize_compile_tokens(tokens: list[str]) -> list[str]:
    """Expand ``@file`` response files and materialize ``-iprefix`` includes."""
    return _materialize_iprefix_flags(_expand_at_response_tokens(tokens))


def _extract_compile_flags(command: str) -> list[str]:
    """Keep defines/includes plus driver search flags needed for cross scrub isystem order.

    ``-specs=`` / ``-march=`` / ``-mabi=`` must survive synthesis (headers) so
    ``compiler -E -v`` sees picolibc/newlib the same way as real firmware TUs.
    """
    if not command.strip():
        return []
    tokens = _normalize_compile_tokens(shlex.split(command))
    keep: list[str] = []
    skip_next = False
    skip_pairs = frozenset(
        {
            "-I",
            "-D",
            "-isystem",
            "-include",
            "-imacros",
            "-iquote",
            "-idirafter",
            "-o",
            "-MF",
            "-MT",
            "-MQ",
        }
    )
    search_prefixes = ("-specs=", "-march=", "-mabi=")
    for index, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if token in ("-c", "-E", "-S", "-M", "-MM", "-MD", "-MMD"):
            continue
        if token.startswith(search_prefixes):
            keep.append(token)
            continue
        if token in skip_pairs:
            if index + 1 < len(tokens):
                keep.extend([token, tokens[index + 1]])
                skip_next = True
            continue
        if token.startswith(("-I", "-D", "-include", "-isystem", "-iquote")):
            keep.append(_repair_define_token(token) if token.startswith("-D") else token)
    return keep


def _language_kind(suffix: str) -> str:
    if suffix in {".h", ".c"}:
        return "c"
    return "cxx"


def _target_repo_rel(target: Path, repo_root: Path) -> Path | None:
    rel = source_key(target, repo_root)
    return Path(rel) if rel is not None else None


def _target_prefers_firmware_template(target: Path, repo_root: Path) -> bool:
    rel = _target_repo_rel(target, repo_root)
    if rel is None:
        return False
    try:
        from consumer_manifest import firmware_compile_source_roots

        roots = firmware_compile_source_roots(repo_root)
    except Exception:
        roots = ()
    rel_posix = rel.as_posix()
    return any(rel_posix == r or rel_posix.startswith(f"{r}/") for r in roots)


def _template_for_target(
    by_file: dict[str, dict],
    target: Path,
    repo_root: Path,
    *,
    host_templates: tuple[dict, ...] | None = None,
    cross_templates: tuple[dict, ...] | None = None,
) -> dict | None:
    target = target.resolve()
    repo_root = repo_root.resolve()
    if host_templates is None:
        host_templates = MergedCompileDatabase.host_template_pool(by_file, repo_root)
    if cross_templates is None:
        cross_templates = MergedCompileDatabase.cross_template_pool(by_file, repo_root)
    storage_key = source_key(target, repo_root)
    if storage_key is not None and storage_key in by_file:
        existing = by_file[storage_key]
        # Host unit-test rows for firmware paths must not be used as the tidy template.
        if not (
            _target_prefers_firmware_template(target, repo_root)
            and cross_templates
            and not is_cross_compile_command(entry_command(existing))
        ):
            return existing
    rel = _target_repo_rel(target, repo_root)
    same_dir = [
        entry
        for key, entry in by_file.items()
        if Path(key).parent == (rel or Path()).parent
    ]
    # Firmware scan roots must inherit a cross/arduino template. Host unit-test compile
    # entries often share the same directory (tests compile firmware/*.cpp on the host) and
    # would otherwise win via same_dir + host-preferring compile_entry_preference — leaving
    # synthesized firmware headers/TUs without Arduino.h / board -D defines.
    if _target_prefers_firmware_template(target, repo_root) and cross_templates:
        same_dir_cross = [
            entry
            for entry in same_dir
            if is_cross_compile_command(entry_command(entry))
        ]
        if same_dir_cross:
            return min(same_dir_cross, key=compile_entry_preference)
        return min(cross_templates, key=compile_entry_preference)
    if same_dir:
        return min(same_dir, key=compile_entry_preference)
    root_prefix = rel.parts[0] if rel is not None and rel.parts else None
    if root_prefix is not None:
        matches: list[dict] = []
        for key, entry in by_file.items():
            if Path(key).parts and Path(key).parts[0] == root_prefix:
                matches.append(entry)
        if matches:
            return min(matches, key=compile_entry_preference)
    if target.suffix == ".h":
        from scan_policy import public_headers_dir as scan_public_headers_dir

        prefix_parts = Path(scan_public_headers_dir(repo_root)).parts
        rel_parts = rel.parts if rel is not None else ()
        if rel_parts[: len(prefix_parts)] == prefix_parts and host_templates:
            return min(host_templates, key=compile_entry_preference)
    candidates = list(by_file.values())
    if not candidates:
        return None
    return min(candidates, key=compile_entry_preference)


def _template_for_cppcheck(
    host_templates: tuple[dict, ...],
    target: Path,
    repo_root: Path,
) -> dict | None:
    """Host CMake template only (no cross-compile / vendor -I paths for cppcheck)."""
    if not host_templates:
        return None
    repo_root = repo_root.resolve()
    rel = _target_repo_rel(target, repo_root)
    if rel is not None:
        same_dir = [
            entry
            for entry in host_templates
            if Path(str(entry.get("file", ""))).parent == rel.parent
            or (
                source_key(entry.get("file", ""), repo_root) is not None
                and Path(source_key(entry.get("file", ""), repo_root) or "").parent == rel.parent
            )
        ]
        if same_dir:
            return min(same_dir, key=compile_entry_preference)
        if rel.parts:
            prefix = rel.parts[0]
            matches = [
                entry
                for entry in host_templates
                if (key := source_key(entry.get("file", ""), repo_root)) is not None
                and Path(key).parts
                and Path(key).parts[0] == prefix
            ]
            if matches:
                return min(matches, key=compile_entry_preference)
    return min(host_templates, key=compile_entry_preference)


def _define_flags_from_command(command: str) -> list[str]:
    """Extract ``-D`` / ``-DNAME=value`` tokens (keep board/frontend macros for cppcheck)."""
    flags = _extract_compile_flags(command)
    out: list[str] = []
    skip_next = False
    for index, token in enumerate(flags):
        if skip_next:
            skip_next = False
            continue
        if token == "-D" and index + 1 < len(flags):
            out.extend([token, flags[index + 1]])
            skip_next = True
            continue
        if token.startswith("-D"):
            out.append(token)
    return out


def _compile_entry_for_cppcheck(
    repo_root: Path,
    target: Path,
    db: MergedCompileDatabase,
    include_dirs: list[str],
) -> dict | None:
    entry = db.entry_for(target)
    if entry is None:
        return None
    command = entry_command(entry)
    if is_cross_compile_command(command):
        template = _template_for_cppcheck(db.host_templates, target, repo_root)
        synthesized = _synthesize_compile_entry(repo_root, target, template, include_dirs)
        define_flags = _define_flags_from_command(command)
        if define_flags:
            tokens = shlex.split(synthesized["command"])
            if tokens:
                synthesized["command"] = shlex.join(
                    [tokens[0], *define_flags, *tokens[1:]]
                )
        return synthesized
    return dict(entry)


def ensure_firmware_compile_commands(repo_root: Path) -> int:
    """Run manifest ``compile_db.firmware`` build commands when compile_commands are missing."""
    from consumer_manifest import compile_db_firmware_entries

    repo_root = repo_root.resolve()
    entries = compile_db_firmware_entries(repo_root)
    if not entries:
        return 0

    up_to_date = True
    for entry in entries:
        path = (repo_root / str(entry["compile_commands_json"])).resolve()
        commands = entry.get("commands", [])
        if not path.is_file() or len(commands) > 1:
            up_to_date = False
            break
    if up_to_date:
        print(
            f"compile database: {_FIRMWARE_COMPILE_DB_LABEL} OK (compile_commands up to date)",
            flush=True,
        )
        return 0

    built_paths = 0
    for index, entry in enumerate(entries):
        rel_compile_db = str(entry["compile_commands_json"])
        path = (repo_root / rel_compile_db).resolve()
        commands = entry.get("commands", [])
        missing = not path.is_file()
        if not missing and len(commands) <= 1:
            built_paths += 1
            continue
        if missing and not commands:
            print(
                "error: firmware compile_commands missing "
                f"({rel_compile_db}); set compile_db.firmware[{index}].commands in the manifest",
                file=sys.stderr,
            )
            return 1
        if not missing and len(commands) > 1:
            print(
                f"compile database: {_FIRMWARE_COMPILE_DB_LABEL}: "
                f"running {len(commands)} firmware build(s) for {rel_compile_db}",
                flush=True,
            )
        for cmd in commands:
            print(f"+ {cmd}", flush=True)
            if subprocess.run(cmd, cwd=repo_root, shell=True, check=False).returncode != 0:
                return 1
        if not path.is_file():
            print(
                f"error: {_FIRMWARE_COMPILE_DB_LABEL} finished but compile_commands still missing: "
                f"{rel_compile_db}",
                file=sys.stderr,
            )
            return 1
        built_paths += 1

    print(
        f"compile database: {_FIRMWARE_COMPILE_DB_LABEL} OK "
        f"({built_paths} compile_commands.json)",
        flush=True,
    )
    return 0


def _synthesize_compile_entry(
    repo_root: Path,
    target: Path,
    template: dict | None,
    include_dirs: list[str],
) -> dict:
    from consumer_manifest import header_role_for_path

    repo_root = repo_root.resolve()
    rel = source_key(target, repo_root)
    abs_file = str((repo_root / rel).resolve()) if rel is not None else str(target.resolve())
    suffix = target.suffix.lower()
    template_command = entry_command(template, shlex_args=True) if template is not None else ""
    template_tokens = (
        _normalize_compile_tokens(shlex.split(template_command)) if template_command else []
    )
    if suffix in {".h", ".hh", ".hpp", ".hxx"}:
        role = header_role_for_path(target, repo_root)
        if role == "cxx_only":
            lang = "-x c++-header"
            std = _std_flag_from_tokens(template_tokens, wants_cxx=True) or "-std=gnu++17"
            driver = "clang++"
        else:
            lang = "-x c-header"
            std = _std_flag_from_tokens(template_tokens, wants_cxx=False) or "-std=gnu11"
            driver = "clang"
    elif suffix == ".c":
        lang = "-x c"
        std = _std_flag_from_tokens(template_tokens, wants_cxx=False) or "-std=gnu11"
        driver = "clang"
    else:
        lang = "-x c++"
        std = _std_flag_from_tokens(template_tokens, wants_cxx=True) or "-std=gnu++17"
        driver = "clang++"

    flags: list[str] = [std, *lang.split()]
    if template is not None:
        if is_cross_compile_command(template_command):
            # Keep the cross GCC/G++ argv0 so scrub can query its sysroot/isystem.
            # Replacing with clang++ here makes scrub treat host clang as the driver.
            template_driver = compile_driver_path(template_command)
            if template_driver is not None:
                driver = str(template_driver)
            else:
                tokens = shlex.split(template_command)
                if tokens and not tokens[0].startswith("-"):
                    driver = tokens[0]
        flags.extend(_extract_compile_flags(template_command))
    parent = Path(abs_file).parent.resolve()
    seen = set(flags)
    for include in include_dirs:
        include_path = (repo_root / include).resolve()
        # Defer the TU directory until last so sketch wrappers that
        # ``#include <same_basename.c>`` resolve the canonical body first.
        if include_path == parent:
            continue
        flag = f"-I{repo_root / include}"
        if flag not in seen:
            flags.append(flag)
            seen.add(flag)
    parent_flag = f"-I{parent}"
    if parent_flag not in seen:
        flags.append(parent_flag)
    command = f"{driver} {' '.join(shlex.quote(flag) for flag in flags)} -c {shlex.quote(abs_file)}"
    return {
        "directory": str(repo_root),
        "command": command,
        "file": abs_file,
    }


def complete_compile_commands_for_scan_roots(
    repo_root: Path,
    by_file: dict[str, dict],
    *,
    scan_paths: list[Path],
    host_templates: tuple[dict, ...] | None = None,
    cross_templates: tuple[dict, ...] | None = None,
) -> int:
    """Ensure every scan.source_roots file has a compile_commands entry. Returns synthesize count."""
    repo_root = repo_root.resolve()
    load(repo_root)
    if host_templates is None:
        host_templates = MergedCompileDatabase.host_template_pool(by_file, repo_root)
    if cross_templates is None:
        cross_templates = MergedCompileDatabase.cross_template_pool(by_file, repo_root)
    include_dirs_raw = cppcheck_config(repo_root).get("include_dirs", [])
    include_dirs = [str(item) for item in include_dirs_raw if isinstance(item, str)]
    synthesized = 0
    for target in clang_tidy_scan_targets(scan_paths):
        storage_key = source_key(target, repo_root)
        if storage_key is None:
            continue
        if storage_key in by_file:
            continue
        template = _template_for_target(
            by_file,
            target,
            repo_root,
            host_templates=host_templates,
            cross_templates=cross_templates,
        )
        by_file[storage_key] = _synthesize_compile_entry(repo_root, target, template, include_dirs)
        synthesized += 1
    return synthesized


CXX_SOURCE_SUFFIXES = frozenset({".cpp", ".hpp", ".cc", ".cxx"})


def _overlay_source_suffixes(overlay: dict) -> frozenset[str] | None:
    raw = overlay.get("suffixes")
    if isinstance(raw, list) and raw:
        return frozenset(str(item) for item in raw if isinstance(item, str) and str(item).startswith("."))
    language = str(overlay.get("language", "")).lower()
    if language == "c":
        return SOURCE_SUFFIXES - CXX_SOURCE_SUFFIXES
    if language in {"cxx", "c++"}:
        return CXX_SOURCE_SUFFIXES
    return None


def _overlay_path_prefixes(overlay: dict, key: str) -> tuple[str, ...]:
    raw = overlay.get(key)
    if isinstance(raw, list):
        return tuple(str(item) for item in raw if isinstance(item, str) and item.strip())
    return ()


def _path_under_prefixes(rel_posix: str, prefixes: tuple[str, ...]) -> bool:
    return any(
        rel_posix == prefix or rel_posix.startswith(f"{prefix}/") for prefix in prefixes
    )


def _sources_for_overlay(sources: list[Path], overlay: dict, repo_root: Path | None = None) -> list[Path]:
    allowed = _overlay_source_suffixes(overlay)
    include = _overlay_path_prefixes(overlay, "paths")
    exclude = _overlay_path_prefixes(overlay, "exclude_paths")
    selected: list[Path] = []
    for path in sources:
        if allowed is not None and path.suffix not in allowed:
            continue
        if include or exclude:
            rel = source_key(path, repo_root.resolve()) if repo_root is not None else None
            rel_posix = rel if rel is not None else path.as_posix()
            if include and not _path_under_prefixes(rel_posix, include):
                continue
            if exclude and _path_under_prefixes(rel_posix, exclude):
                continue
        selected.append(path)
    return sorted(selected)


def filter_clang_tidy_sources(
    db: MergedCompileDatabase,
    *,
    scan_paths: list[Path],
) -> list[Path]:
    """Return TU inputs for clang-tidy after verifying full scan compile-DB coverage."""
    coverage_targets = clang_tidy_scan_targets(scan_paths)
    if not coverage_targets:
        return []
    missing = db.missing_targets(coverage_targets)
    if missing:
        print(
            f"error: compile database missing {len(missing)} scan.source_roots file(s)",
            file=sys.stderr,
        )
        for path in missing[:25]:
            rel = source_key(path, db.repo_root) or path
            print(f"  - {rel}", file=sys.stderr)
        if len(missing) > 25:
            print(f"  ... and {len(missing) - 25} more", file=sys.stderr)
        return []
    return clang_tidy_input_targets(scan_paths)

GCC_ONLY_WARNINGS = (
    "-Warray-bounds=2",
    "-Wbidi-chars=any",
    "-Wduplicated-branches",
    "-Wduplicated-cond",
    "-Werror=implicit",
    "-Werror=incompatible-pointer-types",
    "-Werror=int-conversion",
    "-Wformat-overflow=2",
    "-Wformat-truncation=2",
    "-Wimplicit-fallthrough=5",
    "-Wshift-overflow=2",
    "-Wstrict-overflow=2",
    "-Wstringop-overflow=4",
    "-Wtrampolines",
    "-Warith-conversion",
)
# GCC probe / OpenSSF flags accepted by project GCC but not the Clang frontend used by clang-tidy.
CLANG_FRONTEND_UNSUPPORTED_FLAGS = (
    "-fhardened",
    "-Whardened",
    "-Werror=trampolines",
    "-fstrict-flex-arrays=3",
    "-fzero-init-padding-bits=all",
    "-fzero-init-padding-bits=union",
)
# ESP-IDF / embedded GCC flags with no Clang frontend equivalent.
CLANG_TIDY_CROSS_GCC_STRIP = (
    "-fno-malloc-dce",
    "-fno-tree-switch-conversion",
    "-fstrict-volatile-bitfields",
    "-freorder-blocks",
    "-Wno-old-style-declaration",
    "-fno-jump-tables",
)
CLANG_TIDY_STRIP_FLAGS = frozenset(
    GCC_ONLY_WARNINGS + CLANG_FRONTEND_UNSUPPORTED_FLAGS + CLANG_TIDY_CROSS_GCC_STRIP
)
CLANG_TIDY_STRIP_PREFIXES = (
    "-Werror=",
    "-Wno-error=",
    "-specs=",
    "-fmacro-prefix-map=",
    "-fdebug-prefix-map=",
    "-ffile-prefix-map=",
    "-mcpu=",
    "-mtarget=",
    "-march=",
    "-mabi=",
)


def _format_compile_db_input_status(item) -> str:
    if not item.present:
        return "missing"
    if item.raw_entries is None:
        return "present"
    role = "cross-compile" if item.input_kind == "firmware" else "native host"
    return f"present, {item.raw_entries} raw entries ({role})"


def _print_configure_compile_db_report(
    repo_root: Path,
    *,
    host_projects: list[dict],
    db: MergedCompileDatabase,
    scan_paths: list[Path],
    synthesized: int,
    merge_dir: Path,
    openssf_scope,
) -> None:
    from hardening_verify import format_compile_db_openssf_audit_ok

    repo_root = repo_root.resolve()
    rel_merge = merge_dir.relative_to(repo_root).as_posix()
    targets = clang_tidy_scan_targets(scan_paths)
    by_root = count_cc_paths_by_scan_source_root(targets, repo_root)

    print("compile database: configure-compile-db summary", flush=True)
    print(
        "  job: host CMake configure → merge compile_db.* inputs → scan-scoped outputs",
        flush=True,
    )

    if host_projects:
        print(
            f"  [1] host CMake configure (compile_db.userspace): {len(host_projects)} project(s)",
            flush=True,
        )
        for project in host_projects:
            print(
                f"      {project['source']} → {project['compile_commands_json']}",
                flush=True,
            )
    else:
        print("  [1] host CMake configure: skipped (no compile_db.userspace entries)", flush=True)

    inputs = compile_db_input_stats(repo_root)
    if inputs:
        print(
            f"  [2] merge inputs (manifest compile_db.*): {len(inputs)} compile_commands.json path(s)",
            flush=True,
        )
        for item in inputs:
            print(
                f"      {item.label}: {item.rel_path} — {_format_compile_db_input_status(item)}",
                flush=True,
            )

    print(f"  [3] merge outputs ({rel_merge}/)", flush=True)
    print(
        f"      compile_commands.json: {len(db.by_key)} scan-scoped entries (clang-tidy -p)",
        flush=True,
    )
    print(
        f"      cppcheck.compile_commands.json: {len(targets)} entries "
        "(host-resynth for cross-compile)",
        flush=True,
    )
    if synthesized:
        word = "y" if synthesized == 1 else "ies"
        print(
            f"      synthesized: {synthesized} entr{word} (no raw DB row; template-filled)",
            flush=True,
        )
    print(
        f"      scan.source_roots coverage: {format_source_root_entry_counts(by_root, repo_root)}",
        flush=True,
    )

    print("  [4] OpenSSF compile_commands audit", flush=True)
    for line in format_compile_db_openssf_audit_ok(openssf_scope):
        print(f"      {line}", flush=True)


def configure_compile_db(
    repo_root: Path,
    *,
    jobs: int = 1,
    quiet: bool = False,
    lint_kit: Path | None = None,
    unsafe_api_paths: list[Path],
    source_paths: list[Path],
) -> int:
    repo_root = repo_root.resolve()
    load(repo_root)
    if not compile_db_is_configured(repo_root):
        if not quiet:
            print(
                "compile database: skip (compile_db not declared in .github/lint-c-cpp.yaml)",
                flush=True,
            )
    if compile_db_is_configured(repo_root) and verify_compile_db_cmake_coverage(repo_root) != 0:
        return 1
    projects = compile_db_userspace_entries(repo_root)
    failures = 0
    if compile_db_is_configured(repo_root) and not projects:
        print(
            "error: compile_db.userspace is required "
            "(declare a list of compile_commands_json and source entries)",
            file=sys.stderr,
        )
        return 1
    if projects:
        generator = cmake_generator()
        for project in projects:
            source = repo_root / str(project["source"])
            build_dir = repo_root / str(project["build_dir"])
            rel_compile_db = str(project["compile_commands_json"])
            if not source.is_dir():
                print(f"error: compile_db source missing: {source}", file=sys.stderr)
                failures += 1
                continue
            build_dir.mkdir(parents=True, exist_ok=True)
            args = [
                "cmake",
                "-S",
                str(source),
                "-B",
                str(build_dir),
                "-G",
                generator,
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            ]
            for item in project.get("cmake_args", []) if isinstance(project.get("cmake_args"), list) else []:
                value = str(item)
                if value.startswith("-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=") and not value.startswith("-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=/"):
                    rel = value.split("=", 1)[1]
                    args.append(f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={repo_root / rel}")
                else:
                    args.append(value)
            print("+", " ".join(args), flush=True)
            if subprocess.run(args, cwd=repo_root, check=False).returncode != 0:
                failures += 1
            elif not (repo_root / rel_compile_db).is_file():
                print(
                    f"error: CMake configure did not produce {rel_compile_db}",
                    file=sys.stderr,
                )
                failures += 1
        if failures:
            return failures
        if compile_db_is_configured(repo_root) and verify_required_compile_commands(
            repo_root, include_firmware=False
        ) != 0:
            return 1

    resolved_kit = (lint_kit or _DEFAULT_LINT_KIT).resolve()
    _policy_helpers = _LINT_LIB / "helpers" / "policy"
    if str(_policy_helpers) not in sys.path:
        sys.path.insert(0, str(_policy_helpers))
    from hardening_verify import compile_db_openssf_audit_scope, verify_compile_commands_openssf

    header_role_issues = cxx_in_c_compatible_header_violations(source_paths, repo_root)
    if header_role_issues:
        print(
            "error: C++ surface in .h still classified c_compatible "
            "(rename to .hpp/.hh/.hxx):",
            file=sys.stderr,
        )
        for issue in header_role_issues[:25]:
            print(f"  {issue}", file=sys.stderr)
        if len(header_role_issues) > 25:
            print(
                f"  ... and {len(header_role_issues) - 25} more",
                file=sys.stderr,
            )
        return 1

    merge_dir = repo_root / clang_tidy_merge_build_dir(repo_root)
    merged_json = merge_dir / "compile_commands.json"
    built = build_merged_compile_database(repo_root, source_paths)
    if built is None:
        return 1
    db, synthesized = built
    write_clang_tidy_compile_commands(db, merged_json, scan_paths=source_paths)
    cppcheck_json = merge_dir / _CPPCHECK_COMPILE_COMMANDS
    write_cppcheck_compile_commands(
        db,
        repo_root,
        cppcheck_json,
        scan_paths=source_paths,
    )
    openssf_scope = compile_db_openssf_audit_scope(
        repo_root,
        resolved_kit,
        source_paths=source_paths,
        entries_by_key=db.by_key,
    )
    openssf_issues = verify_compile_commands_openssf(
        repo_root,
        resolved_kit,
        entries_by_key=db.by_key,
        source_paths=source_paths,
    )
    if openssf_issues:
        print("error: compile_commands OpenSSF hardening audit:", file=sys.stderr)
        for issue in openssf_issues[:25]:
            print(f"  {issue}", file=sys.stderr)
        if len(openssf_issues) > 25:
            print(f"  ... and {len(openssf_issues) - 25} more", file=sys.stderr)
        return 1
    if not quiet:
        _print_configure_compile_db_report(
            repo_root,
            host_projects=projects,
            db=db,
            scan_paths=source_paths,
            synthesized=synthesized,
            merge_dir=merge_dir,
            openssf_scope=openssf_scope,
        )
    return 0


def _cppcheck_paths_for_pass(
    pass_cfg: dict[str, object],
    *,
    source_paths: list[Path],
    unsafe_api_paths: list[Path],
) -> list[Path]:
    scan_job = str(pass_cfg["scan_job"])
    if scan_job == JOB_SOURCE:
        return source_paths
    if scan_job == JOB_UNSAFE_API:
        return unsafe_api_paths
    raise ValueError(f"unsupported cppcheck pass scan_job {scan_job!r}")


def run_cppcheck(
    repo_root: Path,
    lint_kit: Path,
    *,
    jobs: int,
    unsafe_api_paths: list[Path],
    source_paths: list[Path],
) -> int:
    repo_root = repo_root.resolve()
    lint_kit = lint_kit.resolve()
    load(repo_root)
    merge_dir = repo_root / clang_tidy_merge_build_dir(repo_root)
    cppcheck_json = merge_dir / _CPPCHECK_COMPILE_COMMANDS
    if not cppcheck_json.is_file():
        print(
            f"error: missing cppcheck compile database {cppcheck_json} "
            "(run configure-compile-db first)",
            file=sys.stderr,
        )
        return 1
    db = MergedCompileDatabase.from_json(cppcheck_json, repo_root)
    scan_targets = clang_tidy_scan_targets(source_paths)
    missing = db.missing_targets(scan_targets)
    if missing:
        print(
            f"error: cppcheck compile database missing {len(missing)} scan.source_roots file(s); "
            "re-run configure-compile-db",
            file=sys.stderr,
        )
        for path in missing[:25]:
            rel = source_key(path, repo_root) or path
            print(f"  - {rel}", file=sys.stderr)
        if len(missing) > 25:
            print(f"  ... and {len(missing) - 25} more", file=sys.stderr)
        return 1
    cfg = cppcheck_config(repo_root, lint_kit=lint_kit)
    passes = cfg.get("passes")
    if not isinstance(passes, list) or not passes:
        print("error: cppcheck.passes missing in config/cppcheck-manifest.yaml", file=sys.stderr)
        return 1
    from policy_overrides import (
        apply_cppcheck_cli_dials,
        compile_db_override_slug,
        config_has_by_compile_db,
        override_dials_for_compile_db,
        owning_compile_commands_json,
    )

    split_by_db = config_has_by_compile_db(repo_root, "cppcheck")
    failures = 0
    for pass_cfg in passes:
        if not isinstance(pass_cfg, dict):
            continue
        pass_id = str(pass_cfg.get("id", "cppcheck"))
        pass_paths = _cppcheck_paths_for_pass(
            pass_cfg,
            source_paths=source_paths,
            unsafe_api_paths=unsafe_api_paths,
        )
        targets = clang_tidy_scan_targets(pass_paths)
        if not split_by_db:
            print(f"cppcheck ({pass_id}): {len(targets)} file(s)", flush=True)
            common = cppcheck_cli_common_args(
                cfg, lint_kit=lint_kit, pass_cfg=pass_cfg, repo_root=repo_root
            )
            cmd = ["cppcheck", f"-j{jobs}", *common, f"--project={cppcheck_json}"]
            print("+", " ".join(cmd), flush=True)
            if subprocess.run(cmd, cwd=repo_root, check=False).returncode != 0:
                failures += 1
            continue
        groups: dict[str | None, list[Path]] = {}
        for path in targets:
            key = source_key(path, repo_root)
            owner = owning_compile_commands_json(repo_root, key) if key else None
            groups.setdefault(owner, []).append(path)
        base_enable = [str(item) for item in cfg.get("enable", []) if isinstance(item, str)]
        base_suppress = [
            str(item) for item in cfg.get("suppressions", []) if isinstance(item, str)
        ]
        base_flags = [str(item) for item in cfg.get("flags", []) if isinstance(item, str)]
        for owner, group in sorted(groups.items(), key=lambda item: item[0] or ""):
            add, remove = override_dials_for_compile_db(repo_root, "cppcheck", owner)
            enable, suppressions = apply_cppcheck_cli_dials(
                base_enable, base_suppress, add=add, remove=remove
            )
            common = list(base_flags)
            for category in enable:
                if category.strip():
                    common.append(f"--enable={category}")
            for suppression in suppressions:
                if suppression.strip():
                    common.append(f"--suppress={suppression}")
            if owner is None:
                project_json = cppcheck_json
                label = pass_id
            else:
                slug = compile_db_override_slug(owner)
                project_json = merge_dir / f"cppcheck.by-{slug}.compile_commands.json"
                subset = [
                    db.by_key[key]
                    for path in group
                    if (key := source_key(path, repo_root)) is not None and key in db.by_key
                ]
                project_json.write_text(
                    json.dumps(subset, indent=2) + "\n", encoding="utf-8"
                )
                label = f"{pass_id}:{owner}"
            print(f"cppcheck ({label}): {len(group)} file(s)", flush=True)
            cmd = ["cppcheck", f"-j{jobs}", *common, f"--project={project_json}"]
            print("+", " ".join(cmd), flush=True)
            if subprocess.run(cmd, cwd=repo_root, check=False).returncode != 0:
                failures += 1
    if failures:
        return failures
    print("cppcheck: OK (config/cppcheck-manifest.yaml)", flush=True)
    return 0


def _gcc_cxx_isystem_flags() -> list[str]:
    gpp = Path("/usr/bin/g++")
    if not gpp.is_file():
        gpp = Path("g++")
    return _compiler_isystem_flags(gpp, language="c++")


def _write_clang_tidy_config_for_source_roots(
    lint_kit: Path,
    out_path: Path,
    *,
    base_config: str,
    header_filter: str,
    overrides_dir: Path | None = None,
) -> None:
    base_path = lint_kit / "config" / base_config
    if overrides_dir is not None:
        candidate = overrides_dir / base_config
        if candidate.is_file():
            base_path = candidate
    text = base_path.read_text(encoding="utf-8")
    text = re.sub(
        r"^HeaderFilterRegex:.*$",
        f"HeaderFilterRegex: '{header_filter}'",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(r"^ExcludeHeaderFilterRegex:.*\n", "", text, flags=re.MULTILINE)
    out_path.write_text(text, encoding="utf-8")


def ensure_clang_tidy_configs_for_source_roots(
    repo_root: Path,
    lint_kit: Path,
    merge_dir: Path,
    overlays: list[dict],
) -> Path:
    """Materialize overlay configs with role-specific HeaderFilterRegex (C vs C++ headers)."""
    from policy_overrides import lint_overrides_dir

    repo_root = repo_root.resolve()
    lint_kit = lint_kit.resolve()
    merge_dir.mkdir(parents=True, exist_ok=True)
    overrides_dir = lint_overrides_dir(repo_root)
    if not overrides_dir.is_dir():
        overrides_dir = None
    seen: set[str] = set()
    for overlay in overlays:
        config_name = str(overlay.get("config", ".clang-tidy-cxx"))
        if config_name in seen:
            continue
        seen.add(config_name)
        base_config = str(overlay.get("base_config", config_name))
        header_filter = clang_tidy_header_filter_regex_for_overlay(repo_root, overlay)
        _write_clang_tidy_config_for_source_roots(
            lint_kit,
            merge_dir / config_name,
            base_config=base_config,
            header_filter=header_filter,
            overrides_dir=overrides_dir,
        )
    return merge_dir


def _compiler_driver_search_flags(tokens: list[str]) -> list[str]:
    """Driver flags that change GCC's built-in include search (``-specs=``, ``-march=``).

    Toolchains such as ESP-IDF put these in ``@cflags`` response files. Clang cannot
    honor ``-specs=``, so scrub must pass them into ``compiler -E -v`` when building
    ``-isystem`` paths — otherwise newlib-first search breaks ``#include_next``.
    """
    return [
        token
        for token in tokens
        if token.startswith(("-specs=", "-march=", "-mabi="))
    ]


def _compiler_isystem_flags(
    compiler: Path,
    *,
    language: str,
    extra_flags: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    """Return ``-isystem`` flags from ``compiler -x<lang> -E -v`` (cross or host)."""
    argv = [str(compiler), *list(extra_flags or ()), f"-x{language}", "-E", "-v", "-"]
    try:
        proc = subprocess.run(
            argv,
            input=b"",
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    flags: list[str] = []
    capture = False
    for line in proc.stderr.decode(errors="replace").splitlines():
        if "#include <...> search starts here:" in line:
            capture = True
            continue
        if capture:
            if line.startswith("End of search list"):
                break
            path = line.strip()
            if path:
                flags.extend(["-isystem", path])
    return flags


def _cross_sysroot(compiler: Path) -> Path | None:
    try:
        proc = subprocess.run(
            [str(compiler), "-print-sysroot"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    text = proc.stdout.strip()
    if not text:
        return None
    path = Path(text)
    return path if path.is_dir() else None


def _is_gnu_cross_driver(path: Path) -> bool:
    name = path.name.lower()
    if "clang" in name:
        return False
    return "gcc" in name or "g++" in name or name.endswith("-c++")


def _resolve_cross_toolchain_driver(command: str, *, target: str) -> Path | None:
    """Prefer the recorded cross GCC/G++ driver for sysroot/isystem queries."""
    driver = compile_driver_path(command)
    if driver is not None and _is_gnu_cross_driver(driver):
        return driver
    host = host_target_triple()
    for suffix in ("g++", "gcc", "c++"):
        candidate_name = f"{target}-{suffix}"
        resolved = shutil.which(candidate_name)
        if not resolved:
            continue
        path = Path(resolved)
        triple = compiler_target_triple(path)
        if triple is None:
            continue
        if host is not None and triple == host:
            continue
        return path
    return driver if driver is not None and _is_gnu_cross_driver(driver) else None


def _cross_toolchain_include_paths(compiler: Path, *, target: str) -> list[Path]:
    prefix = compiler.parent.parent
    paths: list[Path] = []
    for relative in (Path("picolibc/include"), Path(target) / "include"):
        candidate = prefix / relative
        if candidate.is_dir():
            paths.append(candidate)
    return paths


def _repair_define_token(token: str) -> str:
    """Ensure ``-DNAME=value with spaces`` keeps a C string literal for clang."""
    if not token.startswith("-D") or "=" not in token[2:]:
        return token
    name, _, value = token[2:].partition("=")
    if not value or (value.startswith('"') and value.endswith('"')):
        return token
    if " " in value or "\t" in value:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'-D{name}="{escaped}"'
    return token


def _std_flag_from_tokens(tokens: list[str], *, wants_cxx: bool) -> str | None:
    """Return the last ``-std=`` flag matching the language family, if any."""
    chosen: str | None = None
    for token in tokens:
        if not token.startswith("-std="):
            continue
        if wants_cxx == ("++" in token):
            chosen = token
    return chosen


def _scrub_cross_compile_command_argv(command: str, *, source_file: str) -> list[str] | None:
    target = clang_target_for_command(command)
    host = host_target_triple()
    if not target or (host is not None and target == host):
        return None
    toolchain = _resolve_cross_toolchain_driver(command, target=target)
    if toolchain is None:
        return None
    raw_tokens = shlex.split(command)
    driver_token = raw_tokens[0]
    tokens = _normalize_compile_tokens(raw_tokens)
    # After ``@cflags`` expansion so ``-specs=`` / ``-march=`` are visible.
    search_flags = _compiler_driver_search_flags(tokens)
    suffix = Path(source_file).suffix.lower()
    header_suffixes = {".h", ".hh", ".hpp", ".hxx"}
    is_header = suffix in header_suffixes
    # Preserve synthesized cxx_only ``.h`` (``-x c++-header``) across scrub.
    wants_cxx = suffix in {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".hh"} or (
        is_header and ("c++-header" in raw_tokens or "-x c++-header" in command)
    )
    # Keep the compile DB dialect (e.g. ESP-IDF ``-std=gnu23``). Strict ``-std=c11``
    # drops GNU ``asm`` and fails freestanding SDK headers during tidy parse.
    preserved_std = _std_flag_from_tokens(tokens, wants_cxx=wants_cxx)
    if is_header:
        lang_std = preserved_std or ("-std=gnu++17" if wants_cxx else "-std=gnu11")
        lang_x = ["-x", "c++-header" if wants_cxx else "c-header"]
        isystem_lang = "c++" if wants_cxx else "c"
    elif wants_cxx:
        lang_std = preserved_std or "-std=gnu++17"
        lang_x = ["-x", "c++"]
        isystem_lang = "c++"
    else:
        lang_std = preserved_std or "-std=gnu11"
        lang_x = ["-x", "c"]
        isystem_lang = "c"
    drop_std_prefixes = ("-std=c", "-std=gnu")
    source_names = {source_file, Path(source_file).name}
    kept: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token == driver_token:
            continue
        if token in CLANG_TIDY_STRIP_FLAGS or token == "-Werror":
            continue
        if any(token.startswith(prefix) for prefix in CLANG_TIDY_STRIP_PREFIXES):
            continue
        if token.startswith(("--target=", "-target=")):
            continue
        if token in {"--target", "-target"}:
            skip_next = True
            continue
        if token.startswith(drop_std_prefixes) or token in {
            "-x",
            "-x c",
            "-x c++",
            "-x c-header",
            "-x c++-header",
        }:
            if token == "-x":
                skip_next = True
            continue
        if token.startswith("-x"):
            continue
        if token == "-o":
            skip_next = True
            continue
        if token == "-c":
            kept.extend(["-c", *lang_x, source_file])
            continue
        # Drop the original TU path (any extension) so scrub does not duplicate it.
        if (not token.startswith("-")) and (
            token in source_names
            or token.endswith(
                (".c", ".cpp", ".S", ".cc", ".cxx", ".ino", ".h", ".hh", ".hpp", ".hxx")
            )
        ):
            continue
        kept.append(_repair_define_token(token))
    out = [
        "clang",
        f"--target={target}",
        lang_std,
        "-Wno-unknown-warning-option",
        "-Wno-unused-command-line-argument",
        "-Wno-c++11-narrowing",
        "-ferror-limit=0",
    ]
    sysroot = _cross_sysroot(toolchain)
    if sysroot is not None:
        out.append(f"--sysroot={sysroot}")
    isystem_flags = _compiler_isystem_flags(
        toolchain, language=isystem_lang, extra_flags=search_flags
    )
    specs_usable = any(flag.startswith("-specs=") for flag in search_flags)
    if not isystem_flags and specs_usable:
        # Stale ``-specs=`` (unrepaired host path) makes ``gcc -E -v`` fail; retry
        # without specs and prepend toolchain libc roots so picolibc stays first.
        soft_flags = [flag for flag in search_flags if not flag.startswith("-specs=")]
        isystem_flags = _compiler_isystem_flags(
            toolchain, language=isystem_lang, extra_flags=soft_flags
        )
        specs_usable = False
    if not specs_usable:
        # C: keep libc/picolibc first (ESP-IDF ``_REENT`` / newlib vs picolibc).
        # C++: never prepend libc ahead of libstdc++ — that breaks
        # ``#include_next <stdlib.h>`` from ``<cstdlib>`` under clang.
        extra_isystem: list[str] = []
        for include_path in _cross_toolchain_include_paths(toolchain, target=target):
            path_s = str(include_path)
            if path_s in extra_isystem or path_s in isystem_flags:
                continue
            extra_isystem.extend(["-isystem", path_s])
        if isystem_lang == "c++":
            isystem_flags = isystem_flags + extra_isystem
        else:
            isystem_flags = extra_isystem + isystem_flags
    out.extend(isystem_flags)
    out.extend(kept)
    if "-c" not in out:
        out.extend(["-c", *lang_x, source_file])
    return out


def _scrub_cross_compile_command(command: str, *, source_file: str) -> str:
    argv = _scrub_cross_compile_command_argv(command, source_file=source_file)
    if argv is None:
        return command
    return shlex.join(argv)


def scrub_compile_entry_for_clang_tidy(entry: dict) -> dict:
    normalized = dict(entry)
    source_file = str(normalized.get("file", ""))
    command = entry_command(normalized)
    if command and is_cross_compile_command(command):
        argv = _scrub_cross_compile_command_argv(command, source_file=source_file)
        if argv is not None:
            # Prefer argv form so -D values with spaces/quotes are not re-shell-parsed.
            normalized["arguments"] = argv
            normalized.pop("command", None)
            return normalized
        return normalized

    if "command" in normalized and isinstance(normalized["command"], str):
        cmd = normalized["command"]
        cmd = re.sub(r"\s+-fsanitize=\S+", "", cmd)
        cmd = re.sub(r"\s+-fno-sanitize-recover=\S+", "", cmd)
        for flag in CLANG_TIDY_STRIP_FLAGS:
            cmd = cmd.replace(" " + flag, "")
        normalized["command"] = cmd
    args = normalized.get("arguments")
    if isinstance(args, list):
        out_args: list[str] = []
        skip_next = False
        for arg in _normalize_compile_tokens([str(a) for a in args]):
            if skip_next:
                skip_next = False
                continue
            if arg in ("-fsanitize", "-fno-sanitize-recover"):
                skip_next = True
                continue
            if arg.startswith("-fsanitize=") or arg.startswith("-fno-sanitize-recover="):
                continue
            if arg in CLANG_TIDY_STRIP_FLAGS or arg == "-Werror":
                continue
            if any(arg.startswith(prefix) for prefix in CLANG_TIDY_STRIP_PREFIXES):
                continue
            out_args.append(arg)
        normalized["arguments"] = out_args
    return normalized


def _ensure_firmware_compile_commands_if_missing(repo_root: Path) -> int:
    """Build firmware compile_commands.json only when manifest paths are absent."""
    from consumer_manifest import (
        compile_db_firmware_compile_command_paths,
        compile_db_firmware_supplies_compile_db,
    )

    if not compile_db_firmware_supplies_compile_db(repo_root):
        return 0
    paths = compile_db_firmware_compile_command_paths(repo_root)
    if paths and all(path.is_file() for path in paths):
        return 0
    return ensure_firmware_compile_commands(repo_root)


def build_merged_compile_database(
    repo_root: Path,
    scan_paths: list[Path],
) -> tuple[MergedCompileDatabase, int] | None:
    """Merge firmware + userspace compile DBs once; synthesize missing scan targets."""
    repo_root = repo_root.resolve()
    if _ensure_firmware_compile_commands_if_missing(repo_root) != 0:
        return None
    if compile_db_is_configured(repo_root) and verify_required_compile_commands(repo_root) != 0:
        return None
    db = MergedCompileDatabase.from_richest(repo_root)
    cross_templates = MergedCompileDatabase.cross_template_pool(db.by_key, repo_root)
    synthesized = complete_compile_commands_for_scan_roots(
        repo_root,
        db.by_key,
        scan_paths=scan_paths,
        host_templates=db.host_templates,
        cross_templates=cross_templates,
    )
    targets = clang_tidy_scan_targets(scan_paths)
    if not targets:
        return db.narrowed_to_scan_targets(scan_paths), synthesized
    missing = db.missing_targets(targets)
    if missing:
        print(
            f"error: failed to synthesize compile database entries for {len(missing)} file(s)",
            file=sys.stderr,
        )
        return None
    return db.narrowed_to_scan_targets(scan_paths), synthesized


def write_clang_tidy_compile_commands(
    db: MergedCompileDatabase,
    out_path: Path,
    *,
    scan_paths: list[Path],
) -> None:
    """Write scrubbed compile_commands.json for clang-tidy ``-p``."""
    targets = clang_tidy_scan_targets(scan_paths)
    if not targets:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("[]\n", encoding="utf-8")
        return

    repo_root = db.repo_root
    cross_templates = MergedCompileDatabase.cross_template_pool(db.by_key, repo_root)
    include_dirs_raw = cppcheck_config(repo_root).get("include_dirs", [])
    include_dirs = [str(item) for item in include_dirs_raw if isinstance(item, str)]

    extra = _gcc_cxx_isystem_flags()
    merged: list[dict] = []
    for target in targets:
        entry = db.entry_for(target)
        if entry is None:
            continue
        # Host unit tests often compile firmware/*.cpp into the userspace compile DB.
        # Those host entries lack Arduino/board -I/-D; clang-tidy needs a firmware
        # (cross) template for those paths. Leave db.by_key unchanged for OpenSSF/cppcheck.
        if (
            cross_templates
            and _target_prefers_firmware_template(target, repo_root)
            and not is_cross_compile_command(entry_command(entry))
        ):
            template = _template_for_target(
                db.by_key,
                target,
                repo_root,
                host_templates=db.host_templates,
                cross_templates=cross_templates,
            )
            entry = _synthesize_compile_entry(repo_root, target, template, include_dirs)
        scrubbed = scrub_compile_entry_for_clang_tidy(entry)
        cmd = entry_command(scrubbed)
        # Host libstdc++ -isystem paths break --target= cross TUs (e.g. floatn.h __TC__).
        if (
            extra
            and "--target=" not in cmd
            and not is_cross_compile_command(cmd)
            and re.search(r"(^|[\s/])(g\+\+|c\+\+)([\s\"]|$)", cmd)
        ):
            scrubbed["command"] = cmd + " " + " ".join(extra)
            scrubbed.pop("arguments", None)
        merged.append(scrubbed)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    scope_issues = assert_compile_db_entries_in_scan_scope(
        merged, repo_root, label=str(out_path)
    )
    if scope_issues:
        for issue in scope_issues:
            print(f"error: {issue}", file=sys.stderr)
        raise RuntimeError(
            f"{out_path}: compile DB contains out-of-scope / gitignored file= entries"
        )


def write_cppcheck_compile_commands(
    db: MergedCompileDatabase,
    repo_root: Path,
    out_path: Path,
    *,
    scan_paths: list[Path],
) -> None:
    """Write host-only compile_commands.json for cppcheck ``--project`` (no vendor -I)."""
    repo_root = repo_root.resolve()
    load(repo_root)
    include_dirs_raw = cppcheck_config(repo_root).get("include_dirs", [])
    include_dirs = [str(item) for item in include_dirs_raw if isinstance(item, str)]
    targets = clang_tidy_scan_targets(scan_paths)
    if not targets:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("[]\n", encoding="utf-8")
        return
    merged: list[dict] = []
    for target in targets:
        entry = _compile_entry_for_cppcheck(repo_root, target, db, include_dirs)
        if entry is not None:
            merged.append(entry)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    scope_issues = assert_compile_db_entries_in_scan_scope(
        merged, repo_root, label=str(out_path)
    )
    if scope_issues:
        for issue in scope_issues:
            print(f"error: {issue}", file=sys.stderr)
        raise RuntimeError(
            f"{out_path}: cppcheck compile DB contains out-of-scope / gitignored file= entries"
        )


def merge_compile_commands(
    repo_root: Path,
    out_path: Path,
    *,
    scan_paths: list[Path],
) -> bool:
    built = build_merged_compile_database(repo_root, scan_paths)
    if built is None:
        return False
    db, synthesized = built
    try:
        write_clang_tidy_compile_commands(db, out_path, scan_paths=scan_paths)
        write_cppcheck_compile_commands(
            db,
            repo_root,
            out_path.parent / _CPPCHECK_COMPILE_COMMANDS,
            scan_paths=scan_paths,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return False
    return True


def _emit_clang_tidy_pass_batches(
    *,
    pass_id: str,
    label: str,
    sources: list[Path],
    overlays: list[dict],
    config_dir: Path,
    repo_root: Path,
    lint_kit: Path | None = None,
) -> int:
    if not sources:
        return 0
    print(f"clang-tidy ({label}): {len(sources)} source file(s)", file=sys.stderr)
    from policy_overrides import (
        OVERRIDE_KEY_BY_CLANG_TIDY_CONFIG,
        compile_db_override_slug,
        config_has_by_compile_db,
        materialize_clang_tidy_config_for_compile_db,
        owning_compile_commands_json,
    )
    from repo_paths import source_key

    batches = 0
    for overlay in overlays:
        overlay_id = str(overlay["id"])
        config_name = str(overlay.get("config", ".clang-tidy-cxx"))
        overlay_sources = _sources_for_overlay(sources, overlay, repo_root)
        if not overlay_sources:
            continue
        override_key = OVERRIDE_KEY_BY_CLANG_TIDY_CONFIG.get(config_name)
        split_by_db = (
            override_key is not None
            and config_has_by_compile_db(repo_root, override_key)
            and lint_kit is not None
        )
        if not split_by_db:
            batches += 1
            print(
                json.dumps(
                    {
                        "pass": pass_id,
                        "overlay": overlay_id,
                        "config": str(config_dir / config_name),
                        "files": [str(path) for path in overlay_sources],
                    }
                )
            )
            continue
        groups: dict[str | None, list[Path]] = {}
        for path in overlay_sources:
            key = source_key(path, repo_root)
            owner = owning_compile_commands_json(repo_root, key) if key else None
            groups.setdefault(owner, []).append(path)
        base_config = str(overlay.get("base_config", config_name))
        kit_text = (lint_kit / "config" / base_config).read_text(encoding="utf-8")
        header_filter = clang_tidy_header_filter_regex_for_overlay(repo_root, overlay)
        kit_text = re.sub(
            r"^HeaderFilterRegex:.*$",
            f"HeaderFilterRegex: '{header_filter}'",
            kit_text,
            flags=re.MULTILINE,
        )
        kit_text = re.sub(r"^ExcludeHeaderFilterRegex:.*\n", "", kit_text, flags=re.MULTILINE)
        for owner, group in sorted(groups.items(), key=lambda item: item[0] or ""):
            if owner is None:
                out_name = config_name
            else:
                out_name = f"{config_name}.by-{compile_db_override_slug(owner)}"
            out_path = config_dir / out_name
            materialize_clang_tidy_config_for_compile_db(
                repo_root,
                base_config_name=config_name,
                base_text=kit_text,
                out_path=out_path,
                compile_commands_json=owner,
            )
            batches += 1
            print(
                json.dumps(
                    {
                        "pass": pass_id,
                        "overlay": (
                            overlay_id
                            if owner is None
                            else f"{overlay_id}:{owner}"
                        ),
                        "config": str(out_path),
                        "files": [str(path) for path in group],
                    }
                )
            )
    batched = {
        str(path)
        for overlay in overlays
        for path in _sources_for_overlay(sources, overlay, repo_root)
    }
    if batched != {str(path) for path in sources}:
        missing = sorted({str(path) for path in sources} - batched)
        print(
            f"error: clang-tidy ({label}) batches missing {len(missing)} source file(s)",
            file=sys.stderr,
        )
        for path in missing[:25]:
            print(f"  - {path}", file=sys.stderr)
        return 1
    if batches == 0:
        print(f"clang-tidy ({label}): skip (no overlay matched any source suffix)", file=sys.stderr)
    return 0


def _emit_header_role_batches(
    *,
    pass_id: str,
    label: str,
    role: str,
    language: str,
    default_config: str,
    suffixes: list[str],
    scan_paths: list[Path],
    overlays: list[dict],
    config_dir: Path,
    repo_root: Path,
    db: MergedCompileDatabase,
    lint_kit: Path | None = None,
) -> int:
    """Emit dedicated clang-tidy argv batches for one header role."""
    del default_config  # overlay.config is authoritative
    headers = [
        path
        for path in iter_headers_for_role(scan_paths, repo_root, role=role)
        if db.has(path)
    ]
    if not headers:
        return 0
    role_overlays = [
        overlay
        for overlay in overlays
        if (
            str(overlay.get("language", "")).lower() == language
            or (language == "cxx" and str(overlay.get("language", "")).lower() in {"cxx", "c++"})
        )
    ]
    role_label = "c-compatible" if role == "c_compatible" else "cxx-only"
    if not role_overlays:
        print(
            f"error: clang-tidy ({label}): {role} headers present but no "
            f"{language.upper()} overlay",
            file=sys.stderr,
        )
        return 1
    header_overlays: list[dict] = []
    for overlay in role_overlays:
        header_overlay = dict(overlay)
        header_overlay["suffixes"] = list(suffixes)
        header_overlay["id"] = f"{overlay['id']}-headers"
        header_overlays.append(header_overlay)
    return _emit_clang_tidy_pass_batches(
        pass_id=pass_id,
        label=f"{label} {role_label} headers",
        sources=headers,
        overlays=header_overlays,
        config_dir=config_dir,
        repo_root=repo_root,
        lint_kit=lint_kit,
    )


def _emit_c_compatible_header_batches(
    *,
    pass_id: str,
    label: str,
    scan_paths: list[Path],
    overlays: list[dict],
    config_dir: Path,
    repo_root: Path,
    db: MergedCompileDatabase,
    lint_kit: Path | None = None,
) -> int:
    """Lint shared ``.h`` (POSIX/UAPI C surface) under C clang-tidy as ``-x c-header``."""
    return _emit_header_role_batches(
        pass_id=pass_id,
        label=label,
        role="c_compatible",
        language="c",
        default_config=".clang-tidy-c",
        suffixes=[".h"],
        scan_paths=scan_paths,
        overlays=overlays,
        config_dir=config_dir,
        repo_root=repo_root,
        db=db,
        lint_kit=lint_kit,
    )


def _emit_cxx_only_header_batches(
    *,
    pass_id: str,
    label: str,
    scan_paths: list[Path],
    overlays: list[dict],
    config_dir: Path,
    repo_root: Path,
    db: MergedCompileDatabase,
    lint_kit: Path | None = None,
) -> int:
    """Lint C++-only headers (``.hpp``/``.hh``/``.hxx``) under C++ config."""
    return _emit_header_role_batches(
        pass_id=pass_id,
        label=label,
        role="cxx_only",
        language="cxx",
        default_config=".clang-tidy-cxx",
        suffixes=[".h", ".hpp", ".hh", ".hxx"],
        scan_paths=scan_paths,
        overlays=overlays,
        config_dir=config_dir,
        repo_root=repo_root,
        db=db,
        lint_kit=lint_kit,
    )

def print_clang_tidy_batches(
    repo_root: Path,
    lint_kit: Path,
    *,
    source_paths: list[Path],
    unsafe_api_paths: list[Path],
) -> int:
    repo_root = repo_root.resolve()
    merge_dir = repo_root / clang_tidy_merge_build_dir(repo_root)
    merged_json = merge_dir / "compile_commands.json"
    if not merged_json.is_file():
        print(
            f"error: missing merged compile database {merged_json} "
            "(run configure-compile-db first)",
            file=sys.stderr,
        )
        return 1
    db = MergedCompileDatabase.from_json(merged_json, repo_root)

    source_overlays = clang_tidy_overlays(repo_root)
    unsafe_overlays = clang_tidy_unsafe_overlays(repo_root)
    if not source_overlays and not unsafe_overlays:
        print("clang-tidy: skip (no clang-tidy overlays configured)", file=sys.stderr)
        return 0

    config_dir = ensure_clang_tidy_configs_for_source_roots(
        repo_root,
        lint_kit,
        merge_dir,
        source_overlays + unsafe_overlays,
    )

    source_targets = filter_clang_tidy_sources(db, scan_paths=source_paths)
    if not source_targets:
        return 1
    unsafe_targets = filter_clang_tidy_sources(db, scan_paths=unsafe_api_paths)
    if not unsafe_targets:
        return 1

    failures = 0
    if source_overlays:
        failures |= _emit_clang_tidy_pass_batches(
            pass_id="source",
            label="source",
            sources=source_targets,
            overlays=source_overlays,
            config_dir=config_dir,
            repo_root=repo_root,
            lint_kit=lint_kit,
        )
        failures |= _emit_c_compatible_header_batches(
            pass_id="source",
            label="source",
            scan_paths=source_paths,
            overlays=source_overlays,
            config_dir=config_dir,
            repo_root=repo_root,
            db=db,
            lint_kit=lint_kit,
        )
        failures |= _emit_cxx_only_header_batches(
            pass_id="source",
            label="source",
            scan_paths=source_paths,
            overlays=source_overlays,
            config_dir=config_dir,
            repo_root=repo_root,
            db=db,
            lint_kit=lint_kit,
        )
    if unsafe_overlays:
        failures |= _emit_clang_tidy_pass_batches(
            pass_id="unsafe_api",
            label="unsafe-api",
            sources=unsafe_targets,
            overlays=unsafe_overlays,
            config_dir=config_dir,
            repo_root=repo_root,
            lint_kit=lint_kit,
        )
        failures |= _emit_c_compatible_header_batches(
            pass_id="unsafe_api",
            label="unsafe-api",
            scan_paths=unsafe_api_paths,
            overlays=unsafe_overlays,
            config_dir=config_dir,
            repo_root=repo_root,
            db=db,
            lint_kit=lint_kit,
        )
        failures |= _emit_cxx_only_header_batches(
            pass_id="unsafe_api",
            label="unsafe-api",
            scan_paths=unsafe_api_paths,
            overlays=unsafe_overlays,
            config_dir=config_dir,
            repo_root=repo_root,
            db=db,
            lint_kit=lint_kit,
        )
    return failures


def run_self_test() -> int:
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        bootstrap_scan_manifest(
            repo,
            source_roots=("core", "port", "include", "esp-idf", "userspace", "tests"),
        )
        cases = [
            (repo / "userspace/x.c", "userspace/x.c"),
            (Path("/src/userspace/x.c"), "userspace/x.c"),
            (Path("/src/core/x.c"), "core/x.c"),
            (Path("/src/tests/core/test_x.c"), "tests/core/test_x.c"),
            (Path("/src/third-party/esp-idf/x.c"), None),
            (Path("/opt/vendor/lib/x.cpp"), None),
            (Path("/src/vendor/x.c"), None),
        ]
        for src, expected in cases:
            rel = repo_relative_source(src, repo)
            actual = rel.as_posix() if rel is not None else None
            if actual != expected:
                print(f"self-test FAIL: {src} -> {actual} (expected {expected})", file=sys.stderr)
                ok = False

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bootstrap_scan_manifest(root, source_roots=("core", "port", "include"))
        c_filter = clang_tidy_header_filter_regex(root, role="c_compatible")
        cxx_filter = clang_tidy_header_filter_regex(root, role="cxx_only")
        if "core|port|include" not in c_filter.replace("\\-", "-"):
            print(
                f"self-test FAIL: clang_tidy_header_filter_regex(c) -> {c_filter}",
                file=sys.stderr,
            )
            ok = False
        if r"\.h$" not in c_filter:
            print(
                f"self-test FAIL: c_compatible filter must anchor .h: {c_filter}",
                file=sys.stderr,
            )
            ok = False
        if "hpp" not in cxx_filter:
            print(
                f"self-test FAIL: cxx_only filter must include hpp: {cxx_filter}",
                file=sys.stderr,
            )
            ok = False
        merge = root / "build" / "clang-tidy-compile-db"
        ensure_clang_tidy_configs_for_source_roots(
            root,
            _DEFAULT_LINT_KIT,
            merge,
            [{"id": "c", "language": "c", "config": ".clang-tidy-c"}],
        )
        scoped = (merge / ".clang-tidy-c").read_text(encoding="utf-8")
        if "ExcludeHeaderFilterRegex" in scoped:
            print("self-test FAIL: source clang-tidy config must not use ExcludeHeaderFilterRegex", file=sys.stderr)
            ok = False
        if f"HeaderFilterRegex: '{c_filter}'" not in scoped:
            print("self-test FAIL: scoped clang-tidy config missing c_compatible HeaderFilterRegex", file=sys.stderr)
            ok = False
        ensure_clang_tidy_configs_for_source_roots(
            root,
            _DEFAULT_LINT_KIT,
            merge,
            [{"id": "cxx", "language": "cxx", "config": ".clang-tidy-cxx"}],
        )
        cxx_scoped = (merge / ".clang-tidy-cxx").read_text(encoding="utf-8")
        if f"HeaderFilterRegex: '{cxx_filter}'" not in cxx_scoped:
            print("self-test FAIL: cxx config missing cxx_only HeaderFilterRegex", file=sys.stderr)
            ok = False
        ensure_clang_tidy_configs_for_source_roots(
            root,
            _DEFAULT_LINT_KIT,
            merge,
            [{"id": "unsafe-c", "language": "c", "config": ".clang-tidy-unsafe-c"}],
        )
        unsafe_scoped = (merge / ".clang-tidy-unsafe-c").read_text(encoding="utf-8")
        if "ExcludeHeaderFilterRegex" in unsafe_scoped:
            print(
                "self-test FAIL: unsafe-api clang-tidy config must not use ExcludeHeaderFilterRegex",
                file=sys.stderr,
            )
            ok = False
        header_rx = re.compile(c_filter)
        cxx_rx = re.compile(cxx_filter)
        third_party = str((root / "third-party/esp-idf/components/foo.h").resolve())
        port_h = str((root / "port/foo.h").resolve())
        port_hpp = str((root / "port/foo.hpp").resolve())
        if header_rx.search(third_party):
            print(
                f"self-test FAIL: header filter must not match third-party includes: {third_party}",
                file=sys.stderr,
            )
            ok = False
        if not header_rx.search(port_h):
            print(
                f"self-test FAIL: c_compatible filter must match .h under source_roots: {port_h}",
                file=sys.stderr,
            )
            ok = False
        if header_rx.search(port_hpp):
            print(
                f"self-test FAIL: c_compatible filter must not match .hpp: {port_hpp}",
                file=sys.stderr,
            )
            ok = False
        if not cxx_rx.search(port_hpp):
            print(
                f"self-test FAIL: cxx_only filter must match .hpp under source_roots: {port_hpp}",
                file=sys.stderr,
            )
            ok = False
        if cxx_rx.search(port_h):
            print(
                f"self-test FAIL: cxx_only filter must not match shared .h: {port_h}",
                file=sys.stderr,
            )
            ok = False

    cross_cmd = "/opt/toolchain/bin/cross-gcc -march=rv32imac -c /src/port/board.c"
    with tempfile.NamedTemporaryFile(mode="w", suffix="-gcc", delete=False) as fake_cc:
        fake_cc.write("#!/bin/sh\n")
        fake_cc.flush()
        fake_path = Path(fake_cc.name)
    try:
        fake_path.chmod(0o755)
        cross_cmd = f"{fake_path} -march=rv32imac -c /src/port/board.c"
        from unittest.mock import patch

        import compile_db_util

        compile_db_util.clear_cross_target_cache()
        with patch.object(compile_db_util, "host_target_triple", return_value="x86_64-host"), patch.object(
            compile_db_util,
            "compiler_target_triple",
            return_value="riscv32-esp-elf",
        ):
            scrubbed = _scrub_cross_compile_command(
                cross_cmd,
                source_file="/src/port/board.c",
            )
        if "--target=riscv32-esp-elf" not in scrubbed:
            print(
                f"self-test FAIL: cross scrub missing clang --target: {scrubbed}",
                file=sys.stderr,
            )
            ok = False
        header_cmd = f"{fake_path} -std=c11 -x c-header -c /src/port/board.h"
        with patch.object(compile_db_util, "host_target_triple", return_value="x86_64-host"), patch.object(
            compile_db_util,
            "compiler_target_triple",
            return_value="riscv32-esp-elf",
        ):
            header_argv = _scrub_cross_compile_command_argv(
                header_cmd,
                source_file="/src/port/board.h",
            )
        if header_argv is None:
            print("self-test FAIL: header scrub returned None", file=sys.stderr)
            ok = False
        elif header_argv.count("/src/port/board.h") != 1:
            print(
                f"self-test FAIL: header scrub must not duplicate TU path: {header_argv}",
                file=sys.stderr,
            )
            ok = False
        elif "-x" not in header_argv or "c-header" not in header_argv:
            print(
                f"self-test FAIL: header scrub missing -x c-header: {header_argv}",
                file=sys.stderr,
            )
            ok = False
    finally:
        fake_path.unlink(missing_ok=True)

    # Synthesis must keep -specs=/-march= so cross scrub gets picolibc-first isystems.
    extracted = _extract_compile_flags(
        "riscv32-esp-elf-gcc -march=rv32imac -specs=/tmp/picolibc.specs "
        "-I/tmp/platform_include -DFOO=1 -c /tmp/x.c"
    )
    if not any(t.startswith("-specs=") for t in extracted):
        print(
            f"self-test FAIL: _extract_compile_flags must keep -specs=: {extracted}",
            file=sys.stderr,
        )
        ok = False
    if not any(t.startswith("-march=") for t in extracted):
        print(
            f"self-test FAIL: _extract_compile_flags must keep -march=: {extracted}",
            file=sys.stderr,
        )
        ok = False

    from git_ignore import run_self_test as git_ignore_self_test

    if git_ignore_self_test() != 0:
        ok = False

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bootstrap_scan_manifest(root, source_roots=("core",))
        (root / "core").mkdir(parents=True)
        (root / "core" / "app.c").write_text("void app(void) {}\n", encoding="utf-8")
        source_paths = resolve_scan_paths(JOB_SOURCE, repo_root=root)
        app = str((root / "core/app.c").resolve())
        vendor = str((root / "third-party/vendor.c").resolve())
        stub_entries = {
            "core/app.c": {"directory": str(root), "command": "clang -std=c11 -c", "file": app},
            "third-party/vendor.c": {
                "directory": str(root),
                "command": "clang -std=c11 -c",
                "file": vendor,
            },
        }
        merge_dir = root / "build" / "clang-tidy-compile-db"
        original_loader = load_richest_compile_entries
        try:
            globals()["load_richest_compile_entries"] = lambda _repo: dict(stub_entries)
            if not merge_compile_commands(
                root,
                merge_dir / "compile_commands.json",
                scan_paths=source_paths,
            ):
                print("self-test FAIL: merge_compile_commands stub vendor entries", file=sys.stderr)
                ok = False
            else:
                merged_files = {
                    compile_file_repo_rel(entry.get("file", ""), root)
                    for entry in json.loads(
                        (merge_dir / "compile_commands.json").read_text(encoding="utf-8")
                    )
                }
                if "third-party/vendor.c" in merged_files or merged_files != {"core/app.c"}:
                    print(
                        "self-test FAIL: merged compile DB must contain only scan targets "
                        f"(got {merged_files})",
                        file=sys.stderr,
                    )
                    ok = False
        finally:
            globals()["load_richest_compile_entries"] = original_loader

    # Ingest fail-closed: raw firmware DB full of third-party/esp-idf must not enter richest keys.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bootstrap_scan_manifest(root, source_roots=("core", "esp-idf"))
        (root / ".gitignore").write_text("third-party/\nbuild/\n", encoding="utf-8")
        (root / "core").mkdir(parents=True)
        (root / "esp-idf" / "main").mkdir(parents=True)
        (root / "third-party" / "esp-idf" / "components").mkdir(parents=True)
        (root / "core" / "app.c").write_text("void app(void) {}\n", encoding="utf-8")
        (root / "esp-idf" / "main" / "app_main.c").write_text(
            "void app_main(void) {}\n", encoding="utf-8"
        )
        (root / "third-party" / "esp-idf" / "components" / "vendor.c").write_text(
            "void vendor(void) {}\n", encoding="utf-8"
        )
        fw_db = root / "esp-idf" / "build" / "compile_commands.json"
        fw_db.parent.mkdir(parents=True, exist_ok=True)
        fw_db.write_text(
            json.dumps(
                [
                    {
                        "directory": str(root),
                        "command": "xtensa-esp-elf-gcc -c",
                        "file": str(
                            (root / "third-party/esp-idf/components/vendor.c").resolve()
                        ),
                    },
                    {
                        "directory": str(root),
                        "command": "xtensa-esp-elf-gcc -c",
                        "file": str((root / "esp-idf/main/app_main.c").resolve()),
                    },
                    {
                        "directory": str(root),
                        "command": "clang -c",
                        "file": str(
                            (
                                root / "build/lint/tests/_deps/googletest-src/gtest-all.cc"
                            ).resolve()
                        ),
                    },
                ]
            ),
            encoding="utf-8",
        )
        host_db = root / "build" / "lint" / "userspace" / "compile_commands.json"
        host_db.parent.mkdir(parents=True, exist_ok=True)
        host_db.write_text(
            json.dumps(
                [
                    {
                        "directory": str(root),
                        "command": "clang -c",
                        "file": str((root / "core/app.c").resolve()),
                    }
                ]
            ),
            encoding="utf-8",
        )
        import yaml as _yaml

        manifest_path = root / ".github" / "lint-c-cpp.yaml"
        data = _yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        data["compile_db"] = {
            "firmware": [
                {"compile_commands_json": "esp-idf/build/compile_commands.json"}
            ],
            "userspace": [
                {
                    "compile_commands_json": "build/lint/userspace/compile_commands.json",
                    "source": "userspace",
                }
            ],
        }
        manifest_path.write_text(_yaml.safe_dump(data), encoding="utf-8")
        richest = load_richest_compile_entries(root)
        if any("third-party" in key for key in richest) or any(
            "_deps" in key or key.startswith("build/") for key in richest
        ):
            print(
                f"self-test FAIL: richest must drop gitignored ingest keys (got {sorted(richest)})",
                file=sys.stderr,
            )
            ok = False
        elif set(richest) != {"core/app.c", "esp-idf/main/app_main.c"}:
            print(
                f"self-test FAIL: richest keys unexpected: {sorted(richest)}",
                file=sys.stderr,
            )
            ok = False
        else:
            cross = MergedCompileDatabase.cross_template_pool(richest, root)
            if any(
                "third-party" in (compile_file_repo_rel(entry.get("file", ""), root) or "")
                for entry in cross
            ):
                print(
                    "self-test FAIL: cross_template_pool must not include third-party entries",
                    file=sys.stderr,
                )
                ok = False

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bootstrap_scan_manifest(
            root,
            source_roots=("core", "port", "include", "userspace"),
        )
        (root / "core").mkdir(parents=True)
        (root / "port").mkdir(parents=True)
        (root / "include" / "sample").mkdir(parents=True)
        (root / "userspace").mkdir(parents=True)
        (root / "core" / "app.c").write_text("void app(void) {}\n", encoding="utf-8")
        (root / "port" / "board.c").write_text("void board(void) {}\n", encoding="utf-8")
        (root / "include" / "sample" / "api.h").write_text("#pragma once\n", encoding="utf-8")
        (root / "userspace" / "x.c").write_text("void x(void) {}\n", encoding="utf-8")
        partial_entry = {
            "directory": str(root),
            "command": f"clang -std=c11 -I{root / 'include' / 'sample'} -c",
            "file": str((root / "userspace" / "x.c").resolve()),
        }
        userspace_key = compile_file_repo_rel(partial_entry["file"], root)
        by_file = {userspace_key: partial_entry} if userspace_key else {}
        source_paths = resolve_scan_paths(JOB_SOURCE, repo_root=root)
        synthesized = complete_compile_commands_for_scan_roots(
            root, by_file, scan_paths=source_paths
        )
        if synthesized != 3:
            print(
                f"self-test FAIL: complete_compile_commands synthesized {synthesized}, expected 3",
                file=sys.stderr,
            )
            ok = False
        out_path = root / "merged.json"
        out_path.write_text(json.dumps(list(by_file.values()), indent=2), encoding="utf-8")
        db = MergedCompileDatabase(root.resolve(), by_file)
        selected = {
            path.relative_to(root).as_posix()
            for path in filter_clang_tidy_sources(db, scan_paths=source_paths)
        }
        expected = {
            "core/app.c",
            "port/board.c",
            "userspace/x.c",
        }
        if selected != expected:
            print(f"self-test FAIL: filter_clang_tidy_sources -> {selected}", file=sys.stderr)
            ok = False
        # Headers remain in compile-DB coverage / HeaderFilterRegex scope, not tidy argv.
        coverage = {
            (source_key(path, root) or path.as_posix())
            for path in clang_tidy_scan_targets(source_paths)
        }
        if "include/sample/api.h" not in coverage:
            print("self-test FAIL: header missing from compile-DB coverage targets", file=sys.stderr)
            ok = False

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bootstrap_scan_manifest(root, source_roots=("userspace",))
        (root / "userspace").mkdir(parents=True)
        (root / "userspace" / "solo.c").write_text("void solo(void) {}\n", encoding="utf-8")
        source_paths = resolve_scan_paths(JOB_SOURCE, repo_root=root)
        merge_dir = root / "build" / "clang-tidy-compile-db"
        if not merge_compile_commands(
            root, merge_dir / "compile_commands.json", scan_paths=source_paths
        ):
            print("self-test FAIL: merge_compile_commands without cmake projects", file=sys.stderr)
            ok = False
        elif not filter_clang_tidy_sources(
            MergedCompileDatabase.from_json(merge_dir / "compile_commands.json", root),
            scan_paths=source_paths,
        ):
            print("self-test FAIL: merge_compile_commands did not cover solo.c", file=sys.stderr)
            ok = False

    repo = Path(tempfile.mkdtemp()) / "repo"
    repo.mkdir()
    (repo / ".github").mkdir(parents=True)
    (repo / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
        "  source_roots: [core]\n",
        encoding="utf-8",
    )
    unsafe_paths = resolve_scan_paths(JOB_UNSAFE_API, repo_root=repo)
    source_paths = resolve_scan_paths(JOB_SOURCE, repo_root=repo)
    if configure_compile_db(
        repo,
        quiet=True,
        unsafe_api_paths=unsafe_paths,
        source_paths=source_paths,
    ) != 0:
        print("self-test FAIL: configure_compile_db", file=sys.stderr)
        ok = False

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".github").mkdir(parents=True)
        (root / ".github" / "lint-c-cpp.yaml").write_text(
            "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
            "  source_roots: [core]\n"
            "compile_db:\n"
            "  firmware:\n"
            "    - compile_commands_json: fw/build/compile_commands.json\n"
            "      commands:\n"
            "        - make idf-build\n"
            "  userspace:\n"
            "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
            "      source: userspace\n",
            encoding="utf-8",
        )
        with contextlib.redirect_stderr(io.StringIO()):
            missing_firmware = verify_required_compile_commands(root)
        if missing_firmware == 0:
            print(
                "self-test FAIL: verify_required_compile_commands expected missing firmware",
                file=sys.stderr,
            )
            ok = False

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bootstrap_scan_manifest(root, source_roots=("userspace",))
        (root / ".github" / "lint-c-cpp.yaml").write_text(
            "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
            "  source_roots: [userspace]\n"
            "compile_db:\n"
            "  firmware:\n"
            "    - compile_commands_json: fw/build/compile_commands.json\n"
            "      commands:\n"
            "        - make idf-build\n"
            "  userspace:\n"
            "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
            "      source: userspace\n",
            encoding="utf-8",
        )
        (root / "userspace").mkdir(parents=True)
        (root / "userspace" / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(userspace C)\n",
            encoding="utf-8",
        )
        with contextlib.redirect_stderr(io.StringIO()):
            missing_host = verify_required_compile_commands(root, include_firmware=False)
        if missing_host == 0:
            print(
                "self-test FAIL: verify_required_compile_commands expected missing host",
                file=sys.stderr,
            )
            ok = False

    if ok:
        print("compile-db-lint self-test: OK")
        return 0
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--lint-kit", type=Path, dest="lint_kit")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--unsafe-api-paths-file",
        type=Path,
        help="Repo-relative paths from consumer_manifest.py scan-paths unsafe_api",
    )
    parser.add_argument(
        "--source-paths-file",
        type=Path,
        help="Repo-relative paths from consumer_manifest.py scan-paths source",
    )
    sub = parser.add_subparsers(dest="command")

    cfg = sub.add_parser("configure-compile-db")
    cfg.add_argument("--jobs", type=int, default=1)

    sub.add_parser("ensure-firmware-compile-db")

    cp = sub.add_parser("run-cppcheck")
    cp.add_argument("--jobs", type=int, default=1)

    sub.add_parser("clang-tidy-batches")

    args = parser.parse_args()
    if args.self_test:
        return run_self_test()

    if not args.command:
        parser.error("command is required unless --self-test is set")
    repo = args.repo_root.resolve()
    kit = args.lint_kit.resolve() if args.lint_kit else _DEFAULT_LINT_KIT

    unsafe_api_paths = (
        read_paths_file(args.unsafe_api_paths_file, repo)
        if args.unsafe_api_paths_file is not None
        else None
    )
    source_paths = (
        read_paths_file(args.source_paths_file, repo)
        if args.source_paths_file is not None
        else None
    )

    if args.command == "ensure-firmware-compile-db":
        load(repo)
        return ensure_firmware_compile_commands(repo)
    if args.command == "configure-compile-db":
        if unsafe_api_paths is None or source_paths is None:
            parser.error(
                "--unsafe-api-paths-file and --source-paths-file are required "
                "for configure-compile-db"
            )
        return configure_compile_db(
            repo,
            jobs=args.jobs,
            lint_kit=kit,
            unsafe_api_paths=unsafe_api_paths,
            source_paths=source_paths,
        )
    if args.command == "run-cppcheck":
        if unsafe_api_paths is None or source_paths is None:
            parser.error(
                "--unsafe-api-paths-file and --source-paths-file are required for run-cppcheck"
            )
        return run_cppcheck(
            repo,
            kit,
            jobs=args.jobs,
            unsafe_api_paths=unsafe_api_paths,
            source_paths=source_paths,
        )
    if args.command == "clang-tidy-batches":
        if source_paths is None or unsafe_api_paths is None:
            parser.error(
                "--source-paths-file and --unsafe-api-paths-file are required "
                "for clang-tidy-batches"
            )
        return print_clang_tidy_batches(
            repo,
            kit,
            source_paths=source_paths,
            unsafe_api_paths=unsafe_api_paths,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
