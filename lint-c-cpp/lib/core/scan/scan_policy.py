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
# Scan scope and policy accessors from lint-c-cpp.yaml.
# Paths: consumer_manifest.py scan-paths <job> → --paths-file. Unsafe wrappers stay
# in scope; individual checks may waive only the APIs their wrapper implements.
# BANNED_C_API_NAMES is the SoT for Python banned_libc_io (includes heap + output APIs).

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from consumer_manifest import (
    load as load_lint_manifest,
    manifest_path,
    policy_block,
    project_prefix,
    project_prefix_macro,
    scan_exclude_gitignore_enabled,
    scan_source_roots,
    scan_walk_skip_dir_names,
    section,
)

# Policy / tidy / OpenSSF / format TUs and headers. Arduino ``.ino`` is not a
# normal translation unit here — only license headers + codespell (see profiles).
SOURCE_SUFFIXES = frozenset(
    {".h", ".hh", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx"}
)
INO_SUFFIX = ".ino"

# --- Central scan job profiles (single registry) ---
JOB_SOURCE = "source"
JOB_UNSAFE_API = "unsafe_api"
JOB_NOLINT = "nolint"
JOB_MARKDOWN = "markdown"
JOB_FORMAT_C = "format_c"
JOB_YAML = "yaml"
JOB_SHELL = "shell"
JOB_ALL_FILES = "all_files"
JOB_CODESPELL = "codespell"
JOB_LICENSE = "license"
JOB_CMAKE = "cmake"
JOB_PYTHON = "python"

_CODESPELL_SUFFIXES = SOURCE_SUFFIXES | frozenset(
    {INO_SUFFIX, ".md", ".yaml", ".yml"}
)
_FORMAT_C_SUFFIXES = SOURCE_SUFFIXES

_SCAN_JOB_PROFILES: dict[str, dict[str, object]] = {
    JOB_SOURCE: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": SOURCE_SUFFIXES},
    JOB_UNSAFE_API: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": SOURCE_SUFFIXES},
    JOB_NOLINT: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": True, "suffixes": SOURCE_SUFFIXES},
    JOB_MARKDOWN: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": frozenset({".md"})},
    JOB_FORMAT_C: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": _FORMAT_C_SUFFIXES},
    JOB_YAML: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": frozenset({".yaml", ".yml"})},
    JOB_SHELL: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": frozenset({".sh"})},
    JOB_ALL_FILES: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": None},
    JOB_CODESPELL: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": _CODESPELL_SUFFIXES},
    JOB_LICENSE: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": None},
    JOB_PYTHON: {"exclude_unsafe_wrappers": False, "exclude_nolint_allowed": False, "suffixes": frozenset({".py"})},
}

# Whole-repo walks (respecting VCS/gitignore dir skips), not limited to scan.source_roots.
_REPO_WIDE_SCAN_JOBS = frozenset(
    {
        JOB_MARKDOWN,
        JOB_SHELL,
        JOB_YAML,
        JOB_CODESPELL,
        JOB_LICENSE,
        JOB_ALL_FILES,
        JOB_PYTHON,
    }
)

# Lint steps that must resolve paths via JOB_UNSAFE_API (see iter_job_paths).
UNSAFE_API_SCAN_STEPS = frozenset(
    {
        "banned_libc_io",
        "banned_cxx_heap",
        "null_nodiscard",
        "raii_lifetime",
        "cppcheck",
    }
)

# bugprone-unsafe-functions targets in the unsafe-api clang-tidy pass. The output
# filter waives only intentional non-heap wrapper diagnostics, not whole files.
CLANG_TIDY_UNSAFE_FUNCTIONS = frozenset(
    {"strcpy", "strcat", "sprintf", "vsprintf", "gets"}
)

BANNED_OUTPUT_C_API_NAMES = frozenset(
    {
        "printf",
        "fprintf",
        "dprintf",
        "snprintf",
        "vsnprintf",
        "vprintf",
        "vfprintf",
        "vdprintf",
        "wprintf",
        "fwprintf",
        "vwprintf",
        "vfwprintf",
        "puts",
        "fputs",
        "fputc",
        "putc",
        "putchar",
        "putwchar",
        "fputwc",
        "fputws",
        "perror",
        "fwrite",
        "fflush",
    }
)

BANNED_HEAP_C_API_NAMES = frozenset(
    {
        "aligned_alloc",
        "calloc",
        "free",
        "malloc",
        "realloc",
    }
)

BANNED_C_API_NAMES = tuple(
    sorted(
        {
            "strcpy",
            "strcat",
            "sprintf",
            "vsprintf",
            "gets",
            "scanf",
            "sscanf",
            "fscanf",
            "popen",
            "system",
            "atoi",
            "atol",
            "atoll",
            "strtol",
            "strtoll",
            "strtoul",
            "strtoull",
            "strtoimax",
            "strtoumax",
        }
        | BANNED_OUTPUT_C_API_NAMES
        | BANNED_HEAP_C_API_NAMES
    )
)
BANNED_C_API_CALL = re.compile(
    r"\b(" + "|".join(sorted(BANNED_C_API_NAMES, key=len, reverse=True)) + r")\s*\("
)


def _policy(repo_root: Path) -> dict[str, Any]:
    return policy_block(repo_root)


def _unsafe_api(repo_root: Path) -> dict[str, Any]:
    block = _policy(repo_root).get("unsafe_api")
    return block if isinstance(block, dict) else {}


def _bounds(_repo_root: Path) -> dict[str, Any]:
    """Kit-owned bounds dials (no consumer ``policy.bounds``)."""
    return {}


def _str_set(raw: object) -> frozenset[str]:
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(str(item) for item in raw if isinstance(item, str))


def canonical_index_files(repo_root: Path) -> frozenset[str]:
    return _discovered_module_index_files(repo_root)


def bootstrap_policy_yaml(prefix: str) -> str:
    """Synthetic-repo defaults only — consumer manifests must declare these explicitly."""
    return (
        "policy:\n"
        "  constants_headers: [limits.h, board_config.h, config.h]\n"
        "  nolint_allowed: null\n"
        "  overrides:\n"
        "    clang-format: {add: null, remove: null, by_compile_db: null}\n"
        "    clang-tidy-c: {add: null, remove: null, by_compile_db: null}\n"
        "    clang-tidy-cxx: {add: null, remove: null, by_compile_db: null}\n"
        "    clang-tidy-shared-c-cxx: {add: null, remove: null, by_compile_db: null}\n"
        "    clang-tidy-unsafe-c: {add: null, remove: null, by_compile_db: null}\n"
        "    clang-tidy-unsafe-cxx: {add: null, remove: null, by_compile_db: null}\n"
        "    cppcheck: {add: null, remove: null, by_compile_db: null}\n"
        "    openssf-hardening: {add: null, remove: null, by_compile_db: null}\n"
        "  resource_lifetime: null\n"
        "  shared_c_cxx_source_roots: null\n"
        "  unsafe_api:\n"
        f"    header: {prefix}_null.h\n"
        "    include_headers: [attrs.h, mem_util.h]\n"
    )


def constants_header_basenames(repo_root: Path) -> frozenset[str]:
    """Project-wide cap/constant headers (magic-literals + module-index exclusions)."""
    raw = _policy(repo_root).get("constants_headers")
    if isinstance(raw, list) and raw:
        return _str_set(raw)
    raise ValueError(
        f"{manifest_path(repo_root)}: policy.constants_headers is required (no kit default)"
    )


def index_skip_stems(repo_root: Path) -> frozenset[str]:
    """Auto-derived: constants_headers, unsafe_api wrappers, and fixed prefix stems."""
    stems = {Path(name).stem for name in constants_header_basenames(repo_root)}
    prefix = project_prefix(repo_root)
    stems |= {f"{prefix}_null", f"{prefix}_parse"}
    for rel in unsafe_wrapper_rel_paths(repo_root):
        stems.add(Path(rel).stem)
    return frozenset(stems)


def canonical_bounds_headers(repo_root: Path) -> frozenset[str]:
    return constants_header_basenames(repo_root)


def magic_literal_constants_header_basenames(repo_root: Path) -> frozenset[str]:
    index = canonical_index_files(repo_root)
    headers = {name for name in index if name.endswith((".h", ".hpp"))}
    return headers | canonical_bounds_headers(repo_root)


def canonical_null_header(repo_root: Path) -> str:
    block = _unsafe_api(repo_root)
    value = block.get("header", block.get("null_header"))
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ValueError(
        f"{manifest_path(repo_root)}: policy.unsafe_api.header is required (no kit default)"
    )


def _normalize_root_prefix(root: str) -> str:
    root = root.rstrip("/")
    return f"{root}/"


@dataclass(frozen=True)
class LicenseHeaderKind:
    style: str


def license_header_classify(path: Path) -> LicenseHeaderKind | None:
    """Return SPDX header style for a path, or None when the file is out of scope."""
    name = path.name
    suf = path.suffix.lower()
    if name in {"Makefile", "GNUmakefile", "makefile"}:
        return LicenseHeaderKind("hash")
    if name == "CMakeLists.txt" or suf in {".cmake"}:
        return LicenseHeaderKind("hash")
    if name.startswith("Dockerfile") or name.endswith(".Dockerfile"):
        return LicenseHeaderKind("hash")
    if suf in {".sh", ".bash", ".mk", ".yaml", ".yml", ".py"}:
        return LicenseHeaderKind("hash")
    if suf in SOURCE_SUFFIXES | {INO_SUFFIX}:
        return LicenseHeaderKind("cpp")
    if suf == ".md":
        return LicenseHeaderKind("md")
    return None


def iter_cmake_lists_under_scan_scope(repo_root: Path) -> list[Path]:
    """Every CMakeLists.txt under scan.source_roots (all nested directories)."""
    repo_root = repo_root.resolve()
    skip = scan_walk_skip_dir_names(repo_root)
    paths: list[Path] = []
    for root_name in scan_source_roots(repo_root):
        base = repo_root / root_name
        if not base.is_dir():
            continue
        for path in walk_tree(base, skip):
            if path.name == "CMakeLists.txt":
                paths.append(path)
    return sorted(paths)


def discover_all_directories(repo_root: Path) -> tuple[str, ...]:
    """Every directory under scan.source_roots (respecting universal walk skips)."""
    repo_root = repo_root.resolve()
    skip = scan_walk_skip_dir_names(repo_root)
    dirs: set[str] = set()
    for root_name in scan_source_roots(repo_root):
        base = repo_root / root_name
        if not base.is_dir():
            continue
        for dirpath, dirnames, _ in os.walk(base, topdown=True):
            prune_walk_dirnames(dirnames, skip)
            rel = Path(dirpath).relative_to(repo_root).as_posix()
            if rel and rel != ".":
                dirs.add(rel)
    return tuple(sorted(dirs))


def discover_source_directories(
    repo_root: Path,
    *,
    suffixes: frozenset[str] = SOURCE_SUFFIXES,
) -> tuple[str, ...]:
    """Unique repo-relative directories containing scanned source files."""
    return job_source_directories(repo_root, JOB_SOURCE, suffixes=suffixes)


def discover_cppcheck_include_dirs(repo_root: Path) -> list[str]:
    """Include paths for cppcheck: policy public_headers_dir plus every source directory."""
    repo_root = repo_root.resolve()
    dirs: set[str] = set()
    prefix = public_headers_dir(repo_root)
    prefix_path = repo_root / prefix
    if prefix_path.is_dir():
        dirs.add(prefix)
        parent = Path(prefix).parent
        if parent != Path(".") and (repo_root / parent).is_dir():
            dirs.add(parent.as_posix())
    dirs.update(discover_source_directories(repo_root))
    return sorted(dirs)


def tests_path_prefixes(repo_root: Path) -> tuple[str, ...]:
    """Directories treated as test trees for bounds/hardening policy."""
    raw_list = _bounds(repo_root).get("tests_path_prefixes")
    if isinstance(raw_list, list) and raw_list:
        return tuple(_normalize_root_prefix(str(item).rstrip("/")) for item in raw_list if isinstance(item, str))
    raw = _bounds(repo_root).get("tests_path_prefix")
    if isinstance(raw, str) and raw.strip():
        return (_normalize_root_prefix(raw.strip().rstrip("/")),)
    discovered: list[str] = []
    for root in scan_source_roots(repo_root):
        if re.search(r"test", Path(root).name, re.IGNORECASE):
            discovered.append(_normalize_root_prefix(root))
    return tuple(discovered)


def _discovered_module_index_files(repo_root: Path) -> frozenset[str]:
    """Driver .c/.h pairs: headers under public_headers_dir with a matching .c anywhere in scan scope."""
    header_dir = repo_root / public_headers_dir(repo_root)
    if not header_dir.is_dir():
        return frozenset()
    c_stems = {
        path.stem
        for path in iter_job_paths(repo_root, JOB_SOURCE, suffixes=frozenset({".c"}))
    }
    names: set[str] = set()
    for header in header_dir.glob("*.h"):
        stem = header.stem
        if stem in index_skip_stems(repo_root) or stem.startswith("port_"):
            continue
        if stem in c_stems:
            names.add(header.name)
            names.add(f"{stem}.c")
    return frozenset(names)


def public_headers_dir(repo_root: Path) -> str:
    """Repo-relative directory of public/API headers (required; no kit default)."""
    scan = section(repo_root, "scan")
    value = scan.get("public_headers_dir")
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ValueError(
        f"{manifest_path(repo_root)}: scan.public_headers_dir is required (no kit default)"
    )


def null_include_headers(repo_root: Path) -> frozenset[str]:
    block = _unsafe_api(repo_root)
    raw = block.get("include_headers", block.get("null_include_headers"))
    if not isinstance(raw, list) or not raw:
        raise ValueError(
            f"{manifest_path(repo_root)}: policy.unsafe_api.include_headers is required "
            "(no kit default)"
        )
    return _str_set(raw)


def canonical_parse_impl_files(repo_root: Path) -> frozenset[str]:
    prefix = project_prefix(repo_root)
    candidates = {f"{prefix}_parse.c", f"{prefix}_parse.h"}
    found: set[str] = set()
    for path in iter_job_paths(repo_root, JOB_SOURCE):
        if path.name in candidates:
            found.add(path.name)
    return frozenset(found)


def _normalize_repo_rel_path(raw: str) -> str:
    return raw.strip().lstrip("./").replace("\\", "/")


def unsafe_wrapper_rel_paths(repo_root: Path) -> frozenset[str]:
    """Repo-relative paths exempt from unsafe-API enforcement (policy, cppcheck, clang-tidy).

    Authoritative: only ``policy.unsafe_api.wrapper_files`` grants an exemption.
    When it is absent the exemption set is empty (every source is enforced).
    """
    block = _unsafe_api(repo_root)
    raw = block.get("wrapper_files")
    if isinstance(raw, list) and raw:
        return frozenset(
            _normalize_repo_rel_path(item)
            for item in raw
            if isinstance(item, str) and item.strip()
        )
    return frozenset()


def path_is_unsafe_wrapper(path: Path, repo_root: Path) -> bool:
    repo_root = repo_root.resolve()
    try:
        rel = path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        return False
    return rel in unsafe_wrapper_rel_paths(repo_root)


def nolint_allowed_rel_paths(repo_root: Path) -> frozenset[str]:
    """Repo-relative paths where Google/clang-tidy NOLINT suppressions are permitted."""
    raw = _policy(repo_root).get("nolint_allowed")
    if not isinstance(raw, list) or not raw:
        return frozenset()
    return frozenset(
        _normalize_repo_rel_path(item)
        for item in raw
        if isinstance(item, str) and item.strip()
    )


def path_is_nolint_allowed(path: Path, repo_root: Path) -> bool:
    repo_root = repo_root.resolve()
    try:
        rel = path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        return False
    return rel in nolint_allowed_rel_paths(repo_root)


def resource_lifetime_pairs(repo_root: Path) -> tuple[dict[str, Any], ...]:
    """Acquire/release pairs from ``policy.resource_lifetime.pairs`` only (no auto-discovery)."""
    block = _policy(repo_root).get("resource_lifetime", {})
    if not isinstance(block, dict):
        return ()
    raw = block.get("pairs", [])
    if not isinstance(raw, list) or not raw:
        return ()
    pairs: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        acquire = item.get("acquire", [])
        release = item.get("release", [])
        pairs.append(
            {
                "label": str(item.get("label", "")),
                "acquire": tuple(str(x) for x in acquire if isinstance(x, str)),
                "release": tuple(str(x) for x in release if isinstance(x, str)),
                "canonical_files": frozenset(
                    str(x) for x in item.get("canonical_files", []) if isinstance(x, str)
                ),
                "hint": str(item.get("hint", "")),
            }
        )
    return tuple(pairs)


def bounds_path_prefixes(repo_root: Path) -> tuple[str, ...]:
    raw = _bounds(repo_root).get("path_prefixes", [])
    if isinstance(raw, list) and raw:
        out: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                continue
            out.append(_normalize_root_prefix(item.rstrip("/")))
        return tuple(out)
    prefixes: list[str] = []
    for root in scan_source_roots(repo_root):
        prefixes.append(_normalize_root_prefix(root))
    return tuple(prefixes)


def is_bounds_tu(repo_root: Path, rel_posix: str) -> bool:
    prefixes = bounds_path_prefixes(repo_root)
    if not prefixes:
        return False
    return any(rel_posix.startswith(prefix) for prefix in prefixes)


def bounded_recursion_annotation(repo_root: Path) -> str:
    value = _bounds(repo_root).get("bounded_recursion_annotation")
    if isinstance(value, str) and value:
        return value
    return f"{project_prefix_macro(repo_root)}_BOUNDED_RECURSION"


def static_assert_macro(repo_root: Path) -> str:
    value = _bounds(repo_root).get("static_assert_macro")
    if isinstance(value, str) and value:
        return value
    return f"{project_prefix_macro(repo_root)}_STATIC_ASSERT"


def stack_array_path_prefixes(repo_root: Path) -> tuple[str, ...]:
    raw = _bounds(repo_root).get("stack_array_path_prefixes", [])
    if isinstance(raw, list) and raw:
        return tuple(str(item).rstrip("/") for item in raw if isinstance(item, str))
    return tuple(prefix.rstrip("/") for prefix in bounds_path_prefixes(repo_root))


def stack_array_min(repo_root: Path) -> int:
    value = _bounds(repo_root).get("stack_array_min", 100)
    return int(value) if isinstance(value, (int, float)) else 100


_SAFE_HELPER_SUBSTRINGS = ("copy_", "try_", "span_ok", "parse_", "bounded_")


def _header_paths_for_names(repo_root: Path, names: frozenset[str]) -> list[Path]:
    wanted = set(names)
    paths: list[Path] = []
    for path in iter_job_paths(repo_root, JOB_SOURCE):
        if path.name in wanted:
            paths.append(path)
    return paths


def _wrapper_header_basenames(repo_root: Path) -> frozenset[str]:
    """Header basenames from policy.unsafe_api.wrapper_files."""
    names: set[str] = set()
    for rel in unsafe_wrapper_rel_paths(repo_root):
        if rel.endswith((".h", ".hpp")):
            names.add(Path(rel).name)
    return frozenset(names)


def _default_safe_indexing_helpers(repo_root: Path) -> frozenset[str]:
    header_names = _wrapper_header_basenames(repo_root) | canonical_parse_impl_files(repo_root)
    prefix = project_prefix(repo_root)
    fn_re = re.compile(rf"\b({re.escape(prefix)}_\w+)\s*\(")
    tokens: set[str] = set()
    for path in _header_paths_for_names(repo_root, header_names):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in fn_re.finditer(text):
            name = match.group(1)
            if any(part in name for part in _SAFE_HELPER_SUBSTRINGS):
                tokens.add(f"{name}(")
    return frozenset(tokens)


def safe_indexing_helpers(repo_root: Path) -> frozenset[str]:
    """Discover ``{c_api_prefix}_*`` span/copy/parse helper calls from canonical headers."""
    return _default_safe_indexing_helpers(repo_root)


def _dir_name_skipped(name: str, skip_patterns: frozenset[str]) -> bool:
    """True when a directory basename matches any skip pattern (literal or glob)."""
    return any(fnmatch.fnmatch(name, pattern) for pattern in skip_patterns)


def prune_walk_dirnames(
    dirnames: list[str],
    skip_dir_names: frozenset[str],
) -> None:
    dirnames[:] = [
        name
        for name in dirnames
        if not _dir_name_skipped(name, skip_dir_names)
        and not (name.startswith(".") and name != ".github")
    ]


def walk_tree(root: Path, skip_dir_names: frozenset[str]) -> list[Path]:
    root = root.resolve()
    if not root.exists():
        return []
    if root.is_file():
        return [root]
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        prune_walk_dirnames(dirnames, skip_dir_names)
        base = Path(dirpath)
        files.extend(base / name for name in filenames)
    return files


def _suffix_in_scope(path: Path, suffixes: frozenset[str] | None) -> bool:
    """Case-insensitive suffix membership so ``.C``/``.H``/``.CPP`` cannot bypass scans."""
    if suffixes is None:
        return True
    return path.suffix.lower() in suffixes


def _walk_repo_wide_paths(
    repo_root: Path,
    *,
    suffixes: frozenset[str] | None,
) -> list[Path]:
    """Repo-wide walk for docs/tooling paths outside scan.source_roots."""
    repo_root = repo_root.resolve()
    skip = scan_walk_skip_dir_names(repo_root)
    paths: list[Path] = []
    for path in walk_tree(repo_root, skip):
        if not _suffix_in_scope(path, suffixes):
            continue
        paths.append(path)
    from git_ignore import drop_gitignored_paths

    if scan_exclude_gitignore_enabled(repo_root):
        return drop_gitignored_paths(repo_root, sorted(paths))
    return sorted(paths)


def _walk_scoped_paths(
    repo_root: Path,
    *,
    suffixes: frozenset[str] | None = SOURCE_SUFFIXES,
) -> list[Path]:
    repo_root = repo_root.resolve()
    roots = scan_source_roots(repo_root)
    if not roots:
        raise ValueError(
            f"{manifest_path(repo_root)}: scan.source_roots must list at least one directory"
        )
    skip = scan_walk_skip_dir_names(repo_root)
    paths: list[Path] = []
    for root_name in roots:
        base = repo_root / root_name
        if not base.exists():
            continue
        for path in walk_tree(base, skip):
            if not _suffix_in_scope(path, suffixes):
                continue
            paths.append(path)
    from git_ignore import drop_gitignored_paths

    if scan_exclude_gitignore_enabled(repo_root):
        return drop_gitignored_paths(repo_root, sorted(paths))
    return sorted(paths)


def scan_job_profile(job: str) -> dict[str, object]:
    try:
        return _SCAN_JOB_PROFILES[job]
    except KeyError as exc:
        known = ", ".join(sorted(_SCAN_JOB_PROFILES))
        raise ValueError(f"unknown scan job {job!r} (known: {known})") from exc


def read_paths_file(paths_file: Path, repo_root: Path) -> list[Path]:
    """Load scan-paths output: repo-relative lines → sorted absolute paths (resolve once).

    Gitignore and ``scan.source_roots`` are applied upstream by ``scan-paths``;
    this function only validates and resolves to absolute paths under ``repo_root``.
    """
    repo_root = repo_root.resolve()
    paths: list[Path] = []
    for raw in paths_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if Path(line).is_absolute():
            raise ValueError(f"{paths_file}: absolute path not allowed: {line}")
        resolved = (repo_root / line).resolve()
        if resolved != repo_root and repo_root not in resolved.parents:
            raise ValueError(f"{paths_file}: path escapes repo root: {line}")
        paths.append(resolved)
    return sorted(paths)


def iter_job_paths(
    repo_root: Path,
    job: str,
    *,
    suffixes: frozenset[str] | None = None,
) -> list[Path]:
    """Central file list for a lint job; applies wrapper_files and nolint_allowed exclusions."""
    repo_root = repo_root.resolve()
    if job == JOB_CMAKE:
        return iter_cmake_lists_under_scan_scope(repo_root)

    profile = scan_job_profile(job)
    effective_suffixes = suffixes if suffixes is not None else profile["suffixes"]  # type: ignore[assignment]
    if job in _REPO_WIDE_SCAN_JOBS:
        paths = _walk_repo_wide_paths(repo_root, suffixes=effective_suffixes)
    else:
        paths = _walk_scoped_paths(repo_root, suffixes=effective_suffixes)
    if profile.get("exclude_unsafe_wrappers"):
        wrappers = unsafe_wrapper_rel_paths(repo_root)
        if wrappers:
            paths = [
                path
                for path in paths
                if path.relative_to(repo_root).as_posix() not in wrappers
            ]
    if profile.get("exclude_nolint_allowed"):
        allowed = nolint_allowed_rel_paths(repo_root)
        if allowed:
            paths = [
                path
                for path in paths
                if path.relative_to(repo_root).as_posix() not in allowed
            ]
    if job == JOB_LICENSE:
        paths = [path for path in paths if license_header_classify(path) is not None]
        # Dialed/kit-generated OpenSSF cmake: fail-on-change rewrite keeps them in sync.
        paths = [
            path
            for path in paths
            if not _is_generated_openssf_cmake_module(path, repo_root)
        ]
    return paths


def _is_generated_openssf_cmake_module(path: Path, repo_root: Path) -> bool:
    try:
        rel = path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return False
    if not rel.startswith("cmake/"):
        return False
    name = path.name
    return (
        name == "Hardening.cmake"
        or name == "CompilerHardeningProbes.cmake"
        or (name.startswith("Hardening.by-") and name.endswith(".cmake"))
        or (name.startswith("Hardening.flags.by-") and name.endswith(".mk"))
    )


def job_source_directories(
    repo_root: Path,
    job: str,
    *,
    suffixes: frozenset[str] | None = None,
) -> tuple[str, ...]:
    """Unique repo-relative directories containing files for a scan job."""
    dirs: set[str] = set()
    repo_root = repo_root.resolve()
    for path in iter_job_paths(repo_root, job, suffixes=suffixes):
        rel_dir = path.parent.relative_to(repo_root).as_posix()
        if rel_dir:
            dirs.add(rel_dir)
    return tuple(sorted(dirs))


def filter_compile_commands_excluding_wrappers(repo_root: Path, db: Path) -> Path:
    """Return compile_commands.json path with policy.unsafe_api.wrapper_files entries removed."""
    import json

    wrappers = unsafe_wrapper_rel_paths(repo_root)
    if not wrappers:
        return db
    data = json.loads(db.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return db
    repo_root = repo_root.resolve()
    filtered: list[dict] = []
    for entry in data:
        file_raw = entry.get("file")
        if not isinstance(file_raw, str):
            continue
        file_path = Path(file_raw)
        try:
            rel = file_path.resolve().relative_to(repo_root).as_posix()
        except ValueError:
            rel = file_path.as_posix()
        if rel in wrappers:
            continue
        filtered.append(entry)
    if len(filtered) == len(data):
        return db
    out = db.parent / f"cppcheck-filtered.{db.name}"
    out.write_text(json.dumps(filtered, indent=2), encoding="utf-8")
    return out


def _path_under_source_root(rel_posix: str, root: str) -> bool:
    if root in (".", ""):
        return True
    return rel_posix == root or rel_posix.startswith(f"{root}/")


def path_in_scan_scope(rel: Path | str, repo_root: Path) -> bool:
    """True when a repo-relative path is under scan.source_roots and not gitignored."""
    repo_root = repo_root.resolve()
    rel_path = Path(rel)
    rel_posix = rel_path.as_posix()
    roots = scan_source_roots(repo_root)
    if not roots:
        return False
    if not any(_path_under_source_root(rel_posix, root) for root in roots):
        return False
    if not scan_exclude_gitignore_enabled(repo_root):
        return True
    from git_ignore import git_repo_available, path_gitignored

    if git_repo_available(repo_root):
        return not path_gitignored(repo_root, rel_posix)
    if any(
        _dir_name_skipped(part, scan_walk_skip_dir_names(repo_root))
        for part in rel_path.parts
    ):
        return False
    return True


def bootstrap_scan_manifest(
    repo_root: Path,
    *,
    source_roots: tuple[str, ...] = ("core", "port", "include", "userspace", "tests", "esp-idf"),
) -> None:
    """Ensure synthetic test repos have scan.source_roots in the consumer manifest."""
    manifest = repo_root / ".github" / "lint-c-cpp.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    prefix = project_prefix(repo_root)
    if manifest.is_file():
        try:
            import yaml
        except ImportError:
            yaml = None  # type: ignore[assignment]
        if yaml is not None:
            data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                data = {}
            scan = data.setdefault("scan", {})
            if not isinstance(scan, dict):
                scan = {}
                data["scan"] = scan
            changed = False
            if not scan_source_roots(repo_root):
                scan["source_roots"] = list(source_roots)
                changed = True
            policy = data.setdefault("policy", {})
            if not isinstance(policy, dict):
                policy = {}
                data["policy"] = policy
                changed = True
            if "constants_headers" not in policy:
                policy_data = yaml.safe_load(bootstrap_policy_yaml(prefix))["policy"]
                for key, value in policy_data.items():
                    if key not in policy:
                        policy[key] = value
                        changed = True
                        continue
                    if key == "unsafe_api" and isinstance(value, dict):
                        block = policy.setdefault("unsafe_api", {})
                        if not isinstance(block, dict):
                            block = {}
                            policy["unsafe_api"] = block
                        for sub_key, sub_value in value.items():
                            if sub_key not in block:
                                block[sub_key] = sub_value
                                changed = True
            if changed:
                manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
            return
    roots_yaml = ", ".join(source_roots)
    manifest.write_text(
        "scan:\n"
        f"  c_api_prefix: {prefix}\n"
        f"  c_macro_prefix: {project_prefix_macro(repo_root)}\n"
        f"  public_headers_dir: include/{prefix}\n"
        f"  exclude_gitignore: true\n"
        f"  source_roots: [{roots_yaml}]\n"
        f"{bootstrap_policy_yaml(prefix)}",
        encoding="utf-8",
    )


def scan_scope_summary(repo_root: Path) -> dict[str, object]:
    """Resolved scan scope from .github/lint-c-cpp.yaml for CI and debugging."""
    return {
        "source_roots": list(scan_source_roots(repo_root)),
        "source_directories": list(discover_source_directories(repo_root)),
        "all_directories": list(discover_all_directories(repo_root)),
        "walk_skip_dir_names": sorted(scan_walk_skip_dir_names(repo_root)),
        "exclude_gitignore": scan_exclude_gitignore_enabled(repo_root),
        "scan_jobs": {
            job: {
                "exclude_unsafe_wrappers": bool(profile.get("exclude_unsafe_wrappers")),
                "exclude_nolint_allowed": bool(profile.get("exclude_nolint_allowed")),
                "suffixes": (
                    sorted(profile["suffixes"])  # type: ignore[arg-type]
                    if profile.get("suffixes") is not None
                    else None
                ),
            }
            for job, profile in sorted(_SCAN_JOB_PROFILES.items())
        },
        "unsafe_api_scan_steps": sorted(UNSAFE_API_SCAN_STEPS),
        "unsafe_wrapper_files": sorted(unsafe_wrapper_rel_paths(repo_root)),
        "nolint_allowed_files": sorted(nolint_allowed_rel_paths(repo_root)),
        "nolint_enforced_source_count": len(iter_job_paths(repo_root, JOB_NOLINT)),
        "unsafe_enforced_source_count": len(iter_job_paths(repo_root, JOB_UNSAFE_API)),
    }


def is_canonical_index_file(path: Path, repo_root: Path) -> bool:
    return path.name in canonical_index_files(repo_root)


def _mask_comments_and_strings(text: str, *, mask_strings: bool = True) -> str:
    """Neutralize comments (and, by default, string/char literals) in one pass.

    Comment bodies are replaced with spaces. When ``mask_strings`` is true, string
    and char-literal interiors are also blanked (delimiters kept); when false their
    contents are preserved verbatim (used by include scanners, whose header token
    ``"path"`` must survive) while the pass still tracks string state so a ``/*``
    inside a string never opens a comment. Length and newlines are preserved
    exactly so ``line_number_at`` and match offsets map 1:1 onto the original text.

    A single left-to-right pass is required: a regex that strips block comments
    before strings lets a string literal containing ``/*`` open a fake comment that
    hides real code (and vice-versa).
    """
    normal, line_comment, block_comment, string_lit, char_lit = range(5)
    state = normal
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == normal:
            if c == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = line_comment
            elif c == "/" and nxt == "*":
                out.append("  ")
                i += 2
                state = block_comment
            elif c == '"':
                out.append('"')
                i += 1
                state = string_lit
            elif c == "'":
                out.append("'")
                i += 1
                state = char_lit
            else:
                out.append(c)
                i += 1
        elif state == line_comment:
            if c == "\n":
                out.append("\n")
                state = normal
            else:
                out.append(" ")
            i += 1
        elif state == block_comment:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = normal
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        else:  # string_lit or char_lit
            closer = '"' if state == string_lit else "'"
            if c == "\\":
                if mask_strings:
                    out.append(" ")
                    if i + 1 < n:
                        out.append("\n" if nxt == "\n" else " ")
                else:
                    out.append(c)
                    if i + 1 < n:
                        out.append(nxt)
                i += 2
            elif c == closer:
                out.append(closer)
                i += 1
                state = normal
            else:
                if mask_strings:
                    out.append("\n" if c == "\n" else " ")
                else:
                    out.append(c)
                i += 1
    return "".join(out)


def strip_comments_and_strings(text: str) -> str:
    return _mask_comments_and_strings(text)


def blank_comments_and_strings(text: str) -> str:
    return _mask_comments_and_strings(text)


def strip_comments_only(text: str) -> str:
    """Length-preserving comment removal that keeps string/char contents intact.

    String-aware, so a ``/*`` inside a string literal does not open a comment.
    Use for include scanners where the ``"header"`` token must be preserved.
    """
    return _mask_comments_and_strings(text, mask_strings=False)


def comment_view(text: str) -> str:
    """Length-preserving view keeping only comment bodies; code/strings become spaces.

    The inverse of :func:`strip_comments_only`: string-aware and multi-line-block
    aware, so a token only matches if it truly sits inside a comment (not inside a
    string literal, and even when the block comment spans several lines).
    """
    normal, line_comment, block_comment, string_lit, char_lit = range(5)
    state = normal
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == normal:
            if c == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = line_comment
            elif c == "/" and nxt == "*":
                out.append("  ")
                i += 2
                state = block_comment
            elif c == '"':
                out.append(" ")
                i += 1
                state = string_lit
            elif c == "'":
                out.append(" ")
                i += 1
                state = char_lit
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif state == line_comment:
            if c == "\n":
                out.append("\n")
                state = normal
            else:
                out.append(c)
            i += 1
        elif state == block_comment:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = normal
            else:
                out.append(c)
                i += 1
        else:  # string_lit or char_lit
            closer = '"' if state == string_lit else "'"
            if c == "\\":
                out.append(" ")
                if i + 1 < n:
                    out.append("\n" if nxt == "\n" else " ")
                i += 2
            elif c == closer:
                out.append(" ")
                i += 1
                state = normal
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
    return "".join(out)


def line_number_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def is_preprocessor_at(text: str, pos: int) -> bool:
    line_start = text.rfind("\n", 0, pos) + 1
    return text[line_start:pos].lstrip().startswith("#")
