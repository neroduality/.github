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
# Single loader for consumer .github/lint-c-cpp.yaml — kit scripts read config here only.

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

_MANIFEST_NAME = "lint-c-cpp.yaml"

# Ordered kit vocabulary for lint.sh sections (fail-closed allowlist in consumer manifest).
KNOWN_LINT_JOBS_ORDERED: tuple[str, ...] = (
    "license",
    "yamllint",
    "markdownlint",
    "format",
    "openssf",
    "compile_db",
    "clang_tidy",
    "banned_cxx_heap",
    "banned_libc_io",
    "null_nodiscard",
    "relative_includes",
    "duplicate_includes",
    "shared_constant_dupes",
    "magic_literals",
    "guard_clause_style",
    "pointer_bounds",
    "raii_lifetime",
    "nolint_audit",
    "spec_traceability",
    "cppcheck",
    "firmware_compile_db",
)
KNOWN_LINT_JOBS: frozenset[str] = frozenset(KNOWN_LINT_JOBS_ORDERED)


def manifest_path(repo_root: Path) -> Path:
    return repo_root.resolve() / ".github" / _MANIFEST_NAME


def load(repo_root: Path, *, required: bool = False) -> dict[str, Any]:
    path = manifest_path(repo_root)
    if not path.is_file():
        if required:
            raise FileNotFoundError(f"missing consumer lint manifest: {path}")
        return {}
    if yaml is None:
        raise RuntimeError("PyYAML is required (install the python3-yaml package)")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected mapping at top level")
    return data


def section(repo_root: Path, name: str) -> dict[str, Any]:
    data = load(repo_root)
    block = data.get(name)
    return block if isinstance(block, dict) else {}


def enabled_lint_jobs(repo_root: Path) -> frozenset[str]:
    """Jobs listed under ``enabled_lint_jobs`` (intersection with known vocabulary)."""
    raw = load(repo_root).get("enabled_lint_jobs")
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(
        item.strip()
        for item in raw
        if isinstance(item, str) and item.strip() in KNOWN_LINT_JOBS
    )


def lint_job_enabled(repo_root: Path, job: str) -> bool:
    return job in enabled_lint_jobs(repo_root)


def enabled_lint_jobs_ordered(repo_root: Path) -> tuple[str, ...]:
    enabled = enabled_lint_jobs(repo_root)
    return tuple(job for job in KNOWN_LINT_JOBS_ORDERED if job in enabled)


def enabled_lint_jobs_yaml_block() -> str:
    """Full allowlist YAML snippet for fixtures and consumer templates."""
    lines = ["enabled_lint_jobs:"]
    lines.extend(f"  - {job}" for job in KNOWN_LINT_JOBS_ORDERED)
    return "\n".join(lines) + "\n"


def _scan_prefixes(repo_root: Path) -> dict[str, Any]:
    return section(repo_root, "scan")


def project_prefix(repo_root: Path, default: str = "project") -> str:
    """Lowercase snake_case C API prefix (functions, include/ subtree)."""
    prefixes = _scan_prefixes(repo_root)
    for key in ("c_api_prefix", "prefix"):
        value = prefixes.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if load(repo_root):
        raise ValueError(f"{manifest_path(repo_root)}: scan.c_api_prefix is required")
    return default


def project_prefix_macro(repo_root: Path, default: str = "PROJECT") -> str:
    """Uppercase preprocessor macro prefix (NULL, NODISCARD, compile defs)."""
    prefixes = _scan_prefixes(repo_root)
    for key in ("c_macro_prefix", "prefix_macro"):
        value = prefixes.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if load(repo_root):
        raise ValueError(f"{manifest_path(repo_root)}: scan.c_macro_prefix is required")
    return default


_ALWAYS_EXCLUDED_DIRS = frozenset({".git"})


def scan_exclude_gitignore_enabled(repo_root: Path) -> bool:
    scan = section(repo_root, "scan")
    value = scan.get("exclude_gitignore", True)
    return value is not False


def _gitignore_dir_names(repo_root: Path) -> frozenset[str]:
    """Directory-name patterns to prune during scan walks (walk optimization only).

    When ``scan.exclude_gitignore`` is true and the repo is a git work tree,
    ``git check-ignore`` in ``git_ignore.path_gitignored`` is authoritative for
    final path scope; this set only avoids descending into obvious vendor trees.
    """
    names: set[str] = set(_ALWAYS_EXCLUDED_DIRS)
    gitignore = repo_root / ".gitignore"
    if not gitignore.is_file():
        return frozenset(names)

    for raw in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not line.endswith("/"):
            continue  # file pattern (or ambiguous) — not a directory prune
        line = line[:-1]
        line = re.sub(r"^(?:\./|/)", "", line)
        line = re.sub(r"^\*\*/", "", line)
        segment = line.split("/")[-1]
        if segment:
            names.add(segment)
    return frozenset(names)


def scan_walk_skip_dir_names(repo_root: Path) -> frozenset[str]:
    """Directory names pruned on every kit scan walk (VCS + .gitignore when enabled)."""
    if scan_exclude_gitignore_enabled(repo_root):
        return _gitignore_dir_names(repo_root)
    return frozenset(_ALWAYS_EXCLUDED_DIRS)


def scan_source_roots(repo_root: Path) -> tuple[str, ...]:
    scan = section(repo_root, "scan")
    raw = scan.get("source_roots", [])
    if not isinstance(raw, list):
        return ()
    return tuple(str(item) for item in raw if isinstance(item, str))


DEFAULT_CODESPELL_SOURCE_SUFFIXES = (".c", ".cpp", ".h", ".hpp", ".ino")  # .ino: typos only; not a TU
DEFAULT_CODESPELL_DOC_SUFFIXES = (".md", ".yaml", ".yml")

_DEFINE_HARDENING_RE = re.compile(r"define_hardening\s*\((.*?)\)", re.DOTALL | re.IGNORECASE)
_C_STANDARD_RE = re.compile(r"C_STANDARD\s+(\d+)", re.IGNORECASE)
_CXX_STANDARD_RE = re.compile(r"CXX_STANDARD\s+(\d+)", re.IGNORECASE)
_HARDENING_TARGET_RE = re.compile(r"TARGET\s+(\w+)", re.IGNORECASE)


def _parse_define_hardening_block(text: str) -> dict[str, str]:
    match = _DEFINE_HARDENING_RE.search(text)
    if not match:
        return {}
    block = match.group(1)
    parsed: dict[str, str] = {}
    target = _HARDENING_TARGET_RE.search(block)
    c_match = _C_STANDARD_RE.search(block)
    cxx_match = _CXX_STANDARD_RE.search(block)
    if target:
        parsed["interface_target"] = target.group(1)
    if c_match:
        parsed["c_standard"] = c_match.group(1)
    if cxx_match:
        parsed["cxx_standard"] = cxx_match.group(1)
    return parsed


def discover_hardening_cmake_roots(repo_root: Path) -> list[dict[str, str]]:
    """Find CMakeLists.txt under scan.source_roots that adopt cmake/Hardening.cmake."""
    from scan_policy import JOB_CMAKE

    repo_root = repo_root.resolve()
    roots: list[dict[str, str]] = []

    for path in resolve_scan_paths(JOB_CMAKE, repo_root=repo_root):
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        if not re.search(r"Hardening(?:\.by-[A-Za-z0-9_.-]+)?\.cmake", text):
            continue

        parsed = _parse_define_hardening_block(text) if "define_hardening(" in text else {}
        interface_target = parsed.get("interface_target", "hardening")
        if "define_hardening(" in text and interface_target not in text:
            continue

        roots.append(
            {
                "file": rel,
                "c_standard": parsed.get("c_standard", ""),
                "cxx_standard": parsed.get("cxx_standard", ""),
                "interface_target": interface_target,
            }
        )

    return sorted(roots, key=lambda item: item["file"])


_CPPCHECK_C_STD_BY_CMAKE: dict[int, str] = {
    89: "c89",
    99: "c99",
    11: "c11",
    17: "c17",
    23: "c23",
}
_CPPCHECK_CXX_STD_BY_CMAKE: dict[int, str] = {
    98: "c++98",
    11: "c++11",
    14: "c++14",
    17: "c++17",
    20: "c++20",
    23: "c++23",
}


def _cppcheck_std_for_cmake(language: str, cmake_standard: int) -> str | None:
    table = _CPPCHECK_C_STD_BY_CMAKE if language == "c" else _CPPCHECK_CXX_STD_BY_CMAKE
    if cmake_standard in table:
        return table[cmake_standard]
    known = sorted(table)
    for value in reversed(known):
        if cmake_standard >= value:
            return table[value]
    return None


def discover_project_cppcheck_standards(repo_root: Path) -> dict[str, str]:
    """Highest C_STANDARD / CXX_STANDARD from define_hardening() CMake roots."""
    c_values: list[int] = []
    cxx_values: list[int] = []
    for root in discover_hardening_cmake_roots(repo_root):
        raw_c = str(root.get("c_standard", "")).strip()
        raw_cxx = str(root.get("cxx_standard", "")).strip()
        if raw_c.isdigit():
            c_values.append(int(raw_c))
        if raw_cxx.isdigit():
            cxx_values.append(int(raw_cxx))
    out: dict[str, str] = {}
    if c_values:
        label = _cppcheck_std_for_cmake("c", max(c_values))
        if label:
            out["c"] = label
    if cxx_values:
        label = _cppcheck_std_for_cmake("cxx", max(cxx_values))
        if label:
            out["cxx"] = label
    return out


def _apply_cppcheck_standards(cfg: dict[str, Any], repo_root: Path) -> None:
    standards = cfg.get("standards")
    if not isinstance(standards, dict):
        standards = {}
    project = discover_project_cppcheck_standards(repo_root)
    for key in ("c", "cxx"):
        if project.get(key):
            standards[key] = project[key]
    cfg["standards"] = standards


def resolve_scan_paths(
    job: str,
    *,
    repo_root: Path,
) -> list[Path]:
    """Single registry API for consumer lint path lists."""
    from scan_policy import iter_job_paths

    return iter_job_paths(repo_root.resolve(), job)


def codespell_paths(repo_root: Path) -> list[str]:
    """Spell-check targets under scan.source_roots (docs + sources share one scope)."""
    from scan_policy import JOB_CODESPELL

    return [
        path.relative_to(repo_root.resolve()).as_posix()
        for path in resolve_scan_paths(JOB_CODESPELL, repo_root=repo_root)
    ]


def policy_block(repo_root: Path) -> dict[str, Any]:
    return section(repo_root, "policy")


_DEFAULT_CLANG_TIDY_MERGE_DIR = "build/clang-tidy-compile-db"


def compile_db_config(repo_root: Path) -> dict[str, Any]:
    block = section(repo_root, "compile_db")
    return block if isinstance(block, dict) else {}


def compile_db_is_configured(repo_root: Path) -> bool:
    return bool(compile_db_config(repo_root))


def _compile_db_list_entries(block: dict[str, Any], key: str) -> list[dict[str, Any]]:
    raw = block.get(key)
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _normalize_userspace_entry(item: dict[str, Any]) -> dict[str, Any] | None:
    compile_db = item.get("compile_commands_json")
    source = item.get("source")
    if not isinstance(compile_db, str) or not compile_db.strip():
        return None
    if not isinstance(source, str) or not source.strip():
        return None
    rel_source = source.strip()
    rel_compile_db = compile_db.strip()
    cmake_args = item.get("cmake_args")
    return {
        "name": rel_source.replace("/", "-"),
        "source": rel_source,
        "build_dir": Path(rel_compile_db).parent.as_posix(),
        "compile_commands_json": rel_compile_db,
        "cmake_args": (
            [str(arg).strip() for arg in cmake_args if isinstance(arg, str) and str(arg).strip()]
            if isinstance(cmake_args, list)
            else []
        ),
    }


def compile_db_userspace_entries(repo_root: Path) -> list[dict[str, Any]]:
    """Host CMake entries from ``compile_db.userspace`` list (manifest-only)."""
    block = compile_db_config(repo_root)
    projects: list[dict[str, Any]] = []
    for item in _compile_db_list_entries(block, "userspace"):
        normalized = _normalize_userspace_entry(item)
        if normalized is not None:
            projects.append(normalized)
    return projects


def compile_db_projects(repo_root: Path) -> list[dict[str, Any]]:
    return compile_db_userspace_entries(repo_root)


def _normalize_firmware_entry(item: dict[str, Any]) -> dict[str, Any] | None:
    compile_db = item.get("compile_commands_json")
    if not isinstance(compile_db, str) or not compile_db.strip():
        return None
    commands = item.get("commands")
    if not isinstance(commands, list):
        commands = []
    return {
        "compile_commands_json": compile_db.strip(),
        "commands": [str(cmd).strip() for cmd in commands if isinstance(cmd, str) and cmd.strip()],
    }


def compile_db_firmware_entries(repo_root: Path) -> list[dict[str, Any]]:
    """Firmware compile DB entries from ``compile_db.firmware`` list."""
    block = compile_db_config(repo_root)
    entries: list[dict[str, Any]] = []
    for item in _compile_db_list_entries(block, "firmware"):
        normalized = _normalize_firmware_entry(item)
        if normalized is not None:
            entries.append(normalized)
    return entries


def _cmake_lists_declares_project(cmake_lists: Path) -> bool:
    """True when CMakeLists.txt declares a top-level ``project()`` target."""
    try:
        text = cmake_lists.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(r"\bproject\s*\(", text))


def compile_db_firmware_tree_prefixes(repo_root: Path) -> frozenset[str]:
    """Repo-relative directory prefixes from ``compile_db.firmware`` compile_commands_json paths."""
    prefixes: set[str] = set()
    for entry in compile_db_firmware_entries(repo_root):
        rel = Path(str(entry["compile_commands_json"]))
        for index in range(1, len(rel.parts)):
            prefixes.add(Path(*rel.parts[:index]).as_posix())
    return frozenset(prefixes)


def _cmake_root_under_firmware_tree(rel: Path, prefixes: frozenset[str]) -> bool:
    rel_posix = rel.as_posix()
    return any(
        rel_posix == prefix or rel_posix.startswith(f"{prefix}/") for prefix in prefixes
    )


def _firmware_entry_covers_cmake_root(entry: dict[str, Any], cmake_root: Path) -> bool:
    root_posix = cmake_root.as_posix()
    json_posix = str(entry["compile_commands_json"])
    return json_posix == root_posix or json_posix.startswith(f"{root_posix}/")


def discover_cmake_project_roots(repo_root: Path) -> list[Path]:
    """Outermost CMake ``project()`` roots under scan.source_roots."""
    from scan_policy import JOB_CMAKE

    repo_root = repo_root.resolve()
    candidates = [
        path.parent.relative_to(repo_root) for path in resolve_scan_paths(JOB_CMAKE, repo_root=repo_root)
    ]
    candidates.sort(key=lambda rel: (len(rel.parts), rel.as_posix()))
    outermost: list[Path] = []
    for rel in candidates:
        rel_posix = rel.as_posix()
        if any(
            other != rel and rel_posix.startswith(f"{other.as_posix()}/")
            for other in candidates
        ):
            continue
        cmake_lists = repo_root / rel / "CMakeLists.txt"
        if _cmake_lists_declares_project(cmake_lists):
            outermost.append(rel)
    return sorted(outermost, key=lambda item: item.as_posix())


def compile_db_cmake_coverage_issues(repo_root: Path) -> list[str]:
    """Return errors when a discovered CMake root lacks a matching compile_db entry."""
    if not compile_db_is_configured(repo_root):
        return []
    load(repo_root)
    repo_root = repo_root.resolve()
    issues: list[str] = []
    firmware_prefixes = compile_db_firmware_tree_prefixes(repo_root)
    firmware_source_roots = firmware_compile_source_roots(repo_root)
    host_entries = {str(entry["source"]): entry for entry in compile_db_userspace_entries(repo_root)}
    firmware_entries = compile_db_firmware_entries(repo_root)

    for rel in discover_cmake_project_roots(repo_root):
        rel_posix = rel.as_posix()
        if firmware_prefixes and _cmake_root_under_firmware_tree(rel, firmware_prefixes):
            if not any(_firmware_entry_covers_cmake_root(entry, rel) for entry in firmware_entries):
                issues.append(
                    "discovered firmware CMake root "
                    f"{rel_posix!r} has no matching compile_db.firmware entry "
                    "(declare compile_commands_json under that tree)"
                )
            continue
        # Arduino-style: OpenSSF CMake adoption under firmware/ while compile_commands.json
        # lives out-of-tree (e.g. build/lint/firmware/). Covered by any firmware entry.
        if any(
            rel_posix == root or rel_posix.startswith(f"{root}/")
            for root in firmware_source_roots
        ):
            if not firmware_entries:
                issues.append(
                    "discovered firmware CMake root "
                    f"{rel_posix!r} has no compile_db.firmware entry"
                )
            continue
        if rel_posix not in host_entries:
            issues.append(
                "discovered host CMake root "
                f"{rel_posix!r} has no matching compile_db.userspace entry "
                f"(add `- compile_commands_json: …` with source: {rel_posix})"
            )
    return issues


def verify_compile_db_cmake_coverage(repo_root: Path) -> int:
    issues = compile_db_cmake_coverage_issues(repo_root)
    if not issues:
        return 0
    print("error: compile_db does not cover discovered CMake project roots:", file=sys.stderr)
    for issue in issues:
        print(f"  - {issue}", file=sys.stderr)
    return 1


def resolve_lint_kit(lint_kit: Path | None = None) -> Path:
    """Lint kit root (config/cppcheck-manifest.yaml and OpenSSF manifest live here)."""
    if lint_kit is not None:
        return lint_kit.resolve()
    import os

    for key in ("LINT_KIT",):
        raw = os.environ.get(key, "").strip()
        if raw:
            path = Path(raw).resolve()
            if path.is_dir():
                return path
    candidate = Path(__file__).resolve().parents[3]
    if (candidate / "config" / "cppcheck-manifest.yaml").is_file():
        return candidate
    raise FileNotFoundError("lint kit root not found (set LINT_KIT)")


def load_lint_kit_cppcheck_manifest(lint_kit: Path) -> dict[str, Any]:
    path = lint_kit.resolve() / "config" / "cppcheck-manifest.yaml"
    if yaml is None:
        raise RuntimeError("PyYAML is required (install the python3-yaml package)")
    if not path.is_file():
        raise FileNotFoundError(f"missing kit cppcheck manifest: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected mapping at top level")
    issues = validate_cppcheck_manifest(data)
    if issues:
        raise ValueError("\n".join(issues))
    return data


def _cppcheck_unknown_keys(mapping: dict[str, Any], allowed: frozenset[str], label: str) -> list[str]:
    unknown = sorted(key for key in mapping if key not in allowed)
    if not unknown:
        return []
    return [
        f"config/cppcheck-manifest.yaml: unknown {label}: {', '.join(unknown)} "
        f"(allowed: {', '.join(sorted(allowed))})"
    ]


_CPPCHECK_TOP_LEVEL_KEYS = frozenset({"cppcheck"})
_CPPCHECK_BLOCK_KEYS = frozenset({"cli", "docs_url", "passes"})
_CPPCHECK_PASS_KEYS = frozenset({"id", "scan_job"})
_CPPCHECK_CLI_KEYS = frozenset({"enable", "flags", "suppressions"})


def validate_cppcheck_manifest(data: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    issues.extend(_cppcheck_unknown_keys(data, _CPPCHECK_TOP_LEVEL_KEYS, "top-level keys"))
    block = data.get("cppcheck")
    if not isinstance(block, dict):
        issues.append("config/cppcheck-manifest.yaml: cppcheck must be a mapping")
        return issues
    issues.extend(_cppcheck_unknown_keys(block, _CPPCHECK_BLOCK_KEYS, "cppcheck fields"))
    raw_passes = block.get("passes")
    if not isinstance(raw_passes, list) or not raw_passes:
        issues.append("config/cppcheck-manifest.yaml: cppcheck.passes must be a non-empty list")
    else:
        for index, item in enumerate(raw_passes):
            if not isinstance(item, dict):
                issues.append(f"config/cppcheck-manifest.yaml: cppcheck.passes[{index}] must be a mapping")
                continue
            issues.extend(
                _cppcheck_unknown_keys(
                    item,
                    _CPPCHECK_PASS_KEYS,
                    f"cppcheck.passes[{index}] fields",
                )
            )
    cli = block.get("cli")
    if isinstance(cli, dict):
        issues.extend(_cppcheck_unknown_keys(cli, _CPPCHECK_CLI_KEYS, "cppcheck.cli fields"))
    return issues


def _normalize_cppcheck_passes(block: dict[str, Any]) -> list[dict[str, Any]]:
    from scan_policy import JOB_SOURCE

    raw = block.get("passes")
    if not isinstance(raw, list) or not raw:
        raise ValueError("cppcheck.passes must be a non-empty list in config/cppcheck-manifest.yaml")
    allowed_jobs = frozenset({JOB_SOURCE})
    passes: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"cppcheck.passes[{index}] must be a mapping")
        pass_id = str(item.get("id", "")).strip()
        scan_job = str(item.get("scan_job", "")).strip()
        if not pass_id:
            raise ValueError(f"cppcheck.passes[{index}].id is required")
        if scan_job not in allowed_jobs:
            raise ValueError(
                f"cppcheck.passes[{index}].scan_job must be one of "
                f"{sorted(allowed_jobs)!r}, got {scan_job!r}"
            )
        passes.append({"id": pass_id, "scan_job": scan_job})
    return passes


def _lint_kit_cppcheck_defaults(lint_kit: Path) -> dict[str, Any]:
    block = load_lint_kit_cppcheck_manifest(lint_kit).get("cppcheck", {})
    if not isinstance(block, dict):
        block = {}
    cli = block.get("cli", {})
    if not isinstance(cli, dict):
        cli = {}
    return {
        "passes": _normalize_cppcheck_passes(block),
        "dir_scan": False,
        "dir_scan_suffixes": [".c", ".cpp"],
        "standards": {
            "c": "c11",
            "cxx": "c++17",
        },
        "flags": [str(item) for item in cli.get("flags", []) if isinstance(item, str)],
        "enable": [str(item) for item in cli.get("enable", []) if isinstance(item, str)],
        "suppressions": [str(item) for item in cli.get("suppressions", []) if isinstance(item, str)],
    }


def _default_cppcheck_include_dirs(repo_root: Path) -> list[str]:
    from scan_policy import discover_cppcheck_include_dirs

    return discover_cppcheck_include_dirs(repo_root)


def _default_cppcheck_config(repo_root: Path, *, lint_kit: Path | None = None) -> dict[str, Any]:
    kit = resolve_lint_kit(lint_kit)
    merged = _lint_kit_cppcheck_defaults(kit)
    _apply_cppcheck_standards(merged, repo_root)
    projects = compile_db_projects(repo_root)
    merged["include_dirs"] = _default_cppcheck_include_dirs(repo_root)
    merged["compile_db_from"] = [str(item.get("name")) for item in projects if item.get("name")]
    return merged


def shared_c_cxx_source_roots(repo_root: Path) -> tuple[str, ...]:
    """Repo-relative roots whose C++ TUs use ``.clang-tidy-shared-c-cxx`` (C interop surface).

    All ``.c`` still uses ``.clang-tidy-c``. Host-only C++ stays on ``.clang-tidy-cxx``.
    """
    policy = section(repo_root, "policy")
    if not isinstance(policy, dict):
        return ()
    roots = policy.get("shared_c_cxx_source_roots", [])
    if not isinstance(roots, list):
        return ()
    return tuple(
        Path(str(item).strip()).as_posix()
        for item in roots
        if isinstance(item, str) and item.strip()
    )


# Backward-compatible alias used by compile-DB firmware template preference.
def clang_tidy_firmware_source_roots(repo_root: Path) -> tuple[str, ...]:
    return shared_c_cxx_source_roots(repo_root)


def _default_clang_tidy_overlays(repo_root: Path) -> list[dict[str, Any]]:
    from scan_policy import JOB_SOURCE

    if not resolve_scan_paths(JOB_SOURCE, repo_root=repo_root):
        return []
    shared_roots = list(shared_c_cxx_source_roots(repo_root))
    overlays: list[dict[str, Any]] = [
        {
            "id": "c",
            "language": "c",
            "config": ".clang-tidy-c",
            "suffixes": [".c"],
        },
        {
            "id": "cxx",
            "language": "cxx",
            "config": ".clang-tidy-cxx",
            "suffixes": [".cpp", ".cc", ".cxx"],
        },
    ]
    if not shared_roots:
        return overlays
    # Host C++ keeps strict .clang-tidy-cxx; shared C/C++ interop C++ uses kit shared config.
    overlays[1]["exclude_paths"] = shared_roots
    overlays.append(
        {
            "id": "shared-c-cxx",
            "language": "cxx",
            "config": ".clang-tidy-shared-c-cxx",
            "suffixes": [".cpp", ".cc", ".cxx"],
            "paths": shared_roots,
        }
    )
    return overlays


def _default_clang_tidy_unsafe_overlays(repo_root: Path) -> list[dict[str, Any]]:
    from scan_policy import JOB_UNSAFE_API

    if not resolve_scan_paths(JOB_UNSAFE_API, repo_root=repo_root):
        return []
    return [
        {
            "id": "unsafe-c",
            "language": "c",
            "config": ".clang-tidy-unsafe-c",
            "suffixes": [".c"],
        },
        {
            "id": "unsafe-cxx",
            "language": "cxx",
            "config": ".clang-tidy-unsafe-cxx",
            "suffixes": [".cpp", ".cc", ".cxx"],
        },
    ]


def clang_tidy_unsafe_overlays(repo_root: Path) -> list[dict[str, Any]]:
    return _default_clang_tidy_unsafe_overlays(repo_root)


def clang_tidy_merge_build_dir(repo_root: Path) -> str:
    return _DEFAULT_CLANG_TIDY_MERGE_DIR


# POSIX / Linux UAPI model: shared project headers are a C surface (C naming, typedef,
# extern "C"). C++ may include them but must not re-style them under C++ clang-tidy rules.
# Extension-only: ``.h`` → c_compatible; ``.hpp``/``.hh``/``.hxx`` → cxx_only.
C_COMPATIBLE_HEADER_SUFFIXES = frozenset({".h"})
CXX_ONLY_HEADER_SUFFIXES = frozenset({".hpp", ".hh", ".hxx"})
HeaderRole = str  # "c_compatible" | "cxx_only"


def firmware_compile_source_roots(repo_root: Path) -> tuple[str, ...]:
    """Repo-relative roots that prefer cross/firmware compile templates.

    Union of:
      - ``policy.shared_c_cxx_source_roots`` except host unit-test trees (``tests/…``)
      - ``esp-idf`` when it is a ``scan.source_roots`` entry (LiFi / ESP-IDF pilots)

    ``tests/…`` may still use the shared-c-cxx clang-tidy overlay (C interop surface) via
    ``shared_c_cxx_source_roots``, but must keep host CMake compile commands.
    """
    from scan_policy import scan_source_roots

    roots: list[str] = []
    seen: set[str] = set()
    for root in shared_c_cxx_source_roots(repo_root):
        if root == "tests" or root.startswith("tests/"):
            continue
        if root not in seen:
            roots.append(root)
            seen.add(root)
    if "esp-idf" in scan_source_roots(repo_root) and "esp-idf" not in seen:
        roots.append("esp-idf")
    return tuple(roots)


def header_role_for_path(path: Path, repo_root: Path) -> HeaderRole:
    """Classify a header for clang-tidy reporting (C surface vs C++-only).

    Extension-only (POSIX/UAPI-aligned):
      ``.h``  → c_compatible (lint under C policy)
      ``.hpp``/``.hh``/``.hxx`` → cxx_only (lint under C++ policy)

    C++ surface must use ``.hpp``/``.hh``/``.hxx`` (no path-prefix overrides).
    """
    del repo_root  # role is extension-only
    suffix = path.suffix.lower()
    if suffix in CXX_ONLY_HEADER_SUFFIXES:
        return "cxx_only"
    if suffix in C_COMPATIBLE_HEADER_SUFFIXES:
        return "c_compatible"
    # Unknown header suffix: treat as C-compatible (safer for mixed APIs).
    return "c_compatible"


def iter_headers_for_role(
    scan_paths: list[Path],
    repo_root: Path,
    *,
    role: HeaderRole,
) -> list[Path]:
    """Scan headers whose role matches ``role`` (for dedicated C-header tidy pass)."""
    return sorted(
        path
        for path in scan_paths
        if path.suffix.lower()
        in (C_COMPATIBLE_HEADER_SUFFIXES | CXX_ONLY_HEADER_SUFFIXES)
        and header_role_for_path(path, repo_root) == role
    )


def clang_tidy_header_filter_regex(
    repo_root: Path,
    *,
    role: HeaderRole = "c_compatible",
) -> str:
    """Positive ``HeaderFilterRegex`` for one header role under ``scan.source_roots``.

    - ``c_compatible``: ``.h`` under ``source_roots``
    - ``cxx_only``: ``.hpp``/``.hh``/``.hxx`` under ``source_roots``

    C++ overlays must use ``cxx_only`` so shared ``.h`` C APIs are not re-styled as CamelCase
    when a ``.cpp`` TU includes them. Shared ``.h`` are reported under C config (C TUs and/or
    the dedicated ``-x c-header`` pass).
    """
    from scan_policy import scan_source_roots

    roots = scan_source_roots(repo_root)
    if not roots:
        return ".*"
    repo_root = repo_root.resolve()
    inner = "|".join(re.escape(str(root)) for root in roots)
    prefix = re.escape(str(repo_root))
    root_pat = rf"{prefix}/({inner})/"
    ext_pat = r"\.(hpp|hh|hxx)" if role == "cxx_only" else r"\.h"
    return rf"{root_pat}.*{ext_pat}$"


# Unambiguous C++ surface in a ``.h`` that is still classified c_compatible.
# Dual C/C++ headers that only use ``std::uintN_t`` are not matched — fix those in source.
# ``auto`` matches C++ deduction forms only (not C storage-class ``auto int x``).
_CXX_IN_C_HEADER_RE = re.compile(
    r"(?m)^[ \t]*(?:"
    r"namespace\s+\w|"
    r"class\s+\w|"
    r"template\s*<|"
    r"(?:public|private|protected)\s*:|"
    r"#\s*include\s*<"
    r"(?:c[a-z]+|string|string_view|vector|optional|functional|memory|map|set|array|deque|list)"
    r">|"
    r"using\s+\w|"
    r"enum\s+\w+\s*:|"
    r".*\b(?:noexcept|override|static_cast|reinterpret_cast|const_cast|dynamic_cast)\b|"
    r".*\b(?:const\s+auto\b|auto\s*[*&]|\bauto\s+\w+\s*=)|"
    r".*\bstd::(?:string|string_view|vector|optional|function|unique_ptr|shared_ptr|"
    r"map|set|array|deque|list)\b|"
    r".*=\s*delete\b"
    r")"
)


def _strip_c_comments_for_header_role_scan(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*?$", "", text, flags=re.M)


def cxx_in_c_compatible_header_violations(
    scan_paths: list[Path],
    repo_root: Path,
) -> list[str]:
    """Fail-closed: C++-only syntax in ``.h`` still classified ``c_compatible``.

    Pilots must rename C++ headers to ``.hpp``/``.hh``/``.hxx`` before the dedicated
    ``-x c-header`` pass analyzes those files as C.
    """
    repo_root = repo_root.resolve()
    from repo_paths import source_key

    violations: list[str] = []
    for path in iter_headers_for_role(scan_paths, repo_root, role="c_compatible"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            violations.append(f"{path}: unreadable ({exc})")
            continue
        if _CXX_IN_C_HEADER_RE.search(_strip_c_comments_for_header_role_scan(text)):
            rel = source_key(path, repo_root) or path.as_posix()
            violations.append(
                f"{rel}: C++ surface in .h classified c_compatible — "
                "rename to .hpp/.hh/.hxx"
            )
    return violations


def clang_tidy_header_filter_regex_for_overlay(
    repo_root: Path,
    overlay: dict[str, Any],
) -> str:
    """Pick HeaderFilterRegex from overlay language (c → c_compatible, cxx → cxx_only)."""
    language = str(overlay.get("language", "")).lower()
    if language in {"cxx", "c++"}:
        return clang_tidy_header_filter_regex(repo_root, role="cxx_only")
    return clang_tidy_header_filter_regex(repo_root, role="c_compatible")


def toolchain_block(repo_root: Path) -> dict[str, Any]:
    block = section(repo_root, "toolchain")
    return block if isinstance(block, dict) else {}


def spec_traceability_block(repo_root: Path) -> dict[str, Any]:
    block = section(repo_root, "spec_traceability")
    return block if isinstance(block, dict) else {}


def compile_db_required_compile_command_paths(repo_root: Path) -> list[tuple[str, Path]]:
    """Return ``(label, path)`` for every manifest-declared compile_commands.json."""
    repo_root = repo_root.resolve()
    if not compile_db_is_configured(repo_root):
        return []
    load(repo_root)
    required: list[tuple[str, Path]] = []
    for path in compile_db_firmware_compile_command_paths(repo_root):
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            rel = path
        required.append((f"firmware:{rel.as_posix()}", path))
    for project in compile_db_userspace_entries(repo_root):
        rel_compile_db = str(project["compile_commands_json"])
        required.append(
            (
                f"userspace:{project['source']}",
                (repo_root / rel_compile_db).resolve(),
            )
        )
    return required


def compile_db_firmware_compile_command_paths(repo_root: Path) -> list[Path]:
    """Repo-absolute paths to firmware compile_commands.json from the manifest."""
    repo_root = repo_root.resolve()
    paths: list[Path] = []
    for entry in compile_db_firmware_entries(repo_root):
        paths.append((repo_root / str(entry["compile_commands_json"])).resolve())
    return paths


def compile_db_firmware_build_commands(repo_root: Path) -> list[str]:
    """Shell commands from all ``compile_db.firmware`` list entries."""
    commands: list[str] = []
    for entry in compile_db_firmware_entries(repo_root):
        commands.extend(entry.get("commands", []))
    return commands


def firmware_diagnostics_gate_source_keys(repo_root: Path) -> frozenset[str]:
    """Deprecated no-op: ``-Werror*`` waivers require ``policy.overrides.openssf-hardening``."""
    del repo_root
    return frozenset()


def compile_db_firmware_supplies_compile_db(repo_root: Path) -> bool:
    return bool(compile_db_firmware_entries(repo_root))


def cppcheck_config(repo_root: Path, *, lint_kit: Path | None = None) -> dict[str, Any]:
    """Kit manifest + auto-discovered project paths; standards from highest define_hardening()."""
    return _default_cppcheck_config(repo_root, lint_kit=lint_kit)


def cppcheck_cli_common_args(
    cfg: dict[str, Any],
    *,
    lint_kit: Path,
    pass_cfg: dict[str, Any] | None = None,
    repo_root: Path | None = None,
) -> list[str]:
    """Shared cppcheck CLI flags from config/cppcheck-manifest.yaml (+ global overrides)."""
    del pass_cfg  # reserved for future per-pass dials
    args = [str(item) for item in cfg.get("flags", []) if isinstance(item, str)]
    enable = [str(item) for item in cfg.get("enable", []) if isinstance(item, str)]
    suppressions = [str(item) for item in cfg.get("suppressions", []) if isinstance(item, str)]
    if repo_root is not None:
        from policy_overrides import apply_cppcheck_cli_dials, global_override_dials

        add, remove = global_override_dials(repo_root, "cppcheck")
        enable, suppressions = apply_cppcheck_cli_dials(
            enable, suppressions, add=add, remove=remove
        )
    for category in enable:
        if category.strip():
            args.append(f"--enable={category}")
    for suppression in suppressions:
        if suppression.strip():
            args.append(f"--suppress={suppression}")
    del lint_kit
    return args


def clang_tidy_overlays(repo_root: Path) -> list[dict[str, Any]]:
    return _default_clang_tidy_overlays(repo_root)


def _shell_script_files(repo_root: Path) -> list[str]:
    from scan_policy import JOB_SHELL

    return sorted(
        path.relative_to(repo_root.resolve()).as_posix()
        for path in resolve_scan_paths(JOB_SHELL, repo_root=repo_root)
    )


def shell_script_paths(repo_root: Path) -> list[str]:
    return _shell_script_files(repo_root)


def toolchain_script(repo_root: Path) -> Path | None:
    block = toolchain_block(repo_root)
    rel = block.get("script")
    if not isinstance(rel, str) or not rel.strip():
        return None
    path = (repo_root / rel).resolve()
    return path if path.is_file() else None


def workflow_bare_vm_waivers(repo_root: Path) -> frozenset[tuple[str, str]]:
    block = section(repo_root, "workflow")
    raw = block.get("bare_vm_waivers", [])
    if not isinstance(raw, list):
        return frozenset()
    waivers: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        workflow = item.get("workflow")
        job = item.get("job")
        if isinstance(job, str) and job.strip().casefold() == "lint":
            continue
        if isinstance(workflow, str) and isinstance(job, str) and workflow.strip() and job.strip():
            waivers.add((workflow.strip(), job.strip()))
    return frozenset(waivers)


def spec_traceability_path(repo_root: Path) -> Path | None:
    block = spec_traceability_block(repo_root)
    rel = block.get("manifest")
    if isinstance(rel, str) and rel.strip():
        return repo_root / rel.strip()

    yamllint = section(repo_root, "yamllint")
    files = yamllint.get("files", []) if isinstance(yamllint.get("files"), list) else []
    for item in files:
        if isinstance(item, dict) and item.get("schema") == "spec_traceability":
            path = item.get("path")
            if isinstance(path, str):
                return repo_root / path
    return None


def yamllint_manifest_paths(repo_root: Path) -> tuple[list[Path], list[str]]:
    """Resolved paths from yamllint.files (authoritative when configured)."""
    yamllint = section(repo_root, "yamllint")
    if not isinstance(yamllint, dict):
        return [], []
    files = yamllint.get("files", [])
    if not isinstance(files, list) or not files:
        return [], []
    repo_root = repo_root.resolve()
    paths: list[Path] = []
    errors: list[str] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        rel = item.get("path")
        if not isinstance(rel, str) or not rel.strip():
            continue
        rel = rel.strip()
        path = repo_root / rel
        if not path.is_file():
            errors.append(f"yamllint.files path not found: {rel}")
            continue
        paths.append(path.resolve())
    return sorted(paths), errors


def cli_compile_db_projects(repo_root: Path) -> int:
    for project in compile_db_projects(repo_root):
        print(json.dumps(project, sort_keys=True))
    return 0


def cli_clang_tidy_overlays(repo_root: Path) -> int:
    for overlay in clang_tidy_overlays(repo_root):
        print(json.dumps(overlay, sort_keys=True))
    return 0


def cli_scan_source_roots(repo_root: Path) -> int:
    for item in scan_source_roots(repo_root):
        print(item)
    return 0


def cli_hardening_cmake_roots(repo_root: Path) -> int:
    for root in discover_hardening_cmake_roots(repo_root):
        print(json.dumps(root, sort_keys=True))
    return 0


def cli_scan_paths(repo_root: Path, job: str) -> int:
    root = repo_root.resolve()
    for path in resolve_scan_paths(job, repo_root=root):
        print(path.relative_to(root).as_posix())
    return 0


def cli_scan_config(repo_root: Path) -> int:
    from scan_policy import scan_scope_summary

    print(json.dumps(scan_scope_summary(repo_root), indent=2, sort_keys=True))
    return 0


def cli_scan_source_directories(repo_root: Path) -> int:
    from scan_policy import discover_source_directories

    for item in discover_source_directories(repo_root):
        print(item)
    return 0


def cli_scan_all_directories(repo_root: Path) -> int:
    from scan_policy import discover_all_directories

    for item in discover_all_directories(repo_root):
        print(item)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("compile-db-projects", help="Print compile_db entries as JSON lines")
    sub.add_parser("clang-tidy-overlays", help="Print auto-discovered clang-tidy overlays as JSON lines")
    sub.add_parser("scan-source-roots", help="Print scan.source_roots entries")
    sub.add_parser("hardening-cmake-roots", help="Print auto-discovered hardening CMake roots as JSON lines")
    scan_paths = sub.add_parser("scan-paths", help="Print repo-relative paths for a scan job profile")
    scan_paths.add_argument(
        "job",
        choices=(
            "source",
            "unsafe_api",
            "nolint",
            "markdown",
            "format_c",
            "yaml",
            "shell",
            "all_files",
            "codespell",
            "license",
            "cmake",
        ),
        help="Scan job from scan_policy (consumer repo)",
    )
    sub.add_parser("scan-config", help="Print resolved scan scope summary as JSON")
    sub.add_parser("scan-source-directories", help="Print directories containing scanned sources")
    sub.add_parser("scan-all-directories", help="Print every directory under scan.source_roots")
    sub.add_parser(
        "enabled-lint-jobs",
        help="Print enabled count, known count, then space-separated enabled job IDs",
    )

    args = parser.parse_args()
    repo = args.repo_root.resolve()
    if args.command == "scan-paths":
        return cli_scan_paths(repo, args.job)
    if args.command == "enabled-lint-jobs":
        ordered = enabled_lint_jobs_ordered(repo)
        print(f"{len(ordered)} {len(KNOWN_LINT_JOBS_ORDERED)}")
        print(" ".join(ordered))
        return 0
    handlers = {
        "compile-db-projects": cli_compile_db_projects,
        "clang-tidy-overlays": cli_clang_tidy_overlays,
        "scan-source-roots": cli_scan_source_roots,
        "hardening-cmake-roots": cli_hardening_cmake_roots,
        "scan-config": cli_scan_config,
        "scan-source-directories": cli_scan_source_directories,
        "scan-all-directories": cli_scan_all_directories,
    }
    return handlers[args.command](repo)


if __name__ == "__main__":
    raise SystemExit(main())
