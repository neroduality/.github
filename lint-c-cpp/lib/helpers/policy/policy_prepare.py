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

"""Central path preparation and PolicyConfig materialization (only place with path logic)."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from consumer_manifest import project_prefix, project_prefix_macro
from policy_config import (
    K_CANONICAL_NULL,
    K_CXX,
    K_HEADER,
    K_MAGIC_SHARED,
    K_STACK_ARRAY,
    K_TU,
    NullPolicy,
    PolicyConfig,
    RaiiPair,
)
from scan_policy import (
    bounded_recursion_annotation,
    canonical_bounds_headers,
    canonical_null_header,
    public_headers_dir as scan_public_headers_dir,
    is_canonical_index_file,
    magic_literal_constants_header_basenames,
    null_include_headers,
    resource_lifetime_pairs,
    safe_indexing_helpers,
    stack_array_min,
    stack_array_path_prefixes,
)

_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"})
_HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx"})
_TU_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})


def _include_dir_prefix(repo_root: Path) -> str:
    raw = scan_public_headers_dir(repo_root)
    if raw.startswith("include/"):
        return raw.split("include/", 1)[1]
    return raw


def _approved_null_includes(repo_root: Path) -> frozenset[str]:
    headers: set[str] = set(null_include_headers(repo_root))
    canon = canonical_null_header(repo_root)
    headers.add(canon)
    dir_prefix = _include_dir_prefix(repo_root)
    headers.add(f"{dir_prefix}/{canon}")
    for header in null_include_headers(repo_root):
        headers.add(f"{dir_prefix}/{header}")
    return frozenset(headers)


def _build_null_policy(repo_root: Path) -> NullPolicy:
    prefix_macro = project_prefix_macro(repo_root)
    null_macro = f"{prefix_macro}_NULL"
    nodiscard_macro = f"{prefix_macro}_NODISCARD"
    nodiscard = re.escape(nodiscard_macro)
    null_re = re.escape(null_macro)
    return NullPolicy(
        prefix_macro=prefix_macro,
        null_macro=null_macro,
        nodiscard_macro=nodiscard_macro,
        canonical_header=canonical_null_header(repo_root),
        null_includes=_approved_null_includes(repo_root),
        include_dir_prefix=_include_dir_prefix(repo_root),
        bool_head=re.compile(
            rf"^(?:\s*(?:{nodiscard}|\[\[nodiscard\]\])\s+)?"
            r"(?:static\s+inline\s+)?bool\s*$"
        ),
        bool_decl=re.compile(
            rf"(?:{nodiscard}|\[\[nodiscard\]\])\s+"
            r"(?:static\s+inline\s+)?bool\s+\w+\s*\("
            r"|"
            r"(?:static\s+inline\s+)?bool\s+\w+\s*\(",
            re.MULTILINE,
        ),
        nodiscard_on_field=re.compile(
            rf"{nodiscard}\s+(?:bool|\[\[nodiscard\]\]\s+bool)\s+\w+\s*\{{"
        ),
        null_define=re.compile(rf"#define\s+{null_re}\s+nullptr\b"),
        null_define_null=re.compile(rf"#define\s+{null_re}\s+NULL\b"),
        null_token=re.compile(rf"\b{null_re}\b"),
    )


def _spec_tracked_symbols(repo_root: Path) -> frozenset[str]:
    try:
        import yaml

        from consumer_manifest import spec_traceability_path
    except ImportError:
        return frozenset()
    path = spec_traceability_path(repo_root)
    if not path or not path.is_file():
        return frozenset()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    constants = data.get("constants")
    if not isinstance(constants, list):
        return frozenset()
    symbols: set[str] = set()
    for entry in constants:
        if isinstance(entry, dict):
            symbol = entry.get("symbol")
            if isinstance(symbol, str) and symbol.strip():
                symbols.add(symbol.strip())
    return frozenset(symbols)


def _build_raii_pairs(repo_root: Path) -> tuple[RaiiPair, ...]:
    pairs: list[RaiiPair] = []
    for pair in resource_lifetime_pairs(repo_root):
        pairs.append(
            RaiiPair(
                label=str(pair["label"]),
                hint=str(pair["hint"]),
                acquire_rx=tuple(re.compile(p) for p in pair["acquire"]),
                release_rx=tuple(re.compile(p) for p in pair["release"]),
                canonical_files=frozenset(
                    (repo_root / rel).resolve()
                    for rel in pair["canonical_files"]
                ),
            )
        )
    return tuple(pairs)


def _canonical_null_paths(repo_root: Path) -> frozenset[Path]:
    canon_name = canonical_null_header(repo_root)
    found: set[Path] = set()
    for path in _walk_manifest_paths(repo_root):
        if path.name == canon_name:
            found.add(path.resolve())
    return frozenset(found)


def _walk_manifest_paths(repo_root: Path) -> list[Path]:
    from scan_policy import iter_job_paths, JOB_SOURCE

    return iter_job_paths(repo_root, JOB_SOURCE)


def _stack_array_eligible(repo_root: Path, path: Path) -> bool:
    if path.suffix.lower() not in _TU_SUFFIXES:
        return False
    rel = path.relative_to(repo_root.resolve()).as_posix()
    for root in stack_array_path_prefixes(repo_root):
        if rel == root or rel.startswith(f"{root}/"):
            return True
    return False


def _assign_kinds(repo_root: Path, paths: list[Path]) -> dict[Path, frozenset[str]]:
    repo_root = repo_root.resolve()
    canon_null = _canonical_null_paths(repo_root)
    shared_magic = magic_literal_constants_header_basenames(repo_root)
    kinds: dict[Path, frozenset[str]] = {}
    for path in paths:
        resolved = path.resolve()
        roles: set[str] = set()
        suffix = path.suffix.lower()
        if suffix in _HEADER_SUFFIXES:
            roles.add(K_HEADER)
        if suffix in _CXX_SUFFIXES:
            roles.add(K_CXX)
        if suffix in _TU_SUFFIXES:
            roles.add(K_TU)
        if resolved in canon_null:
            roles.add(K_CANONICAL_NULL)
        if path.name in shared_magic:
            roles.add(K_MAGIC_SHARED)
        if _stack_array_eligible(repo_root, path):
            roles.add(K_STACK_ARRAY)
        kinds[resolved] = frozenset(roles)
    return kinds


def _cxx_only(_repo_root: Path, paths: list[Path]) -> list[Path]:
    return [path for path in paths if path.suffix.lower() in _CXX_SUFFIXES]


def _magic_literals_paths(repo_root: Path, paths: list[Path]) -> list[Path]:
    skip = canonical_bounds_headers(repo_root)
    return [path for path in paths if path.name not in skip]


def _pointer_bounds_paths(repo_root: Path, paths: list[Path]) -> list[Path]:
    return [path for path in paths if not is_canonical_index_file(path, repo_root)]


_SCRIPT_FILTERS: dict[str, Callable[[Path, list[Path]], list[Path]]] = {
    "banned_cxx_heap.py": _cxx_only,
    "magic_literals.py": _magic_literals_paths,
    "pointer_bounds.py": _pointer_bounds_paths,
}


def prepare_paths(script: str, repo_root: Path, paths: list[Path]) -> list[Path]:
    """Script-specific path list refinement after central scan-paths."""
    filter_fn = _SCRIPT_FILTERS.get(Path(script).name)
    if filter_fn is None:
        return sorted({path.resolve() for path in paths})
    return sorted({path.resolve() for path in filter_fn(repo_root, paths)})


def _load_license_header(repo_root: Path) -> str | None:
    manifest = repo_root / ".github" / "lint-c-cpp.yaml"
    if not manifest.is_file():
        return None
    try:
        import yaml
    except ImportError:
        return None
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    blob = data.get("license_header")
    return blob if isinstance(blob, str) and blob.strip() else None


def build_config(repo_root: Path, paths: list[Path]) -> PolicyConfig:
    repo_root = repo_root.resolve()
    resolved = sorted({path.resolve() for path in paths})
    path_labels = {path: path.relative_to(repo_root).as_posix() for path in resolved}
    return PolicyConfig(
        repo_root=repo_root,
        c_api_prefix=project_prefix(repo_root),
        c_macro_prefix=project_prefix_macro(repo_root),
        null_policy=_build_null_policy(repo_root),
        raii_pairs=_build_raii_pairs(repo_root),
        safe_indexing_helpers=safe_indexing_helpers(repo_root),
        spec_tracked_symbols=_spec_tracked_symbols(repo_root),
        stack_array_min=stack_array_min(repo_root),
        bounded_recursion_annotation=bounded_recursion_annotation(repo_root),
        kinds=_assign_kinds(repo_root, resolved),
        path_labels=path_labels,
        license_header=_load_license_header(repo_root),
    )
