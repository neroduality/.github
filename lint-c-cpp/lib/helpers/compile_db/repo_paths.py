#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Single normalization for scan paths, compile DB keys, and downstream audits.
# Every lint job that maps a filesystem path to a repo-relative source uses
# ``source_key()`` here -- not ad hoc ``Path.resolve()`` / string compares.

from __future__ import annotations

from pathlib import Path

_CONTAINER_PATH_PREFIXES = ("/src/", "/workspace/")


def _repo_rel_from_container_absolute(posix: str) -> str | None:
    for prefix in _CONTAINER_PATH_PREFIXES:
        if posix.startswith(prefix):
            return posix[len(prefix) :]
    return None


def _repo_rel_from_source_root_markers(posix: str, repo_root: Path) -> str | None:
    from consumer_manifest import load
    from scan_policy import scan_source_roots

    load(repo_root)
    for root in scan_source_roots(repo_root):
        marker = f"/{root}/"
        idx = posix.find(marker)
        if idx != -1:
            return posix[idx + 1 :]
    return None


def source_key(file_path: str | Path, repo_root: Path) -> str | None:
    """Stable repo-relative key for a source path under any absolute prefix."""
    repo_root = repo_root.resolve()
    path = Path(file_path)
    posix = path.as_posix()

    try:
        return path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        pass

    container_rel = _repo_rel_from_container_absolute(posix)
    if container_rel is not None:
        return container_rel

    return _repo_rel_from_source_root_markers(posix, repo_root)


def foreign_repo_prefix_for_file(file_path: str | Path, repo_root: Path) -> str | None:
    """Absolute prefix to rewrite when a compile DB was generated under another root."""
    rel = source_key(file_path, repo_root)
    if rel is None:
        return None
    posix = Path(file_path).as_posix()
    if not posix.endswith(rel):
        return None
    try:
        Path(file_path).resolve().relative_to(repo_root.resolve())
        return None
    except ValueError:
        pass
    prefix = posix[: -len(rel)].rstrip("/")
    return prefix or None


def detect_foreign_repo_prefix(entries: list[dict], repo_root: Path) -> str | None:
    """Shortest foreign checkout root shared by compile DB rows (never a nested subdir)."""
    prefixes: list[str] = []
    for entry in entries:
        file_name = entry.get("file")
        if not isinstance(file_name, str):
            continue
        prefix = foreign_repo_prefix_for_file(file_name, repo_root)
        if prefix:
            prefixes.append(prefix)
    if not prefixes:
        return None
    return min(prefixes, key=lambda value: (len(value), value))


def rebase_absolute_paths(text: str, *, foreign_prefix: str, repo_root: Path) -> str:
    repo = repo_root.resolve().as_posix()
    foreign = foreign_prefix.rstrip("/")
    return text.replace(foreign, repo) if foreign in text else text
