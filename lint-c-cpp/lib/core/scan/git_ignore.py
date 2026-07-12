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

"""Authoritative gitignore checks via ``git check-ignore`` (not .gitignore regex parsing)."""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from pathlib import Path

_GIT_REPO_CACHE: dict[Path, bool] = {}
_ALWAYS_SKIP_DIR_NAMES = frozenset({".git"})


def clear_git_repo_cache() -> None:
    """Test hook: drop cached ``git_repo_available`` results."""
    _GIT_REPO_CACHE.clear()


def git_repo_available(repo_root: Path) -> bool:
    """True when ``repo_root`` is inside a git work tree and ``git`` is on PATH."""
    repo_root = repo_root.resolve()
    cached = _GIT_REPO_CACHE.get(repo_root)
    if cached is not None:
        return cached
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        _GIT_REPO_CACHE[repo_root] = False
        return False
    ok = proc.returncode == 0 and proc.stdout.strip() == "true"
    _GIT_REPO_CACHE[repo_root] = ok
    return ok


def _gitignore_dir_basename_patterns(repo_root: Path) -> frozenset[str]:
    """Directory basename patterns from ``.gitignore`` ``foo/`` lines (no-git fallback)."""
    names: set[str] = set(_ALWAYS_SKIP_DIR_NAMES)
    gitignore = repo_root / ".gitignore"
    if not gitignore.is_file():
        return frozenset(names)
    for raw in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not line.endswith("/"):
            continue
        line = line[:-1]
        line = re.sub(r"^(?:\./|/)", "", line)
        line = re.sub(r"^\*\*/", "", line)
        segment = line.split("/")[-1]
        if segment:
            names.add(segment)
    return frozenset(names)


def _path_matches_dir_basename_skip(rel_posix: str, patterns: frozenset[str]) -> bool:
    return any(
        any(fnmatch.fnmatch(part, pattern) for pattern in patterns)
        for part in Path(rel_posix).parts
    )


def _parse_check_ignore_stdout(raw: bytes) -> frozenset[str]:
    if not raw:
        return frozenset()
    return frozenset(item for item in raw.decode("utf-8", errors="replace").split("\0") if item)


def _basename_fallback_ignored(repo_root: Path, rel_paths: list[str]) -> frozenset[str]:
    patterns = _gitignore_dir_basename_patterns(repo_root)
    return frozenset(
        rel for rel in rel_paths if _path_matches_dir_basename_skip(rel, patterns)
    )


def paths_gitignored(repo_root: Path, rel_paths: list[str]) -> frozenset[str]:
    """Return repo-relative paths that ``git check-ignore`` matches.

    When git is unavailable, fail closed for ``.gitignore`` directory basenames
    (``third-party/``, ``build/``, …) so vendor trees are not treated as in-scope.
    """
    repo_root = repo_root.resolve()
    if not rel_paths:
        return frozenset()
    if not git_repo_available(repo_root):
        return _basename_fallback_ignored(repo_root, rel_paths)
    payload = "\0".join(rel_paths) + "\0"
    try:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "check-ignore",
                "--stdin",
                "-z",
            ],
            input=payload.encode("utf-8"),
            capture_output=True,
            check=False,
        )
    except OSError:
        return _basename_fallback_ignored(repo_root, rel_paths)
    if proc.returncode not in (0, 1):
        return _basename_fallback_ignored(repo_root, rel_paths)
    return _parse_check_ignore_stdout(proc.stdout)


def path_gitignored(repo_root: Path, rel: Path | str) -> bool:
    rel_posix = Path(rel).as_posix()
    return rel_posix in paths_gitignored(repo_root, [rel_posix])


def drop_gitignored_paths(repo_root: Path, paths: list[Path]) -> list[Path]:
    """Remove paths that gitignore policy excludes (check-ignore, or no-git basename fallback)."""
    repo_root = repo_root.resolve()
    if not paths:
        return paths
    rels: list[str] = []
    for path in paths:
        try:
            rels.append(path.relative_to(repo_root).as_posix())
        except ValueError:
            rels.append(path.as_posix())
    ignored = paths_gitignored(repo_root, rels)
    if not ignored:
        return paths
    return [path for path, rel in zip(paths, rels) if rel not in ignored]


def run_self_test() -> int:
    """Mocked batch parsing checks (no git subprocesses)."""
    from unittest.mock import patch

    ok = True
    root = Path("/fake/repo")

    parsed = _parse_check_ignore_stdout(b"third-party/vendor.c\x00")
    if parsed != frozenset({"third-party/vendor.c"}):
        print(f"git_ignore self-test FAIL: parse stdout -> {parsed}", file=sys.stderr)
        ok = False

    def fake_run(
        args: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
        if "rev-parse" in args:
            return subprocess.CompletedProcess(args, 0, stdout="true\n", stderr="")
        if "check-ignore" in args:
            raw = kwargs.get("input", b"")
            if not isinstance(raw, (bytes, bytearray)):
                raw = b""
            paths = [part for part in raw.decode("utf-8", errors="replace").split("\0") if part]
            ignored = [path for path in paths if path.startswith("third-party/")]
            stdout = ("\0".join(ignored) + "\0").encode("utf-8") if ignored else b""
            return subprocess.CompletedProcess(args, 0 if ignored else 1, stdout=stdout, stderr=b"")
        raise AssertionError(f"unexpected subprocess.run args: {args}")

    clear_git_repo_cache()
    with patch("subprocess.run", side_effect=fake_run):
        if not git_repo_available(root):
            print("git_ignore self-test FAIL: mocked git_repo_available", file=sys.stderr)
            ok = False
        ignored = paths_gitignored(root, ["third-party/vendor.c", "core/app.c"])
        if ignored != frozenset({"third-party/vendor.c"}):
            print(f"git_ignore self-test FAIL: paths_gitignored -> {ignored}", file=sys.stderr)
            ok = False
        kept = drop_gitignored_paths(
            root,
            [root / "core/app.c", root / "third-party/vendor.c"],
        )
        if [path.as_posix() for path in kept] != ["/fake/repo/core/app.c"]:
            print(f"git_ignore self-test FAIL: drop_gitignored_paths -> {kept}", file=sys.stderr)
            ok = False

    # No git work tree: basename fallback must still exclude third-party/ / build/.
    clear_git_repo_cache()
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        fallback_root = Path(tmp)
        (fallback_root / ".gitignore").write_text("third-party/\nbuild/\n", encoding="utf-8")
        ignored = paths_gitignored(
            fallback_root,
            ["third-party/vendor.c", "core/app.c", "build/out.c"],
        )
        if ignored != frozenset({"third-party/vendor.c", "build/out.c"}):
            print(
                f"git_ignore self-test FAIL: no-git basename fallback -> {ignored}",
                file=sys.stderr,
            )
            ok = False
        kept = drop_gitignored_paths(
            fallback_root,
            [
                fallback_root / "core/app.c",
                fallback_root / "third-party/vendor.c",
                fallback_root / "build/out.c",
            ],
        )
        if [path.relative_to(fallback_root).as_posix() for path in kept] != ["core/app.c"]:
            print(
                f"git_ignore self-test FAIL: no-git drop_gitignored_paths -> {kept}",
                file=sys.stderr,
            )
            ok = False

    if ok:
        print("git_ignore self-test: OK")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(run_self_test())
