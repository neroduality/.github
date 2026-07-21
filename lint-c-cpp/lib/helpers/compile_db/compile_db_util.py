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

"""Shared compile-database helpers for compile_db_lint and hardening_verify."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from consumer_manifest import (
    compile_db_firmware_build_commands,
    compile_db_is_configured,
    compile_db_required_compile_command_paths,
    compile_db_userspace_entries,
    load,
    verify_compile_db_cmake_coverage,
)
from repo_paths import (
    detect_foreign_repo_prefix,
    foreign_repo_prefix_for_file,
    rebase_absolute_paths,
    source_key,
)

# Backward-compatible alias for callers outside this package.
compile_file_repo_rel = source_key

_OPENSSF_RICHNESS_ANCHORS = (
    "-Wall",
    "-Wextra",
    "-Wbidi-chars=any",
    "-fhardened",
    "-fstack-clash-protection",
    "-fstrict-flex-arrays=3",
)

_COMPILER_TARGET_CACHE: dict[str, str] = {}


def clear_cross_target_cache() -> None:
    """Test hook: drop cached ``-dumpmachine`` results."""
    _COMPILER_TARGET_CACHE.clear()
    host_target_triple.cache_clear()
    _is_cross_compile_command_impl.cache_clear()


def cmake_generator() -> str:
    return "Ninja" if shutil.which("ninja") else "Unix Makefiles"


def entry_command(entry: dict[str, Any], *, shlex_args: bool = False) -> str:
    command = entry.get("command")
    if isinstance(command, str) and (not shlex_args or command.strip()):
        return command
    args = entry.get("arguments")
    if isinstance(args, list) and args:
        if shlex_args:
            return shlex.join(str(item) for item in args)
        return " ".join(str(arg) for arg in args)
    return ""


def compile_command_richness(command: str) -> int:
    return sum(1 for flag in _OPENSSF_RICHNESS_ANCHORS if flag in command)


def compile_driver_path(command: str) -> Path | None:
    """Return the compiler driver CMake recorded as argv0 in a compile command."""
    if not command.strip():
        return None
    tokens = shlex.split(command)
    if not tokens or tokens[0].startswith("-"):
        return None
    driver_token = tokens[0]
    path = Path(driver_token)
    if path.is_file():
        return path.resolve()
    resolved = shutil.which(driver_token)
    if resolved:
        return Path(resolved)
    return None


def explicit_clang_target_from_command(command: str) -> str | None:
    """Read ``--target`` / ``-target`` already present in a compile command."""
    tokens = shlex.split(command)
    for index, token in enumerate(tokens):
        for prefix in ("--target=", "-target="):
            if token.startswith(prefix):
                value = token[len(prefix) :]
                return value or None
        if token in ("--target", "-target") and index + 1 < len(tokens):
            value = tokens[index + 1]
            return value or None
    return None


def _run_dumpmachine(compiler: Path) -> str | None:
    try:
        proc = subprocess.run(
            [str(compiler), "-dumpmachine"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def compiler_target_triple(compiler: Path) -> str | None:
    """Target triple configured in the toolchain (``compiler -dumpmachine``)."""
    key = str(compiler.resolve())
    cached = _COMPILER_TARGET_CACHE.get(key)
    if cached is not None:
        return cached
    value = _run_dumpmachine(compiler)
    if value is not None:
        _COMPILER_TARGET_CACHE[key] = value
    return value


@lru_cache(maxsize=1)
def host_target_triple() -> str | None:
    """Host triple for the lint machine (prefer ``clang``, else ``cc``)."""
    for candidate in ("clang", "cc", "gcc"):
        resolved = shutil.which(candidate)
        if not resolved:
            continue
        value = _run_dumpmachine(Path(resolved))
        if value:
            return value
    return None


def clang_target_for_command(command: str) -> str | None:
    """Clang ``--target`` value for a compile command (explicit flag or driver triple)."""
    explicit = explicit_clang_target_from_command(command)
    if explicit:
        return explicit
    driver = compile_driver_path(command)
    if driver is None:
        return None
    return compiler_target_triple(driver)


def is_cross_compile_command(command: str) -> bool:
    """True when the compile command's driver targets a different triple than the host."""
    if not command.strip():
        return False
    return _is_cross_compile_command_impl(command)


def _normalize_target_triple(triple: str) -> str:
    normalized = triple.strip().lower()
    if normalized.endswith("-gnu"):
        normalized = normalized[:-4]
    return normalized


@lru_cache(maxsize=4096)
def _is_cross_compile_command_impl(command: str) -> bool:
    target = clang_target_for_command(command)
    host = host_target_triple()
    if not target or not host:
        return False
    return _normalize_target_triple(target) != _normalize_target_triple(host)


def compile_entry_preference(entry: dict[str, Any]) -> tuple[int, int]:
    """Lower is better: host clang-tidy entries beat cross-compiler firmware entries."""
    command = entry_command(entry)
    cross = 1 if is_cross_compile_command(command) else 0
    return (cross, -compile_command_richness(command))


def storage_key_prefers_firmware_compile(key: str, repo_root: Path | None = None) -> bool:
    """True when this storage key should prefer a cross/firmware compile entry.

    When ``repo_root`` is provided, uses ``firmware_compile_source_roots`` (manifest +
    esp-idf-in-scan). Without ``repo_root``, falls back to ``esp-idf`` when that is the
    first path segment.
    """
    parts = Path(key).parts
    if not parts:
        return False
    rel = Path(*parts).as_posix()
    if repo_root is not None:
        try:
            from consumer_manifest import firmware_compile_source_roots

            roots = firmware_compile_source_roots(repo_root)
        except Exception:
            roots = ("esp-idf",) if parts[0] == "esp-idf" else ()
        return any(rel == r or rel.startswith(f"{r}/") for r in roots)
    return parts[0] == "esp-idf"


def compile_entry_merge_preference(
    entry: dict[str, Any],
    key: str,
    *,
    repo_root: Path | None = None,
) -> tuple[int, int]:
    """Lower is better. Firmware keys prefer cross-compiler template entries."""
    command = entry_command(entry)
    richness = compile_command_richness(command)
    if storage_key_prefers_firmware_compile(key, repo_root):
        cross = 0 if is_cross_compile_command(command) else 1
        return (cross, -richness)
    cross = 1 if is_cross_compile_command(command) else 0
    return (cross, -richness)


def project_build_dirs(repo_root: Path) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    repo_root = repo_root.resolve()
    for project in compile_db_userspace_entries(repo_root):
        name = str(project.get("name") or project.get("source"))
        mapping[name] = repo_root / str(project["build_dir"])
    return mapping


@dataclass(frozen=True)
class RequiredCompileDbArtifact:
    path: Path
    kind: str
    label: str
    hint: str


def iter_required_compile_command_json(
    repo_root: Path,
    *,
    include_firmware: bool = True,
) -> Iterator[RequiredCompileDbArtifact]:
    """Yield every compile_commands.json declared in compile_db.firmware and userspace."""
    repo_root = repo_root.resolve()
    load(repo_root)
    for label, path in compile_db_required_compile_command_paths(repo_root):
        kind, _, detail = label.partition(":")
        if not include_firmware and kind == "firmware":
            continue
        if kind == "firmware":
            commands = compile_db_firmware_build_commands(repo_root)
            hint = "run: " + "; ".join(commands) if commands else (
                "set compile_db.firmware.commands in .github/lint-c-cpp.yaml"
            )
        else:
            hint = (
                "run configure-compile-db "
                f"(CMake export for source {detail!r} → {path.relative_to(repo_root).as_posix()})"
            )
        yield RequiredCompileDbArtifact(
            path=path,
            kind=kind,
            label=detail,
            hint=hint,
        )


def verify_required_compile_commands(
    repo_root: Path,
    *,
    include_firmware: bool = True,
) -> int:
    """Fail when compile_db omits a CMake root or a declared compile_commands.json is absent."""
    repo_root = repo_root.resolve()
    if compile_db_is_configured(repo_root) and verify_compile_db_cmake_coverage(repo_root) != 0:
        return 1
    missing = [
        item
        for item in iter_required_compile_command_json(
            repo_root, include_firmware=include_firmware
        )
        if not item.path.is_file()
    ]
    if not missing:
        return 0
    print("error: required compile_commands.json missing:", file=sys.stderr)
    for item in missing:
        try:
            rel = item.path.relative_to(repo_root)
        except ValueError:
            rel = item.path
        print(f"  - {item.kind} ({item.label}): {rel.as_posix()}", file=sys.stderr)
        print(f"    {item.hint}", file=sys.stderr)
    return 1


def rebase_compile_entry_paths(
    entry: dict[str, Any],
    repo_root: Path,
    foreign_prefix: str,
) -> dict[str, Any]:
    """Rewrite absolute paths from a foreign repo prefix to the current repo_root."""
    normalized = dict(entry)

    def rebase_text(text: str) -> str:
        return rebase_absolute_paths(text, foreign_prefix=foreign_prefix, repo_root=repo_root)

    file_name = normalized.get("file")
    if isinstance(file_name, str):
        normalized["file"] = rebase_text(file_name)
    command = entry_command(normalized)
    if command:
        normalized["command"] = rebase_text(command)
        normalized.pop("arguments", None)
    args = entry.get("arguments")
    if isinstance(args, list):
        normalized["arguments"] = [
            rebase_text(str(arg)) if isinstance(arg, str) else arg for arg in args
        ]
    directory = normalized.get("directory")
    if isinstance(directory, str):
        normalized["directory"] = rebase_text(directory)
    output = normalized.get("output")
    if isinstance(output, str):
        normalized["output"] = rebase_text(output)
    return normalized


def canonical_compile_entry(
    entry: dict[str, Any],
    repo_root: Path,
    *,
    foreign_prefix: str | None = None,
) -> dict[str, Any] | None:
    """Normalize a compile DB row to the current repo_root and repo-relative storage key."""
    file_name = entry.get("file")
    if not isinstance(file_name, str) or not file_name.strip():
        return None
    normalized = dict(entry)
    prefix = foreign_prefix or foreign_repo_prefix_for_file(normalized.get("file", ""), repo_root)
    if prefix:
        normalized = rebase_compile_entry_paths(normalized, repo_root, prefix)
    rel = source_key(normalized.get("file", ""), repo_root)
    if rel is None:
        return None
    normalized["file"] = str((repo_root / rel).resolve())
    normalized["storage_key"] = rel
    if isinstance(normalized.get("directory"), str):
        normalized["directory"] = str(repo_root.resolve())
    return normalized


def compile_db_index_keys(entries: list[dict[str, Any]], repo_root: Path) -> set[str]:
    keys: set[str] = set()
    for entry in entries:
        rel = source_key(entry.get("file", ""), repo_root)
        if rel:
            keys.add(rel)
    return keys


_INCLUDE_QUOTED_RE = re.compile(r'^[ \t]*#[ \t]*include[ \t]+"([^"]+)"', re.MULTILINE)
_INCLUDE_MACRO_RE = re.compile(r'^[ \t]*#[ \t]*include[ \t]+([A-Za-z_]\w*(?:[ \t]*\([^)\n]*\))?)[ \t]*$', re.MULTILINE)
_IDENTIFIER_RE = re.compile(r'[A-Za-z_]\w*')
_AMALGAMATION_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})


def _command_quote_include_dirs(command: str, repo_root: Path) -> list[Path]:
    """Repo-absolute ``-I``/``-iquote`` search dirs parsed from a compile command."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    dirs: list[Path] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        for flag in ("-iquote", "-I"):
            if token == flag and index + 1 < len(tokens):
                dirs.append(Path(tokens[index + 1]))
                index += 1
                break
            if token.startswith(flag) and len(token) > len(flag):
                dirs.append(Path(token[len(flag):]))
                break
        index += 1
    resolved: list[Path] = []
    for entry in dirs:
        resolved.append(entry if entry.is_absolute() else (repo_root / entry))
    return resolved


def _command_defines(command: str) -> dict[str, str]:
    """``-D NAME=value`` / ``-DNAME`` macro definitions from a compile command."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    defines: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        payload: str | None = None
        if token == "-D" and index + 1 < len(tokens):
            payload = tokens[index + 1]
            index += 1
        elif token.startswith("-D") and len(token) > 2:
            payload = token[2:]
        if payload is not None:
            name, _, value = payload.partition("=")
            defines[name] = value if _ else "1"
        index += 1
    return defines


def _macro_include_target(spec: str, defines: dict[str, str]) -> str | None:
    """Resolve a macro-form ``#include`` (e.g. ``STRINGIFY(BOARD_UNIT)``) to a filename.

    The innermost ``-D``-defined identifier wins; surrounding quotes on the macro value are
    stripped. Covers the common board-selection pattern ``#include MACRO(BOARD_UNIT)`` where
    ``-DBOARD_UNIT=foo.cpp`` picks the translation unit pulled into the compiled host TU.
    """
    for ident in reversed(_IDENTIFIER_RE.findall(spec)):
        if ident in defines:
            value = defines[ident].strip().strip('"')
            return value or None
    return None


def amalgamation_included_source_keys(
    repo_root: Path,
    host_sources: Iterator[tuple[Path, str]],
) -> frozenset[str]:
    """Repo-relative keys of source files pulled into a compiled TU via ``#include``.

    Unity/amalgamation builds compile one wrapper TU that ``#include``s sibling ``.c``/``.cpp``
    sources — quoted (``#include "foo.cpp"``) or via a ``-D``-selected macro path
    (``#include MACRO(BOARD_UNIT)``) — resolved against the TU's own dir and its ``-I``/
    ``-iquote`` dirs. Those included sources are never standalone TUs, so they carry no compile
    DB entry of their own — yet their object code (and hardening flags) come from the including
    TU. Callers pass only hardened host TUs, so every returned key is genuinely compiled with
    the required flags.
    """
    repo_root = repo_root.resolve()
    covered: set[str] = set()
    visited: set[Path] = set()

    def resolve_target(target: str, search_dirs: list[Path]) -> Path | None:
        for directory in search_dirs:
            candidate = directory / target
            if candidate.is_file():
                return candidate.resolve()
        return None

    def walk(file_path: Path, include_dirs: list[Path], defines: dict[str, str]) -> None:
        if file_path in visited:
            return
        visited.add(file_path)
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        search_dirs = [file_path.parent, *include_dirs]
        targets: list[str] = [match.group(1) for match in _INCLUDE_QUOTED_RE.finditer(text)]
        for match in _INCLUDE_MACRO_RE.finditer(text):
            macro_target = _macro_include_target(match.group(1), defines)
            if macro_target is not None:
                targets.append(macro_target)
        for target in targets:
            resolved = resolve_target(target, search_dirs)
            if resolved is None:
                continue
            if resolved.suffix.lower() in _AMALGAMATION_SOURCE_SUFFIXES:
                key = source_key(resolved, repo_root)
                if key is not None:
                    covered.add(key)
            walk(resolved, include_dirs, defines)

    for source_path, command in host_sources:
        walk(
            Path(source_path).resolve(),
            _command_quote_include_dirs(command, repo_root),
            _command_defines(command),
        )
    return frozenset(covered)


PROVENANCE_KEY = "_lint_kit_compile_db_provenance"

# Fields clang/cppcheck compile_commands.json parsers accept (plus optional output).
_PUBLIC_COMPILE_ENTRY_KEYS = frozenset({"directory", "file", "command", "arguments", "output"})


def entry_compile_db_provenance(entry: dict[str, Any] | None) -> list[str]:
    """Return compile_commands_json paths that contributed ``entry`` (may be empty)."""
    if not isinstance(entry, dict):
        return []
    raw = entry.get(PROVENANCE_KEY)
    if isinstance(raw, list):
        return [Path(str(item)).as_posix() for item in raw if item]
    if isinstance(raw, str) and raw.strip():
        return [Path(raw.strip()).as_posix()]
    return []


def public_compile_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Drop kit-private keys (e.g. provenance) before writing clang/cppcheck JSON."""
    return {key: value for key, value in entry.items() if key in _PUBLIC_COMPILE_ENTRY_KEYS}

def _merge_compile_entries(
    by_file: dict[str, dict[str, Any]],
    db_path: Path,
    repo_root: Path,
    *,
    provenance: str | None = None,
) -> None:
    from scan_policy import path_in_scan_scope

    if not db_path.is_file():
        return
    repo_root = repo_root.resolve()
    raw_entries = json.loads(db_path.read_text(encoding="utf-8"))
    foreign_prefix = detect_foreign_repo_prefix(raw_entries, repo_root)
    for entry in raw_entries:
        normalized = canonical_compile_entry(
            entry,
            repo_root,
            foreign_prefix=foreign_prefix,
        )
        if normalized is None:
            continue
        key = str(normalized.pop("storage_key"))
        # Fail closed at ingest: never retain gitignored / out-of-source_roots TUs
        # (e.g. LiFi third-party/esp-idf rows from the raw IDF compile DB).
        if not path_in_scan_scope(key, repo_root):
            continue
        if provenance:
            prior = normalized.get(PROVENANCE_KEY)
            if isinstance(prior, list):
                if provenance not in prior:
                    prior.append(provenance)
            else:
                normalized[PROVENANCE_KEY] = [provenance]
        existing = by_file.get(key)
        if existing is not None:
            # Preserve provenance from every DB that listed this source.
            if provenance:
                existing_prov = existing.setdefault(PROVENANCE_KEY, [])
                if isinstance(existing_prov, list) and provenance not in existing_prov:
                    existing_prov.append(provenance)
            if compile_entry_merge_preference(
                normalized, key, repo_root=repo_root
            ) >= compile_entry_merge_preference(existing, key, repo_root=repo_root):
                continue
            # Keep accumulated provenance on the preferred entry.
            if isinstance(existing.get(PROVENANCE_KEY), list):
                preferred_prov = normalized.setdefault(PROVENANCE_KEY, [])
                if isinstance(preferred_prov, list):
                    for item in existing[PROVENANCE_KEY]:
                        if item not in preferred_prov:
                            preferred_prov.append(item)
        by_file[key] = normalized


def load_compile_entries_by_db(repo_root: Path) -> dict[str, dict[str, dict[str, Any]]]:
    """Per-database compile entries keyed by manifest ``compile_commands_json`` path."""
    repo_root = repo_root.resolve()
    load(repo_root)
    by_db: dict[str, dict[str, dict[str, Any]]] = {}
    from consumer_manifest import (
        compile_db_firmware_entries,
        compile_db_userspace_entries,
    )

    declared: list[tuple[str, Path]] = []
    for entry in compile_db_firmware_entries(repo_root):
        rel = Path(str(entry["compile_commands_json"])).as_posix()
        declared.append((rel, (repo_root / rel).resolve()))
    for entry in compile_db_userspace_entries(repo_root):
        rel = Path(str(entry["compile_commands_json"])).as_posix()
        declared.append((rel, (repo_root / rel).resolve()))

    for rel, db_path in declared:
        bucket: dict[str, dict[str, Any]] = {}
        _merge_compile_entries(bucket, db_path, repo_root, provenance=rel)
        for entry in bucket.values():
            entry[PROVENANCE_KEY] = [rel]
        by_db[rel] = bucket
    return by_db


def load_richest_compile_entries(repo_root: Path) -> dict[str, dict[str, Any]]:
    repo_root = repo_root.resolve()
    load(repo_root)
    by_file: dict[str, dict[str, Any]] = {}
    for _label, db_path in compile_db_required_compile_command_paths(repo_root):
        try:
            rel = db_path.relative_to(repo_root).as_posix()
        except ValueError:
            rel = db_path.as_posix()
        _merge_compile_entries(by_file, db_path, repo_root, provenance=rel)
    return by_file


def assert_compile_db_entries_in_scan_scope(
    entries: list[dict[str, Any]],
    repo_root: Path,
    *,
    label: str,
) -> list[str]:
    """Return issues when any compile-db ``file=`` is outside scan scope / gitignored."""
    from scan_policy import path_in_scan_scope

    repo_root = repo_root.resolve()
    issues: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = source_key(entry.get("file", ""), repo_root)
        if key is None:
            issues.append(f"{label}: compile DB entry escapes repo root: {entry.get('file')!r}")
            continue
        if not path_in_scan_scope(key, repo_root):
            issues.append(f"{label}: out-of-scope / gitignored compile DB file: {key}")
    return issues


@dataclass(frozen=True)
class MergedCompileDatabase:
    """Canonical merged compile DB: repo-relative keys, absolute paths under repo_root."""

    repo_root: Path
    by_key: dict[str, dict[str, Any]]
    host_templates: tuple[dict[str, Any], ...] = ()

    def key_for(self, path: str | Path) -> str | None:
        return source_key(path, self.repo_root)

    def has(self, path: str | Path) -> bool:
        key = self.key_for(path)
        return key is not None and key in self.by_key

    def entry_for(self, path: str | Path) -> dict[str, Any] | None:
        key = self.key_for(path)
        if key is None:
            return None
        return self.by_key.get(key)

    def missing_targets(self, targets: list[Path]) -> list[Path]:
        return [target for target in targets if not self.has(target)]

    @staticmethod
    def scan_target_keys(scan_paths: list[Path], repo_root: Path) -> frozenset[str]:
        keys: set[str] = set()
        for target in scan_paths:
            key = source_key(target, repo_root)
            if key is not None:
                keys.add(key)
        return frozenset(keys)

    @staticmethod
    def host_template_pool(
        by_key: dict[str, dict[str, Any]],
        repo_root: Path,
    ) -> tuple[dict[str, Any], ...]:
        from scan_policy import path_in_scan_scope

        pool: list[dict[str, Any]] = []
        for key, entry in by_key.items():
            if not path_in_scan_scope(key, repo_root):
                continue
            if not is_cross_compile_command(entry_command(entry)):
                pool.append(entry)
        return tuple(pool)

    @staticmethod
    def cross_template_pool(
        by_key: dict[str, dict[str, Any]],
        repo_root: Path,
    ) -> tuple[dict[str, Any], ...]:
        """Cross-compile templates from in-scope keys only (never third-party/gitignored)."""
        from scan_policy import path_in_scan_scope

        pool: list[dict[str, Any]] = []
        for key, entry in by_key.items():
            if not path_in_scan_scope(key, repo_root):
                continue
            if is_cross_compile_command(entry_command(entry)):
                pool.append(entry)
        return tuple(pool)

    def narrowed_to_scan_targets(self, scan_paths: list[Path]) -> MergedCompileDatabase:
        """Keep only manifest scan targets; retain host templates for cppcheck synthesis."""
        keys = self.scan_target_keys(scan_paths, self.repo_root)
        return MergedCompileDatabase(
            self.repo_root,
            {key: self.by_key[key] for key in keys if key in self.by_key},
            self.host_templates,
        )

    @classmethod
    def from_richest(cls, repo_root: Path) -> MergedCompileDatabase:
        resolved = repo_root.resolve()
        by_key = load_richest_compile_entries(resolved)
        return cls(resolved, by_key, cls.host_template_pool(by_key, resolved))

    @classmethod
    def from_json(cls, path: Path, repo_root: Path) -> MergedCompileDatabase:
        from scan_policy import path_in_scan_scope

        resolved = repo_root.resolve()
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"invalid compile_commands JSON in {path}")
        by_key: dict[str, dict[str, Any]] = {}
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            key = source_key(entry.get("file", ""), resolved)
            if key is None or not path_in_scan_scope(key, resolved):
                continue
            by_key[key] = entry
        return cls(resolved, by_key)

    def native_userspace_keys(self) -> set[str]:
        """Repo-relative keys present in host userspace compile_commands.json files."""
        keys: set[str] = set()
        load(self.repo_root)
        for project in compile_db_userspace_entries(self.repo_root):
            db = self.repo_root / str(project["compile_commands_json"])
            if not db.is_file():
                continue
            for entry in json.loads(db.read_text(encoding="utf-8")):
                key = source_key(entry.get("file", ""), self.repo_root)
                if key is not None:
                    keys.add(key)
        return keys


_CC_SOURCE_SUFFIXES = frozenset({".c", ".cpp", ".cc", ".cxx"})


@dataclass(frozen=True)
class CompileDbInputStat:
    label: str
    rel_path: str
    present: bool
    raw_entries: int | None
    input_kind: str


def _compile_db_raw_entry_count(path: Path) -> int | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return len(raw) if isinstance(raw, list) else 0


def compile_db_input_stats(repo_root: Path) -> list[CompileDbInputStat]:
    """One row per manifest ``compile_db.*`` compile_commands.json path."""
    repo_root = repo_root.resolve()
    stats: list[CompileDbInputStat] = []
    for label, path in compile_db_required_compile_command_paths(repo_root):
        try:
            rel_path = path.relative_to(repo_root).as_posix()
        except ValueError:
            rel_path = path.as_posix()
        input_kind = "firmware" if label.startswith("firmware:") else "host"
        stats.append(
            CompileDbInputStat(
                label=label,
                rel_path=rel_path,
                present=path.is_file(),
                raw_entries=_compile_db_raw_entry_count(path) if path.is_file() else None,
                input_kind=input_kind,
            )
        )
    return stats


def longest_scan_source_root(rel_posix: str, repo_root: Path) -> str:
    from consumer_manifest import scan_source_roots

    matches = [
        root
        for root in scan_source_roots(repo_root)
        if root in ("", ".") or rel_posix == root or rel_posix.startswith(f"{root}/")
    ]
    if not matches:
        return "(other)"
    return max(matches, key=len)


def count_cc_paths_by_scan_source_root(paths: list[Path], repo_root: Path) -> dict[str, int]:
    """Count C/C++ scan paths grouped by longest matching ``scan.source_roots`` entry."""
    from consumer_manifest import scan_source_roots

    counts = {root: 0 for root in scan_source_roots(repo_root)}
    for path in paths:
        rel = source_key(path, repo_root)
        if rel is None:
            continue
        if Path(rel).suffix.lower() not in _CC_SOURCE_SUFFIXES:
            continue
        root = longest_scan_source_root(rel, repo_root)
        if root in counts:
            counts[root] += 1
    return counts


def format_source_root_entry_counts(counts: dict[str, int], repo_root: Path) -> str:
    from consumer_manifest import scan_source_roots

    parts = [f"{root}:{counts[root]}" for root in scan_source_roots(repo_root) if counts.get(root, 0)]
    return ", ".join(parts) if parts else "(none)"
