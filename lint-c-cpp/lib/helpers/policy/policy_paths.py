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

"""Path loading for hardening_verify (policy_runner owns policy linter paths)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_LINT_LIB = Path(__file__).resolve().parents[2]
if str(_LINT_LIB) not in sys.path:
    sys.path.insert(0, str(_LINT_LIB))
from lint_pythonpath import bootstrap as _bootstrap_lint_pythonpath

_bootstrap_lint_pythonpath()
from consumer_manifest import resolve_scan_paths
from scan_policy import JOB_CMAKE, read_paths_file


def central_scan_paths(job: str, *, repo_root: Path) -> list[Path]:
    """Resolve paths only through the central registry (same as ``scan-paths`` CLI)."""
    return resolve_scan_paths(job, repo_root=repo_root)


def add_hardening_repo_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--paths-file",
        type=Path,
        default=None,
        help="Repo-relative paths (one per line) from consumer_manifest.py scan-paths",
    )
    parser.add_argument("--self-test", action="store_true")


def load_paths(args: argparse.Namespace) -> list[Path]:
    """Load the positive scan target list (required for production runs)."""
    if args.paths_file is None:
        raise SystemExit("error: --paths-file is required (omit only for --self-test)")
    return read_paths_file(args.paths_file, args.repo_root.resolve())


def add_hardening_path_args(parser: argparse.ArgumentParser) -> None:
    add_hardening_repo_args(parser)
    parser.add_argument(
        "--cmake-paths-file",
        type=Path,
        default=None,
        help="Repo-relative CMakeLists.txt paths from consumer_manifest.py scan-paths cmake",
    )


def load_cmake_paths(args: argparse.Namespace) -> list[Path]:
    """Load CMakeLists targets (required for production hardening runs)."""
    if args.cmake_paths_file is None:
        raise SystemExit("error: --cmake-paths-file is required (omit only for --self-test)")
    return read_paths_file(args.cmake_paths_file, args.repo_root.resolve())
