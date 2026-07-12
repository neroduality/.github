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

"""Central entry for policy linters: bootstrap, scan-paths, manifest, invoke lint()."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_POLICY_DIR = Path(__file__).resolve().parent
_LINT_LIB = _POLICY_DIR.parents[1]
if str(_LINT_LIB) not in sys.path:
    sys.path.insert(0, str(_LINT_LIB))
from lint_pythonpath import bootstrap as _bootstrap_lint_pythonpath

_bootstrap_lint_pythonpath()
for _core_sub in ("manifest", "scan", "tools", "workflow"):
    _entry = str(_LINT_LIB / "core" / _core_sub)
    if _entry not in sys.path:
        sys.path.insert(0, _entry)
if str(_POLICY_DIR) not in sys.path:
    sys.path.insert(0, str(_POLICY_DIR))

from consumer_manifest import resolve_scan_paths
from policy_config import PolicyConfig
from policy_prepare import build_config, prepare_paths
from policy_self_test import run as run_policy_self_test
from scan_policy import (
    JOB_LICENSE,
    JOB_NOLINT,
    JOB_SOURCE,
    JOB_UNSAFE_API,
    JOB_YAML,
    bootstrap_scan_manifest,
    read_paths_file,
)

SCRIPT_SCAN_JOBS: dict[str, str] = {
    "banned_libc_io.py": JOB_UNSAFE_API,
    "banned_cxx_heap.py": JOB_UNSAFE_API,
    "null_nodiscard.py": JOB_UNSAFE_API,
    "raii_lifetime.py": JOB_UNSAFE_API,
    "duplicate_includes.py": JOB_SOURCE,
    "magic_literals.py": JOB_SOURCE,
    "guard_clause_style.py": JOB_SOURCE,
    "pointer_bounds.py": JOB_SOURCE,
    "relative_includes.py": JOB_SOURCE,
    "nolint_audit.py": JOB_NOLINT,
    "shared_constant_dupes.py": JOB_SOURCE,
    "spdx_headers.py": JOB_LICENSE,
    "yaml_manifest.py": JOB_YAML,
    "spec_traceability.py": JOB_SOURCE,
}


def _load_module(script_name: str) -> ModuleType:
    key = Path(script_name).name
    path = _POLICY_DIR / key
    if not path.is_file():
        raise SystemExit(f"error: unknown policy script: {key}")
    module_name = f"policy_job_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"error: failed to load policy script: {key}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _resolve_paths(args: argparse.Namespace) -> list[Path]:
    repo_root = args.repo_root.resolve()
    if args.paths_file is not None:
        return read_paths_file(args.paths_file, repo_root)
    job = args.scan_job
    if job is None:
        job = SCRIPT_SCAN_JOBS.get(Path(args.script).name)
        if job is None:
            raise SystemExit(
                f"error: no scan job for {args.script!r} "
                "(pass --scan-job or --paths-file)"
            )
    return resolve_scan_paths(job, repo_root=repo_root)


def _run_lint(module: ModuleType, config: PolicyConfig, paths: list[Path], extras: list[str]) -> int:
    if hasattr(module, "run"):
        return int(module.run(config, paths, extras))

    lint_fn = getattr(module, "lint", None)
    if lint_fn is None:
        raise SystemExit(f"error: {module.__name__} has no lint() or run() entry point")

    errors = lint_fn(paths, config)
    title = getattr(module, "LINT_TITLE", "policy")
    fix_hint = getattr(module, "LINT_FIX_HINT", "")
    ok_detail = getattr(module, "LINT_OK_DETAIL", "")

    if errors:
        print(f"error: {title} violations:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        if fix_hint:
            print(fix_hint, file=sys.stderr)
        return 1

    print(f"{title}: OK")
    if ok_detail:
        print(ok_detail)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", required=True, help="Policy linter basename (e.g. banned_cxx_heap.py)")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--paths-file",
        type=Path,
        default=None,
        help="Repo-relative paths from consumer_manifest.py scan-paths",
    )
    parser.add_argument(
        "--scan-job",
        default=None,
        help="Resolve paths via central scan-paths job (alternative to --paths-file)",
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--fix-hint",
        default="",
        help="Override LINT_FIX_HINT on failure (from lint.sh)",
    )
    args, extras = parser.parse_known_args(argv)

    module = _load_module(args.script)
    if args.self_test:
        job = SCRIPT_SCAN_JOBS.get(Path(args.script).name)
        if job is None:
            raise SystemExit(f"error: no scan job for self-test: {args.script}")
        return run_policy_self_test(module, args.script, job)

    repo_root = args.repo_root.resolve()
    bootstrap_scan_manifest(repo_root)
    raw_paths = _resolve_paths(args)
    paths = prepare_paths(args.script, repo_root, raw_paths)
    config = build_config(repo_root, paths)

    if args.fix_hint:
        module.LINT_FIX_HINT = args.fix_hint  # type: ignore[attr-defined]

    return _run_lint(module, config, paths, extras)


if __name__ == "__main__":
    raise SystemExit(main())
