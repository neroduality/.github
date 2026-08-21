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

"""Central self-test runner: temp repo -> scan-paths -> prepare_paths -> lint(paths)."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import ModuleType

from consumer_manifest import resolve_scan_paths
from policy_prepare import build_config, prepare_paths
from scan_policy import bootstrap_scan_manifest


def run(module: ModuleType, script_name: str, scan_job: str) -> int:
    prepare = getattr(module, "prepare_self_test_repo", None)
    verify = getattr(module, "verify_self_test", None)
    if prepare is None or verify is None:
        legacy = getattr(module, "run_self_test", None) or getattr(module, "self_test", None)
        if legacy is None:
            print(f"error: {script_name} has no self-test entry point", file=sys.stderr)
            return 2
        return int(legacy())

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        prepare(root)
        bootstrap_scan_manifest(root)
        raw_paths = resolve_scan_paths(scan_job, repo_root=root)
        paths = prepare_paths(script_name, root, raw_paths)
        config = build_config(root, paths)
        errors = module.lint(paths, config)
        return int(verify(errors))
