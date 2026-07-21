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

"""Frozen manifest config for policy linters (no path bootstrap)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Precomputed per-file roles (assigned only in policy_prepare.py).
K_HEADER = "header"
K_CXX = "cxx"
K_TU = "tu"
K_CANONICAL_NULL = "canonical_null"
K_MAGIC_SHARED = "magic_shared"
K_STACK_ARRAY = "stack_array"


@dataclass(frozen=True)
class NullPolicy:
    prefix_macro: str
    null_macro: str
    nodiscard_macro: str
    canonical_header: str
    null_includes: frozenset[str]
    include_dir_prefix: str
    bool_head: re.Pattern[str]
    bool_decl: re.Pattern[str]
    nodiscard_on_field: re.Pattern[str]
    null_define: re.Pattern[str]
    null_define_null: re.Pattern[str]
    null_token: re.Pattern[str]


@dataclass(frozen=True)
class RaiiPair:
    label: str
    hint: str
    acquire_rx: tuple[re.Pattern[str], ...]
    release_rx: tuple[re.Pattern[str], ...]
    canonical_files: frozenset[Path]


@dataclass(frozen=True)
class PolicyConfig:
    repo_root: Path
    c_api_prefix: str
    c_macro_prefix: str
    null_policy: NullPolicy
    raii_pairs: tuple[RaiiPair, ...]
    safe_indexing_helpers: frozenset[str]
    spec_tracked_symbols: frozenset[str]
    stack_array_min: int
    bounded_recursion_annotation: str
    kinds: dict[Path, frozenset[str]] = field(default_factory=dict)
    path_labels: dict[Path, str] = field(default_factory=dict)
    license_header: str | None = None

    def has(self, path: Path, kind: str) -> bool:
        return kind in self.kinds.get(path.resolve(), frozenset())

    def label(self, path: Path) -> str:
        resolved = path.resolve()
        return self.path_labels.get(resolved, resolved.as_posix())
