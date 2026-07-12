#!/usr/bin/env bash
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
# Shared minimum-version lookup for kit toolchain shell helpers.
# Source this file; do not execute directly.
# shellcheck shell=bash

lint_kit_tool_min_version() {
  local tool="$1" lint_kit
  lint_kit="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
  python3 - "$lint_kit/config/tool-versions.yaml" "$tool" <<'PY'
import sys
import yaml

data = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
print(data["tools"][sys.argv[2]]["min"])
PY
}
