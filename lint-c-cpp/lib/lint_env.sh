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
# Shared path and environment setup for lint-c-cpp (consumer repos).
# Source from lib/commands/*.sh (do not execute directly).
# shellcheck shell=bash

_lint_env_init() {
  local lib_dir default_root repo_root pythonpath
  lib_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  default_root="$(cd -- "${lib_dir}/.." && pwd)"
  export LINT_KIT="${LINT_KIT:-${default_root}}"
  repo_root="${LINT_REPO_ROOT:-${FIRMWARE_ROOT:-${NERO_LINT_REPO_ROOT:-$(pwd)}}}"
  repo_root="$(cd -- "${repo_root}" && pwd)"
  export LINT_REPO_ROOT="$repo_root"
  pythonpath="${LINT_KIT}/lib/core/manifest"
  pythonpath="${pythonpath}:${LINT_KIT}/lib/core/scan"
  pythonpath="${pythonpath}:${LINT_KIT}/lib/core/tools"
  pythonpath="${pythonpath}:${LINT_KIT}/lib/core/workflow"
  export PYTHONPATH="${pythonpath}${PYTHONPATH:+:${PYTHONPATH}}"
}
