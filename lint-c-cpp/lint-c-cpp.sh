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

set -euo pipefail

# shellcheck source=lib/lint_env.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/lint_env.sh"
_lint_env_init

lib="${LINT_KIT}/lib"
manifest="${lib}/core/manifest"
tools="${lib}/core/tools"
workflow="${lib}/core/workflow"
tests="${lib}/tests"
commands="${lib}/commands"

usage() {
  cat <<'EOF'
Usage: lint-c-cpp.sh <command> [options]

Commands:
  lint [opts]         Run C/C++ lint (consumer .github/lint-c-cpp.yaml)
  precheck            Validate consumer manifest (fail fast)
  workflow-lint       Validate GitHub Actions workflow container policy
  tools [args...]     tool_versions_check.py (verify, resolve, …)
  self-test           Run lint-c-cpp unit tests

Options for lint:
  --custom-lints-only   Stop before compile DB / cppcheck / clang-tidy / firmware DB+build
  -h, --help            Show help

Environment:
  LINT_KIT              Path to lint-c-cpp install (default: script directory)
  LINT_REPO_ROOT        Consumer repo root (default: cwd)
EOF
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

cmd=$1
shift

case "$cmd" in
  lint)
    exec bash "${commands}/lint.sh" "$@"
    ;;
  precheck | pre-check)
    exec python3 "${manifest}/manifest_validate.py" --repo-root "${LINT_REPO_ROOT}"
    ;;
  workflow-lint | workflow_lint)
    python3 "${tools}/tool_versions_check.py" --self-test
    python3 "${tools}/tool_versions_check.py" verify --workflow
    exec python3 "${workflow}/workflow_container_policy.py" --repo-root "${LINT_REPO_ROOT}"
    ;;
  tools)
    exec python3 "${tools}/tool_versions_check.py" "$@"
    ;;
  self-test)
    exec python3 "${tests}/lint_self_test.py" "$@"
    ;;
  -h | --help | help)
    usage
    exit 0
    ;;
  *)
    printf 'error: unknown command: %s\n' "$cmd" >&2
    usage >&2
    exit 2
    ;;
esac
