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

# Python static analysis for consumer helper/build/test scripts: ruff (linter) and
# mypy (type checker). Configuration is kit-owned (config/ruff.toml, config/mypy.ini)
# and applied with --config / --config-file so a consumer pyproject never weakens it.
#
# Tools are executed through `uvx` (the org's Python tool runner, already used for
# zizmor), pinned to the versions in tool-versions.yaml. This helper never installs
# or upgrades tools beyond what uvx fetches on demand.
#
# Usage:
#   bash lib/helpers/toolchain/python_lint.sh [PATH …]
#   bash lib/helpers/toolchain/python_lint.sh --check-config
#
# Sourceable helpers:
#   lint_kit_python_lint_self_test   (self-test: proves ruff flags a known violation)
set -euo pipefail

# shellcheck source=tool_versions.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/tool_versions.sh"

LINT_KIT_RUFF_VERSION="${LINT_KIT_RUFF_VERSION:-$(lint_kit_tool_min_version ruff)}"
LINT_KIT_MYPY_VERSION="${LINT_KIT_MYPY_VERSION:-$(lint_kit_tool_min_version mypy)}"
LINT_KIT_PYTHON_CONFIG_DIR="${LINT_KIT_PYTHON_CONFIG_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../config" && pwd)}"

lint_kit_python_lint_hint() {
  printf '%s\n' \
    'hint: install uv (provides uvx): https://docs.astral.sh/uv/' \
    "      python_lint runs ruff@${LINT_KIT_RUFF_VERSION} and mypy@${LINT_KIT_MYPY_VERSION} via uvx" >&2
}

lint_kit_python_lint_have_uvx() {
  command -v uvx >/dev/null 2>&1
}

# Self-test: a Python file with a known violation must make ruff exit non-zero.
# Mirrors the "an equal error is thrown" contract of the other lint jobs.
lint_kit_python_lint_self_test() {
  local tmp bad
  if ! lint_kit_python_lint_have_uvx; then
    printf 'error: python_lint self-test: uvx not found\n' >&2
    lint_kit_python_lint_hint
    return 1
  fi
  tmp="$(mktemp -d)"
  bad="${tmp}/lint_kit_bad_fixture.py"
  # Unused import (F) + undefined name (F821) — both in the enforced rule set.
  printf 'import os\n\n\ndef broken() -> int:\n    return undefined_symbol\n' >"${bad}"
  if uvx "ruff@${LINT_KIT_RUFF_VERSION}" check \
    --config "${LINT_KIT_PYTHON_CONFIG_DIR}/ruff.toml" "${bad}" >/dev/null 2>&1; then
    rm -rf "${tmp}"
    printf 'error: python_lint self-test: ruff did not flag a known violation\n' >&2
    return 1
  fi
  rm -rf "${tmp}"
  printf 'python_lint self-test: OK\n'
}

lint_kit_python_lint_main() {
  local check_config kit_manifest kit_scan repo_root discover_tmp path
  local -a targets

  usage() {
    cat <<'EOF'
Usage: lib/helpers/toolchain/python_lint.sh [OPTIONS] [PATH …]

Lint Python sources with ruff + mypy (kit-owned config). Paths default to every
*.py file discovered via the consumer manifest (vendored/build trees skipped).

Options:
  --check-config   Print effective ruff/mypy argv and exit 0
  -h, --help       Help

EOF
  }

  kit_manifest="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../core/manifest" && pwd)"
  kit_scan="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../core/scan" && pwd)"
  repo_root="${LINT_REPO_ROOT:-$(pwd)}"
  repo_root="$(cd -- "$repo_root" && pwd)"

  check_config=0
  targets=()
  while (($# > 0)); do
    case "$1" in
      --check-config) check_config=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      --)
        shift
        targets+=("$@")
        break
        ;;
      *)
        targets+=("$1")
        ;;
    esac
    shift
  done

  if ((${#targets[@]} == 0)); then
    discover_tmp="$(mktemp)"
    if ! PYTHONPATH="$kit_manifest:$kit_scan" python3 "$kit_manifest/consumer_manifest.py" \
      --repo-root "$repo_root" scan-paths python >"$discover_tmp"; then
      rm -f "$discover_tmp"
      printf 'error: failed to discover Python targets via consumer manifest\n' >&2
      exit 1
    fi
    while IFS= read -r path; do
      [[ -n $path ]] || continue
      [[ -f "$repo_root/$path" ]] && targets+=("$repo_root/$path")
    done <"$discover_tmp"
    rm -f "$discover_tmp"
  fi

  if ((${#targets[@]} == 0)); then
    printf 'ruff/mypy: OK (no Python sources to check)\n'
    exit 0
  fi

  if ((check_config == 1)); then
    printf 'uvx ruff@%s check --config %q' "$LINT_KIT_RUFF_VERSION" "${LINT_KIT_PYTHON_CONFIG_DIR}/ruff.toml"
    printf ' %q' "${targets[@]}"
    printf '\nuvx mypy@%s --config-file %q --no-incremental' "$LINT_KIT_MYPY_VERSION" "${LINT_KIT_PYTHON_CONFIG_DIR}/mypy.ini"
    printf ' %q' "${targets[@]}"
    printf '\n'
    exit 0
  fi

  if ! lint_kit_python_lint_have_uvx; then
    printf 'error: uvx not found (required for python_lint)\n' >&2
    lint_kit_python_lint_hint
    exit 1
  fi

  cd "$repo_root"

  uvx "ruff@${LINT_KIT_RUFF_VERSION}" check \
    --config "${LINT_KIT_PYTHON_CONFIG_DIR}/ruff.toml" "${targets[@]}"

  uvx "mypy@${LINT_KIT_MYPY_VERSION}" \
    --config-file "${LINT_KIT_PYTHON_CONFIG_DIR}/mypy.ini" --no-incremental "${targets[@]}"

  if ((${#targets[@]} == 1)); then
    printf 'ruff/mypy: OK (1 Python file checked)\n'
  else
    printf 'ruff/mypy: OK (%d Python files checked)\n' "${#targets[@]}"
  fi
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  lint_kit_python_lint_main "$@"
fi
