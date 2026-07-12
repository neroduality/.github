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

# Verify markdownlint-cli for lint parity across distros.
# Minimum versions are read from tool-versions.yaml; this helper never installs tools.
# Debian often ships /usr/bin/nodejs but not /usr/bin/node; npm wrappers need node.
#
# Sourceable helpers (install-linux-deps.sh, lint.sh):
#   lint_kit_ensure_markdownlint
#   lint_kit_markdownlint_collect_targets
#   lint_kit_markdownlint_fail_on_change
#   lint_kit_run_markdownlint
set -euo pipefail

# shellcheck source=tool_versions.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/tool_versions.sh"
# shellcheck source=format_toolchain.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/format_toolchain.sh"

LINT_KIT_MARKDOWNLINT_MIN_VERSION="${LINT_KIT_MARKDOWNLINT_MIN_VERSION:-$(lint_kit_tool_min_version markdownlint)}"
LINT_KIT_NODE_MIN_MAJOR="${LINT_KIT_NODE_MIN_MAJOR:-$(lint_kit_tool_min_version node)}"

lint_kit_markdownlint_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      ensure markdownlint-cli >= ${LINT_KIT_MARKDOWNLINT_MIN_VERSION}" >&2
}

lint_kit_node_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: install Node.js >= ${LINT_KIT_NODE_MIN_MAJOR} (markdownlint-cli runtime)" >&2
}

lint_kit_node_version_major() {
  lint_kit_ensure_node_symlink || true
  lint_kit_have_node || return 1
  node -p 'process.versions.node.split(".")[0]' 2>/dev/null
}

lint_kit_node_ok() {
  local major=""
  major="$(lint_kit_node_version_major)" || return 1
  [[ ${major} -ge ${LINT_KIT_NODE_MIN_MAJOR} ]]
}

lint_kit_have_node() {
  command -v node >/dev/null 2>&1 || command -v nodejs >/dev/null 2>&1
}

lint_kit_ensure_node_symlink() {
  if lint_kit_have_node; then
    return 0
  fi
  if command -v nodejs >/dev/null 2>&1; then
    if [[ ${EUID} -eq 0 ]]; then
      ln -sf /usr/bin/nodejs /usr/local/bin/node 2>/dev/null || true
    else
      mkdir -p "${HOME}/.local/bin"
      ln -sf "$(command -v nodejs)" "${HOME}/.local/bin/node" 2>/dev/null || true
      export PATH="${HOME}/.local/bin:${PATH}"
    fi
  fi
  lint_kit_have_node
}

lint_kit_npm_global_bin() {
  local prefix
  prefix="$(npm prefix -g 2>/dev/null || true)"
  [[ -n ${prefix} ]] || return 1
  printf '%s/bin' "${prefix}"
}

lint_kit_prepend_npm_global_bin() {
  local npm_bin
  npm_bin="$(lint_kit_npm_global_bin)" || return 0
  case ":${PATH}:" in
    *":${npm_bin}:"*) ;;
    *) export PATH="${npm_bin}:${PATH}" ;;
  esac
}

lint_kit_markdownlint_version_raw() {
  local out ver
  command -v markdownlint >/dev/null 2>&1 || return 1
  out="$(markdownlint --version 2>/dev/null | head -n1)" || return 1
  [[ -n ${out} ]] || return 1
  ver="$(printf '%s\n' "${out}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  [[ -n ${ver} ]] || return 1
  printf '%s\n' "${ver}"
}

lint_kit_markdownlint_version_ge() {
  local want="$1"
  local have
  have="$(lint_kit_markdownlint_version_raw)" || return 1
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

lint_kit_ensure_markdownlint() {
  lint_kit_ensure_node_symlink || true
  lint_kit_prepend_npm_global_bin

  if lint_kit_markdownlint_version_ge "$LINT_KIT_MARKDOWNLINT_MIN_VERSION"; then
    return 0
  fi
  lint_kit_markdownlint_hint
  return 1
}

lint_kit_run_markdownlint() {
  lint_kit_prepend_npm_global_bin
  command markdownlint "$@"
}

lint_kit_markdownlint_collect_targets() {
  local repo_root="${1%/}"
  local kit_manifest kit_scan

  [[ -d $repo_root ]] || return 0
  kit_manifest="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../core/manifest" && pwd)"
  kit_scan="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../core/scan" && pwd)"

  PYTHONPATH="$kit_manifest:$kit_scan" python3 "$kit_manifest/consumer_manifest.py" \
    --repo-root "$repo_root" scan-paths markdown
}

lint_kit_markdownlint_fail_on_change() {
  local config="$1"
  shift
  local -a files=("$@")

  if ((${#files[@]} == 0)); then
    lint_kit_formatter_ok_message "markdownlint" 0 0
    return 0
  fi

  local scanned
  scanned="$(lint_kit_count_existing_files "${files[@]}")"

  lint_kit_fail_on_change_begin "${files[@]}"
  lint_kit_run_markdownlint --config "${config}" --fix "${files[@]}" || true
  lint_kit_fail_on_change_end "markdownlint reformatted Markdown" "${files[@]}" || return 1
  if ! lint_kit_run_markdownlint --config "${config}" "${files[@]}"; then
    return 1
  fi

  lint_kit_formatter_ok_message "markdownlint" "${scanned}" 0
}

lint_kit_markdownlint_self_test() {
  local tmp fakebin
  tmp="$(mktemp -d)"
  fakebin="${tmp}/bin"
  mkdir -p "${fakebin}"
  cat >"${fakebin}/markdownlint" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == '--version' ]]; then echo '0.49.0'; exit 0; fi
exit 0
EOF
  chmod +x "${fakebin}/markdownlint"
  # shellcheck disable=SC2030
  PATH="${fakebin}:${PATH}" lint_kit_markdownlint_version_ge 0.48.0 || {
    rm -rf "${tmp}"
    return 1
  }
  if PATH="${fakebin}:${PATH}" lint_kit_markdownlint_version_ge 1.0.0; then
    rm -rf "${tmp}"
    return 1
  fi
  rm -rf "${tmp}"
  printf 'markdownlint self-test: OK\n'
}
