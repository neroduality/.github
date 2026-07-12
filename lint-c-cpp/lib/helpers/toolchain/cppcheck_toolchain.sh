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

# Verify cppcheck for lint parity. The minimum version is read from tool-versions.yaml.
#
# Sourceable helpers (install-linux-deps.sh):
#   lint_kit_ensure_cppcheck
set -euo pipefail

# shellcheck source=tool_versions.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/tool_versions.sh"

LINT_KIT_CPPCHECK_MIN_VERSION="${LINT_KIT_CPPCHECK_MIN_VERSION:-$(lint_kit_tool_min_version cppcheck)}"

lint_kit_cppcheck_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      ensure cppcheck >= ${LINT_KIT_CPPCHECK_MIN_VERSION}" >&2
}

lint_kit_cppcheck_version_raw() {
  command -v cppcheck >/dev/null 2>&1 || return 1
  cppcheck --version 2>/dev/null | sed -n 's/^Cppcheck \([0-9][0-9.]*\).*/\1/p' | head -n1
}

lint_kit_cppcheck_version_ge() {
  local want="$1"
  local have
  have="$(lint_kit_cppcheck_version_raw)" || return 1
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

lint_kit_ensure_cppcheck() {
  lint_kit_cppcheck_version_ge "$LINT_KIT_CPPCHECK_MIN_VERSION"
}

lint_kit_cppcheck_self_test() {
  local tmp fakebin
  tmp="$(mktemp -d)"
  fakebin="${tmp}/bin"
  mkdir -p "${fakebin}"
  cat >"${fakebin}/cppcheck" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == '--version' ]]; then echo 'Cppcheck 2.19.1'; exit 0; fi
exit 0
EOF
  chmod +x "${fakebin}/cppcheck"
  PATH="${fakebin}:${PATH}" lint_kit_cppcheck_version_ge 2.19.1 || {
    rm -rf "${tmp}"
    return 1
  }
  if PATH="${fakebin}:${PATH}" lint_kit_cppcheck_version_ge 2.20.0; then
    rm -rf "${tmp}"
    return 1
  fi
  rm -rf "${tmp}"
  printf 'cppcheck self-test: OK\n'
}
