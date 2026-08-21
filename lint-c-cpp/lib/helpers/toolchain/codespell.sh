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

# Typo detection via codespell -- no hunspell / project wordlist maintenance.
#
# codespell flags common misspellings (teh, recieve, ...), not unknown vocabulary.
# Markdown code fences and HTML license comments are stripped; URLs and hex literals
# are ignored so technical docs stay low-noise without a custom dictionary.
#
# Requires codespell with --ignore-multiline-regex. The minimum version is read
# from tool-versions.yaml; this helper never installs or upgrades tools.
#
# Usage:
#   bash lib/helpers/toolchain/codespell.sh [paths...]
#   bash lib/helpers/toolchain/codespell.sh --check-config
#
# Sourceable helpers (install-linux-deps.sh):
#   lint_kit_ensure_codespell
set -euo pipefail

# shellcheck source=tool_versions.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/tool_versions.sh"

LINT_KIT_CODESPELL_MIN_VERSION="${LINT_KIT_CODESPELL_MIN_VERSION:-$(lint_kit_tool_min_version codespell)}"

lint_kit_codespell_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      ensure codespell >= ${LINT_KIT_CODESPELL_MIN_VERSION}" >&2
}

lint_kit_codespell_supports_multiline_regex() {
  command -v codespell >/dev/null 2>&1 &&
    codespell --help 2>&1 | grep -qF -- '--ignore-multiline-regex'
}

lint_kit_ensure_codespell() {
  lint_kit_codespell_supports_multiline_regex
}

lint_kit_codespell_self_test() {
  local tmp fakebin
  tmp="$(mktemp -d)"
  fakebin="${tmp}/bin"
  mkdir -p "${fakebin}"
  cat >"${fakebin}/codespell" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == '--version' ]]; then echo '2.4.2'; exit 0; fi
if [[ ${1:-} == '--help' ]]; then echo '--ignore-multiline-regex'; exit 0; fi
exit 0
EOF
  chmod +x "${fakebin}/codespell"
  PATH="${fakebin}:${PATH}" lint_kit_codespell_supports_multiline_regex || {
    rm -rf "${tmp}"
    return 1
  }
  rm -rf "${tmp}"
  printf 'codespell self-test: OK\n'
}

lint_kit_codespell_main() {
  local check_config kit_manifest kit_scan repo_root
  local -a targets codespell_args

  usage() {
    cat <<'EOF'
Usage: lib/helpers/toolchain/codespell.sh [OPTIONS] [PATH ...]

Run codespell with repository-standard filters. Paths default to all
Markdown/YAML under the repo (respecting scan exclusions) plus C/C++ sources
under scan.source_roots.

Options:
  --check-config   Print effective codespell argv and exit 0
  -h, --help       Help

EOF
  }

  kit_manifest="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../core/manifest" && pwd)"
  kit_scan="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../core/scan" && pwd)"
  repo_root="${LINT_REPO_ROOT:-$(pwd)}"
  repo_root="$(cd -- "$repo_root" && pwd)"

  # License HTML blocks and fenced code (inline `code` stays checked -- usually prose).
  # shellcheck disable=SC2016
  local IGNORE_MULTILINE_REGEX='(?s)<!--.*?-->|\`\`\`.*?(\`\`\`|$)'

  # URLs, hex, email-ish tokens, long uppercase acronyms, snake_case identifiers,
  # and C/C++ #include directive paths (compiler-verified filenames, not prose --
  # spell-checking them only false-positives on library/vendor names like Synopsys).
  # shellcheck disable=SC2016
  local IGNORE_REGEX='(\bhttps?://\S+\b|\b0x[0-9A-Fa-f]+\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b[A-Z][A-Z0-9_]{2,}\b|\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b|^[ \t]*#[ \t]*include[ \t]*[<"][^">]*[">])'

  local SKIP_GLOBS='*.png,*.jpg,*.jpeg,*.gif,*.webp,*.svg,*.ico,*.bin,*.hex,*.pdf,build,build-*,dist,third-party,_deps,node_modules,.git'
  local CODESPELL_BUILTINS='clear,rare'

  codespell_args=(
    --builtin "$CODESPELL_BUILTINS"
    --ignore-multiline-regex "$IGNORE_MULTILINE_REGEX"
    --ignore-regex "$IGNORE_REGEX"
    -S "$SKIP_GLOBS"
    -q 2
  )

  default_targets() {
    local pattern path discover_tmp
    discover_tmp="$(mktemp)"
    if ! PYTHONPATH="$kit_manifest:$kit_scan" python3 "$kit_manifest/consumer_manifest.py" \
      --repo-root "$repo_root" scan-paths codespell >"$discover_tmp"; then
      rm -f "$discover_tmp"
      printf 'error: failed to discover codespell targets via consumer manifest\n' >&2
      return 1
    fi
    shopt -s nullglob globstar
    while IFS= read -r pattern; do
      [[ -n $pattern ]] || continue
      if [[ $pattern == *[*?[]* ]]; then
        for path in "$repo_root"/$pattern; do
          [[ -f $path ]] && printf '%s\n' "$path"
        done
      else
        path="$repo_root/$pattern"
        [[ -f $path ]] && printf '%s\n' "$path"
      fi
    done <"$discover_tmp"
    rm -f "$discover_tmp"
  }

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
    local discover_tmp
    discover_tmp="$(mktemp)"
    if ! default_targets >"$discover_tmp"; then
      rm -f "$discover_tmp"
      exit 1
    fi
    mapfile -t targets <"$discover_tmp"
    rm -f "$discover_tmp"
  fi

  if ((${#targets[@]} == 0)); then
    printf 'codespell: OK (no files to check)\n'
    exit 0
  fi

  if ! command -v codespell >/dev/null 2>&1; then
    printf 'error: codespell not found\n' >&2
    lint_kit_codespell_hint
    exit 1
  fi

  if ! lint_kit_codespell_supports_multiline_regex; then
    printf 'error: codespell >= %s required (--ignore-multiline-regex); found %s\n' \
      "${LINT_KIT_CODESPELL_MIN_VERSION}" \
      "$(codespell --version 2>/dev/null | head -n1 || echo unknown)" >&2
    lint_kit_codespell_hint
    exit 1
  fi

  if ((check_config == 1)); then
    printf 'codespell'
    printf ' %q' "${codespell_args[@]}"
    printf ' %q' "${targets[@]}"
    printf '\n'
    exit 0
  fi

  cd "$repo_root"
  codespell "${codespell_args[@]}" "${targets[@]}"
  if ((${#targets[@]} == 1)); then
    printf 'codespell: OK (1 file checked)\n'
  else
    printf 'codespell: OK (%d files checked)\n' "${#targets[@]}"
  fi
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  lint_kit_codespell_main "$@"
fi
