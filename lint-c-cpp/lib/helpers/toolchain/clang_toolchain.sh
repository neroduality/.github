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

# Resolve clang-tidy, clang-format, and scan-build for lint parity across distros.
# Minimum versions are read from tool-versions.yaml; this helper never installs tools.
#
# Sourceable helpers (install-linux-deps.sh, lint.sh):
#   lint_kit_ensure_clang_tidy
#   lint_kit_ensure_clang_format
#   lint_kit_ensure_scan_build
set -euo pipefail

# shellcheck source=tool_versions.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/tool_versions.sh"
# shellcheck source=format_toolchain.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/format_toolchain.sh"

LINT_KIT_CLANG_TIDY_MIN_VERSION="${LINT_KIT_CLANG_TIDY_MIN_VERSION:-$(lint_kit_tool_min_version clang_tidy)}"
LINT_KIT_CLANG_TIDY_PREFERRED_MAJOR=21
LINT_KIT_CLANG_FORMAT_MIN_VERSION="${LINT_KIT_CLANG_FORMAT_MIN_VERSION:-$(lint_kit_tool_min_version clang_format)}"
LINT_KIT_SCAN_BUILD_MIN_VERSION="${LINT_KIT_CLANG_TIDY_MIN_VERSION}"

lint_kit_clang_tidy_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: apt install clang-tidy-${LINT_KIT_CLANG_TIDY_PREFERRED_MAJOR} clang-tools-${LINT_KIT_CLANG_TIDY_PREFERRED_MAJOR}" \
    '      or: install clang-tools-extra (Fedora)' >&2
}

lint_kit_clang_format_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: apt install clang-format-${LINT_KIT_CLANG_TIDY_PREFERRED_MAJOR} clang-format-20" \
    '      or: install clang-tools-extra (Fedora >=43)' >&2
}

lint_kit_scan_build_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: apt install clang-tools-${LINT_KIT_CLANG_TIDY_PREFERRED_MAJOR}" \
    '      or: install clang-tools-extra (Fedora)' >&2
}

lint_kit_clang_tidy_install_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/usr/local/bin\n'
  else
    printf '%s\n' "${HOME}/.local/bin"
  fi
}

lint_kit_export_tool_shim_dir() {
  local install_dir="$1"

  export PATH="${install_dir}:${PATH}"
  if [[ -n ${GITHUB_PATH:-} ]] &&
    { [[ ! -f ${GITHUB_PATH} ]] || ! grep -Fxq "${install_dir}" "${GITHUB_PATH}" 2>/dev/null; }; then
    printf '%s\n' "${install_dir}" >>"${GITHUB_PATH}"
  fi
}

lint_kit_clang_tidy_version_raw() {
  local bin="${1:-}"
  if [[ -z ${bin} ]]; then
    command -v clang-tidy >/dev/null 2>&1 || return 1
    bin="$(command -v clang-tidy)"
  fi
  [[ -x ${bin} ]] || return 1
  "${bin}" --version 2>/dev/null |
    sed -n \
      -e 's/.*LLVM version \([0-9][0-9.]*\).*/\1/p' \
      -e 's/.*clang-tidy version \([0-9][0-9.]*\).*/\1/p' |
    head -n1
}

lint_kit_clang_tidy_version_ge() {
  local want="$1"
  local have="${2:-}"
  if [[ -z ${have} ]]; then
    have="$(lint_kit_clang_tidy_version_raw)" || return 1
  fi
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

lint_kit_clang_tidy_candidate_bins() {
  local name
  for name in clang-tidy-21 clang-tidy-20 clang-tidy-19 clang-tidy-18 clang-tidy; do
    command -v "${name}" 2>/dev/null || true
  done
}

lint_kit_find_clang_tidy() {
  local candidate ver best="" best_ver=""
  while IFS= read -r candidate; do
    [[ -n ${candidate} && -x ${candidate} ]] || continue
    ver="$(lint_kit_clang_tidy_version_raw "${candidate}")" || continue
    lint_kit_clang_tidy_version_ge "$LINT_KIT_CLANG_TIDY_MIN_VERSION" "$ver" || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "$best_ver" "$ver" | sort -V | tail -n1)" == "$ver" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done < <(lint_kit_clang_tidy_candidate_bins)
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
}

lint_kit_find_run_clang_tidy() {
  local tidy_bin="$1"
  local base="${tidy_bin##*/}"
  local candidate

  case "${base}" in
    clang-tidy-[0-9][0-9])
      for candidate in "run-${base}" "run-${base}.py"; do
        command -v "${candidate}" >/dev/null 2>&1 && {
          command -v "${candidate}"
          return 0
        }
      done
      ;;
  esac

  for candidate in run-clang-tidy run-clang-tidy.py; do
    command -v "${candidate}" >/dev/null 2>&1 && {
      command -v "${candidate}"
      return 0
    }
  done
  return 1
}

lint_kit_ensure_clang_tidy() {
  local tidy_bin run_bin install_dir
  tidy_bin="$(lint_kit_find_clang_tidy)" || return 1

  install_dir="$(lint_kit_clang_tidy_install_dir)"
  mkdir -p "${install_dir}"
  if [[ ${tidy_bin} != "${install_dir}/clang-tidy" ]]; then
    ln -sf "${tidy_bin}" "${install_dir}/clang-tidy"
  fi

  if run_bin="$(lint_kit_find_run_clang_tidy "${tidy_bin}")"; then
    if [[ ${run_bin} != "${install_dir}/run-clang-tidy" ]]; then
      ln -sf "${run_bin}" "${install_dir}/run-clang-tidy"
    fi
  fi

  lint_kit_export_tool_shim_dir "${install_dir}"

  lint_kit_clang_tidy_version_ge "$LINT_KIT_CLANG_TIDY_MIN_VERSION"
}

lint_kit_clang_format_version_raw() {
  local bin="${1:-}"
  if [[ -z ${bin} ]]; then
    command -v clang-format >/dev/null 2>&1 || return 1
    bin="$(command -v clang-format)"
  fi
  [[ -x ${bin} ]] || return 1
  "${bin}" --version 2>/dev/null |
    sed -n \
      -e 's/.*LLVM version \([0-9][0-9.]*\).*/\1/p' \
      -e 's/.*clang-format version \([0-9][0-9.]*\).*/\1/p' |
    head -n1
}

lint_kit_clang_format_version_ge() {
  local want="$1"
  local have="${2:-}"
  if [[ -z ${have} ]]; then
    have="$(lint_kit_clang_format_version_raw)" || return 1
  fi
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

lint_kit_clang_format_candidate_bins() {
  local name
  for name in clang-format-21 clang-format-20 clang-format; do
    command -v "${name}" 2>/dev/null || true
  done
}

lint_kit_find_clang_format() {
  local candidate ver best="" best_ver=""
  while IFS= read -r candidate; do
    [[ -n ${candidate} && -x ${candidate} ]] || continue
    ver="$(lint_kit_clang_format_version_raw "${candidate}")" || continue
    lint_kit_clang_format_version_ge "$LINT_KIT_CLANG_FORMAT_MIN_VERSION" "$ver" || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "$best_ver" "$ver" | sort -V | tail -n1)" == "$ver" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done < <(lint_kit_clang_format_candidate_bins)
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
}

lint_kit_ensure_clang_format() {
  local format_bin install_dir
  format_bin="$(lint_kit_find_clang_format)" || return 1

  install_dir="$(lint_kit_clang_tidy_install_dir)"
  mkdir -p "${install_dir}"
  if [[ ${format_bin} != "${install_dir}/clang-format" ]]; then
    ln -sf "${format_bin}" "${install_dir}/clang-format"
  fi

  lint_kit_export_tool_shim_dir "${install_dir}"

  lint_kit_clang_format_version_ge "$LINT_KIT_CLANG_FORMAT_MIN_VERSION"
}

_lint_kit_clang_format_inplace() {
  local style="$1"
  local bin="$2"
  shift 2
  local file
  for file in "$@"; do
    [[ -f ${file} ]] || continue
    "${bin}" -i --style="${style}" "${file}"
  done
}

_lint_kit_clang_format_verify() {
  local style="$1"
  local bin="$2"
  shift 2
  local file
  for file in "$@"; do
    [[ -f ${file} ]] || continue
    "${bin}" --dry-run --Werror --style="${style}" "${file}"
  done
}

lint_kit_clang_format_fail_on_change() {
  local style="$1"
  local bin="$2"
  shift 2
  local -a files=("$@")

  if ((${#files[@]} == 0)); then
    lint_kit_formatter_ok_message "clang-format" 0 0
    return 0
  fi

  local scanned
  scanned="$(lint_kit_count_existing_files "${files[@]}")"

  lint_kit_fail_on_change_begin "${files[@]}"
  _lint_kit_clang_format_inplace "${style}" "${bin}" "${files[@]}"
  lint_kit_fail_on_change_end "clang-format reformatted sources" "${files[@]}" || return 1
  _lint_kit_clang_format_verify "${style}" "${bin}" "${files[@]}"
  lint_kit_formatter_ok_message "clang-format" "${scanned}" 0
}

lint_kit_shfmt_fail_on_change() {
  local -a files=("$@")

  if ((${#files[@]} == 0)); then
    lint_kit_formatter_ok_message "shfmt" 0 0
    return 0
  fi

  local scanned
  scanned="$(lint_kit_count_existing_files "${files[@]}")"

  lint_kit_with_fail_on_change "shfmt reformatted shell scripts" "${files[@]}" -- \
    shfmt -w -i 2 -ci -s "${files[@]}" || return 1
  shfmt -d -i 2 -ci -s "${files[@]}"
  lint_kit_formatter_ok_message "shfmt" "${scanned}" 0
}

lint_kit_scan_build_version_raw() {
  local bin="${1:?}" ver base
  [[ -x ${bin} ]] || return 1
  ver="$("${bin}" --version 2>/dev/null |
    sed -n \
      -e 's/.*LLVM version \([0-9][0-9.]*\).*/\1/p' \
      -e 's/.*scan-build version \([0-9][0-9.]*\).*/\1/p' |
    head -n1)"
  [[ -n ${ver} ]] && {
    printf '%s\n' "${ver}"
    return 0
  }
  base="$(basename "${bin}")"
  [[ ${base} =~ ^scan-build-([0-9]+)$ ]] && {
    printf '%s.0.0\n' "${BASH_REMATCH[1]}"
    return 0
  }
  return 1
}

lint_kit_scan_build_version_ge() {
  local want="$1"
  local have="${2:?}"
  [[ -n ${have} ]] || return 1
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n1)" == "$want" ]]
}

lint_kit_find_scan_build() {
  local name candidate ver best="" best_ver=""
  for name in scan-build-21 scan-build-20 scan-build-19 scan-build-18; do
    candidate="$(command -v "${name}" 2>/dev/null)" || continue
    [[ -x ${candidate} ]] || continue
    ver="$(lint_kit_scan_build_version_raw "${candidate}")" || continue
    lint_kit_scan_build_version_ge "$LINT_KIT_SCAN_BUILD_MIN_VERSION" "$ver" || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "$best_ver" "$ver" | sort -V | tail -n1)" == "$ver" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
}

lint_kit_ensure_scan_build() {
  local scan_bin install_dir ver
  scan_bin="$(lint_kit_find_scan_build)" || return 1
  ver="$(lint_kit_scan_build_version_raw "${scan_bin}")" || return 1
  install_dir="$(lint_kit_clang_tidy_install_dir)"
  mkdir -p "${install_dir}"
  [[ ${scan_bin} == "${install_dir}/scan-build" ]] ||
    ln -sf "${scan_bin}" "${install_dir}/scan-build"
  lint_kit_export_tool_shim_dir "${install_dir}"
  lint_kit_scan_build_version_ge "$LINT_KIT_SCAN_BUILD_MIN_VERSION" "$ver"
}
