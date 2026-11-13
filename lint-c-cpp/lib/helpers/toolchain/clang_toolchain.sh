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
# Each tool resolves to the newest NAME-<major> or bare NAME on PATH. Set
# LINT_KIT_LLVM_MAJOR to accept only that major (lint.sh sets it from the
# consumer manifest's toolchain.llvm_major).
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
LINT_KIT_CLANG_FORMAT_MIN_VERSION="${LINT_KIT_CLANG_FORMAT_MIN_VERSION:-$(lint_kit_tool_min_version clang_format)}"

# Major named in install hints: the pinned one, else the clang-tidy minimum.
lint_kit_llvm_hint_major() {
  printf '%s\n' "${LINT_KIT_LLVM_MAJOR:-${LINT_KIT_CLANG_TIDY_MIN_VERSION%%.*}}"
}

lint_kit_clang_tidy_hint() {
  local major
  major="$(lint_kit_llvm_hint_major)"
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: apt install clang-tidy-${major} clang-tools-${major} (apt.llvm.org)" \
    '      or: install clang-tools-extra (Fedora)' >&2
}

lint_kit_clang_format_hint() {
  local major
  major="$(lint_kit_llvm_hint_major)"
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    "      or: apt install clang-format-${major} (apt.llvm.org)" \
    '      or: install clang-tools-extra (Fedora)' >&2
}

lint_kit_scan_build_hint() {
  printf '%s\n' \
    'hint: INSTALL_DEPS=1 bash make/install-linux-deps.sh' \
    '      or: apt install clang-tools' \
    '      or: install clang-tools-extra (Fedora)' >&2
}

# Resolved path of every NAME-<major> on PATH, newest major first, then NAME.
lint_kit_llvm_tool_candidates() {
  local name="${1:?}" candidate
  while IFS= read -r candidate; do
    command -v "${candidate}" 2>/dev/null || true
  done < <(
    { compgen -c -- "${name}-" || true; } |
      sed -n "s/^${name}-\([0-9][0-9]*\)\$/\1/p" | sort -rnu | sed "s/^/${name}-/"
    printf '%s\n' "${name}"
  )
}

# Highest-version NAME at or above MIN; only LINT_KIT_LLVM_MAJOR when set.
# VERSION_FN prints a candidate's version.
lint_kit_find_llvm_tool() {
  local name="$1" min="$2" version_fn="$3"
  local candidate ver best="" best_ver=""
  while IFS= read -r candidate; do
    [[ -n ${candidate} && -x ${candidate} ]] || continue
    ver="$("${version_fn}" "${candidate}")" || continue
    [[ -n ${ver} ]] || continue
    [[ -z ${LINT_KIT_LLVM_MAJOR:-} || ${ver%%.*} == "${LINT_KIT_LLVM_MAJOR}" ]] || continue
    [[ "$(printf '%s\n%s\n' "$min" "$ver" | sort -V | head -n1)" == "$min" ]] || continue
    if [[ -z ${best_ver} ]] ||
      [[ "$(printf '%s\n%s\n' "$best_ver" "$ver" | sort -V | tail -n1)" == "$ver" ]]; then
      best="${candidate}"
      best_ver="${ver}"
    fi
  done < <(lint_kit_llvm_tool_candidates "${name}")
  [[ -n ${best} ]] || return 1
  printf '%s\n' "${best}"
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

lint_kit_find_clang_tidy() {
  lint_kit_find_llvm_tool clang-tidy "$LINT_KIT_CLANG_TIDY_MIN_VERSION" lint_kit_clang_tidy_version_raw
}

# run-clang-tidy of the same major: beside the resolved binary, then
# run-clang-tidy-<major>, then bare.
lint_kit_find_run_clang_tidy() {
  local tidy_bin="$1"
  local dir ver candidate
  local -a names=()

  dir="$(dirname -- "$(readlink -f -- "${tidy_bin}")")"
  for candidate in "${dir}/run-clang-tidy" "${dir}/run-clang-tidy.py"; do
    [[ -x ${candidate} ]] && {
      printf '%s\n' "${candidate}"
      return 0
    }
  done

  ver="$(lint_kit_clang_tidy_version_raw "${tidy_bin}")" || ver=""
  [[ -z ${ver} ]] || names+=("run-clang-tidy-${ver%%.*}" "run-clang-tidy-${ver%%.*}.py")
  for candidate in "${names[@]}" run-clang-tidy run-clang-tidy.py; do
    command -v "${candidate}" 2>/dev/null && return 0
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

lint_kit_find_clang_format() {
  lint_kit_find_llvm_tool clang-format "$LINT_KIT_CLANG_FORMAT_MIN_VERSION" lint_kit_clang_format_version_raw
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

  # shfmt 3.7 and 3.14 disagree on the spacing of a negated arithmetic test,
  # so a script that uses one cannot pass both. "((x == 0))" is stable.
  if grep -nE '\(\(!' "${files[@]}" >&2; then
    printf 'error: shfmt versions disagree on a negated arithmetic test; write ((x == 0))\n' >&2
    return 1
  fi
  lint_kit_with_fail_on_change "shfmt reformatted shell scripts" "${files[@]}" -- \
    shfmt -w -i 2 -ci -s "${files[@]}" || return 1
  shfmt -d -i 2 -ci -s "${files[@]}"
  lint_kit_formatter_ok_message "shfmt" "${scanned}" 0
}

# Presence only: the kit ships no scan-build config, so any LLVM version works.
lint_kit_find_scan_build() {
  local candidate
  while IFS= read -r candidate; do
    [[ -x ${candidate} ]] && {
      printf '%s\n' "${candidate}"
      return 0
    }
  done < <(lint_kit_llvm_tool_candidates scan-build)
  return 1
}

lint_kit_ensure_scan_build() {
  local scan_bin install_dir
  scan_bin="$(lint_kit_find_scan_build)" || return 1
  install_dir="$(lint_kit_clang_tidy_install_dir)"
  mkdir -p "${install_dir}"
  [[ ${scan_bin} == "${install_dir}/scan-build" ]] ||
    ln -sf "${scan_bin}" "${install_dir}/scan-build"
  lint_kit_export_tool_shim_dir "${install_dir}"
}
