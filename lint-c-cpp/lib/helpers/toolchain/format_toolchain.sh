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
# Shared apply-in-place + fail-if-changed gate for lint formatters.
# Source this file; do not execute directly.
# shellcheck shell=bash

LINT_KIT_FAIL_ON_CHANGE_TAIL="commit the updates and re-run"

lint_kit_fail_on_change_error() {
  printf 'error: %s; %s\n' "$1" "${LINT_KIT_FAIL_ON_CHANGE_TAIL}" >&2
}

lint_kit_formatter_ok_message() {
  printf '%s: OK (%d scanned, %d auto-formatted)\n' "$1" "$2" "${3:-0}"
}

lint_kit_count_existing_files() {
  local n=0 f
  for f in "$@"; do
    [[ -f ${f} ]] && n=$((n + 1))
  done
  echo "$n"
}

lint_kit_checksum_files() {
  local f
  for f in "$@"; do
    [[ -f ${f} ]] || continue
    sha256sum "${f}"
  done | LC_ALL=C sort
}

lint_kit_fail_on_change_begin() {
  LINT_KIT_FOC_BEFORE="$(mktemp)"
  lint_kit_checksum_files "$@" >"${LINT_KIT_FOC_BEFORE}"
}

lint_kit_fail_on_change_end() {
  local detail="$1"
  shift
  local after
  after="$(mktemp)"
  lint_kit_checksum_files "$@" >"${after}"
  if ! cmp -s "${LINT_KIT_FOC_BEFORE}" "${after}"; then
    rm -f "${LINT_KIT_FOC_BEFORE}" "${after}"
    unset LINT_KIT_FOC_BEFORE
    lint_kit_fail_on_change_error "${detail}"
    return 1
  fi
  rm -f "${LINT_KIT_FOC_BEFORE}" "${after}"
  unset LINT_KIT_FOC_BEFORE
}

# Run a formatter command; fail if any tracked file checksum changed.
# Usage: lint_kit_with_fail_on_change "detail" file... -- formatter args...
lint_kit_with_fail_on_change() {
  local detail="$1"
  shift
  local -a files=()
  while (($# > 0)) && [[ $1 != "--" ]]; do
    files+=("$1")
    shift
  done
  if [[ ${1:-} != "--" ]]; then
    printf 'error: lint_kit_with_fail_on_change: missing -- before formatter command\n' >&2
    return 2
  fi
  shift
  local -a cmd=("$@")

  if ((${#files[@]} == 0)); then
    return 0
  fi

  lint_kit_fail_on_change_begin "${files[@]}"
  "${cmd[@]}"
  local cmd_ec=$?
  lint_kit_fail_on_change_end "${detail}" "${files[@]}"
  local gate_ec=$?
  ((gate_ec != 0)) && return "${gate_ec}"
  return "${cmd_ec}"
}

lint_kit_format_toolchain_self_test() {
  local tmp file
  tmp="$(mktemp -d)"
  file="${tmp}/sample.txt"
  printf 'before\n' >"${file}"

  if ! lint_kit_with_fail_on_change "sample rewrite" "${file}" -- sed -i 's/before/after/' "${file}" 2>/dev/null; then
    :
  else
    printf 'format-toolchain self-test miss: expected checksum gate failure\n' >&2
    return 1
  fi

  printf 'stable\n' >"${file}"
  lint_kit_fail_on_change_begin "${file}"
  :
  lint_kit_fail_on_change_end "sample noop" "${file}" || {
    printf 'format-toolchain self-test miss: expected stable file to pass\n' >&2
    return 1
  }

  rm -rf "${tmp}"
  printf 'format-toolchain self-test: OK\n'
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  lint_kit_format_toolchain_self_test
fi
