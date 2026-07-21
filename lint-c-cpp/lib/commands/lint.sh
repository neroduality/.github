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
# Generic C/C++ lint driver — all project paths and policy from .github/lint-c-cpp.yaml.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: lint-c-cpp.sh lint [OPTIONS]

Run lint checks for a consumer repo (configure via .github/lint-c-cpp.yaml).

Options:
  --custom-lints-only   Stop before compile DB / cppcheck / clang-tidy / firmware DB+build
  -h, --help            Show help
EOF
}

custom_lints_only=0
while (($# > 0)); do
  case "$1" in
    --custom-lints-only) custom_lints_only=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

# shellcheck source=../lint_env.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/lint_env.sh"
_lint_env_init
repo_root="$LINT_REPO_ROOT"
lint_kit="$LINT_KIT"
lib="${lint_kit}/lib"
manifest="${lib}/core/manifest"
tools="${lib}/core/tools"
workflow="${lib}/core/workflow"
helpers="${lib}/helpers"
toolchain="${helpers}/toolchain"
cd "$repo_root"

write_scan_paths() {
  local job="$1" dest="$2"
  if ! python3 "${manifest}/consumer_manifest.py" --repo-root "$repo_root" scan-paths "$job" >"$dest"; then
    rm -f "$dest"
    printf 'error: scan-paths %s failed\n' "$job" >&2
    exit 1
  fi
}

read_scan_paths_into() {
  local job=$1
  local -n _paths=$2
  local paths_file
  paths_file="$(mktemp)"
  write_scan_paths "$job" "$paths_file"
  mapfile -t _paths <"$paths_file"
  rm -f "$paths_file"
}

toolchain_script_path="$(
  python3 - <<'PY'
from pathlib import Path
from consumer_manifest import toolchain_script
path = toolchain_script(Path.cwd().resolve())
print(path or "")
PY
)"
if [[ -n $toolchain_script_path ]]; then
  bash "$toolchain_script_path" activate
  bash "$toolchain_script_path" verify
fi

clang_config_dir="${lint_kit}/config"
overrides_dir="${repo_root}/build/lint-overrides"
python3 - <<'PY'
from pathlib import Path
from policy_overrides import lint_overrides_dir, materialize_override_configs
from consumer_manifest import resolve_lint_kit
import os

repo = Path.cwd().resolve()
kit = resolve_lint_kit(Path(os.environ["LINT_KIT"]) if os.environ.get("LINT_KIT") else None)
out = lint_overrides_dir(repo)
materialize_override_configs(repo, kit, out)
print(f"policy.overrides: materialized → {out.relative_to(repo)}")
PY
clang_format_config="${overrides_dir}/.clang-format"
if [[ ! -f $clang_format_config ]]; then
  clang_format_config="${clang_config_dir}/.clang-format"
fi
markdownlint_config="${clang_config_dir}/.markdownlint.yaml"
clang_format_style="file:$clang_format_config"

# shellcheck source=../helpers/toolchain/format_toolchain.sh
source "${toolchain}/format_toolchain.sh"
# shellcheck source=../helpers/toolchain/markdownlint_toolchain.sh
source "${toolchain}/markdownlint_toolchain.sh"
# shellcheck source=../helpers/toolchain/cppcheck_toolchain.sh
source "${toolchain}/cppcheck_toolchain.sh"
# shellcheck source=../helpers/toolchain/clang_toolchain.sh
source "${toolchain}/clang_toolchain.sh"
# shellcheck source=../helpers/toolchain/codespell.sh
source "${toolchain}/codespell.sh"
# shellcheck source=../helpers/toolchain/python_lint.sh
source "${toolchain}/python_lint.sh"

shopt -s nullglob

read_scan_paths_into markdown md_files
read_scan_paths_into format_c format_files
read_scan_paths_into shell shell_scripts
read_scan_paths_into python python_files

have_tool() { command -v "$1" >/dev/null 2>&1; }
require_tool() { have_tool "$1" || {
  printf 'error: required tool not found: %s\n' "$1" >&2
  exit 1
}; }
want_tool() { have_tool "$1" || {
  printf 'error: lint tool not found: %s (%s)\n' "$1" "$2" >&2
  exit 1
}; }

want_pyyaml() { python3 -c "import yaml" >/dev/null 2>&1 || {
  printf 'error: PyYAML required (%s)\n' "$1" >&2
  exit 1
}; }

want_markdownlint() {
  lint_kit_ensure_node_symlink || true
  lint_kit_prepend_npm_global_bin
  lint_kit_markdownlint_version_ge "$LINT_KIT_MARKDOWNLINT_MIN_VERSION" || {
    printf 'error: markdownlint not installed (%s)\n' "$1" >&2
    lint_kit_markdownlint_hint
    exit 1
  }
}

want_cppcheck() {
  command -v cppcheck >/dev/null 2>&1 && lint_kit_cppcheck_version_ge "$LINT_KIT_CPPCHECK_MIN_VERSION" && return 0
  lint_kit_cppcheck_hint
  exit 1
}

want_clang_tidy() {
  clang_tidy_bin="$(lint_kit_find_clang_tidy)" || {
    lint_kit_clang_tidy_hint
    exit 1
  }
  run_clang_tidy_bin="$(lint_kit_find_run_clang_tidy "$clang_tidy_bin" || true)"
}

want_clang_format() {
  clang_format_bin="$(lint_kit_find_clang_format)" || {
    lint_kit_clang_format_hint
    exit 1
  }
}

_lint_section_n=0
section() {
  # usage: section JOB_ID "Human-readable title"
  local job_id=$1
  local title=$2
  _lint_section_n=$((_lint_section_n + 1))
  printf '\n── %s. %s — %s ──\n' "$_lint_section_n" "$job_id" "$title"
}
lint_jobs="${LINT_JOBS:-$(nproc)}"

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

run python3 "${tools}/tool_versions_check.py" --self-test
run python3 "${tools}/tool_versions_check.py" verify
run python3 "${manifest}/manifest_validate.py" --repo-root "$repo_root"
run python3 "${tools}/tool_versions_check.py" verify --workflow
run python3 "${workflow}/workflow_container_policy.py" --repo-root "$repo_root"

{
  read -r _enabled_lint_job_count _known_lint_job_count
  read -r _ENABLED_LINT_JOBS
} < <(python3 "${manifest}/consumer_manifest.py" --repo-root "$repo_root" enabled-lint-jobs)
printf 'lint jobs: %s enabled out of %s\n' "$_enabled_lint_job_count" "$_known_lint_job_count"

lint_job_enabled() {
  case " ${_ENABLED_LINT_JOBS} " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

skip_lint_job() {
  printf 'skip: lint job %s (not in enabled_lint_jobs)\n' "$1"
}

run_python_policy_linter() {
  local script=$1 fix_hint=$2
  local script_base
  script_base="$(basename "$script")"
  run python3 "${helpers}/policy/policy_runner.py" --self-test --script "$script_base"
  run python3 "${helpers}/policy/policy_runner.py" \
    --repo-root "$repo_root" \
    --script "$script_base" \
    --fix-hint "$fix_hint" || {
    printf 'Fix: %s\n' "$fix_hint" >&2
    exit 1
  }
}

run_python_with_scan_paths() {
  local script="$1" scan_job="$2"
  shift 2
  run python3 "${helpers}/policy/policy_runner.py" \
    --repo-root "$repo_root" \
    --script "$(basename "$script")" \
    --scan-job "$scan_job" \
    "$@" || exit 1
}

run_python_hardening_verify() {
  local source_paths cmake_paths
  local -a extra_args=("$@")
  source_paths="$(mktemp)"
  cmake_paths="$(mktemp)"
  write_scan_paths source "$source_paths"
  write_scan_paths cmake "$cmake_paths"
  run python3 "${helpers}/policy/hardening_verify.py" \
    --repo-root "$repo_root" \
    --lint-kit "$lint_kit" \
    --paths-file "$source_paths" \
    --cmake-paths-file "$cmake_paths" \
    "${extra_args[@]}" || {
    rm -f "$source_paths" "$cmake_paths"
    exit 1
  }
  rm -f "$source_paths" "$cmake_paths"
}

run_compile_db_lint() {
  local command="$1"
  shift
  local unsafe_paths source_paths need_source=0
  unsafe_paths="$(mktemp)"
  write_scan_paths unsafe_api "$unsafe_paths"
  if [[ $command == configure-compile-db || $command == run-cppcheck ]]; then
    need_source=1
    source_paths="$(mktemp)"
    write_scan_paths source "$source_paths"
  fi
  if ((need_source == 1)); then
    run python3 "${helpers}/compile_db/compile_db_lint.py" \
      --repo-root "$repo_root" \
      --lint-kit "$lint_kit" \
      --unsafe-api-paths-file "$unsafe_paths" \
      --source-paths-file "$source_paths" \
      "$command" "$@" || {
      rm -f "$unsafe_paths" "$source_paths"
      exit 1
    }
    rm -f "$unsafe_paths" "$source_paths"
  else
    run python3 "${helpers}/compile_db/compile_db_lint.py" \
      --repo-root "$repo_root" \
      --lint-kit "$lint_kit" \
      --unsafe-api-paths-file "$unsafe_paths" \
      "$command" "$@" || {
      rm -f "$unsafe_paths"
      exit 1
    }
    rm -f "$unsafe_paths"
  fi
}

verify_clang_tidy_overlay_config() {
  local cfg="$1" out
  out="$("$clang_tidy_bin" --verify-config -config-file="$cfg" 2>&1)" || true
  grep -q 'No config errors detected' <<<"$out" || {
    printf 'error: clang-tidy --verify-config failed for %s\n' "$cfg" >&2
    printf '%s\n' "$out" >&2
    exit 1
  }
}

run_clang_tidy_filtered() {
  local drop_wrappers=0 ec=0 filter_ec=0 compile_db_p="" config_file=""
  local -a files=() pipe_ec=()
  if [[ ${1:-} == --unsafe-api ]]; then
    drop_wrappers=1
    shift
  fi
  while (($# > 0)); do
    case "$1" in
      -p)
        compile_db_p="$2"
        shift 2
        ;;
      -config-file)
        config_file="$2"
        shift 2
        ;;
      *)
        files+=("$1")
        shift
        ;;
    esac
  done
  ((${#files[@]} > 0)) || return 0

  local -a tidy_args=(-j"$lint_jobs" -p "$compile_db_p")
  [[ -n $config_file ]] && tidy_args+=(-config-file="$config_file")
  local filter_py="${helpers}/compile_db/clang_tidy_wrapper_filter.py"

  set +e
  if ((drop_wrappers != 0)); then
    if [[ -n $run_clang_tidy_bin ]]; then
      run "$run_clang_tidy_bin" -warnings-as-errors '*' "${tidy_args[@]}" "${files[@]}" 2>&1 \
        | python3 -u "$filter_py" --repo-root "$repo_root" --stream --wrapper-status
      pipe_ec=("${PIPESTATUS[@]}")
      ec=${pipe_ec[0]}
      filter_ec=${pipe_ec[1]}
    else
      if [[ -n $config_file ]]; then
        run "$clang_tidy_bin" -p "$compile_db_p" --warnings-as-errors='*' -config-file="$config_file" "${files[@]}" 2>&1 \
          | python3 -u "$filter_py" --repo-root "$repo_root" --stream --wrapper-status
      else
        run "$clang_tidy_bin" -p "$compile_db_p" --warnings-as-errors='*' "${files[@]}" 2>&1 \
          | python3 -u "$filter_py" --repo-root "$repo_root" --stream --wrapper-status
      fi
      pipe_ec=("${PIPESTATUS[@]}")
      ec=${pipe_ec[0]}
      filter_ec=${pipe_ec[1]}
    fi
    set -e
    if ((filter_ec == 1)); then
      return 1
    fi
    if ((filter_ec != 0 && filter_ec != 2)); then
      return "$filter_ec"
    fi
    if ((ec != 0)); then
      if ((ec == 1 && filter_ec == 2)); then
        return 0
      fi
      return "$ec"
    fi
    return 0
  fi

  if [[ -n $run_clang_tidy_bin ]]; then
    run "$run_clang_tidy_bin" -warnings-as-errors '*' "${tidy_args[@]}" "${files[@]}"
    ec=$?
  else
    if [[ -n $config_file ]]; then
      run "$clang_tidy_bin" -p "$compile_db_p" --warnings-as-errors='*' -config-file="$config_file" "${files[@]}"
    else
      run "$clang_tidy_bin" -p "$compile_db_p" --warnings-as-errors='*' "${files[@]}"
    fi
    ec=$?
  fi
  set -e
  return "$ec"
}

if lint_job_enabled license; then
  section license "Apply license headers"
  require_tool python3
  run python3 "${helpers}/policy/policy_runner.py" --self-test --script spdx_headers.py
  run_python_with_scan_paths policy/spdx_headers.py license --fail-on-change
else
  skip_lint_job license
fi

if lint_job_enabled yamllint; then
  section yamllint "Sort and format YAML (yamllint)"
  want_pyyaml "yamllint"
  run python3 "${helpers}/policy/policy_runner.py" --self-test --script yaml_manifest.py
  run_python_with_scan_paths policy/yaml_manifest.py yaml --fail-on-change
else
  skip_lint_job yamllint
fi

if lint_job_enabled markdownlint; then
  section markdownlint "Fix and check Markdown (markdownlint)"
  if want_markdownlint "Markdown"; then
    run lint_kit_markdownlint_self_test
    run lint_kit_markdownlint_fail_on_change "$markdownlint_config" "${md_files[@]}"
  fi
else
  skip_lint_job markdownlint
fi

if lint_job_enabled format; then
  section format "Format C/C++, shell, and Python sources (clang-format, shfmt, shellcheck, codespell, ruff, mypy)"
  run lint_kit_format_toolchain_self_test
  if want_clang_format "C/C++ formatting"; then
    run lint_kit_clang_format_fail_on_change "$clang_format_style" "$clang_format_bin" "${format_files[@]}"
  fi
  shell_targets=()
  for rel in "${shell_scripts[@]}"; do
    [[ -f $repo_root/$rel ]] && shell_targets+=("$repo_root/$rel")
  done
  if want_tool shfmt "shell formatting"; then
    run lint_kit_shfmt_fail_on_change "${shell_targets[@]}"
  fi
  if want_tool shellcheck "bash script linting"; then
    if ((${#shell_targets[@]} > 0)); then
      run shellcheck -S warning -x -P SCRIPTDIR "${shell_targets[@]}"
      if ((${#shell_targets[@]} == 1)); then
        printf 'shellcheck: OK (1 shell script checked)\n'
      else
        printf 'shellcheck: OK (%d shell scripts checked)\n' "${#shell_targets[@]}"
      fi
    else
      printf 'shellcheck: OK (no shell scripts to check)\n'
    fi
  fi
  if want_tool codespell "codespell"; then
    run lint_kit_codespell_self_test
    run bash "${toolchain}/codespell.sh"
  fi
  # Python lint (ruff + mypy) shares the format job, like shellcheck/codespell.
  # Only requires uv/uvx when the repo actually has Python sources.
  python_targets=()
  for rel in "${python_files[@]}"; do
    [[ -f $repo_root/$rel ]] && python_targets+=("$repo_root/$rel")
  done
  if ((${#python_targets[@]} > 0)); then
    run lint_kit_python_lint_self_test
    run bash "${toolchain}/python_lint.sh"
  else
    printf 'ruff/mypy: OK (no Python sources to check)\n'
  fi
else
  skip_lint_job format
fi

if ((custom_lints_only == 0)); then
  if lint_job_enabled compile_db; then
    section compile_db "Generate compile databases (host configure → merge → OpenSSF audit)"
    if want_tool cmake "compile database generation"; then
      run python3 "${helpers}/compile_db/compile_db_lint.py" --self-test
      run_compile_db_lint configure-compile-db --jobs "$lint_jobs"
    fi
  else
    skip_lint_job compile_db
  fi
fi

if lint_job_enabled openssf; then
  section openssf "OpenSSF hardening (validate manifest + hardeninglint)"
  run python3 "${helpers}/policy/hardening_verify.py" --self-test
  if ((custom_lints_only != 0)); then
    run_python_hardening_verify --skip-link-audit
  else
    run_python_hardening_verify
  fi
else
  skip_lint_job openssf
fi

if ((custom_lints_only == 0)); then
  if lint_job_enabled clang_tidy; then
    section clang_tidy "Run clang-tidy"
    if want_clang_tidy "C++ static analysis"; then
      merge_dir="${repo_root}/build/clang-tidy-compile-db"
      tidy_log="$(mktemp)"
      tidy_batches_file="$(mktemp)"
      tidy_batches=()
      source_paths="$(mktemp)"
      unsafe_paths="$(mktemp)"
      write_scan_paths source "$source_paths"
      write_scan_paths unsafe_api "$unsafe_paths"
      if ! python3 "${helpers}/compile_db/compile_db_lint.py" \
          --repo-root "$repo_root" \
          --lint-kit "$lint_kit" \
          --source-paths-file "$source_paths" \
          --unsafe-api-paths-file "$unsafe_paths" \
          clang-tidy-batches >"$tidy_batches_file" 2>"$tidy_log"; then
        if [[ -s $tidy_log ]]; then
          cat "$tidy_log" >&2
        fi
        rm -f "$source_paths" "$unsafe_paths" "$tidy_log" "$tidy_batches_file"
        exit 1
      fi
      rm -f "$source_paths" "$unsafe_paths"
      if [[ -s $tidy_log ]]; then
        cat "$tidy_log"
      fi
      rm -f "$tidy_log"
      mapfile -t tidy_batches <"$tidy_batches_file"
      rm -f "$tidy_batches_file"
      if ((${#tidy_batches[@]} == 0)); then
        printf 'clang-tidy (source): OK (no files to check)\n'
        printf 'clang-tidy (unsafe-api): OK (no files to check)\n'
      else
        tidy_source_count=0
        tidy_unsafe_count=0
        any_source=0
        any_unsafe=0
        for batch in "${tidy_batches[@]}"; do
          [[ -n $batch ]] || continue
          read -r pass cfg < <(
            python3 - "$batch" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
print(payload.get("pass", "source"), payload["config"])
PY
          )
          mapfile -t files < <(
            python3 - "$batch" <<'PY'
import json, sys
for item in json.loads(sys.argv[1])["files"]:
    print(item)
PY
          )
          verify_clang_tidy_overlay_config "$cfg"
          if ((${#files[@]} > 0)); then
            if [[ $pass == unsafe_api ]]; then
              run_clang_tidy_filtered --unsafe-api -p "$merge_dir" -config-file "$cfg" "${files[@]}"
            else
              run_clang_tidy_filtered -p "$merge_dir" -config-file "$cfg" "${files[@]}"
            fi
            if [[ $pass == unsafe_api ]]; then
              any_unsafe=1
              tidy_unsafe_count=$((tidy_unsafe_count + ${#files[@]}))
            else
              any_source=1
              tidy_source_count=$((tidy_source_count + ${#files[@]}))
            fi
          fi
        done
        if ((any_source == 0)); then
          printf 'clang-tidy (source): OK (no eligible files in batches)\n'
        else
          printf 'clang-tidy (source): OK (%d files checked)\n' "$tidy_source_count"
        fi
        if ((any_unsafe == 0)); then
          printf 'clang-tidy (unsafe-api): OK (no eligible files in batches)\n'
        else
          printf 'clang-tidy (unsafe-api): OK (%d files checked)\n' "$tidy_unsafe_count"
        fi
      fi
    fi
  else
    skip_lint_job clang_tidy
  fi
fi

if lint_job_enabled banned_cxx_heap; then
  section banned_cxx_heap "Enforce no C++ new/delete (including unsafe wrappers; complements clang-tidy/cppcheck)"
  run_python_policy_linter policy/banned_cxx_heap.py "use stack/static buffers; no C++ new/delete."
else
  skip_lint_job banned_cxx_heap
fi

if lint_job_enabled banned_libc_io; then
  section banned_libc_io "Enforce bounded libc and project I/O wrappers (capability-specific wrapper waivers)"
  run_python_policy_linter policy/banned_libc_io.py "use bounded helpers; list wrappers in policy.unsafe_api.wrapper_files."
else
  skip_lint_job banned_libc_io
fi

if lint_job_enabled null_nodiscard; then
  section null_nodiscard "Require project NULL and NODISCARD macros"
  run_python_policy_linter policy/null_nodiscard.py "use project NULL and NODISCARD macros."
else
  skip_lint_job null_nodiscard
fi

if lint_job_enabled relative_includes; then
  section relative_includes "Ban relative #includes"
  run_python_policy_linter policy/relative_includes.py "use include path basenames; no ../ in #include."
else
  skip_lint_job relative_includes
fi

if lint_job_enabled duplicate_includes; then
  section duplicate_includes "Remove duplicate #includes"
  run_python_policy_linter policy/duplicate_includes.py "remove mixed-angle/quote or macro #include dupes; exact repeats are clang-tidy."
else
  skip_lint_job duplicate_includes
fi

if lint_job_enabled shared_constant_dupes; then
  section shared_constant_dupes "Ban duplicate spec constant definitions"
  run_python_policy_linter policy/shared_constant_dupes.py "one authoritative definition per spec constant."
else
  skip_lint_job shared_constant_dupes
fi

if lint_job_enabled magic_literals; then
  section magic_literals "Require constant placement and bounds (complements clang-tidy)"
  run_python_policy_linter policy/magic_literals.py "fix constant placement and bounds; general magic numbers are enforced by clang-tidy."
else
  skip_lint_job magic_literals
fi

if lint_job_enabled guard_clause_style; then
  section guard_clause_style "Require early-return guard clauses"
  run_python_policy_linter policy/guard_clause_style.py "prefer guard clauses over positive if/return-true wrappers."
else
  skip_lint_job guard_clause_style
fi

if lint_job_enabled pointer_bounds; then
  section pointer_bounds "Require safe external buffer indexing"
  run_python_policy_linter policy/pointer_bounds.py "use approved span/copy helpers for external buffers."
else
  skip_lint_job pointer_bounds
fi

if lint_job_enabled raii_lifetime; then
  section raii_lifetime "Require RAII for C/C++ resource pairs"
  run_python_policy_linter policy/raii_lifetime.py "use project RAII wrappers for acquire/release pairs."
else
  skip_lint_job raii_lifetime
fi

if lint_job_enabled nolint_audit; then
  section nolint_audit "Audit NOLINT / cppcheck inline suppressions (forbidden)"
  run_python_policy_linter policy/nolint_audit.py "remove NOLINT and cppcheck-suppress outside policy.nolint_allowed; fix the underlying issue instead."
else
  skip_lint_job nolint_audit
fi

if lint_job_enabled spec_traceability; then
  if python3 -c "
import sys
from pathlib import Path
from consumer_manifest import spec_traceability_path
sys.exit(0 if spec_traceability_path(Path('$repo_root')) else 1)
"; then
    section spec_traceability "Verify spec traceability manifest"
    want_pyyaml "spec traceability"
    run_python_policy_linter policy/spec_traceability.py "update docs/spec-traceability.yaml or fix source literals."
  fi
else
  skip_lint_job spec_traceability
fi

((custom_lints_only == 1)) && {
  printf '\nAll lint checks passed.\n'
  exit 0
}

if lint_job_enabled cppcheck; then
  section cppcheck "Run cppcheck (config/cppcheck-manifest.yaml)"
  if want_cppcheck "static analysis"; then
    run lint_kit_cppcheck_self_test
    run_compile_db_lint run-cppcheck --jobs "$lint_jobs"
  fi
else
  skip_lint_job cppcheck
fi

if lint_job_enabled firmware_compile_db; then
  section firmware_compile_db "Ensure firmware compile databases (compile_db.firmware)"
  run python3 "${helpers}/compile_db/compile_db_lint.py" \
    --repo-root "$repo_root" \
    --lint-kit "$lint_kit" \
    ensure-firmware-compile-db
else
  skip_lint_job firmware_compile_db
fi

if lint_job_enabled firmware_build; then
  section firmware_build "Build firmware (firmware_build.commands)"
  run python3 "${helpers}/compile_db/compile_db_lint.py" \
    --repo-root "$repo_root" \
    --lint-kit "$lint_kit" \
    run-firmware-build
else
  skip_lint_job firmware_build
fi

printf '\nAll lint checks passed.\n'
