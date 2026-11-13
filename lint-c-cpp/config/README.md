<!-- SPDX-License-Identifier: Apache-2.0 -->
<!--
Copyright (C) 2026 Nero Duality, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Lint kit defaults (`config/`)

Kit-owned baselines. Do not edit in a consumer tree. Configure the project in
`.github/lint-c-cpp.yaml`. Dial these baselines only via `policy.overrides`.
Sources: [References](#references).

| Concern | Rule |
| --- | --- |
| Format / C++ tidy | Google (+ deltas below) |
| C / shared `.h` | POSIX / Linux UAPI C surface |
| OpenSSF | Compiler/linker hardening only |
| Naming | Shared constants `ALL_CAPS`; C++-only `kCamelCase` |

## Consumer manifest keys

| Status | Keys |
| --- | --- |
| Required non-null | `compile_db`, `enabled_lint_jobs`, `license_header`, `policy`, `scan` |
| Required, may be `null` | `firmware_build`, `spec_traceability`, `toolchain`, `workflow`, `yamllint` |

`toolchain.llvm_major` (integer or `null`) selects the clang-format and
clang-tidy major for lint. `null` takes the newest `NAME-<major>` or bare
`NAME` on `PATH` at or above the `tool-versions.yaml` minimum; an integer
accepts only that major and must not be below the minimum. scan-build is
presence-only and ignores it. Lint fails if `LINT_KIT_LLVM_MAJOR` is set in the
environment to anything other than the manifest's value.

The removed `policy.nolint_allowed` key is rejected: suppressions have no
waiver list (see `nolint_audit` below).

## Config files

| File | Role |
| --- | --- |
| `.clang-format` | Format baseline (`BasedOnStyle: Google`) |
| `.clang-tidy-c` | `.c` + c_compatible `.h` (`-x c-header`) |
| `.clang-tidy-cxx` | Host C++ TUs |
| `.clang-tidy-shared-c-cxx` | C++ under `policy.shared_c_cxx_source_roots` |
| `.clang-tidy-unsafe-c` / `-cxx` | Banned APIs only |
| `clang-tidy-coverage.yaml` | Families, alias table, and every check the main overlays leave out (with reason); self-test enforces it |
| `openssf-hardening-manifest.yaml` | OpenSSF coverage + FULL cmake wiring |
| `openssf-guide-tables.txt` | Snapshot of the guide's Table 1 and Table 2 tokens; self-test asserts the manifest covers every row |
| `cppcheck-manifest.yaml` | cppcheck passes / CLI |
| `ruff.toml` / `mypy.ini` | Python lint (`python_lint` job) config |
| `.markdownlint.yaml` | Markdownlint defaults |
| `tool-versions.yaml` | Minimum host tool versions |

## Dialed outputs

`policy.overrides` is YAML. Tools and the compiler need files. Two output trees:

| Path | Used by | Written | Commit? |
| --- | --- | --- | --- |
| `build/lint-overrides/` | clang-format, clang-tidy, OpenSSF lint audit, cppcheck dials | Every lint start | No |
| `cmake/Hardening.cmake`, `Hardening.by-*.cmake`, `Hardening.flags.by-*.mk`, `CompilerHardeningProbes.cmake` | CMake / Make compile+link | Lint regen (fail-on-change) | Yes |

| Dial | `build/lint-overrides/` | `cmake/` |
| --- | --- | --- |
| `clang-format`, `clang-tidy-*`, `cppcheck` | Yes | No |
| `openssf-hardening` | Yes (audit manifest copy) | Yes (Hardening modules / flags.mk) |

Apply order: kit -> global `add`/`remove` -> owning `by_compile_db` (firmware DB wins for firmware roots).

## `enabled_lint_jobs`

Non-empty allowlist of job IDs. Listed jobs run; omitted jobs skip. Unknown,
empty, or duplicate IDs fail validate. Lint prints `lint jobs: X enabled out of
N` (`N` = size of the kit job allowlist below).

Not gated: tool-versions, manifest validate, toolchain precheck, override
materialize. `--custom-lints-only` also skips `compile_db`, `clang_tidy`,
`cppcheck`, `firmware_compile_db`, `firmware_build` when listed.

Lint section banners print the job ID for mapping to this table, e.g.
`── 17. pointer_bounds -- Require safe external buffer indexing ──`.

| ID | Section |
| --- | --- |
| `license` | License / SPDX headers (full `license_header` corpus, exactly once; stacked or legacy `/* */` headers are collapsed) |
| `yamllint` | YAML sort/format |
| `markdownlint` | Markdown |
| `format` | clang-format, shfmt, shellcheck, codespell, ruff, mypy |
| `openssf` | OpenSSF hardeninglint |
| `compile_db` | Host compile DBs + OpenSSF compile-DB audit |
| `clang_tidy` | clang-tidy |
| `banned_cxx_heap` | No C++ `new`/`delete` |
| `banned_libc_io` | Bounded libc / I/O wrappers |
| `null_nodiscard` | Project `NULL` / `NODISCARD` |
| `relative_includes` | No relative `#include` |
| `duplicate_includes` | No duplicate `#include` |
| `shared_constant_dupes` | No duplicate spec constants |
| `magic_literals` | Constant placement / bounds |
| `guard_clause_style` | Early-return guards |
| `pointer_bounds` | External buffer indexing |
| `raii_lifetime` | RAII resource pairs |
| `nolint_audit` | No suppressions of any tool (always on; no waivers) |
| `spec_traceability` | Spec traceability (if path exists) |
| `cppcheck` | cppcheck |
| `firmware_compile_db` | Firmware `compile_commands.json` (like `compile_db`) |
| `firmware_build` | Full firmware builds via `firmware_build.commands` |

## `policy.overrides`

Required keys (each with `add`, `remove`, `by_compile_db`; use `null` if unused):
`clang-format`, `clang-tidy-c`, `clang-tidy-cxx`, `clang-tidy-shared-c-cxx`,
`clang-tidy-unsafe-c`, `clang-tidy-unsafe-cxx`, `cppcheck`, `openssf-hardening`.

| Key | Tokens |
| --- | --- |
| `clang-format` | Style lines (e.g. `ColumnLimit: 100`) |
| `clang-tidy-*` | Checks entries |
| `cppcheck` | Enable / suppress ids |
| `openssf-hardening` | `coverage.flags` / defs -> lint audit + `cmake/` emit |

`openssf-hardening` also accepts an optional `cross` list (no other key does):
host-only link flags to emit on cross builds too. Vocabulary is exactly the
kit's host-only set: `LINKER:-z,pack-relative-relocs` (probe-gated; the sysroot
libc probe still applies, so opting in is safe when the cross sysroot's glibc is
>= 2.36 and a no-op otherwise) plus the dynamic-loader link flags `-pie`,
`LINKER:-z,noexecstack`, `LINKER:-z,now`, `LINKER:-z,relro` (genex-gated; only
the `CMAKE_CROSSCOMPILING` term is lifted, `-pie` keeps its EXECUTABLE term).
Anything else is a manifest error. Linux userspace cross ports (foreign-arch
deb/rpm) opt all five in; bare-metal firmware consumers leave `cross` null.

## clang-format

- `BasedOnStyle: Google`
- Deltas: `SortIncludes: Never`, `IncludeBlocks: Preserve`

## clang-tidy

| Config | Scope | Naming | Reports |
| --- | --- | --- | --- |
| `.clang-tidy-c` | `.c`; c_compatible `.h` | C / POSIX | c_compatible `.h` |
| `.clang-tidy-cxx` | Host C++ | Google C++ | cxx_only |
| `.clang-tidy-shared-c-cxx` | C++ in `shared_c_cxx_source_roots` | Google on TU | cxx_only only |

Positive `HeaderFilterRegex` only. No `ExcludeHeaderFilterRegex`. No
`disabled_checks`. Unsafe overlays: APIs only.

**Explicit check lists:** every overlay starts with `-*` and names each check
by its primary name; the only wildcard is `clang-diagnostic-*` (compiler
warnings, governed by the build's own `-W` flags). A newer clang-tidy therefore
never enables or renames checks behind the kit's back. A name that needs a
newer clang-tidy means bumping the lint container's LLVM first;
`tool-versions.yaml` minimums are the lower of the container's and Fedora 45's
versions.

**Every family check is decided:** the main overlays draw from
`android-cloexec-*`, `bugprone-*`, `cert-*`, `clang-analyzer-*` (incl. the
opt-in and `security.*` analyzer groups), `concurrency-*`,
`cppcoreguidelines-*`, `google-*`, `misc-*`, `modernize-*`, `performance-*`,
`portability-*` and `readability-*`. Each check clang-tidy offers in those
families is either in the overlay's `Checks` or recorded under `left_out` in
[`clang-tidy-coverage.yaml`](clang-tidy-coverage.yaml) with the overlays it is
off for and why. The self-test lists every family on the resolved clang-tidy
and fails on any check that is neither, so the checks a new LLVM release adds
need a decision before the kit moves to it.

**No aliases:** the overlays name primaries only. The coverage file carries
clang-tidy's alias table; an alias is covered, or left out, with its primary.
Aliases do not inherit the primary's `CheckOptions` and some carry different
defaults, so naming both runs one check twice under two configurations, and an
alias can quietly re-enable a check the kit leaves off. `cert-*` is now aliases
only, so the overlays list no `cert-*` names; the CERT rules run under their
primaries (e.g. ERR33-C is `bugprone-unused-return-value` with the CERT C
function list in the unsafe overlays). `llvm-namespace-comment` is the one
`llvm-*` check on, as the primary behind `google-readability-namespace-comments`
with Google's spacing. Each overlay's `CheckOptions` may only configure checks it
lists.

The one thing a check list cannot switch off is the analyzer's
`clang-analyzer-core.*` checkers: clang-tidy runs all of them once any
analyzer check is on (a new release can add one, e.g.
`core.NullPointerArithm` in LLVM 23). The main overlays name every core
checker anyway, and the self-test compares each overlay's `--list-checks`
output against its list.

**Families intentionally not enabled:** `hicpp-*` (near-pure aliases of
enabled checks; would double-report), vendor/domain families with no org
consumer (`abseil-*`, `altera-*`, `boost-*`, `darwin-*`, `fuchsia-*`,
`linuxkernel-*`, `llvm-*` except `llvm-namespace-comment`, `llvmlibc-*`,
`mpi-*`, `objc-*`, `openmp-*`, `zircon-*`).

**Header roles (extension only):** `.h` -> c_compatible; `.hpp`/`.hh`/`.hxx` ->
cxx_only. C++ overlays must not report shared `.h`. C++ in a c_compatible `.h`
fails closed (rename to `.hpp` or fix).

**C naming:** funcs/vars `lower_case`; typedef `lower_case` + `*_t` ignore;
enum/macro/file-scope `const` `UPPER_CASE`; no `k`. Prefer
`typedef struct foo { ... } foo_t`.

**C++ naming:** CamelCase types/funcs; `snake_case` vars; members `_` suffix;
`k`CamelCase constants; macros `UPPER_CASE`. Same options on both C++ overlays.
Per Google, the `k` prefix marks constants fixed for the program's duration:
`constexpr`, `static`, global and class constants get `k`CamelCase. A plain
runtime `const` **local** is ordinary variable style (`lower_case`) -- make it
`constexpr` if it is truly compile-time. Struct fields get `_`; accessors
CamelCase. C++ omits `google-runtime-int`, `google-build-explicit-make-pair`,
`google-upgrade-googletest-case`.

## OpenSSF

Kit file: `openssf-hardening-manifest.yaml` (do not edit).

Deliberate additions beyond the guide's tables: `-ffunction-sections`,
`-fdata-sections`, `LINKER:--gc-sections`, `LINKER:-z,pack-relative-relocs`,
`LINKER:-z,text`, `LINKER:--error-execstack`, `LINKER:--error-rwx-segments`,
`-Wshadow`, `-Wundef`, `-Wformat-signedness`, `-Werror=vla`, `-Walloca`,
`-Wstrict-prototypes`, and `-Wold-style-definition`. They ride the same probes,
dials, and audit as the guide flags. `-fzero-init-padding-bits=unions` is the
guide row the guide spells `union`, which GCC rejects. Blanket `-Werror` is
wrapped in `HARDENING_WERROR` (default ON; source packages pass OFF).

| Key | Meaning |
| --- | --- |
| `coverage.*` | Tokens required by lint audit and used by dialed emit |
| `cmake.*` | FULL wiring (probe / genex / `compile_arch` / link) |
| `guide` / `consumer` | Metadata; required module basenames |

| Checked-in emit | Meaning |
| --- | --- |
| `cmake/Hardening.cmake` | Kit + global dials |
| `cmake/Hardening.by-<slug>.cmake` | + that DB's `by_compile_db` |
| `cmake/Hardening.flags.by-<slug>.mk` | Make vars `NERO_OPENSSF_CFLAGS` / `CXXFLAGS` / `CPPFLAGS` for those dials |
| `cmake/CompilerHardeningProbes.cmake` | Kit FULL probes |

Hand-edits are overwritten; lint fails until committed and re-run.

**Wiring:** each `define_hardening` CMakeLists must `include` the matching
Hardening module. When the build has no CMake include path (Make / Arduino),
`include` `Hardening.flags.by-<slug>.mk` and append those `NERO_OPENSSF_*`
vars to the board's extra-flags Make variable (often `build.extra_flags`).

| Rule | Detail |
| --- | --- |
| `compile_arch` | Host + arch gated; not ungated on cross |
| Host-only link | `-z pack-relative-relocs` = linker probe AND `HAVE_LIBC_DT_RELR` (sysroot glibc >= 2.36) AND native; `-z text`, `--error-execstack`, `--error-rwx-segments` = linker probe AND native; `-pie` / `-z noexecstack` / `-z now` / `-z relro` = native (plus EXECUTABLE for `-pie`); `-fexceptions` = native; `overrides.openssf-hardening.cross` drops the native term per flag |
| Probes | Fail-closed only if cache has OpenSSF `HAVE_*` |
| `-z` link probes | `check_linker_flag` then a bare-spelling re-link; demoted when GNU ld answers `-z <keyword> ignored` (e.g. no DT_RELR for the target) |
| CXX + `-fhardened` | Overlapping defs and CXX fortify use `NOT_FHARDENED` → `HAVE_CXX_FHARDENED` (C uses `HAVE_C_FHARDENED`) |
| Link audit | Each link command in `link.txt`, or each executable / shared link statement in `build.ninja` |
| In effect | Compile and link audits match whole options and apply last-one-wins: a later `-fno-stack-protector`, `-U_FORTIFY_SOURCE`, `-O0`, `-Wno-error`, `-Wl,-z,lazy` or `-no-pie` fails the flag it overrides |

## cppcheck

Heuristics on merged compile DB (`--project`). Banned APIs: `banned_libc_io` +
clang-tidy unsafe -- not cppcheck. Dials: `policy.overrides.cppcheck`.

Baseline: `--enable=warning,style,performance,portability` with
`--check-level=exhaustive`, `--inconclusive`, and `--library=posix`.
`information` (config noise only) and `unusedFunction` (incompatible with
`-j` / per-TU projects) stay off. Kit-level suppressions:
`missingIncludeSystem`, `constParameterCallback` (fixed callback ABIs cannot
take `const` without function-pointer casts), and `_deps/` vendor trees.

## Custom Python checks -- tool overlap map

Custom jobs exist only where clang-tidy/cppcheck cannot express the policy
(project wrappers, waiver semantics, or cross-file invariants). Overlapping
ground is delegated to the tools; the table records the split.

| Job | Delegated to tools | Custom-only remainder |
| --- | --- | --- |
| `banned_cxx_heap` | `malloc`-family via unsafe overlay `CustomFunctions`; `cppcoreguidelines-no-malloc` (unsafe-cxx) | C++ `new`/`delete` incl. placement forms; applies inside wrapper files too |
| `banned_libc_io` | `bugprone-unsafe-functions`, `bugprone-unused-return-value` (CERT ERR33-C list), `clang-analyzer-security.insecureAPI.*` (unsafe overlays) | Project wrapper allowlist (`policy.unsafe_api.wrapper_files`), C++ stream bans, raw fd stdout/stderr writes |
| `null_nodiscard` | `modernize-use-nullptr` stays off by design | Project `NULL`/`NODISCARD` macro convention (canonical null header) |
| `relative_includes` | -- (no tidy/cppcheck equivalent) | Bans `../` in `#include` |
| `duplicate_includes` | Exact repeats: `readability-duplicate-include` | `#pragma once` placement, mixed angle/quote dupes, macro-include dupes |
| `shared_constant_dupes` | -- | One authoritative `{PREFIX}_*` numeric definition across the tree |
| `magic_literals` | General magic numbers: `readability-magic-numbers` (its alias `cppcoreguidelines-avoid-magic-numbers` is not named separately) | Constant placement (canonical headers), stack-array caps, bounded-recursion annotation (`misc-no-recursion` off; see `clang-tidy-coverage.yaml`), printf-index gaps |
| `guard_clause_style` | `readability-simplify-boolean-expr` covers trivial cases (off in C overlay) | Positive if/return-true wrapper shape |
| `pointer_bounds` | `clang-analyzer-*` array bounds, cppcheck buffer checks, sanitizers | Anti-drift gate: span/copy helpers or explicit guards before external-buffer subscripts |
| `raii_lifetime` | `clang-analyzer-unix.Malloc` style leak paths | Project acquire/release pair registry (`policy.resource_lifetime`) |
| `nolint_audit` | -- (meta) | Mandatory in `enabled_lint_jobs` (manifest validation rejects a list without it) and runs repo-wide, with no waiver list. Forbids inline disables for every tool (`NOLINT`, `cppcheck-suppress`, `clang-format off`, `shellcheck disable=`, `noqa`, `type: ignore`, `mypy:`/`pylint:`/`fmt:` directives, `markdownlint-disable`, `yamllint disable`, `zizmor: ignore`, `codespell:ignore`, `LCOV_EXCL`/`GCOVR_EXCL`), C/C++ compiler and analyzer escapes (`#pragma GCC/clang diagnostic ignored/warning`, MSVC `warning(disable` / `warning(push, 0)`, IAR/TI/NVCC `diag_suppress`/`diag_remark`/`diag_warning`, `system_header`, `_Pragma`, `[[clang::suppress]]` / `__attribute__((suppress))`, `no_sanitize`, `__clang_analyzer__` / `__CPPCHECK__` branches), per-function hardening overrides (`#pragma GCC optimize`, `optimize` attributes, `no_stack_protector`, `nocf_check`), the same comment rules in `.inc`/`.inl`/`.ipp`/`.tpp`/`.tcc`/`.ixx`/`.cppm` fragments, warning-off build flags outside comments (`-Wno-*` in any build, CI, script or preset file; `-w` / `--no-warnings` in CMake (incl. `CMakePresets.json`), Make, Meson and Arduino `build_opt.h` / `*.local.txt` files, and `-w` as the value of a compiler-flag variable such as `CFLAGS` or `CMAKE_C_FLAGS` in any file). The OpenSSF compile-DB audit checks the real commands of every scanned TU: host TUs may carry no `-w`, `--no-warnings` or `-Wno-*`; firmware TUs only those the SDK puts on its own TUs in the same database (e.g. the Arduino core's `-Wno-error`); and no TU may mark a directory holding project sources as a system include directory (`-isystem`, `-idirafter`, `-iwithprefix`, CMake `SYSTEM`), while vendored and SDK directories outside the scan scope stay allowed, and repo-local tool config (`.clang-tidy`, `.clang-format`, `.shellcheckrc`, `.codespellrc`, `.markdownlint*`, `.yamllint*`, `ruff.toml`, `mypy.ini`, pyproject/setup.cfg/tox.ini tool sections; `zizmor.yml` / `zizmor.yaml` stay allowed because the consumer, not the kit, runs zizmor). shellcheck also runs with `--norc` and ruff with `--ignore-noqa` |
| `spec_traceability` | -- | Spec manifest <-> source literal cross-check |

## Linting the kit itself

Consumer lint never scans the kit, so run its own checks from `lint-c-cpp/`
before tagging. Shell uses the consumer `format` job's flags; ruff and mypy run
through `uvx` at the `tool-versions.yaml` minimums.

```bash
source lib/helpers/toolchain/tool_versions.sh
ruff="ruff@$(lint_kit_tool_min_version ruff)"
mypy="mypy@$(lint_kit_tool_min_version mypy)"

# Unit tests for every lint job and generator; also audits the kit's own
# sources for suppressions (same rules as the consumer nolint_audit job).
# The clang-tidy tests fail when clang-tidy is missing; set
# LINT_KIT_SELF_TEST_ALLOW_NO_CLANG_TIDY=1 to skip them instead.
bash lint-c-cpp.sh self-test

# Run one kit Python helper with the kit's PYTHONPATH, e.g. a policy self-test.
bash lint-c-cpp.sh python lib/helpers/policy/policy_runner.py --self-test --script nolint_audit.py

# Shell: format check and lint (shfmt -w instead of -d rewrites).
shfmt -d -i 2 -ci -s $(git ls-files '*.sh')
env -u SHELLCHECK_OPTS shellcheck --norc -S warning -x -P SCRIPTDIR $(git ls-files '*.sh')

# Python: format check, lint, types (drop --check to rewrite; ruff check --fix).
uvx "$ruff" format --config config/ruff.toml --check .
uvx "$ruff" check --ignore-noqa --config config/ruff.toml .
uvx "$mypy" --config-file config/mypy.ini --no-incremental lib

# Spelling and Markdown.
codespell lib config cmake lint-c-cpp.sh
markdownlint --config config/.markdownlint.yaml config/README.md
```

## References

| Source | Used for |
| --- | --- |
| [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) | Format; C++ naming; google-* tidy |
| [OpenSSF Compiler Hardening Guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html) | Tables 1-2 + prose flags/defs |
| [POSIX.1-2024 §2](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html) | C APIs; `_t`; `ALL_CAPS` |
| [Linux coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html) | C `snake_case` / caps macros |
