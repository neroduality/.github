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

**Consumer manifest keys**

| Status | Keys |
| --- | --- |
| Required non-null | `compile_db`, `enabled_lint_jobs`, `license_header`, `policy`, `scan` |
| Required, may be `null` | `firmware_build`, `spec_traceability`, `toolchain`, `workflow`, `yamllint` |

## Config files

| File | Role |
| --- | --- |
| `.clang-format` | Format baseline (`BasedOnStyle: Google`) |
| `.clang-tidy-c` | `.c` + c_compatible `.h` (`-x c-header`) |
| `.clang-tidy-cxx` | Host C++ TUs |
| `.clang-tidy-shared-c-cxx` | C++ under `policy.shared_c_cxx_source_roots` |
| `.clang-tidy-unsafe-c` / `-cxx` | Banned APIs only |
| `openssf-hardening-manifest.yaml` | OpenSSF coverage + FULL cmake wiring |
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
| `license` | License / SPDX headers |
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
| `nolint_audit` | No NOLINT / cppcheck-suppress |
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

**Enabled families:** `clang-diagnostic-*`, `clang-analyzer-*` (incl. `optin.*`
and `security.*`), `android-cloexec-*`, `bugprone-*`, `cert-*`,
`concurrency-*`, `cppcoreguidelines-*`, `misc-*`, `modernize-*`,
`performance-*`, `portability-*`, `readability-*`, plus the applicable
`google-*` checks per overlay.

**Families intentionally not enabled:** `hicpp-*` (near-pure aliases of
enabled checks; would double-report), vendor/domain families with no org
consumer (`abseil-*`, `altera-*`, `boost-*`, `darwin-*`, `fuchsia-*`,
`linuxkernel-*`, `llvm-*`, `llvmlibc-*`, `mpi-*`, `objc-*`, `openmp-*`,
`zircon-*`).

**Family-wide disables with rationale:**

| Check | Why off |
| --- | --- |
| `android-cloexec-pipe` | Only remedy is `pipe2()` (not in the POSIX.1-2008 kit baseline); the sanctioned pattern is `fcntl(fd, F_SETFD, FD_CLOEXEC)` immediately after `pipe()` |
| `concurrency-mt-unsafe` | Flags every `strerror`/`getenv`/`setenv` call site with no allowlist and NOLINT is forbidden; on glibc >= 2.32 `strerror` is thread-safe, and test mains legitimately use `setenv`. The real subset it would catch (`sigprocmask` vs `pthread_sigmask` in threaded processes) is a code-review item, not gateable. Same verdict for cppcheck's `threadsafety` addon (adds "stdout is MT-unsafe" noise on top) |
| `misc-header-include-cycle` | Diagnoses cycles inside vendored toolchain cores (e.g. Arduino `Arduino.h` <-> `Serial.h`); the diagnostic escapes `HeaderFilterRegex` because its note chain anchors in a project include, and NOLINT is forbidden so it cannot be waived per-site |
| `misc-include-cleaner` | Needs full IWYU-style header maps; noise on umbrella headers |
| `misc-use-anonymous-namespace` | Google style allows either `static` or an unnamed namespace for internal linkage, and `misc-use-internal-linkage` (kept on) auto-fixes by adding `static` -- enabling both makes the fix of one the violation of the other |
| `misc-no-recursion` | Recursion policy is owned by the `magic_literals` job, which allows explicitly annotated bounded recursion (`{PREFIX}_BOUNDED_RECURSION` + depth cap); NOLINT is forbidden so the tidy check cannot express that waiver |

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
| Probes | Fail-closed only if cache has OpenSSF `HAVE_*` |
| CXX + `-fhardened` | Overlapping defs use `NOT_FHARDENED` |
| Link audit | `link.txt` or `build.ninja` |

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
| `banned_libc_io` | `bugprone-unsafe-functions`, `cert-err33-c`, `clang-analyzer-security.insecureAPI.*` (unsafe overlays) | Project wrapper allowlist (`policy.unsafe_api.wrapper_files`), C++ stream bans, raw fd stdout/stderr writes |
| `null_nodiscard` | `modernize-use-nullptr` stays off by design | Project `NULL`/`NODISCARD` macro convention (canonical null header) |
| `relative_includes` | -- (no tidy/cppcheck equivalent) | Bans `../` in `#include` |
| `duplicate_includes` | Exact repeats: `readability-duplicate-include` | `#pragma once` placement, mixed angle/quote dupes, macro-include dupes |
| `shared_constant_dupes` | -- | One authoritative `{PREFIX}_*` numeric definition across the tree |
| `magic_literals` | General magic numbers: `readability-magic-numbers` / `cppcoreguidelines-avoid-magic-numbers` | Constant placement (canonical headers), stack-array caps, bounded-recursion annotation (`misc-no-recursion` off; see above), printf-index gaps |
| `guard_clause_style` | `readability-simplify-boolean-expr` covers trivial cases (off in C overlay) | Positive if/return-true wrapper shape |
| `pointer_bounds` | `clang-analyzer-*` array bounds, cppcheck buffer checks, sanitizers | Anti-drift gate: span/copy helpers or explicit guards before external-buffer subscripts |
| `raii_lifetime` | `clang-analyzer-unix.Malloc` style leak paths | Project acquire/release pair registry (`policy.resource_lifetime`) |
| `nolint_audit` | -- (meta) | Forbids `NOLINT` / `cppcheck-suppress`; keeps both engines honest |
| `spec_traceability` | -- | Spec manifest <-> source literal cross-check |

## References

| Source | Used for |
| --- | --- |
| [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) | Format; C++ naming; google-* tidy |
| [OpenSSF Compiler Hardening Guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html) | Tables 1-2 + prose flags/defs |
| [POSIX.1-2024 §2](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html) | C APIs; `_t`; `ALL_CAPS` |
| [Linux coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html) | C `snake_case` / caps macros |
