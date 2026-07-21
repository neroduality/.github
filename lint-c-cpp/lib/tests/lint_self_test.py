#!/usr/bin/env python3
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

"""CI gate: helper ``--self-test`` runs plus temporary-repo simulation tests.
Proves policy paths catch violations without false positives on canonical input."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterable
from pathlib import Path
from types import ModuleType


TESTS_DIR = Path(__file__).resolve().parent
LINT_LIB = TESTS_DIR.parent
LINT_KIT = LINT_LIB.parent
HELPERS_DIR = LINT_LIB / "helpers"
POLICY_DIR = HELPERS_DIR / "policy"
COMPILE_DB_DIR = HELPERS_DIR / "compile_db"
TOOLCHAIN_DIR = HELPERS_DIR / "toolchain"
COMMANDS_DIR = LINT_LIB / "commands"
CONFIG_DIR = LINT_KIT / "config"
REPO_ROOT = Path(os.environ.get("LINT_REPO_ROOT", Path.cwd())).resolve()
CORE_DIR = LINT_LIB / "core"
for _core_sub in ("manifest", "scan", "tools", "workflow"):
    _entry = str(CORE_DIR / _core_sub)
    if _entry not in sys.path:
        sys.path.insert(0, _entry)
if str(LINT_LIB) not in sys.path:
    sys.path.insert(0, str(LINT_LIB))
if str(POLICY_DIR) not in sys.path:
    sys.path.insert(0, str(POLICY_DIR))
if str(COMPILE_DB_DIR) not in sys.path:
    sys.path.insert(0, str(COMPILE_DB_DIR))
POLICY_RUNNER = POLICY_DIR / "policy_runner.py"
POLICY_RUNNER_SCRIPTS = frozenset(
    p.name
    for p in POLICY_DIR.glob("*.py")
    if p.name
    not in {
        "__init__.py",
        "policy_paths.py",
        "policy_runner.py",
        "policy_config.py",
        "policy_prepare.py",
        "policy_self_test.py",
        "hardening_verify.py",
    }
)


def policy_self_test_cmd(script: Path) -> list[str]:
    if script.parent == POLICY_DIR and script.name in POLICY_RUNNER_SCRIPTS:
        return [sys.executable, str(POLICY_RUNNER), "--self-test", "--script", script.name]
    return [sys.executable, str(script), "--self-test"]


HELPER_SCRIPTS = tuple(
    sorted(
        p
        for subdir in (POLICY_DIR, COMPILE_DB_DIR)
        for p in subdir.glob("*.py")
        if p.name
        not in {
            "__init__.py",
            "compile_db_util.py",
            "policy_paths.py",
            "policy_runner.py",
            "policy_config.py",
            "policy_prepare.py",
            "policy_self_test.py",
            "repo_paths.py",
        }
    )
)
CORE_SELF_TEST_SCRIPTS = (
    LINT_LIB / "core" / "tools" / "tool_versions_check.py",
)
SHELL_LINTER_SCRIPTS = frozenset(
    script.name for script in TOOLCHAIN_DIR.glob("*.sh")
) | frozenset(script.name for script in COMMANDS_DIR.glob("*.sh"))
SIMULATED_PYTHON_HELPERS = frozenset(
    {
        "magic_literals.py",
        "compile_db_lint.py",
        "clang_tidy_wrapper_filter.py",
        "shared_constant_dupes.py",
        "duplicate_includes.py",
        "guard_clause_style.py",
        "hardening_verify.py",
        "spdx_headers.py",
        "null_nodiscard.py",
        "relative_includes.py",
        "raii_lifetime.py",
        "pointer_bounds.py",
        "spec_traceability.py",
        "yaml_manifest.py",
        "banned_libc_io.py",
        "banned_cxx_heap.py",
        "nolint_audit.py",
    }
)
POLICY_INFRA_SCRIPTS = frozenset(
    {
        "policy_runner.py",
        "policy_config.py",
        "policy_prepare.py",
        "policy_self_test.py",
        "policy_paths.py",
    }
)
SIMULATED_SHELL_LINTER_SCRIPTS = frozenset(
    {
        "lint.sh",
        "clang_toolchain.sh",
        "codespell.sh",
        "cppcheck_toolchain.sh",
        "markdownlint_toolchain.sh",
        "python_lint.sh",
    }
)


def load_helper(script_name: str) -> ModuleType:
    module_name = script_name.replace("/", "_").replace("-", "_").removesuffix(".py")
    script_path = HELPERS_DIR / script_name
    if not script_path.is_file():
        script_path = POLICY_DIR / script_name
    if not script_path.is_file():
        script_path = COMPILE_DB_DIR / script_name
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


_POLICY_TEST_MANIFEST = r"""license_header: |
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

firmware_build:
  commands: ["make firmware"]
spec_traceability: null
toolchain: null
workflow: null

compile_db:
  firmware:
    - commands: ["make firmware-compile-db"]
      compile_commands_json: build/firmware/compile_commands.json
      source: firmware
  userspace:
    - compile_commands_json: build/lint/userspace/compile_commands.json
      source: userspace
      cmake_args: ["-DCMAKE_BUILD_TYPE=Release"]

scan:
  c_api_prefix: sample
  c_macro_prefix: SAMPLE
  exclude_gitignore: true
  public_headers_dir: include/sample
  source_roots: [core, port, include, esp-idf, userspace, tests]

policy:
  constants_headers: [limits.h, board_config.h, config.h]
  nolint_allowed:
    - include/sample/sample_null.h
  overrides:
    clang-format: {add: null, remove: null, by_compile_db: null}
    clang-tidy-c: {add: null, remove: null, by_compile_db: null}
    clang-tidy-cxx: {add: null, remove: null, by_compile_db: null}
    clang-tidy-shared-c-cxx: {add: null, remove: null, by_compile_db: null}
    clang-tidy-unsafe-c: {add: null, remove: null, by_compile_db: null}
    clang-tidy-unsafe-cxx: {add: null, remove: null, by_compile_db: null}
    cppcheck: {add: null, remove: null, by_compile_db: null}
    openssf-hardening: {add: null, remove: null, by_compile_db: null}
  resource_lifetime:
    pairs:
      - label: fopen/fclose
        acquire: ["\\bfopen\\s*\\("]
        release: ["\\bfclose\\s*\\("]
        canonical_files: [include/sample/sample_file_raii.h]
        hint: project file RAII helpers
  shared_c_cxx_source_roots: null
  unsafe_api:
    header: sample_null.h
    include_headers: [attrs.h, mem_util.h]
    wrapper_files:
      - include/sample/sample_null.h
      - include/sample/mem_util.h
      - core/sample_io.c
      - core/sample_parse.h
      - userspace/sample_file_raii.h

yamllint:
  default: null
  files:
    - path: .github/lint-c-cpp.yaml
      schema: lint_config
      sort_by: key
"""

from consumer_manifest import (
    KNOWN_LINT_JOBS_ORDERED,
    enabled_lint_jobs_yaml_block,
)

_ENABLED_LINT_JOBS_YAML = enabled_lint_jobs_yaml_block()
_POLICY_TEST_MANIFEST = (
    _POLICY_TEST_MANIFEST.rstrip() + "\n\n" + _ENABLED_LINT_JOBS_YAML
)

_NULL_OVERRIDES_YAML = (
    "  resource_lifetime: null\n"
    "  shared_c_cxx_source_roots: null\n"
    "  overrides:\n"
    "    clang-format: {add: null, remove: null, by_compile_db: null}\n"
    "    clang-tidy-c: {add: null, remove: null, by_compile_db: null}\n"
    "    clang-tidy-cxx: {add: null, remove: null, by_compile_db: null}\n"
    "    clang-tidy-shared-c-cxx: {add: null, remove: null, by_compile_db: null}\n"
    "    clang-tidy-unsafe-c: {add: null, remove: null, by_compile_db: null}\n"
    "    clang-tidy-unsafe-cxx: {add: null, remove: null, by_compile_db: null}\n"
    "    cppcheck: {add: null, remove: null, by_compile_db: null}\n"
    "    openssf-hardening: {add: null, remove: null, by_compile_db: null}\n"
)

_NULL_TOP_LEVEL_YAML = (
    _ENABLED_LINT_JOBS_YAML
    + "firmware_build:\n  commands: [make firmware]\n"
    "spec_traceability: null\n"
    "toolchain: null\n"
    "workflow: null\n"
    "yamllint: null\n"
)


def write_license_only_manifest(root: Path, *, license_blob: str | None = None) -> None:
    """Minimal consumer manifest so OpenSSF generators can read license_header."""
    blob = license_blob or (
        "  # SPDX-License-Identifier: Apache-2.0\n"
        "  #\n"
        "  # Copyright (C) 2026 Nero Duality, LLC.\n"
        "  #\n"
        "  # Licensed under the Apache License, Version 2.0 (the \"License\");\n"
        "  # you may not use this file except in compliance with the License.\n"
        "  # You may obtain a copy of the License at\n"
        "  #\n"
        "  #     http://www.apache.org/licenses/LICENSE-2.0\n"
        "  #\n"
        "  # Unless required by applicable law or agreed to in writing, software\n"
        "  # distributed under the License is distributed on an \"AS IS\" BASIS,\n"
        "  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n"
        "  # See the License for the specific language governing permissions and\n"
        "  # limitations under the License.\n"
    )
    write(
        root / ".github/lint-c-cpp.yaml",
        "license_header: |\n"
        + blob
        + "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
        "  public_headers_dir: include/sample\n  exclude_gitignore: true\n"
        "  source_roots: [core]\n"
        "compile_db:\n  firmware: []\n  userspace: []\n"
        "policy:\n  constants_headers: [limits.h]\n"
        + _NULL_OVERRIDES_YAML
        + _NULL_TOP_LEVEL_YAML,
    )


def write_canonical_lint_manifest(root: Path) -> None:
    import yaml

    ym = load_helper("policy/yaml_manifest.py")
    manifest_path = root / ".github/lint-c-cpp.yaml"
    raw = render_policy_test_manifest()
    preamble, body = ym.split_yaml_preamble(raw)
    loaded = yaml.safe_load(body) or {}
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        ym.render_lint_config(preamble, ym.canonicalize_lint_config(loaded, "key")),
        encoding="utf-8",
    )


def ensure_license_headers(spdx: ModuleType, paths: list[Path], year: int) -> None:
    """Apply manifest license headers in-place without spdx ``process_file`` stderr noise."""
    for path in paths:
        kind = spdx.classify(path)
        if kind is None or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if kind.style == "hash":
            new_text, _ = spdx.repair_hash(text, year)
        elif kind.style == "cpp":
            new_text, _ = spdx.repair_cpp(text, year)
        elif kind.style == "md":
            new_text, _ = spdx.repair_md(text, year)
        else:
            continue
        path.write_text(new_text, encoding="utf-8")


def write_custom_lints_smoke_repo(root: Path, lint_kit: Path) -> None:
    from hardening_verify import (
        generate_hardening_cmake,
        generate_probes_cmake,
        load_hardening_manifest,
        _normalize_generated_cmake,
    )

    (root / "cmake").mkdir(parents=True)
    for source_root in ("core", "port", "include", "userspace", "tests", "esp-idf"):
        (root / source_root).mkdir(parents=True, exist_ok=True)

    write_canonical_lint_manifest(root)
    kit_manifest = load_hardening_manifest(lint_kit)
    (root / "cmake" / "Hardening.cmake").write_text(
        _normalize_generated_cmake(
            generate_hardening_cmake(kit_manifest, repo_root=root)
        ),
        encoding="utf-8",
    )
    (root / "cmake" / "CompilerHardeningProbes.cmake").write_text(
        _normalize_generated_cmake(generate_probes_cmake(kit_manifest, repo_root=root)),
        encoding="utf-8",
    )
    spdx = load_helper("policy/spdx_headers.py")
    spdx.configure_from_manifest(root)
    year = spdx._year()
    header = spdx.cpp_header_text(year)
    cmake_header = spdx.hash_header_text(year)
    write(
        root / "userspace/CMakeLists.txt",
        cmake_header
        + 'cmake_minimum_required(VERSION 3.20)\n'
        "project(sample C)\n"
        'include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Hardening.cmake")\n'
        "define_hardening(\n  TARGET hardening\n  C_STANDARD 23)\n"
        "add_library(core STATIC core.c)\n"
        "target_link_libraries(core PUBLIC hardening)\n",
    )
    write(
        root / "userspace/core.c",
        header + '#include "sample_null.h"\nvoid sample_core(void) { (void)SAMPLE_NULL; }\n',
    )
    write(
        root / "include/sample/sample_null.h",
        header + "#pragma once\n#define SAMPLE_NULL nullptr\n",
    )
    write(
        root / "include/sample/mem_util.h",
        header + '#pragma once\n#include "sample_null.h"\nstatic inline void sample_copy_bytes(void *d, const void *s, size_t n) { (void)d; (void)s; (void)n; }\n',
    )
    write(
        root / "include/sample/sample_file_raii.h",
        header + "#pragma once\nstruct SampleFileHandle {};\n",
    )
    write(
        root / "include/sample/limits.h",
        header + "#pragma once\nenum { SAMPLE_MAX = 64u };\n",
    )
    write(
        root / "core/ok.c",
        header + '#include "sample_null.h"\nvoid sample_ok(void) { (void)SAMPLE_NULL; }\n',
    )
    write(
        root / ".github/workflows/lint.yml",
        "name: lint\n"
        '"on": [push]\n'
        "jobs:\n"
        "  lint:\n"
        "    runs-on: ubuntu-latest\n"
        "    container: ubuntu:24.04\n"
        "    steps:\n"
        "      - run: echo lint\n",
    )

    clang_format = shutil.which("clang-format")
    if clang_format:
        style = f"file:{lint_kit / 'config' / '.clang-format'}"
        for path in central_job_paths(root, "format_c"):
            subprocess.run(
                [clang_format, "-i", f"--style={style}", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    from consumer_manifest import resolve_scan_paths
    from scan_policy import JOB_LICENSE

    license_paths = [
        path
        for path in resolve_scan_paths(JOB_LICENSE, repo_root=root)
        if path.name not in {"Hardening.cmake", "CompilerHardeningProbes.cmake"}
    ]
    ensure_license_headers(spdx, license_paths, year)


def make_isolated_tool_path(tmp: Path, *tools: str) -> str:
    bindir = tmp / "bin"
    bindir.mkdir()
    for tool in tools:
        source = shutil.which(tool)
        if not source:
            continue
        link = bindir / tool
        if not link.exists():
            link.symlink_to(source)
    return str(bindir)


def path_excluding_binary(name: str) -> str:
    kept: list[str] = []
    for directory in os.environ.get("PATH", "").split(":"):
        if not directory:
            continue
        if (Path(directory) / name).exists():
            continue
        kept.append(directory)
    return ":".join(kept)


def render_policy_test_manifest() -> str:
    import yaml

    helper = load_helper("policy/yaml_manifest.py")
    data = yaml.safe_load(_POLICY_TEST_MANIFEST) or {}
    return helper.render_lint_config("", helper.canonicalize_lint_config(data, "key"))


def write_policy_test_manifest(root: Path) -> None:
    for source_root in ("core", "port", "include", "userspace", "tests", "esp-idf"):
        (root / source_root).mkdir(parents=True, exist_ok=True)
    write(root / ".github/lint-c-cpp.yaml", render_policy_test_manifest())
    # Manifest validation requires policy.resource_lifetime canonical_files to exist.
    write(
        root / "include/sample/sample_file_raii.h",
        "#pragma once\nstruct SampleFileHandle {};\n",
    )


def reported_basenames(errors: list[str]) -> set[str]:
    return {Path(error.split(":", 2)[0]).name for error in errors}


def central_job_paths(root: Path, job: str) -> list[Path]:
    """Same path list ``consumer_manifest.py scan-paths`` would emit for a job."""
    from consumer_manifest import resolve_scan_paths

    return resolve_scan_paths(job, repo_root=root)


def policy_prepared_paths(script_name: str, root: Path, job: str) -> tuple[list[Path], object]:
    """Central scan-paths → prepare_paths → build_config (matches policy_runner)."""
    from policy_prepare import build_config, prepare_paths
    from scan_policy import bootstrap_scan_manifest

    bootstrap_scan_manifest(root)
    raw_paths = central_job_paths(root, job)
    paths = prepare_paths(script_name, root.resolve(), raw_paths)
    config = build_config(root.resolve(), paths)
    return paths, config


def policy_lint(script_name: str, root: Path, job: str) -> list[str]:
    paths, config = policy_prepared_paths(script_name, root, job)
    helper = load_helper(f"policy/{script_name}")
    return helper.lint(paths, config)


def policy_runner_cmd(
    script_name: str,
    root: Path,
    *,
    job: str | None = None,
    paths_file: Path | None = None,
    extras: list[str] | None = None,
) -> list[str]:
    cmd = [sys.executable, str(POLICY_RUNNER), "--repo-root", str(root), "--script", script_name]
    if paths_file is not None:
        cmd.extend(["--paths-file", str(paths_file)])
    elif job is not None:
        cmd.extend(["--scan-job", job])
    else:
        raise ValueError("policy_runner_cmd requires job or paths_file")
    cmd.extend(extras or [])
    return cmd


def write_paths_file(root: Path, job: str, dest: Path) -> list[Path]:
    paths = central_job_paths(root, job)
    dest.write_text(
        "\n".join(path.relative_to(root.resolve()).as_posix() for path in paths) + "\n",
        encoding="utf-8",
    )
    return paths


def assert_simulation_reported(
    testcase: unittest.TestCase,
    reported: set[str],
    *,
    violations: Iterable[str] = (),
    clean: Iterable[str] = (),
) -> None:
    for name in violations:
        testcase.assertIn(name, reported, name)
    for name in clean:
        testcase.assertNotIn(name, reported, name)


def assert_section_order(testcase: unittest.TestCase, text: str, *sections: str) -> None:
    indices = [text.index(section) for section in sections]
    testcase.assertEqual(indices, sorted(indices), msg=sections)


def bash_executable() -> str:
    return shutil.which("bash") or "/bin/bash"


def run_checked(
    args: list[str],
    *,
    cwd: Path = REPO_ROOT,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {args}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def make_fake_executable(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


class NumberedTextTestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._test_number = 0

    def startTest(self, test):
        unittest.TestResult.startTest(self, test)
        self._test_number += 1
        if self.showAll:
            self.stream.write(f"{self._test_number:>2}. {self.getDescription(test)}")
            self.stream.write(" ... ")
            self.stream.flush()
            self._newline = False
        elif self.dots:
            self.stream.write(".")
            self.stream.flush()


class NumberedTextTestRunner(unittest.TextTestRunner):
    resultclass = NumberedTextTestResult


class EmbeddedSelfTests(unittest.TestCase):
    def test_every_helper_self_test_passes(self) -> None:
        scripts = list(HELPER_SCRIPTS) + list(CORE_SELF_TEST_SCRIPTS)
        self.assertGreaterEqual(len(scripts), 1)
        for script in scripts:
            with self.subTest(script=script.name):
                result = subprocess.run(
                    policy_self_test_cmd(script),
                    cwd=REPO_ROOT,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    msg=result.stdout + result.stderr,
                )


class LintStepCoverage(unittest.TestCase):
    def test_every_python_helper_has_independent_simulation(self) -> None:
        helper_names = frozenset(script.name for script in HELPER_SCRIPTS)
        self.assertEqual(helper_names, SIMULATED_PYTHON_HELPERS)

    def test_every_linter_shell_script_has_unit_coverage(self) -> None:
        helper_shell = frozenset(
            script.name
            for script in TOOLCHAIN_DIR.glob("*.sh")
            if script.name not in {"tool_versions.sh", "format_toolchain.sh"}
        )
        expected = SIMULATED_SHELL_LINTER_SCRIPTS - {"lint.sh"}
        self.assertEqual(helper_shell, expected)
        self.assertIn("lint.sh", SIMULATED_SHELL_LINTER_SCRIPTS)

    def test_ci_lint_python_helper_steps_are_covered(self) -> None:
        ci_text = (COMMANDS_DIR / "lint.sh").read_text(encoding="utf-8")
        wrapper_text = (POLICY_DIR / "spec_traceability.py").read_text(encoding="utf-8")
        referenced = frozenset(re.findall(r"\b[a-z][a-z0-9_-]*\.py\b", ci_text + wrapper_text))
        core_scripts = frozenset(
            {
                "consumer_manifest.py",
                "manifest_validate.py",
                "tool_versions_check.py",
                "workflow_container_policy.py",
            }
        )
        policy_referenced = referenced - core_scripts - POLICY_INFRA_SCRIPTS
        self.assertTrue(policy_referenced)
        self.assertEqual(policy_referenced, SIMULATED_PYTHON_HELPERS)

    def test_ci_lint_argument_parser_help_and_unknown_arg(self) -> None:
        help_result = run_checked(["bash", str(COMMANDS_DIR / "lint.sh"), "--help"])
        self.assertIn("--custom-lints-only", help_result.stdout)

        bad_result = subprocess.run(
            ["bash", str(COMMANDS_DIR / "lint.sh"), "--definitely-not-a-real-flag"],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(bad_result.returncode, 2)
        self.assertIn("unknown argument", bad_result.stderr)

    def test_ci_lint_fails_closed_when_tidy_batch_generation_fails(self) -> None:
        ci_text = (COMMANDS_DIR / "lint.sh").read_text(encoding="utf-8")
        self.assertIn(
            'clang-tidy-batches >"$tidy_batches_file" 2>"$tidy_log"; then',
            ci_text,
        )
        self.assertIn(
            'rm -f "$source_paths" "$unsafe_paths" "$tidy_log" "$tidy_batches_file"',
            ci_text,
        )
        self.assertNotIn("tidy_batch_ec=$?", ci_text)
        self.assertNotRegex(
            ci_text,
            r"done\s*<\s*<\(\s*python3[\s\S]+?clang-tidy-batches",
        )

    def test_cppcheck_banned_apis_live_in_python_not_cfg(self) -> None:
        from scan_policy import BANNED_C_API_NAMES, BANNED_HEAP_C_API_NAMES

        # Exact set formerly in deleted config/cppcheck-forbidden-apis.cfg.
        former_cfg = frozenset(
            {
                "aligned_alloc",
                "atoi",
                "atol",
                "atoll",
                "calloc",
                "dprintf",
                "fflush",
                "fprintf",
                "fputc",
                "fputs",
                "fputwc",
                "fputws",
                "free",
                "fscanf",
                "fwprintf",
                "fwrite",
                "gets",
                "malloc",
                "perror",
                "popen",
                "printf",
                "putc",
                "putchar",
                "puts",
                "putwchar",
                "realloc",
                "scanf",
                "snprintf",
                "sprintf",
                "sscanf",
                "strcat",
                "strcpy",
                "strtoimax",
                "strtol",
                "strtoll",
                "strtoul",
                "strtoull",
                "strtoumax",
                "system",
                "vdprintf",
                "vfprintf",
                "vfwprintf",
                "vprintf",
                "vsnprintf",
                "vsprintf",
                "vwprintf",
                "wprintf",
            }
        )
        self.assertEqual(frozenset(BANNED_C_API_NAMES), former_cfg)
        self.assertTrue(BANNED_HEAP_C_API_NAMES <= frozenset(BANNED_C_API_NAMES))
        self.assertFalse((CONFIG_DIR / "cppcheck-forbidden-apis.cfg").is_file())

    def test_policy_overrides_required_and_rejects_bad_shape(self) -> None:
        from policy_overrides import validate_policy_overrides

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            data = __import__("yaml").safe_load(
                (root / ".github/lint-c-cpp.yaml").read_text(encoding="utf-8")
            )
            manifest = root / ".github/lint-c-cpp.yaml"
            missing = dict(data)
            missing["policy"] = {k: v for k, v in data["policy"].items() if k != "overrides"}
            issues = validate_policy_overrides(missing, manifest, root)
            self.assertTrue(any("policy.overrides is required" in item for item in issues))

            bad_key = __import__("copy").deepcopy(data)
            bad_key["policy"]["overrides"]["not-a-config"] = {"add": None, "remove": None}
            issues = validate_policy_overrides(bad_key, manifest, root)
            self.assertTrue(any("unknown policy.overrides keys" in item for item in issues))

            missing_add = __import__("copy").deepcopy(data)
            del missing_add["policy"]["overrides"]["clang-tidy-c"]["add"]
            issues = validate_policy_overrides(missing_add, manifest, root)
            self.assertTrue(
                any(
                    "clang-tidy-c missing required keys" in item and "add" in item
                    for item in issues
                )
            )

            bad_db = __import__("copy").deepcopy(data)
            bad_db["policy"]["overrides"]["clang-tidy-c"]["by_compile_db"] = [
                {
                    "compile_commands_json": "build/missing/compile_commands.json",
                    "add": None,
                    "remove": None,
                }
            ]
            issues = validate_policy_overrides(bad_db, manifest, root)
            self.assertTrue(any("is not declared under compile_db" in item for item in issues))

            ok_db = __import__("copy").deepcopy(data)
            ok_db["policy"]["overrides"]["clang-tidy-c"]["by_compile_db"] = [
                {
                    "compile_commands_json": "build/lint/userspace/compile_commands.json",
                    "add": None,
                    "remove": ["bugprone-easily-swappable-parameters"],
                }
            ]
            self.assertEqual(validate_policy_overrides(ok_db, manifest, root), [])

    def test_apply_clang_tidy_checks_overrides_add_and_remove(self) -> None:
        from policy_overrides import apply_clang_tidy_checks_overrides

        base = (
            "---\nChecks: >\n"
            "  bugprone-*,\n"
            "  -bugprone-easily-swappable-parameters,\n"
            "  readability-identifier-naming,\n\n"
            "WarningsAsErrors: '*'\n"
        )
        out = apply_clang_tidy_checks_overrides(
            base,
            add=("readability-magic-numbers",),
            remove=("bugprone-easily-swappable-parameters", "readability-identifier-naming"),
        )
        self.assertIn("readability-magic-numbers", out)
        self.assertIn("-bugprone-easily-swappable-parameters", out)
        # removed check must not remain enabled without leading '-'
        enabled = [
            tok.strip()
            for tok in out.split("Checks:", 1)[1].split("WarningsAsErrors", 1)[0].split(",")
            if tok.strip() and not tok.strip().startswith("-") and tok.strip() != ">"
        ]
        self.assertNotIn("readability-identifier-naming", enabled)
        self.assertIn("readability-magic-numbers", enabled)

    def test_materialize_override_configs_null_copies_kit_configs(self) -> None:
        from policy_overrides import lint_overrides_dir, materialize_override_configs

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            out = lint_overrides_dir(root)
            materialize_override_configs(root, LINT_KIT, out)
            self.assertTrue((out / ".clang-format").is_file())
            self.assertTrue((out / ".clang-tidy-c").is_file())
            self.assertTrue((out / "cppcheck-overrides.json").is_file())
            self.assertTrue((out / "openssf-hardening-manifest.yaml").is_file())
            self.assertEqual(
                (out / ".clang-format").read_text(encoding="utf-8"),
                (CONFIG_DIR / ".clang-format").read_text(encoding="utf-8"),
            )
            tidy = (out / ".clang-tidy-c").read_text(encoding="utf-8")
            kit_tidy = (CONFIG_DIR / ".clang-tidy-c").read_text(encoding="utf-8")
            # Checks body unchanged when add/remove are null (HeaderFilter may differ later).
            self.assertEqual(
                tidy.split("Checks:", 1)[1].split("WarningsAsErrors", 1)[0],
                kit_tidy.split("Checks:", 1)[1].split("WarningsAsErrors", 1)[0],
            )


    def test_override_regression_format_tidy_openssf_global_and_by_compile_db(self) -> None:
        """Regression: format / tidy / OpenSSF overrides — global and by_compile_db."""
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch

        import yaml
        from policy_overrides import (
            apply_clang_format_style_overrides,
            apply_clang_tidy_checks_overrides,
            compile_db_override_slug,
            lint_overrides_dir,
            materialize_clang_tidy_config_for_compile_db,
            materialize_override_configs,
            openssf_manifest_for_audit,
            override_dials_for_compile_db,
            override_dials_for_source,
        )

        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        _policy = HELPERS_DIR / "policy"
        if str(_policy) not in sys.path:
            sys.path.insert(0, str(_policy))
        import compile_db_lint
        import compile_db_util
        from hardening_verify import (
            compile_db_audit_flags_for_context,
            load_hardening_manifest,
            verify_compile_commands_openssf,
        )

        fw_json = "build/lint/firmware/compile_commands.json"
        host_json = "build/lint/tests/compile_commands.json"
        werror_family = [
            "-Werror",
            "-Werror=format-security",
            "-Werror=implicit",
            "-Werror=incompatible-pointer-types",
            "-Werror=int-conversion",
        ]

        def _base_manifest(*, format_block: str, tidy_c_block: str, openssf_block: str) -> str:
            return (
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  exclude_gitignore: true\n"
                "  source_roots: [firmware, tests]\n"
                "compile_db:\n"
                "  firmware:\n"
                f"    - commands: [make fw]\n      compile_commands_json: {fw_json}\n"
                "      source: firmware\n"
                "  userspace:\n"
                "    - cmake_args: null\n"
                f"      compile_commands_json: {host_json}\n"
                "      source: tests\n"
                "policy:\n  constants_headers: [limits.h]\n"
                "  nolint_allowed: null\n  resource_lifetime: null\n"
                "  shared_c_cxx_source_roots: [firmware]\n"
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n"
                "  overrides:\n"
                f"    clang-format:\n{format_block}"
                f"    clang-tidy-c:\n{tidy_c_block}"
                "    clang-tidy-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-shared-c-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-unsafe-c: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-unsafe-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    cppcheck: {add: null, remove: null, by_compile_db: null}\n"
                f"    openssf-hardening:\n{openssf_block}"
                + _ENABLED_LINT_JOBS_YAML
                + "firmware_build:\n  commands: [make firmware]\n"
                "spec_traceability: null\ntoolchain: null\nworkflow: null\nyamllint: null\n"
            )

        null_block = "      add: null\n      remove: null\n      by_compile_db: null\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / ".github/lint-c-cpp.yaml", _base_manifest(
                format_block=null_block, tidy_c_block=null_block, openssf_block=null_block
            ))
            write(root / "firmware/src/fw.c", "void fw(void) {}\n")
            write(root / "tests/host.c", "void host(void) {}\n")
            write(root / "include/sample/sample_null.h", "#pragma once\n")
            out = lint_overrides_dir(root)

            # --- null: kit identity ---
            materialize_override_configs(root, LINT_KIT, out)
            self.assertEqual(
                (out / ".clang-format").read_text(encoding="utf-8"),
                (CONFIG_DIR / ".clang-format").read_text(encoding="utf-8"),
            )
            kit_tidy = (CONFIG_DIR / ".clang-tidy-c").read_text(encoding="utf-8")
            mat_tidy = (out / ".clang-tidy-c").read_text(encoding="utf-8")
            self.assertEqual(
                mat_tidy.split("Checks:", 1)[1].split("WarningsAsErrors", 1)[0],
                kit_tidy.split("Checks:", 1)[1].split("WarningsAsErrors", 1)[0],
            )
            kit_openssf = load_hardening_manifest(LINT_KIT)
            mat_openssf = yaml.safe_load(
                (out / "openssf-hardening-manifest.yaml").read_text(encoding="utf-8")
            )
            self.assertEqual(mat_openssf["coverage"]["flags"], kit_openssf["coverage"]["flags"])

            # --- unit helpers: format / tidy apply ---
            fmt = apply_clang_format_style_overrides(
                "BasedOnStyle: Google\nSortIncludes: Never\n",
                add=("ColumnLimit: 100",),
                remove=("SortIncludes",),
            )
            self.assertIn("ColumnLimit: 100", fmt)
            self.assertNotIn("SortIncludes", fmt)
            tidy = apply_clang_tidy_checks_overrides(
                "---\nChecks: >\n  bugprone-*,\n  readability-identifier-naming,\n\nWarningsAsErrors: '*'\n",
                add=("readability-magic-numbers",),
                remove=("readability-identifier-naming",),
            )
            self.assertIn("readability-magic-numbers", tidy)
            self.assertNotIn(
                "readability-identifier-naming",
                [
                    t.strip()
                    for t in tidy.split("Checks:", 1)[1].split("WarningsAsErrors", 1)[0].split(",")
                    if t.strip() and not t.strip().startswith("-") and t.strip() != ">"
                ],
            )

            # --- global format / tidy / openssf materialize ---
            fmt_global = (
                "      add:\n        - 'ColumnLimit: 88'\n"
                "      remove:\n        - SortIncludes\n"
                "      by_compile_db: null\n"
            )
            tidy_global = (
                "      add:\n        - readability-magic-numbers\n"
                "      remove:\n        - readability-identifier-naming\n"
                "      by_compile_db: null\n"
            )
            openssf_global = (
                "      add:\n        - -fNFC-regression-flag\n"
                "      remove:\n"
                + "".join(f"        - {flag}\n" for flag in werror_family)
                + "      by_compile_db: null\n"
            )
            write(root / ".github/lint-c-cpp.yaml", _base_manifest(
                format_block=fmt_global, tidy_c_block=tidy_global, openssf_block=openssf_global
            ))
            materialize_override_configs(root, LINT_KIT, out)
            fmt_out = (out / ".clang-format").read_text(encoding="utf-8")
            self.assertIn("ColumnLimit: 88", fmt_out)
            self.assertNotIn("SortIncludes:", fmt_out)
            tidy_out = (out / ".clang-tidy-c").read_text(encoding="utf-8")
            self.assertIn("readability-magic-numbers", tidy_out)
            enabled = [
                t.strip()
                for t in tidy_out.split("Checks:", 1)[1].split("WarningsAsErrors", 1)[0].split(",")
                if t.strip() and not t.strip().startswith("-") and t.strip() != ">"
            ]
            self.assertNotIn("readability-identifier-naming", enabled)
            openssf_out = yaml.safe_load(
                (out / "openssf-hardening-manifest.yaml").read_text(encoding="utf-8")
            )
            flags = {str(f) for f in openssf_out["coverage"]["flags"]}
            self.assertIn("-fNFC-regression-flag", flags)
            for flag in werror_family:
                self.assertNotIn(flag, flags)
            audited = openssf_manifest_for_audit(root, kit_openssf, lookup_key=None)
            audited_flags = compile_db_audit_flags_for_context(
                audited, cross_compile=True, probe_cache={}, language="C"
            )
            for flag in werror_family:
                self.assertNotIn(flag, audited_flags)

            # --- by_compile_db: format + tidy + openssf (firmware only) ---
            fmt_by = (
                "      add: null\n"
                "      remove: null\n"
                "      by_compile_db:\n"
                f"        - compile_commands_json: {fw_json}\n"
                "          add:\n            - 'ColumnLimit: 77'\n"
                "          remove:\n            - IncludeBlocks\n"
            )
            tidy_by = (
                "      add:\n        - modernize-use-nullptr\n"
                "      remove: null\n"
                "      by_compile_db:\n"
                f"        - compile_commands_json: {fw_json}\n"
                "          add: null\n"
                "          remove:\n            - bugprone-easily-swappable-parameters\n"
            )
            openssf_by = (
                "      add: null\n"
                "      remove: null\n"
                "      by_compile_db:\n"
                f"        - compile_commands_json: {fw_json}\n"
                "          add: null\n"
                "          remove:\n"
                + "".join(f"            - {flag}\n" for flag in werror_family)
            )
            write(root / ".github/lint-c-cpp.yaml", _base_manifest(
                format_block=fmt_by, tidy_c_block=tidy_by, openssf_block=openssf_by
            ))
            # Write DBs before ownership / dial resolution.
            fw_path = root / fw_json
            host_path = root / host_json
            fw_path.parent.mkdir(parents=True, exist_ok=True)
            host_path.parent.mkdir(parents=True, exist_ok=True)
            host_flags = (
                "-Wall -Wextra -Wformat -Wformat=2 -Wconversion -Wsign-conversion "
                "-Wimplicit-fallthrough -Werror -Werror=format-security "
                "-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing "
                "-fstack-protector-strong -fhardened -fcf-protection=full -O2 -fexceptions"
            )
            fw_cmd = (
                host_flags.replace(" -Werror -Werror=format-security", "")
                .replace("-fhardened", "-Whardened")
                + f" -c {(root / 'firmware/src/fw.c').resolve()}"
            )
            fw_cmd = f"arm-none-eabi-gcc {fw_cmd}"
            fw_path.write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "command": fw_cmd,
                            "file": str((root / "firmware/src/fw.c").resolve()),
                        }
                    ]
                ),
                encoding="utf-8",
            )
            host_path.write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "command": (
                                f"/usr/bin/cc {host_flags} -c "
                                f"{(root / 'tests/host.c').resolve()}"
                            ),
                            "file": str((root / "tests/host.c").resolve()),
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (root / "build/lint/tests/CMakeCache.txt").write_text(
                "# probes unconfigured in this fixture\n", encoding="utf-8"
            )

            materialize_override_configs(root, LINT_KIT, out)
            # Global format unchanged (no global dials); by-db file has firmware dials.
            self.assertEqual(
                (out / ".clang-format").read_text(encoding="utf-8"),
                (CONFIG_DIR / ".clang-format").read_text(encoding="utf-8"),
            )
            fw_slug = compile_db_override_slug(fw_json)
            fw_fmt = (out / f".clang-format.by-{fw_slug}").read_text(encoding="utf-8")
            self.assertIn("ColumnLimit: 77", fw_fmt)
            self.assertNotIn("IncludeBlocks:", fw_fmt)
            self.assertFalse((out / f".clang-format.by-{compile_db_override_slug(host_json)}").exists())

            # Dial resolution: firmware gets by_db remove; host only global add.
            _a, fw_remove = override_dials_for_source(root, "clang-tidy-c", "firmware/src/fw.c")
            self.assertIn("bugprone-easily-swappable-parameters", fw_remove or ())
            host_add, host_remove = override_dials_for_source(
                root, "clang-tidy-c", "tests/host.c"
            )
            self.assertIn("modernize-use-nullptr", host_add or ())
            self.assertIsNone(host_remove)
            # Global+by_db merge on firmware: global add kept, by_db remove applied.
            fw_add, _ = override_dials_for_compile_db(root, "clang-tidy-c", fw_json)
            self.assertIn("modernize-use-nullptr", fw_add or ())

            # OpenSSF by_db: firmware without -Werror passes; host without fails.
            entries = {
                "firmware/src/fw.c": {
                    "directory": str(root),
                    "command": fw_cmd,
                    "file": str((root / "firmware/src/fw.c").resolve()),
                },
                "tests/host.c": {
                    "directory": str(root),
                    "command": (
                        f"/usr/bin/cc {host_flags} -c "
                        f"{(root / 'tests/host.c').resolve()}"
                    ),
                    "file": str((root / "tests/host.c").resolve()),
                },
            }

            def mock_host_triple() -> str:
                return "x86_64-host"

            def mock_compiler_target(compiler: Path) -> str | None:
                return "arm-none-eabi" if "arm-none" in compiler.name else "x86_64-host"

            with patch.object(compile_db_util, "host_target_triple", mock_host_triple), patch.object(
                compile_db_util, "compiler_target_triple", side_effect=mock_compiler_target
            ):
                issues = verify_compile_commands_openssf(
                    root,
                    LINT_KIT,
                    entries_by_key=entries,
                    source_paths=[root / "firmware/src/fw.c", root / "tests/host.c"],
                )
                self.assertEqual(issues, [], issues)
                entries["tests/host.c"]["command"] = (
                    f"/usr/bin/cc {host_flags.replace(' -Werror -Werror=format-security', '')} "
                    f"-c {(root / 'tests/host.c').resolve()}"
                )
                issues = verify_compile_commands_openssf(
                    root,
                    LINT_KIT,
                    entries_by_key=entries,
                    source_paths=[root / "tests/host.c"],
                )
                self.assertTrue(any("-Werror" in item for item in issues), issues)

            # Tidy by_db: firmware batch config disables check; host batch keeps global-only.
            merge_dir = root / "build/clang-tidy-compile-db"
            merge_dir.mkdir(parents=True)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = compile_db_lint._emit_clang_tidy_pass_batches(
                    pass_id="source",
                    label="source",
                    sources=[root / "firmware/src/fw.c", root / "tests/host.c"],
                    overlays=[
                        {
                            "id": "c",
                            "language": "c",
                            "config": ".clang-tidy-c",
                            "suffixes": [".c"],
                        }
                    ],
                    config_dir=merge_dir,
                    repo_root=root,
                    lint_kit=LINT_KIT,
                )
            self.assertEqual(rc, 0)
            emitted = buf.getvalue()
            self.assertIn(f".clang-tidy-c.by-{fw_slug}", emitted)
            fw_cfg = (merge_dir / f".clang-tidy-c.by-{fw_slug}").read_text(encoding="utf-8")
            self.assertIn("-bugprone-easily-swappable-parameters", fw_cfg)
            self.assertIn("modernize-use-nullptr", fw_cfg)
            host_slug = compile_db_override_slug(host_json)
            host_cfg_path = merge_dir / f".clang-tidy-c.by-{host_slug}"
            self.assertTrue(host_cfg_path.is_file())
            host_cfg = host_cfg_path.read_text(encoding="utf-8")
            self.assertIn("modernize-use-nullptr", host_cfg)
            # Host-only config must not disable the firmware-only remove unless global.
            # (remove is by_db firmware-only; host may still list the check enabled.)
            host_enabled = [
                t.strip()
                for t in host_cfg.split("Checks:", 1)[1].split("WarningsAsErrors", 1)[0].split(",")
                if t.strip() and not t.strip().startswith("-") and t.strip() != ">"
            ]
            # firmware remove must not appear as a bare disable-only on host path from by_db;
            # kit may already disable it — assert firmware cfg has explicit disable token.
            self.assertIn("-bugprone-easily-swappable-parameters", fw_cfg)

            # materialize_clang_tidy_config_for_compile_db merges global+by_db from kit text.
            written = materialize_clang_tidy_config_for_compile_db(
                root,
                base_config_name=".clang-tidy-c",
                base_text=kit_tidy,
                out_path=merge_dir / "direct-fw.clang-tidy",
                compile_commands_json=fw_json,
            )
            direct = written.read_text(encoding="utf-8")
            self.assertIn("modernize-use-nullptr", direct)
            self.assertIn("-bugprone-easily-swappable-parameters", direct)

    def test_openssf_override_materialize_and_audit_covers_nfc_cases(self) -> None:

        """OpenSSF overrides must affect materialize + compile-DB audit (NFC dual-board).

        Cases: null (kit strict), global remove/add, by_compile_db firmware-only -Werror
        waive (host stays strict), dual firmware JSON paths.
        """
        from unittest.mock import patch

        import yaml
        from policy_overrides import (
            apply_openssf_coverage_flag_overrides,
            lint_overrides_dir,
            materialize_override_configs,
            openssf_manifest_for_audit,
            openssf_override_dials_for_source,
        )

        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        _policy = HELPERS_DIR / "policy"
        if str(_policy) not in sys.path:
            sys.path.insert(0, str(_policy))
        import compile_db_util
        from hardening_verify import (
            compile_db_audit_flags_for_context,
            generate_hardening_cmake,
            generate_hardening_flags_mk,
            load_hardening_manifest,
            verify_compile_commands_openssf,
        )

        werror_family = [
            "-Werror",
            "-Werror=format-security",
            "-Werror=implicit",
            "-Werror=incompatible-pointer-types",
            "-Werror=int-conversion",
        ]
        kit_manifest = load_hardening_manifest(LINT_KIT)
        kit_flags = {
            str(item) for item in kit_manifest.get("coverage", {}).get("flags", [])
        }
        for flag in werror_family:
            self.assertIn(flag, kit_flags)

        # Unit: coverage.flags dials only (cmake templates unchanged).
        stripped = apply_openssf_coverage_flag_overrides(
            kit_manifest, add=None, remove=tuple(werror_family)
        )
        stripped_flags = {
            str(item) for item in stripped.get("coverage", {}).get("flags", [])
        }
        for flag in werror_family:
            self.assertNotIn(flag, stripped_flags)
        self.assertIn("-Wall", stripped_flags)
        augmented = apply_openssf_coverage_flag_overrides(
            kit_manifest,
            add=("-fNFC-test-flag", "NFC_TEST_ASSERTIONS"),
            remove=("_GLIBCXX_ASSERTIONS",),
        )
        self.assertIn(
            "-fNFC-test-flag",
            {str(item) for item in augmented.get("coverage", {}).get("flags", [])},
        )
        augmented_definitions = {
            str(item) for item in augmented.get("coverage", {}).get("definitions", [])
        }
        self.assertIn("NFC_TEST_ASSERTIONS", augmented_definitions)
        self.assertNotIn("_GLIBCXX_ASSERTIONS", augmented_definitions)
        license_root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, license_root, True)
        write_license_only_manifest(license_root)
        generated_make = generate_hardening_flags_mk(augmented, repo_root=license_root)
        c_line = next(
            line for line in generated_make.splitlines()
            if line.startswith("NERO_OPENSSF_CFLAGS")
        )
        cxx_line = next(
            line for line in generated_make.splitlines()
            if line.startswith("NERO_OPENSSF_CXXFLAGS")
        )
        cpp_line = next(
            line for line in generated_make.splitlines()
            if line.startswith("NERO_OPENSSF_CPPFLAGS")
        )
        self.assertIn("-fNFC-test-flag", c_line)
        self.assertIn("-fNFC-test-flag", cxx_line)
        self.assertIn("-DNFC_TEST_ASSERTIONS", cpp_line)
        self.assertNotIn("_GLIBCXX_ASSERTIONS", cpp_line)
        generated_cmake = generate_hardening_cmake(augmented, repo_root=license_root)
        self.assertIn("-fNFC-test-flag", generated_cmake)
        self.assertIn("NFC_TEST_ASSERTIONS", generated_cmake)
        self.assertNotIn("_GLIBCXX_ASSERTIONS", generated_cmake)

        host_flags = (
            "-Wall -Wextra -Wformat -Wformat=2 -Wconversion -Wsign-conversion "
            "-Wimplicit-fallthrough -Werror -Werror=format-security "
            "-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing "
            "-fstack-protector-strong -fhardened -fcf-protection=full -O2 -fexceptions"
        )
        # Firmware without in-command -Werror* (out-of-band gate / Arduino vendor noise).
        fw_flags_no_werror = (
            host_flags.replace(" -Werror -Werror=format-security", "")
            .replace("-fhardened", "-Whardened")
        )
        cross_flags_full = host_flags.replace("-fhardened", "-Whardened")

        def _nfc_repo(root: Path, *, openssf_overrides: str) -> None:
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: nero_nfc\n  c_macro_prefix: NERO_NFC\n"
                "  public_headers_dir: firmware/nfc_core/common\n"
                "  exclude_gitignore: true\n"
                "  source_roots: [firmware, tests, userspace]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - commands: [make TARGET=arduino_uno_r4wifi firmware-compile-db]\n"
                "      compile_commands_json: build/lint/firmware/arduino/compile_commands.json\n"
                "      source: firmware\n"
                "    - commands: [make TARGET=nucleo_wba65ri firmware-compile-db]\n"
                "      compile_commands_json: build/lint/firmware/nucleo/compile_commands.json\n"
                "      source: firmware\n"
                "  userspace:\n"
                "    - cmake_args: [-DCMAKE_BUILD_TYPE=Release]\n"
                "      compile_commands_json: build/lint/tests/compile_commands.json\n"
                "      source: tests\n"
                "policy:\n  constants_headers: [nero_nfc_limits.h]\n"
                "  nolint_allowed: null\n"
                "  resource_lifetime: null\n"
                "  shared_c_cxx_source_roots: [firmware, tests/firmware]\n"
                "  unsafe_api:\n    header: nero_nfc_null.h\n"
                "    include_headers: [nero_nfc_attrs.h]\n"
                "    wrapper_files: [firmware/nfc_core/common/nero_nfc_null.h]\n"
                "  overrides:\n"
                "    clang-format: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-c: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-shared-c-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-unsafe-c: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-unsafe-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    cppcheck: {add: null, remove: null, by_compile_db: null}\n"
                f"    openssf-hardening:\n{openssf_overrides}"
                + _ENABLED_LINT_JOBS_YAML
                + "firmware_build:\n  commands: [make firmware]\n"
                "spec_traceability: null\n"
                "toolchain: null\n"
                "workflow: null\n"
                "yamllint: null\n",
            )
            for rel in (
                "firmware/nfc/src/board.c",
                "firmware/reader/src/reader.c",
                "tests/host_ut.c",
            ):
                write(root / rel, "void f(void) {}\n")
            write(
                root / "firmware/nfc_core/common/nero_nfc_null.h",
                "#pragma once\n",
            )

        def _write_db(root: Path, rel: str, file_rel: str, command: str) -> None:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            src = (root / file_rel).resolve()
            path.write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "command": command,
                            "file": str(src),
                        }
                    ]
                ),
                encoding="utf-8",
            )

        null_overrides = (
            "      add: null\n"
            "      remove: null\n"
            "      by_compile_db: null\n"
        )
        global_remove = (
            "      add: null\n"
            "      remove:\n"
            + "".join(f"        - {flag}\n" for flag in werror_family)
            + "      by_compile_db: null\n"
        )
        global_add = (
            "      add:\n"
            "        - -fNFC-test-flag\n"
            "      remove: null\n"
            "      by_compile_db: null\n"
        )
        fw_by_db = (
            "      add: null\n"
            "      remove: null\n"
            "      by_compile_db:\n"
            "        - compile_commands_json: build/lint/firmware/arduino/compile_commands.json\n"
            "          add: null\n"
            "          remove:\n"
            + "".join(f"            - {flag}\n" for flag in werror_family)
            + "        - compile_commands_json: build/lint/firmware/nucleo/compile_commands.json\n"
            "          add: null\n"
            "          remove:\n"
            + "".join(f"            - {flag}\n" for flag in werror_family)
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _nfc_repo(root, openssf_overrides=null_overrides)
            out = lint_overrides_dir(root)
            materialize_override_configs(root, LINT_KIT, out)
            mat = yaml.safe_load(
                (out / "openssf-hardening-manifest.yaml").read_text(encoding="utf-8")
            )
            self.assertEqual(
                mat["coverage"]["flags"],
                kit_manifest["coverage"]["flags"],
            )

            # Global remove materializes into lint-overrides and audit dials.
            _nfc_repo(root, openssf_overrides=global_remove)
            materialize_override_configs(root, LINT_KIT, out)
            mat = yaml.safe_load(
                (out / "openssf-hardening-manifest.yaml").read_text(encoding="utf-8")
            )
            mat_flags = {str(item) for item in mat["coverage"]["flags"]}
            for flag in werror_family:
                self.assertNotIn(flag, mat_flags)
            audited = openssf_manifest_for_audit(root, kit_manifest, lookup_key=None)
            audited_flags = compile_db_audit_flags_for_context(
                audited, cross_compile=True, probe_cache={}, language="C"
            )
            for flag in werror_family:
                self.assertNotIn(flag, audited_flags)

            _nfc_repo(root, openssf_overrides=global_add)
            materialize_override_configs(root, LINT_KIT, out)
            mat = yaml.safe_load(
                (out / "openssf-hardening-manifest.yaml").read_text(encoding="utf-8")
            )
            self.assertIn("-fNFC-test-flag", mat["coverage"]["flags"])

            # NFC: by_compile_db waives -Werror* only for firmware DBs; host stays strict.
            _nfc_repo(root, openssf_overrides=fw_by_db)
            arduino_db = "build/lint/firmware/arduino/compile_commands.json"
            nucleo_db = "build/lint/firmware/nucleo/compile_commands.json"
            tests_db = "build/lint/tests/compile_commands.json"
            _write_db(
                root,
                arduino_db,
                "firmware/nfc/src/board.c",
                f"/opt/arm-none-eabi-gcc {fw_flags_no_werror} -c "
                f"{(root / 'firmware/nfc/src/board.c').resolve()}",
            )
            _write_db(
                root,
                nucleo_db,
                "firmware/reader/src/reader.c",
                f"/opt/arm-none-eabi-gcc {fw_flags_no_werror} -c "
                f"{(root / 'firmware/reader/src/reader.c').resolve()}",
            )
            _write_db(
                root,
                tests_db,
                "tests/host_ut.c",
                f"/usr/bin/cc {host_flags} -c {(root / 'tests/host_ut.c').resolve()}",
            )
            (root / "build/lint/tests/CMakeCache.txt").write_text(
                "# probes unconfigured in this fixture\n", encoding="utf-8"
            )

            add, remove = openssf_override_dials_for_source(
                root, "firmware/nfc/src/board.c"
            )
            self.assertTrue(remove)
            for flag in werror_family:
                self.assertIn(flag, remove)
            host_add, host_remove = openssf_override_dials_for_source(
                root, "tests/host_ut.c"
            )
            self.assertIsNone(host_remove)

            entries = {
                "firmware/nfc/src/board.c": {
                    "directory": str(root),
                    "command": (
                        f"/opt/arm-none-eabi-gcc {fw_flags_no_werror} -c "
                        f"{(root / 'firmware/nfc/src/board.c').resolve()}"
                    ),
                    "file": str((root / "firmware/nfc/src/board.c").resolve()),
                },
                "firmware/reader/src/reader.c": {
                    "directory": str(root),
                    "command": (
                        f"/opt/arm-none-eabi-gcc {fw_flags_no_werror} -c "
                        f"{(root / 'firmware/reader/src/reader.c').resolve()}"
                    ),
                    "file": str((root / "firmware/reader/src/reader.c").resolve()),
                },
                "tests/host_ut.c": {
                    "directory": str(root),
                    "command": (
                        f"/usr/bin/cc {host_flags} -c "
                        f"{(root / 'tests/host_ut.c').resolve()}"
                    ),
                    "file": str((root / "tests/host_ut.c").resolve()),
                },
            }
            sources = [root / key for key in entries]

            def mock_host_triple() -> str:
                return "x86_64-host"

            def mock_compiler_target(compiler: Path) -> str | None:
                name = compiler.name
                if "arm-none" in name:
                    return "arm-none-eabi"
                return "x86_64-host"

            with patch.object(compile_db_util, "host_target_triple", mock_host_triple), patch.object(
                compile_db_util, "compiler_target_triple", side_effect=mock_compiler_target
            ):
                issues = verify_compile_commands_openssf(
                    root,
                    LINT_KIT,
                    entries_by_key=entries,
                    source_paths=sources,
                )
                self.assertEqual(issues, [], issues)

                # Host missing -Werror still fails (by_compile_db did not match tests DB).
                entries["tests/host_ut.c"]["command"] = (
                    f"/usr/bin/cc {host_flags.replace(' -Werror -Werror=format-security', '')} "
                    f"-c {(root / 'tests/host_ut.c').resolve()}"
                )
                issues = verify_compile_commands_openssf(
                    root,
                    LINT_KIT,
                    entries_by_key=entries,
                    source_paths=sources,
                )
                self.assertTrue(
                    any("tests/host_ut.c" in item and "-Werror" in item for item in issues),
                    issues,
                )

                # Without overrides, firmware missing -Werror fails.
                _nfc_repo(root, openssf_overrides=null_overrides)
                entries["tests/host_ut.c"]["command"] = (
                    f"/usr/bin/cc {host_flags} -c {(root / 'tests/host_ut.c').resolve()}"
                )
                issues = verify_compile_commands_openssf(
                    root,
                    LINT_KIT,
                    entries_by_key={
                        "firmware/nfc/src/board.c": {
                            "directory": str(root),
                            "command": (
                                f"/opt/arm-none-eabi-gcc {fw_flags_no_werror} -c "
                                f"{(root / 'firmware/nfc/src/board.c').resolve()}"
                            ),
                            "file": str((root / "firmware/nfc/src/board.c").resolve()),
                            compile_db_util.PROVENANCE_KEY: [arduino_db],
                        },
                    },
                    source_paths=[root / "firmware/nfc/src/board.c"],
                )
                self.assertTrue(
                    any(
                        "firmware/nfc/src/board.c" in item and "-Werror" in item
                        for item in issues
                    ),
                    issues,
                )

                # Global remove waives firmware and host alike.
                _nfc_repo(root, openssf_overrides=global_remove)
                issues = verify_compile_commands_openssf(
                    root,
                    LINT_KIT,
                    entries_by_key={
                        "firmware/nfc/src/board.c": {
                            "directory": str(root),
                            "command": (
                                f"/opt/arm-none-eabi-gcc {fw_flags_no_werror} -c "
                                f"{(root / 'firmware/nfc/src/board.c').resolve()}"
                            ),
                            "file": str((root / "firmware/nfc/src/board.c").resolve()),
                        },
                        "tests/host_ut.c": {
                            "directory": str(root),
                            "command": (
                                f"/usr/bin/cc "
                                f"{host_flags.replace(' -Werror -Werror=format-security', '')} "
                                f"-c {(root / 'tests/host_ut.c').resolve()}"
                            ),
                            "file": str((root / "tests/host_ut.c").resolve()),
                        },
                    },
                    source_paths=[
                        root / "firmware/nfc/src/board.c",
                        root / "tests/host_ut.c",
                    ],
                )
                self.assertEqual(issues, [], issues)


    def test_override_by_compile_db_ownership_and_tidy_cppcheck_dials(self) -> None:
        """by_compile_db uses firmware-prefer ownership; tidy/cppcheck dials apply."""
        import io
        from contextlib import redirect_stdout
        from policy_overrides import (
            apply_cppcheck_cli_dials,
            owning_compile_commands_json,
            override_dials_for_source,
        )

        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  exclude_gitignore: true\n"
                "  source_roots: [firmware, tests]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - commands: [make fw]\n"
                "      compile_commands_json: build/lint/firmware/compile_commands.json\n"
                "      source: firmware\n"
                "  userspace:\n"
                "    - cmake_args: null\n"
                "      compile_commands_json: build/lint/tests/compile_commands.json\n"
                "      source: tests\n"
                "policy:\n  constants_headers: [limits.h]\n"
                "  nolint_allowed: null\n  resource_lifetime: null\n"
                "  shared_c_cxx_source_roots: [firmware]\n"
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n"
                "  overrides:\n"
                "    clang-format: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-c:\n"
                "      add: null\n"
                "      remove: null\n"
                "      by_compile_db:\n"
                "        - compile_commands_json: build/lint/firmware/compile_commands.json\n"
                "          add: null\n"
                "          remove: [bugprone-easily-swappable-parameters]\n"
                "    clang-tidy-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-shared-c-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-unsafe-c: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-unsafe-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    cppcheck:\n"
                "      add: null\n"
                "      remove: null\n"
                "      by_compile_db:\n"
                "        - compile_commands_json: build/lint/firmware/compile_commands.json\n"
                "          add: null\n"
                "          remove: [nullPointer]\n"
                "    openssf-hardening: {add: null, remove: null, by_compile_db: null}\n"
                + _ENABLED_LINT_JOBS_YAML
                + "firmware_build:\n  commands: [make firmware]\n"
                "spec_traceability: null\ntoolchain: null\nworkflow: null\nyamllint: null\n",
            )
            write(root / "firmware/src/fw.c", "void fw(void) {}\n")
            write(root / "firmware/src/fw.h", "#pragma once\nvoid fw(void);\n")
            write(root / "tests/host.c", "void host(void) {}\n")
            write(root / "include/sample/sample_null.h", "#pragma once\n")
            fw_db = root / "build/lint/firmware/compile_commands.json"
            tests_db = root / "build/lint/tests/compile_commands.json"
            fw_db.parent.mkdir(parents=True)
            tests_db.parent.mkdir(parents=True)
            fw_entry = {
                "directory": str(root),
                "command": f"arm-none-eabi-gcc -c {(root / 'firmware/src/fw.c').resolve()}",
                "file": str((root / "firmware/src/fw.c").resolve()),
            }
            # Same firmware TU also present in host tests DB (amalgamation / UT compile).
            host_fw_entry = {
                "directory": str(root),
                "command": f"/usr/bin/cc -c {(root / 'firmware/src/fw.c').resolve()}",
                "file": str((root / "firmware/src/fw.c").resolve()),
            }
            host_entry = {
                "directory": str(root),
                "command": f"/usr/bin/cc -c {(root / 'tests/host.c').resolve()}",
                "file": str((root / "tests/host.c").resolve()),
            }
            fw_db.write_text(json.dumps([fw_entry]), encoding="utf-8")
            tests_db.write_text(json.dumps([host_fw_entry, host_entry]), encoding="utf-8")

            self.assertEqual(
                owning_compile_commands_json(root, "firmware/src/fw.c"),
                "build/lint/firmware/compile_commands.json",
            )
            self.assertEqual(
                owning_compile_commands_json(root, "tests/host.c"),
                "build/lint/tests/compile_commands.json",
            )
            _add, remove = override_dials_for_source(
                root, "clang-tidy-c", "firmware/src/fw.c"
            )
            self.assertIn("bugprone-easily-swappable-parameters", remove or ())
            _add, host_remove = override_dials_for_source(
                root, "clang-tidy-c", "tests/host.c"
            )
            self.assertIsNone(host_remove)

            enable, suppress = apply_cppcheck_cli_dials(
                ["warning"],
                [],
                add=None,
                remove=("nullPointer",),
            )
            self.assertIn("nullPointer", suppress)

            # Tidy batch emit splits firmware vs host configs when by_compile_db is set.
            merge_dir = root / "build/clang-tidy-compile-db"
            merge_dir.mkdir(parents=True)
            (merge_dir / "compile_commands.json").write_text(
                json.dumps([fw_entry, host_entry]), encoding="utf-8"
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = compile_db_lint._emit_clang_tidy_pass_batches(
                    pass_id="source",
                    label="source",
                    sources=[root / "firmware/src/fw.c", root / "tests/host.c"],
                    overlays=[
                        {
                            "id": "c",
                            "language": "c",
                            "config": ".clang-tidy-c",
                            "suffixes": [".c"],
                        }
                    ],
                    config_dir=merge_dir,
                    repo_root=root,
                    lint_kit=LINT_KIT,
                )
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn(".clang-tidy-c.by-build__lint__firmware__compile_commands_json", out)
            self.assertTrue(
                (merge_dir / ".clang-tidy-c.by-build__lint__firmware__compile_commands_json").is_file()
            )
            fw_cfg = (
                merge_dir / ".clang-tidy-c.by-build__lint__firmware__compile_commands_json"
            ).read_text(encoding="utf-8")
            self.assertIn("-bugprone-easily-swappable-parameters", fw_cfg)

            # Synthesized headers inherit every database profile covering their
            # manifest source root.
            header_buf = io.StringIO()
            with redirect_stdout(header_buf):
                header_rc = compile_db_lint._emit_clang_tidy_pass_batches(
                    pass_id="source",
                    label="headers",
                    sources=[root / "firmware/src/fw.h"],
                    overlays=[
                        {
                            "id": "c-headers",
                            "language": "c",
                            "config": ".clang-tidy-c",
                            "suffixes": [".h"],
                        }
                    ],
                    config_dir=merge_dir,
                    repo_root=root,
                    lint_kit=LINT_KIT,
                )
            self.assertEqual(header_rc, 0)
            self.assertIn(
                ".clang-tidy-c.by-build__lint__firmware__compile_commands_json",
                header_buf.getvalue(),
            )

    def test_manifest_validate_rejects_missing_policy_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "compile_db:\n  firmware:\n"
                "    - commands: [make fw]\n"
                "      compile_commands_json: build/fw/compile_commands.json\n"
                "      source: firmware\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  source_roots: [core, userspace]\n"
                "policy:\n  constants_headers: [limits.h]\n"
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("policy.overrides is required", result.stderr)

    def test_cppcheck_manifest_drives_runner_defaults(self) -> None:
        from consumer_manifest import (
            cppcheck_cli_common_args,
            cppcheck_config,
            load_lint_kit_cppcheck_manifest,
            resolve_lint_kit,
        )

        kit = resolve_lint_kit(LINT_KIT)
        manifest = load_lint_kit_cppcheck_manifest(kit)
        block = manifest["cppcheck"]
        self.assertEqual(len(block["passes"]), 1)
        self.assertEqual(block["passes"][0]["id"], "source")
        self.assertEqual(block["passes"][0]["scan_job"], "source")
        self.assertNotIn("library", block)
        self.assertNotIn("scan", block)
        self.assertNotIn("standards_fallback", block)
        self.assertEqual(block["cli"]["enable"], ["warning"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/a.c", "int a;\n")
            cfg = cppcheck_config(root, lint_kit=kit)
            self.assertEqual(len(cfg["passes"]), 1)
            self.assertFalse(cfg.get("dir_scan"))
            self.assertEqual(cfg["standards"]["c"], "c11")
            self.assertEqual(cfg["standards"]["cxx"], "c++17")
            source_args = cppcheck_cli_common_args(cfg, lint_kit=kit, pass_cfg=cfg["passes"][0])
            self.assertIn("--quiet", source_args)
            self.assertTrue(any(item.startswith("--enable=warning") for item in source_args))
            self.assertFalse(any(item.startswith("--library=") for item in source_args))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(
                root / "userspace/CMakeLists.txt",
                'include("../cmake/Hardening.cmake")\n'
                "define_hardening(\n  TARGET hardening\n  C_STANDARD 23 CXX_STANDARD 20)\n"
                "target_link_libraries(app PRIVATE hardening)\n",
            )
            cfg = cppcheck_config(root, lint_kit=kit)
            self.assertEqual(cfg["standards"]["c"], "c23")
            self.assertEqual(cfg["standards"]["cxx"], "c++20")

    def test_codespell_helper_config_uses_multiline_and_noise_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "codespell",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--help' ]]; then echo 'codespell --ignore-multiline-regex'; exit 0; fi\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'codespell 2.4.2'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            result = run_checked(
                ["bash", str(TOOLCHAIN_DIR / "codespell.sh"), "--check-config", "docs/example.md"],
                env=env,
            )
        self.assertIn("--ignore-multiline-regex", result.stdout)
        self.assertIn("--ignore-regex", result.stdout)
        self.assertIn("docs/example.md", result.stdout)

    def test_codespell_helper_fails_when_binary_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tool_path = make_isolated_tool_path(
                Path(tmp),
                "bash",
                "python3",
                "dirname",
                "mktemp",
                "grep",
                "head",
                "sed",
            )
            env = {**os.environ, "PATH": tool_path}
            result = subprocess.run(
                ["bash", str(TOOLCHAIN_DIR / "codespell.sh"), "--check-config", "README.md"],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("codespell not found", result.stderr)

    def test_codespell_helper_fails_when_version_too_old(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "codespell",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--help' ]]; then echo 'codespell 1.0.0'; exit 0; fi\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'codespell 1.0.0'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            result = subprocess.run(
                ["bash", str(TOOLCHAIN_DIR / "codespell.sh"), "--check-config", "README.md"],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--ignore-multiline-regex", result.stderr)

    def test_codespell_discovers_repo_yaml_without_source_roots(self) -> None:
        from consumer_manifest import resolve_scan_paths

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / ".github").mkdir(parents=True)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan: {}\n",
            )
            paths = {
                path.relative_to(root).as_posix()
                for path in resolve_scan_paths("codespell", repo_root=root)
            }
        self.assertIn(".github/lint-c-cpp.yaml", paths)

    def test_codespell_default_targets_fail_when_manifest_discovery_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            fakebin = Path(tmp) / "bin"
            fakebin.mkdir()
            make_fake_executable(
                fakebin,
                "codespell",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--help' ]]; then echo 'codespell --ignore-multiline-regex'; exit 0; fi\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'codespell 2.4.2'; exit 0; fi\n"
                "exit 0\n",
            )
            make_fake_executable(
                fakebin,
                "python3",
                "#!/usr/bin/env bash\nexit 9\n",
            )
            env = {
                **os.environ,
                "PATH": f"{fakebin}:{os.environ['PATH']}",
                "LINT_REPO_ROOT": str(root),
            }
            result = subprocess.run(
                ["bash", str(TOOLCHAIN_DIR / "codespell.sh")],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertNotEqual(result.returncode, 0)

    def test_python_lint_is_wired_into_format_job(self) -> None:
        # ruff + mypy run inside the `format` job (like shellcheck/codespell),
        # not as a separate enabled_lint_jobs entry.
        self.assertNotIn("python_lint", KNOWN_LINT_JOBS_ORDERED)
        self.assertTrue((CONFIG_DIR / "ruff.toml").is_file())
        self.assertTrue((CONFIG_DIR / "mypy.ini").is_file())
        self.assertTrue((TOOLCHAIN_DIR / "python_lint.sh").is_file())
        lint_sh = (COMMANDS_DIR / "lint.sh").read_text(encoding="utf-8")
        self.assertIn('source "${toolchain}/python_lint.sh"', lint_sh)
        self.assertIn("run lint_kit_python_lint_self_test", lint_sh)
        self.assertIn('run bash "${toolchain}/python_lint.sh"', lint_sh)
        self.assertNotIn('section python_lint', lint_sh)
        # The python steps live under the format section, after codespell.
        format_idx = lint_sh.index("section format ")
        codespell_idx = lint_sh.index('run bash "${toolchain}/codespell.sh"')
        python_idx = lint_sh.index('run bash "${toolchain}/python_lint.sh"')
        self.assertLess(format_idx, codespell_idx)
        self.assertLess(codespell_idx, python_idx)

    def test_python_lint_helper_check_config_emits_ruff_and_mypy(self) -> None:
        result = run_checked(
            ["bash", str(TOOLCHAIN_DIR / "python_lint.sh"), "--check-config", "docs/example.py"],
        )
        self.assertIn("uvx ruff@", result.stdout)
        self.assertIn("uvx mypy@", result.stdout)
        self.assertIn("ruff.toml", result.stdout)
        self.assertIn("mypy.ini", result.stdout)
        self.assertIn("docs/example.py", result.stdout)

    @unittest.skipUnless(shutil.which("uvx"), "uvx required for python_lint self-test")
    def test_python_lint_self_test_flags_violation(self) -> None:
        # The self-test proves ruff flags a known violation — "an equal error is thrown"
        # for the python_lint job, matching the other jobs' pre-run self-tests.
        result = subprocess.run(
            [
                "bash",
                "-c",
                f'source "{TOOLCHAIN_DIR / "python_lint.sh"}"; lint_kit_python_lint_self_test',
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("python_lint self-test: OK", result.stdout)

    def test_manifest_validate_requires_compile_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("compile_db is required", result.stderr)

    def test_compile_db_audit_flags_werror_only_via_override_dials(self) -> None:
        """``-Werror*`` stays required unless dial-removed (no silent diagnostics_gate)."""
        import hardening_verify
        from policy_overrides import apply_openssf_coverage_flag_overrides

        manifest = {
            "coverage": {
                "flags": [
                    "-Wall",
                    "-Wconversion",
                    "-Werror",
                    "-Werror=format-security",
                    "-fstack-protector-strong",
                ],
                "definitions": [],
            },
            "cmake": {
                "common": {
                    "compile": [
                        "-Wall",
                        "-Wconversion",
                        "-Werror",
                        "-Werror=format-security",
                        "-fstack-protector-strong",
                    ],
                    "compile_probe_gated": [],
                    "compile_genex_gated": [],
                    "link_probe_gated": [],
                    "link_genex_gated": [],
                },
                "C": {
                    "compile_probe_gated": [],
                    "compile_genex_gated": [],
                },
                "CXX": {"definitions_genex_gated": []},
            },
        }
        strict, _ = hardening_verify.compile_db_audit_flags_for_context(
            manifest, cross_compile=True, probe_cache={}, language="C"
        )
        self.assertIn("-Werror", strict)
        self.assertIn("-Werror=format-security", strict)
        dialed = apply_openssf_coverage_flag_overrides(
            manifest,
            add=None,
            remove=("-Werror", "-Werror=format-security"),
        )
        waived, _ = hardening_verify.compile_db_audit_flags_for_context(
            dialed, cross_compile=True, probe_cache={}, language="C"
        )
        self.assertNotIn("-Werror", waived)
        self.assertNotIn("-Werror=format-security", waived)
        self.assertIn("-Wall", waived)
        self.assertIn("-Wconversion", waived)
        self.assertIn("-fstack-protector-strong", waived)

    def test_amalgamation_included_source_keys_quoted_and_macro(self) -> None:
        import compile_db_util

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "fw/src/host.cpp",
                  '#include "impl.cpp"\n#include NFC_STRINGIFY(BOARD_UNIT)\n')
            write(root / "fw/src/impl.cpp", "int impl(void){return 0;}\n")
            write(root / "fw/port/board_unit.cpp", "int board(void){return 1;}\n")
            write(root / "fw/orphan/orphan.cpp", "int orphan(void){return 2;}\n")
            command = (
                "arm-none-eabi-g++ -I" + str(root / "fw/port")
                + " -DBOARD_UNIT=board_unit.cpp -c " + str(root / "fw/src/host.cpp")
            )
            covered = compile_db_util.amalgamation_included_source_keys(
                root, iter([(root / "fw/src/host.cpp", command)])
            )
        self.assertIn("fw/src/impl.cpp", covered)
        self.assertIn("fw/port/board_unit.cpp", covered)
        self.assertNotIn("fw/orphan/orphan.cpp", covered)

    def test_amalgamation_does_not_waive_in_command_flag_failures(self) -> None:
        """Amalgamation may clear missing-entry only — never a failed flag audit."""
        from hardening_verify import verify_compile_commands_openssf

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_canonical_lint_manifest(root)
            (root / "core").mkdir()
            host = root / "core/host.c"
            child = root / "core/child.c"
            host.write_text('#include "child.c"\nvoid host(void) {}\n', encoding="utf-8")
            child.write_text("void child(void) {}\n", encoding="utf-8")
            weak = (
                "-Wall -Wextra -Wformat -Wformat=2 -Wconversion -Wsign-conversion "
                "-Wimplicit-fallthrough -Werror -Werror=format-security "
                "-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing "
                "-fstack-protector-strong"
            )
            entries = {
                "core/host.c": {
                    "directory": str(root),
                    "command": f"/usr/bin/cc {weak} -c {host.resolve()}",
                    "file": str(host.resolve()),
                },
                # child has an entry that also fails flags — must not be waived by include.
                "core/child.c": {
                    "directory": str(root),
                    "command": f"/usr/bin/cc {weak} -c {child.resolve()}",
                    "file": str(child.resolve()),
                },
            }
            issues = verify_compile_commands_openssf(
                root, LINT_KIT, entries_by_key=entries, source_paths=[host, child]
            )
        self.assertTrue(any("core/child.c" in item and "missing" in item for item in issues), issues)
        self.assertTrue(any("core/host.c" in item and "missing" in item for item in issues), issues)

    def test_hardening_include_wiring_requires_by_slug_for_dialed_compile_db(self) -> None:
        """Dialed Hardening.by-<slug> must be included by that compile_db's CMakeLists."""
        from hardening_verify import (
            load_hardening_manifest,
            verify_hardening_include_wiring,
            write_generated_hardening_cmake,
            write_generated_probes_cmake,
            _expected_consumer_hardening_modules,
            _normalize_generated_cmake,
        )
        from policy_overrides import compile_db_override_slug

        fw_json = "build/lint/firmware/compile_commands.json"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cmake").mkdir(parents=True)
            (root / "firmware").mkdir()
            (root / "userspace").mkdir()
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  exclude_gitignore: true\n"
                "  source_roots: [firmware, userspace, esp-idf]\n"
                "compile_db:\n  firmware:\n"
                f"    - compile_commands_json: {fw_json}\n"
                "      source: firmware\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  constants_headers: [limits.h]\n"
                + _NULL_OVERRIDES_YAML.replace(
                    "openssf-hardening: {add: null, remove: null, by_compile_db: null}\n",
                    "openssf-hardening:\n"
                    "      add: null\n"
                    "      remove: null\n"
                    "      by_compile_db:\n"
                    f"        - compile_commands_json: {fw_json}\n"
                    "          add: null\n"
                    "          remove: [-Werror]\n",
                ),
            )
            kit_manifest = load_hardening_manifest(LINT_KIT)
            for name, body in _expected_consumer_hardening_modules(
                root, kit_manifest
            ).items():
                (root / "cmake" / name).write_text(body, encoding="utf-8")
            slug = compile_db_override_slug(fw_json)
            by_name = f"Hardening.by-{slug}.cmake"
            flags_mk = f"Hardening.flags.by-{slug}.mk"
            self.assertTrue((root / "cmake" / by_name).is_file())
            self.assertTrue((root / "cmake" / flags_mk).is_file())
            # Wrong include on firmware tree:
            write(
                root / "esp-idf/main/CMakeLists.txt",
                'include("${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Hardening.cmake")\n'
                "define_hardening(TARGET hardening C_STANDARD 17)\n",
            )
            write(
                root / "userspace/CMakeLists.txt",
                'include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Hardening.cmake")\n'
                "define_hardening(TARGET hardening C_STANDARD 23)\n",
            )
            issues = verify_hardening_include_wiring(
                root,
                kit_manifest,
                cmake_paths=[
                    root / "esp-idf/main/CMakeLists.txt",
                    root / "userspace/CMakeLists.txt",
                ],
            )
            self.assertTrue(
                any("esp-idf/main" in item and by_name in item for item in issues),
                issues,
            )
            # Fix firmware include → wiring OK (CMake path; flags.mk optional).
            write(
                root / "esp-idf/main/CMakeLists.txt",
                f'include("${{CMAKE_CURRENT_SOURCE_DIR}}/../../cmake/{by_name}")\n'
                "define_hardening(TARGET hardening C_STANDARD 17)\n",
            )
            issues = verify_hardening_include_wiring(
                root,
                kit_manifest,
                cmake_paths=[
                    root / "esp-idf/main/CMakeLists.txt",
                    root / "userspace/CMakeLists.txt",
                ],
            )
            self.assertEqual(issues, [], issues)

    def test_hardening_flags_mk_arduino_wiring_without_cmake_include(self) -> None:
        """Firmware by_compile_db may wire via Hardening.flags.by-*.mk only (Arduino)."""
        from hardening_verify import (
            load_hardening_manifest,
            verify_hardening_include_wiring,
            _expected_consumer_hardening_modules,
        )
        from policy_overrides import compile_db_override_slug

        fw_json = "build/lint/firmware/arduino/compile_commands.json"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cmake").mkdir(parents=True)
            (root / "make").mkdir()
            (root / "userspace").mkdir()
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  exclude_gitignore: true\n"
                "  source_roots: [firmware, userspace]\n"
                "compile_db:\n  firmware:\n"
                f"    - compile_commands_json: {fw_json}\n"
                "      source: firmware\n"
                "      commands: [make firmware-compile-db]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  constants_headers: [limits.h]\n"
                + _NULL_OVERRIDES_YAML.replace(
                    "openssf-hardening: {add: null, remove: null, by_compile_db: null}\n",
                    "openssf-hardening:\n"
                    "      add: null\n"
                    "      remove: null\n"
                    "      by_compile_db:\n"
                    f"        - compile_commands_json: {fw_json}\n"
                    "          add: null\n"
                    "          remove: [-Werror]\n",
                ),
            )
            kit_manifest = load_hardening_manifest(LINT_KIT)
            for name, body in _expected_consumer_hardening_modules(
                root, kit_manifest
            ).items():
                (root / "cmake" / name).write_text(body, encoding="utf-8")
            slug = compile_db_override_slug(fw_json)
            flags_mk = f"Hardening.flags.by-{slug}.mk"
            write(
                root / "userspace/CMakeLists.txt",
                'include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Hardening.cmake")\n'
                "define_hardening(TARGET hardening C_STANDARD 23)\n",
            )
            issues = verify_hardening_include_wiring(
                root,
                kit_manifest,
                cmake_paths=[root / "userspace/CMakeLists.txt"],
            )
            self.assertTrue(
                any(fw_json in item and flags_mk in item for item in issues),
                issues,
            )
            write(
                root / "make/arduino-flags.mk",
                f"include $(CURDIR)/cmake/{flags_mk}\n"
                "NFC_BUILD_EXTRA_FLAGS += $(NERO_OPENSSF_CFLAGS)\n",
            )
            issues = verify_hardening_include_wiring(
                root,
                kit_manifest,
                cmake_paths=[root / "userspace/CMakeLists.txt"],
            )
            self.assertEqual(issues, [], issues)

    def test_generate_hardening_cmake_gates_compile_arch_fcf_protection(self) -> None:
        """-fcf-protection must be host+x86_64 gated, never a bare cross compile option."""
        from hardening_verify import generate_hardening_cmake, load_hardening_manifest

        with tempfile.TemporaryDirectory() as tmp:
            license_root = Path(tmp)
            write_license_only_manifest(license_root)
            body = generate_hardening_cmake(
                load_hardening_manifest(LINT_KIT), repo_root=license_root
            )
        self.assertNotIn("$<$<COMPILE_LANGUAGE:C>:-fcf-protection=full>", body)
        self.assertIn("-fcf-protection=full", body)
        self.assertIn("_hardening_host", body)
        self.assertIn("x86_64", body)

    def test_usable_openssf_probe_cache_ignores_unrelated_cmakecache(self) -> None:
        """Caches without OpenSSF HAVE_* keys do not fail-closed probe-gated audit."""
        from hardening_verify import (
            compile_db_audit_flags_for_context,
            load_hardening_manifest,
            _usable_openssf_probe_cache,
        )

        kit_manifest = load_hardening_manifest(LINT_KIT)
        unrelated = {"SOME_OTHER_BOOL": True, "CMAKE_BUILD_TYPE": True}
        self.assertEqual(_usable_openssf_probe_cache(unrelated, kit_manifest), {})
        flags, probe_issues = compile_db_audit_flags_for_context(
            kit_manifest,
            cross_compile=True,
            probe_cache={},
            language="C",
            command="",
            build_type=None,
        )
        self.assertEqual(probe_issues, [])
        self.assertIn("-Wall", flags)
        self.assertNotIn("-fhardened", flags)

    def test_openssf_cmake_fail_on_change_rewrites_then_requires_rerun(self) -> None:
        """Hand-edited Hardening.cmake is overwritten; lint asks to commit and re-run."""
        from format_fail_on_change import FAIL_ON_CHANGE_TAIL
        from hardening_verify import (
            generate_hardening_cmake,
            generate_probes_cmake,
            load_hardening_manifest,
            sync_kit_cmake_regen,
            _normalize_generated_cmake,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit = root / "kit"
            (root / "cmake").mkdir(parents=True)
            (root / "userspace").mkdir()
            shutil.copytree(LINT_KIT / "config", kit / "config")
            (kit / "cmake").mkdir(parents=True)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  exclude_gitignore: true\n"
                "  source_roots: [userspace]\n"
                "compile_db:\n  firmware: []\n  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  constants_headers: [limits.h]\n"
                + _NULL_OVERRIDES_YAML
                + "firmware_build: null\n"
                "spec_traceability: null\n"
                "toolchain: null\n"
                "workflow: null\n"
                "yamllint: null\n",
            )
            kit_manifest = load_hardening_manifest(kit)
            expected = _normalize_generated_cmake(
                generate_hardening_cmake(kit_manifest, repo_root=root)
            )
            (root / "cmake" / "Hardening.cmake").write_text(
                expected.replace("-Wall", "-Wextra"), encoding="utf-8"
            )
            (root / "cmake" / "CompilerHardeningProbes.cmake").write_text(
                _normalize_generated_cmake(
                    generate_probes_cmake(kit_manifest, repo_root=root)
                ),
                encoding="utf-8",
            )
            issues = sync_kit_cmake_regen(root, kit, kit_manifest)
            self.assertTrue(issues, issues)
            self.assertTrue(all(FAIL_ON_CHANGE_TAIL in item for item in issues), issues)
            self.assertEqual(
                _normalize_generated_cmake(
                    (root / "cmake" / "Hardening.cmake").read_text(encoding="utf-8")
                ),
                expected,
            )
            # Second pass is clean.
            self.assertEqual(sync_kit_cmake_regen(root, kit, kit_manifest), [])

    def test_kit_generated_cmake_matches_shipped_templates(self) -> None:
        from hardening_verify import (
            generate_hardening_cmake,
            generate_probes_cmake,
            load_hardening_manifest,
            _normalize_generated_cmake,
        )

        manifest = load_hardening_manifest(LINT_KIT)
        with tempfile.TemporaryDirectory() as tmp:
            license_root = Path(tmp)
            # Shipped kit templates use the full Apache license_header corpus.
            write_license_only_manifest(license_root)
            bodies = {
                "Hardening.cmake": generate_hardening_cmake(
                    manifest, repo_root=license_root
                ),
                "CompilerHardeningProbes.cmake": generate_probes_cmake(
                    manifest, repo_root=license_root
                ),
            }
        for name, body in bodies.items():
            shipped = (LINT_KIT / "cmake" / name).read_text(encoding="utf-8")
            self.assertEqual(
                _normalize_generated_cmake(shipped),
                _normalize_generated_cmake(body),
                f"stale kit cmake/{name}",
            )

    def test_userspace_link_txt_openssf_requires_dialed_link_tokens(self) -> None:
        from hardening_verify import load_hardening_manifest, verify_userspace_link_txt_openssf

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  exclude_gitignore: true\n"
                "  source_roots: [userspace]\n"
                "compile_db:\n  firmware: []\n  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  constants_headers: [limits.h]\n"
                + _NULL_OVERRIDES_YAML,
            )
            build = root / "build/lint/userspace"
            build.mkdir(parents=True)
            (build / "CMakeCache.txt").write_text(
                "CMAKE_BUILD_TYPE:STRING=Release\n", encoding="utf-8"
            )
            link = build / "CMakeFiles/app.dir/link.txt"
            link.parent.mkdir(parents=True)
            link.write_text("cc -pie -o app a.o\n", encoding="utf-8")
            kit_manifest = load_hardening_manifest(LINT_KIT)
            issues = verify_userspace_link_txt_openssf(root, LINT_KIT, kit_manifest)
        self.assertTrue(any("LINKER:-z,relro" in item for item in issues), issues)

    def test_openssf_prose_tokens_are_dialable_in_coverage_flags(self) -> None:
        from hardening_verify import OPENSSF_PROSE_FLAGS, load_hardening_manifest
        from policy_overrides import apply_openssf_coverage_flag_overrides

        manifest = load_hardening_manifest(LINT_KIT)
        flags = {str(item) for item in manifest["coverage"]["flags"]}
        for token in OPENSSF_PROSE_FLAGS:
            self.assertIn(token, flags)
        dialed = apply_openssf_coverage_flag_overrides(
            manifest, add=None, remove=tuple(sorted(OPENSSF_PROSE_FLAGS))
        )
        remaining = {str(item) for item in dialed["coverage"]["flags"]}
        for token in OPENSSF_PROSE_FLAGS:
            self.assertNotIn(token, remaining)

    def test_manifest_validate_rejects_removed_secondary_sketch_exemption(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n"
                "  firmware_lint_exemptions:\n"
                "    secondary_sketch_only_sources: [firmware/reader]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: build/fw/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make fw]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/us/compile_commands.json\n"
                "      source: core\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("removed policy fields: firmware_lint_exemptions", result.stderr)

    def test_ino_is_license_and_codespell_only(self) -> None:
        from scan_policy import (
            JOB_CODESPELL,
            JOB_FORMAT_C,
            JOB_LICENSE,
            JOB_SOURCE,
            SOURCE_SUFFIXES,
            iter_job_paths,
            license_header_classify,
        )

        self.assertNotIn(".ino", SOURCE_SUFFIXES)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  // test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [firmware]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: build/fw/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make fw]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/us/compile_commands.json\n"
                "      source: firmware\n",
            )
            sketch = root / "firmware/sketch.ino"
            write(sketch, "void setup() {}\nvoid loop() {}\n")
            write(root / "firmware/app.c", "int main(void) { return 0; }\n")
            self.assertIsNotNone(license_header_classify(sketch))
            source_names = {p.name for p in iter_job_paths(root, JOB_SOURCE)}
            format_names = {p.name for p in iter_job_paths(root, JOB_FORMAT_C)}
            codespell_names = {p.name for p in iter_job_paths(root, JOB_CODESPELL)}
            license_names = {p.name for p in iter_job_paths(root, JOB_LICENSE)}
        self.assertIn("app.c", source_names)
        self.assertNotIn("sketch.ino", source_names)
        self.assertNotIn("sketch.ino", format_names)
        self.assertIn("sketch.ino", codespell_names)
        self.assertIn("sketch.ino", license_names)

    def test_manifest_validate_rejects_legacy_embedded_c_impossible_clang_tidy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [firmware]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n"
                "  firmware_lint_exemptions:\n"
                "    embedded_c_impossible_clang_tidy:\n"
                "      source_roots: [firmware]\n"
                "      disabled_checks:\n"
                "        - cppcoreguidelines-pro-bounds-pointer-arithmetic\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: build/fw/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make fw]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/us/compile_commands.json\n"
                "      source: core\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("removed policy fields: firmware_lint_exemptions", result.stderr)

    def test_manifest_validate_rejects_unknown_firmware_exemption_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n"
                "  firmware_lint_exemptions:\n"
                "    disable_everything: [firmware]\n"
                "compile_db:\n  firmware:\n"
                "    - compile_commands_json: build/fw/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make fw]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/us/compile_commands.json\n"
                "      source: core\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("removed policy fields: firmware_lint_exemptions", result.stderr)

    def test_manifest_validate_requires_unsafe_api_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api: {}\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("policy.unsafe_api.header must be a non-empty string", result.stderr)

    def test_manifest_validate_requires_unsafe_api_wrapper_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("policy.unsafe_api.wrapper_files", result.stderr)

    def test_enabled_lint_jobs_api_and_validate(self) -> None:
        import yaml
        from consumer_manifest import (
            enabled_lint_jobs,
            enabled_lint_jobs_ordered,
            lint_job_enabled,
            manifest_path,
        )

        self.assertEqual(len(KNOWN_LINT_JOBS_ORDERED), 22)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            self.assertEqual(enabled_lint_jobs_ordered(root), KNOWN_LINT_JOBS_ORDERED)
            self.assertTrue(lint_job_enabled(root, "license"))
            ok = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(ok.returncode, 0, ok.stderr)

            path = manifest_path(root)
            partial = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            partial["enabled_lint_jobs"] = ["license", "format"]
            path.write_text(yaml.safe_dump(partial, sort_keys=False), encoding="utf-8")
            self.assertEqual(enabled_lint_jobs(root), frozenset({"license", "format"}))
            self.assertFalse(lint_job_enabled(root, "openssf"))

            status = subprocess.run(
                [
                    sys.executable,
                    str(CORE_DIR / "manifest" / "consumer_manifest.py"),
                    "--repo-root",
                    str(root),
                    "enabled-lint-jobs",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            lines = status.stdout.strip().splitlines()
            self.assertEqual(lines[0], "2 22")
            self.assertEqual(lines[1], "license format")

            empty = dict(partial)
            empty["enabled_lint_jobs"] = []
            path.write_text(yaml.safe_dump(empty, sort_keys=False), encoding="utf-8")
            bad_empty = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(bad_empty.returncode, 1)
            self.assertIn("enabled_lint_jobs must be non-empty", bad_empty.stderr)

            unknown = dict(partial)
            unknown["enabled_lint_jobs"] = ["license", "not_a_real_job"]
            path.write_text(yaml.safe_dump(unknown, sort_keys=False), encoding="utf-8")
            bad_unknown = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(bad_unknown.returncode, 1)
            self.assertIn("unknown job 'not_a_real_job'", bad_unknown.stderr)

            dup = dict(partial)
            dup["enabled_lint_jobs"] = ["license", "license"]
            path.write_text(yaml.safe_dump(dup, sort_keys=False), encoding="utf-8")
            bad_dup = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(bad_dup.returncode, 1)
            self.assertIn("duplicate job 'license'", bad_dup.stderr)

    def test_manifest_validate_rejects_unknown_top_level_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "analysis:\n  compile_db: []\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  canonical:\n    null_header: sample_null.h\n"
                "    null_include_headers: [attrs.h]\n"
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown top-level fields: analysis", result.stderr)

    def test_manifest_validate_rejects_legacy_bounds_and_index_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  bounds:\n    shared_header_basenames: [limits.h]\n"
                "  canonical:\n    null_header: sample_null.h\n"
                "    null_include_headers: [attrs.h]\n"
                "    index_skip_stems: [mem_util]\n"
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown policy fields: canonical", result.stderr)
        self.assertIn("removed policy fields: bounds", result.stderr)

    def test_manifest_validate_rejects_legacy_c_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "c_prefixes:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown top-level fields: c_prefixes", result.stderr)

    def test_manifest_validate_rejects_legacy_null_macro_and_unsafe_api_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  null_macro:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "  unsafe_api_policy:\n    wrapper_files: [include/sample/sample_null.h]\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown policy fields: null_macro", result.stderr)
        self.assertIn("unsafe_api_policy", result.stderr)

    def test_manifest_validate_rejects_legacy_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "build:\n"
                "  - name: firmware compile\n"
                "    commands:\n"
                "      - make lint-firmware\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML +
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample/sample_null.h]\n",
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown top-level fields: build", result.stderr)

    def test_custom_lints_only_smoke_runs_on_synthetic_repo(self) -> None:
        tool_check = subprocess.run(
            [sys.executable, str(CORE_DIR / "tools" / "tool_versions_check.py"), "verify"],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(
            tool_check.returncode,
            0,
            msg=f"host lint tools missing or too old:\n{tool_check.stderr}",
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            write_custom_lints_smoke_repo(root, LINT_KIT)
            env = {
                **os.environ,
                "LINT_KIT": str(LINT_KIT),
                "LINT_REPO_ROOT": str(root),
            }
            result = subprocess.run(
                ["bash", str(LINT_KIT / "lint-c-cpp.sh"), "lint", "--custom-lints-only"],
                cwd=root,
                env=env,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("All lint checks passed.", result.stdout)

    def test_codespell_paths_auto_discovers_docs_yaml_and_source_roots(self) -> None:
        from consumer_manifest import codespell_paths

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/note.md", "# ok\n")
            write(root / "core/config.yml", "name: ci\n")
            write(root / "core/foo.c", "int foo(void) { return 0; }\n")
            write(root / "third-party/vendor/README.md", "# skip\n")
            (root / "third-party").mkdir(parents=True, exist_ok=True)
            write(root / ".gitignore", "third-party/\n")
            paths = set(codespell_paths(root))
        self.assertIn("core/note.md", paths)
        self.assertIn("core/config.yml", paths)
        self.assertIn("core/foo.c", paths)
        self.assertNotIn("third-party/vendor/README.md", paths)

    def test_path_in_scan_scope_rejects_third_party_without_git(self) -> None:
        from scan_policy import path_in_scan_scope

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  exclude_gitignore: true\n  source_roots:\n    - .\n",
            )
            write(root / ".gitignore", "third-party/\n")
            self.assertTrue(path_in_scan_scope("tracked.c", root))
            self.assertFalse(path_in_scan_scope("third-party/leak.c", root))
            self.assertFalse(path_in_scan_scope("third-party/esp-idf/leak.c", root))

    def test_path_in_scan_scope_uses_mocked_git_check_ignore(self) -> None:
        from unittest.mock import patch

        from scan_policy import bootstrap_scan_manifest, path_in_scan_scope

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap_scan_manifest(root, source_roots=("core",))
            with patch("git_ignore.git_repo_available", return_value=True), patch(
                "git_ignore.paths_gitignored",
                side_effect=lambda _repo, rels: frozenset(
                    path for path in rels if path == "core/cache.c"
                ),
            ):
                self.assertTrue(path_in_scan_scope("core/app.c", root))
                self.assertFalse(path_in_scan_scope("core/cache.c", root))

    def test_markdownlint_collect_targets_finds_repo_markdown_excluding_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  source_roots:\n    - .\n",
            )
            write(root / ".gitignore", "third-party/\nbuild/\n")
            write(root / "README.md", "# ok\n")
            write(root / "INSTALLATION.md", "# ok\n")
            write(root / "docs/CCID.md", "# ok\n")
            write(root / "third-party/vendor/IGNORE.md", "# skip\n")
            write(root / "build/out/IGNORE.md", "# skip\n")
            script = (
                f"source {str(TOOLCHAIN_DIR / 'markdownlint_toolchain.sh')!r}; "
                f"mapfile -t targets < <(lint_kit_markdownlint_collect_targets {str(root)!r}); "
                'printf "%s\n" "${targets[@]}"'
            )
            result = run_checked(["bash", "-c", script])
            lines = set(result.stdout.strip().splitlines())
            self.assertEqual(
                {
                    "README.md",
                    "INSTALLATION.md",
                    "docs/CCID.md",
                },
                lines,
            )

    def test_markdown_scan_finds_docs_outside_source_roots(self) -> None:
        from scan_policy import iter_job_paths, JOB_MARKDOWN

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: nero_lifi\n  c_macro_prefix: NERO_LIFI\n"
                "  public_headers_dir: include/nero_lifi\n"
                "  source_roots: [core, port, include, userspace, tests, esp-idf]\n",
            )
            write(root / "README.md", "# root\n")
            write(root / "docs/TUTORIAL.md", "# docs\n")
            write(root / "core/README.md", "# core\n")
            paths = {p.relative_to(root).as_posix() for p in iter_job_paths(root, JOB_MARKDOWN)}
        self.assertEqual(paths, {"README.md", "docs/TUTORIAL.md", "core/README.md"})

    def test_license_scan_finds_repo_files_outside_source_roots(self) -> None:
        from scan_policy import iter_job_paths, JOB_LICENSE

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: nero_lifi\n  c_macro_prefix: NERO_LIFI\n"
                "  public_headers_dir: include/nero_lifi\n"
                "  source_roots: [core, port, include, userspace, tests, esp-idf]\n",
            )
            write(root / "README.md", "# root\n")
            write(root / "make/install.sh", "#!/bin/sh\n")
            write(root / "core/app.c", "void app(void) {}\n")
            paths = {p.relative_to(root).as_posix() for p in iter_job_paths(root, JOB_LICENSE)}
        self.assertIn("README.md", paths)
        self.assertIn("make/install.sh", paths)
        self.assertIn(".github/lint-c-cpp.yaml", paths)
        self.assertIn("core/app.c", paths)

    def test_source_scan_covers_all_c_cxx_suffixes_without_case_bypass(self) -> None:
        from scan_policy import (
            JOB_CODESPELL,
            JOB_FORMAT_C,
            JOB_SOURCE,
            JOB_UNSAFE_API,
            iter_job_paths,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  source_roots: [core]\n",
            )
            names = (
                "lower.c",
                "source.cc",
                "source.cpp",
                "source.cxx",
                "Header.H",
                "header.hh",
                "header.hpp",
                "header.hxx",
                "Upper.CXX",
            )
            for name in names:
                write(root / "core" / name, "int value;\n")
            expected = {f"core/{name}" for name in names}
            for job in (JOB_SOURCE, JOB_UNSAFE_API, JOB_FORMAT_C, JOB_CODESPELL):
                job_paths = iter_job_paths(root, job)
                paths = {path.relative_to(root).as_posix() for path in job_paths}
                self.assertTrue(expected <= paths, (job, sorted(expected - paths)))
            from policy_prepare import prepare_paths

            heap_paths = {
                path.relative_to(root).as_posix()
                for path in prepare_paths(
                    "banned_cxx_heap.py",
                    root,
                    iter_job_paths(root, JOB_UNSAFE_API),
                )
            }
            self.assertIn("core/Upper.CXX", heap_paths)
            self.assertIn("core/header.hxx", heap_paths)

    def test_read_paths_file_rejects_out_of_repo_and_absolute(self) -> None:
        from scan_policy import read_paths_file

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "core").mkdir()
            (root / "core/ok.c").write_text("int a;\n", encoding="utf-8")
            good = root / "good.txt"
            good.write_text("core/ok.c\n", encoding="utf-8")
            self.assertEqual(read_paths_file(good, root), [root / "core/ok.c"])
            for bad in ("../escape.c", "/etc/passwd", "core/../../escape.c"):
                pf = root / "bad.txt"
                pf.write_text(bad + "\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_paths_file(pf, root)

    def test_shell_scan_finds_scripts_outside_source_roots(self) -> None:
        from scan_policy import iter_job_paths, JOB_SHELL

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: nero_lifi\n  c_macro_prefix: NERO_LIFI\n"
                "  public_headers_dir: include/nero_lifi\n"
                "  source_roots: [core, port, include, userspace, tests, esp-idf]\n",
            )
            write(root / "make/install.sh", "#!/usr/bin/env bash\n")
            write(root / ".github/scripts/ci.sh", "#!/usr/bin/env bash\n")
            write(root / "core/build.sh", "#!/usr/bin/env bash\n")
            paths = {p.relative_to(root).as_posix() for p in iter_job_paths(root, JOB_SHELL)}
        self.assertEqual(
            paths,
            {".github/scripts/ci.sh", "core/build.sh", "make/install.sh"},
        )

    def test_markdownlint_fail_on_change_rewrites_then_requires_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp) / "bin"
            fakebin.mkdir()
            make_fake_executable(
                fakebin,
                "npm",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == 'prefix' && ${2:-} == '-g' ]]; then echo '/dev/null'; exit 0; fi\n"
                "exit 0\n",
            )
            make_fake_executable(
                fakebin,
                "node",
                "#!/usr/bin/env bash\nif [[ ${1:-} == '-p' ]]; then echo 20; exit 0; fi\nexit 0\n",
            )
            make_fake_executable(
                fakebin,
                "markdownlint",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo '0.49.0'; exit 0; fi\n"
                "fix=0\n"
                "while (($# > 0)); do\n"
                "  if [[ $1 == '--fix' ]]; then fix=1; shift; continue; fi\n"
                "  if [[ $1 == '--config' ]]; then shift 2; continue; fi\n"
                "  if ((fix)) && [[ -f $1 ]]; then sed -i 's/[[:space:]]*$//' \"$1\"; fi\n"
                "  shift\n"
                "done\n"
                "exit 0\n",
            )
            root = Path(tmp) / "repo"
            root.mkdir()
            write(root / "README.md", "# Title\n\nExtra line   \n")
            config = CONFIG_DIR / ".markdownlint.yaml"
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ.get('PATH', '')}"}
            script = (
                f"source {str(TOOLCHAIN_DIR / 'markdownlint_toolchain.sh')!r}; "
                f"cd {str(root)!r}; "
                "set +e; "
                f"lint_kit_markdownlint_fail_on_change {str(config)!r} README.md; "
                "ec=$?; "
                "lint_kit_markdownlint_fail_on_change "
                f"{str(config)!r} README.md; "
                "ec2=$?; "
                "set -e; "
                '[[ $ec -eq 1 && $ec2 -eq 0 ]]'
            )
            result = run_checked([bash_executable(), "-c", script], env=env)
        self.assertIn("markdownlint: OK (1 scanned, 0 auto-formatted)", result.stdout)

    def test_markdownlint_helper_version_parsing_and_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "markdownlint",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo '0.49.0'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            script = (
                f"source {str(TOOLCHAIN_DIR / 'markdownlint_toolchain.sh')!r}; "
                "got=$(lint_kit_markdownlint_version_raw); "
                "[[ $got == 0.49.0 ]]; "
                "lint_kit_markdownlint_version_ge 0.48.0; "
                "if lint_kit_markdownlint_version_ge 1.0.0; then exit 9; fi"
            )
            run_checked(["bash", "-c", script], env=env)

    def test_clang_tidy_helper_selects_new_enough_tidy_format_and_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "clang-tidy",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'LLVM version 99.0.0'; exit 0; fi\n"
                "exit 0\n",
            )
            make_fake_executable(fakebin, "run-clang-tidy", "#!/usr/bin/env bash\nexit 0\n")
            make_fake_executable(
                fakebin,
                "clang-format",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'clang-format version 99.0.0'; exit 0; fi\n"
                "exit 0\n",
            )
            make_fake_executable(fakebin, "scan-build-21", "#!/usr/bin/env bash\nexit 0\n")
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            script = (
                f"source {str(TOOLCHAIN_DIR / 'clang_toolchain.sh')!r}; "
                "tidy=$(lint_kit_find_clang_tidy); [[ $tidy == */clang-tidy ]]; "
                "runner=$(lint_kit_find_run_clang_tidy \"$tidy\"); [[ $runner == */run-clang-tidy ]]; "
                "fmt=$(lint_kit_find_clang_format); [[ $fmt == */clang-format ]]; "
                "scan=$(lint_kit_find_scan_build); [[ $scan == */scan-build-21 ]]; "
                "lint_kit_clang_tidy_version_ge 21.0.0 \"$(lint_kit_clang_tidy_version_raw \"$tidy\")\"; "
                "lint_kit_clang_format_version_ge 20.0.0 \"$(lint_kit_clang_format_version_raw \"$fmt\")\"; "
                "lint_kit_scan_build_version_ge 21.0.0 \"$(lint_kit_scan_build_version_raw \"$scan\")\""
            )
            run_checked(["bash", "-c", script], env=env)

    def test_clang_tidy_helper_persists_shim_dir_for_github_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp) / "fakebin"
            github_path = Path(tmp) / "github-path"
            fakebin.mkdir()
            make_fake_executable(
                fakebin,
                "clang-format-21",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'clang-format version 21.0.0'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {
                **os.environ,
                "GITHUB_PATH": str(github_path),
                "HOME": str(Path(tmp) / "home"),
                "PATH": f"{fakebin}:{os.environ['PATH']}",
            }
            script = (
                f"source {str(TOOLCHAIN_DIR / 'clang_toolchain.sh')!r}; "
                "lint_kit_ensure_clang_format; "
                "shim=$(lint_kit_clang_tidy_install_dir); "
                "fmt=$(lint_kit_find_clang_format); [[ -x \"$fmt\" ]]; "
                "[[ $(grep -Fx \"$shim\" \"$GITHUB_PATH\" | wc -l) -eq 1 ]]; "
                "lint_kit_ensure_clang_format; "
                "[[ $(grep -Fx \"$shim\" \"$GITHUB_PATH\" | wc -l) -eq 1 ]]"
            )
            run_checked(["bash", "-c", script], env=env)

    def test_ci_lint_invokes_resolved_llvm_tool_binaries(self) -> None:
        ci_text = (COMMANDS_DIR / "lint.sh").read_text(encoding="utf-8")
        ci_code = "\n".join(
            line for line in ci_text.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn('clang_tidy_bin="$(lint_kit_find_clang_tidy)"', ci_text)
        self.assertIn('clang_format_bin="$(lint_kit_find_clang_format)"', ci_text)
        self.assertNotRegex(ci_code, r"(?m)^\s*(run\s+)?clang-tidy(\s|$)")
        self.assertNotRegex(ci_code, r"(?m)^\s*(run\s+)?clang-format(\s|$)")
        self.assertIn('"$clang_tidy_bin" --verify-config', ci_text)
        self.assertIn('run "$run_clang_tidy_bin"', ci_text)
        self.assertNotIn('"$clang_tidy_bin" --quiet', ci_text)
        self.assertIn("lint_kit_clang_format_fail_on_change", ci_text)
        self.assertIn("lint_kit_shfmt_fail_on_change", ci_text)
        self.assertIn("shellcheck -S warning", ci_text)
        self.assertIn("format_toolchain.sh", (TOOLCHAIN_DIR / "clang_toolchain.sh").read_text(encoding="utf-8"))
        self.assertIn("format_toolchain.sh", (TOOLCHAIN_DIR / "markdownlint_toolchain.sh").read_text(encoding="utf-8"))
        format_section = 'section format "Format C/C++, shell, and Python sources (clang-format, shfmt, shellcheck, codespell, ruff, mypy)"'
        self.assertIn(format_section, ci_text)
        self.assertNotIn('section "Fix misspellings (codespell)"', ci_text)
        openssf_section = 'section openssf "OpenSSF hardening (validate manifest + hardeninglint)"'
        clang_tidy_section = 'section clang_tidy "Run clang-tidy"'
        memory_section = (
            'section banned_cxx_heap "Enforce no C++ new/delete '
            '(including unsafe wrappers; complements clang-tidy/cppcheck)"'
        )
        assert_section_order(
            self,
            ci_text,
            format_section,
            "lint_kit_format_toolchain_self_test",
            "shellcheck -S warning",
            'run bash "${toolchain}/codespell.sh"',
            'section compile_db "Generate compile databases (host configure → merge → OpenSSF audit)"',
            openssf_section,
            clang_tidy_section,
            memory_section,
        )
        self.assertLess(
            ci_text.index(clang_tidy_section),
            ci_text.index('section cppcheck "Run cppcheck'),
        )
        self.assertNotIn('section "Run manifest build steps"', ci_text)
        self.assertNotIn('section "Firmware:', ci_text)

    def test_production_scan_discovery_avoids_hardcoded_root_skips(self) -> None:
        production_files = [
            CORE_DIR / "scan" / "scan_policy.py",
            CORE_DIR / "manifest" / "consumer_manifest.py",
            COMPILE_DB_DIR / "compile_db_lint.py",
            COMMANDS_DIR / "lint.sh",
        ]
        forbidden = (
            'if root == "include"',
            'if root == "esp-idf"',
            'if root in ("include"',
            '_COMPILE_DB_SKIP_ROOTS',
            'for root in ("core", "port", "esp-idf/main")',
            '"esp-idf" not in frozenset(scan_source_roots',
            'rel.startswith("tests/")',
        )
        for path in production_files:
            text = path.read_text(encoding="utf-8")
            for pattern in forbidden:
                self.assertNotIn(pattern, text, msg=f"{path}: found hardcoded scan skip {pattern!r}")

    def test_format_fail_on_change_shared_gates(self) -> None:
        result = run_checked(
            [sys.executable, str(CORE_DIR / "tools" / "format_fail_on_change.py")],
        )
        self.assertIn("format-fail-on-change self-test: OK", result.stdout)
        result = run_checked(["bash", str(TOOLCHAIN_DIR / "format_toolchain.sh")])
        self.assertIn("format-toolchain self-test: OK", result.stdout)

    def test_clang_format_fail_on_change_rewrites_then_requires_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp) / "bin"
            fakebin.mkdir()
            make_fake_executable(
                fakebin,
                "clang-format-21",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'clang-format version 21.0.0'; exit 0; fi\n"
                "if [[ ${1:-} == '-i' ]]; then\n"
                "  shift\n"
                "  while (($# > 0)); do\n"
                '    if [[ $1 == --style=* ]]; then shift; continue; fi\n'
                '    if [[ -f $1 ]]; then sed -i \'s/{return/{ return/; s/;}/; }/\' "$1"; fi\n'
                "    shift\n"
                "  done\n"
                "  exit 0\n"
                "fi\n"
                "exit 0\n",
            )
            root = Path(tmp) / "repo"
            root.mkdir()
            write(root / "core/sample.c", "int main(void){return 0;}\n")
            config = CONFIG_DIR / ".clang-format"
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ.get('PATH', '')}"}
            script = (
                f"source {str(TOOLCHAIN_DIR / 'clang_toolchain.sh')!r}; "
                "fmt=$(lint_kit_find_clang_format); "
                "[[ -n $fmt ]]; "
                f"cd {str(root)!r}; "
                "set +e; "
                f"lint_kit_clang_format_fail_on_change 'file:{str(config)}' \"$fmt\" core/sample.c; "
                "ec=$?; "
                f"lint_kit_clang_format_fail_on_change 'file:{str(config)}' \"$fmt\" core/sample.c; "
                "ec2=$?; "
                "set -e; "
                '[[ $ec -eq 1 && $ec2 -eq 0 ]]'
            )
            result = run_checked([bash_executable(), "-c", script], env=env)
        self.assertIn("clang-format: OK (1 scanned, 0 auto-formatted)", result.stdout)

    def test_tool_versions_verify_rejects_under_version_cppcheck(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp) / "bin"
            fakebin.mkdir()
            make_fake_executable(
                fakebin,
                "cppcheck",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'Cppcheck 1.0.0'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ.get('PATH', '')}"}
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "tools" / "tool_versions_check.py"), "verify"],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("cppcheck 1.0.0 < required", result.stderr)

    def test_cppcheck_helper_version_gate_accepts_required_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = Path(tmp)
            make_fake_executable(
                fakebin,
                "cppcheck",
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == '--version' ]]; then echo 'Cppcheck 2.19.1'; exit 0; fi\n"
                "exit 0\n",
            )
            env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
            script = (
                f"source {str(TOOLCHAIN_DIR / 'cppcheck_toolchain.sh')!r}; "
                "got=$(lint_kit_cppcheck_version_raw); [[ $got == 2.19.1 ]]; "
                "lint_kit_cppcheck_version_ge 2.19.1; "
                "if lint_kit_cppcheck_version_ge 2.20.0; then exit 9; fi"
            )
            run_checked(["bash", "-c", script], env=env)

    def test_spec_traceability_wrapper_has_self_test_mode(self) -> None:
        result = run_checked(
            [sys.executable, str(POLICY_RUNNER), "--self-test", "--script", "spec_traceability.py"]
        )
        self.assertIn("spec-traceability-check self-test: OK", result.stdout)
        self.assertNotIn("yamllint self-test: OK", result.stdout)

    def test_custom_lints_only_runs_spec_traceability_before_exit(self) -> None:
        script = (COMMANDS_DIR / "lint.sh").read_text(encoding="utf-8")
        self.assertIn("spec_traceability_path", script)
        format_section = 'section format "Format C/C++, shell, and Python sources (clang-format, shfmt, shellcheck, codespell, ruff, mypy)"'
        assert_section_order(
            self,
            script,
            format_section,
            "lint_kit_format_toolchain_self_test",
            "shellcheck -S warning",
            'run bash "${toolchain}/codespell.sh"',
            'if ((custom_lints_only == 0)); then',
            'section compile_db "Generate compile databases (host configure → merge → OpenSSF audit)"',
            'section openssf "OpenSSF hardening (validate manifest + hardeninglint)"',
            'section clang_tidy "Run clang-tidy"',
            'section banned_cxx_heap "Enforce no C++ new/delete (including unsafe wrappers; complements clang-tidy/cppcheck)"',
            "((custom_lints_only == 1))",
            'section cppcheck "Run cppcheck (config/cppcheck-manifest.yaml)"',
            'section firmware_compile_db "Ensure firmware compile databases (compile_db.firmware)"',
            'ensure-firmware-compile-db',
            'section firmware_build "Build firmware (firmware_build.commands)"',
            'run-firmware-build',
        )
        self.assertLess(
            script.index('section spec_traceability "Verify spec traceability manifest"'),
            script.index("((custom_lints_only == 1))"),
        )
        self.assertNotIn('section "Run manifest build steps"', script)
        self.assertIn('section firmware_compile_db "Ensure firmware compile databases (compile_db.firmware)"', script)
        self.assertIn("ensure-firmware-compile-db", script)
        self.assertIn("run-firmware-build", script)
        self.assertLess(
            script.index("configure-compile-db"),
            script.index('ensure-firmware-compile-db'),
        )
        self.assertLess(
            script.index('ensure-firmware-compile-db'),
            script.index('run-firmware-build'),
        )

    def test_ci_lint_runs_hardening_manifest_and_linter(self) -> None:
        script = (COMMANDS_DIR / "lint.sh").read_text(encoding="utf-8")
        self.assertIn("manifest_validate.py", script)
        self.assertIn("workflow_container_policy.py", script)
        self.assertIn("verify --workflow", script)
        self.assertIn("policy/hardening_verify.py", script)
        self.assertIn("compile_db/compile_db_lint.py", script)
        self.assertIn("configure-compile-db", script)
        self.assertLess(
            script.index("configure-compile-db"),
            script.rindex("run_python_hardening_verify"),
        )
        self.assertIn("ensure-firmware-compile-db", script)
        self.assertNotIn('section "Run manifest build steps"', script)

    def test_compile_db_firmware_commands_read_manifest(self) -> None:
        from consumer_manifest import compile_db_firmware_build_commands

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: build/compile_commands.json\n"
                "      source: firmware\n"
                "      commands:\n"
                "        - make idf-build\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n",
            )
            self.assertEqual(compile_db_firmware_build_commands(root), ["make idf-build"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n",
            )
            self.assertEqual(compile_db_firmware_build_commands(root), [])

    def test_verify_required_compile_commands_fails_when_missing(self) -> None:
        import compile_db_util
        from scan_policy import bootstrap_scan_manifest

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: esp-idf/build/compile_commands.json\n"
                "      source: esp-idf\n"
                "      commands:\n"
                "        - make idf-build\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n",
            )
            self.assertEqual(compile_db_util.verify_required_compile_commands(root), 1)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap_scan_manifest(root, source_roots=("userspace",))
            (root / ".github" / "lint-c-cpp.yaml").write_text(
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [userspace]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: fw/build/compile_commands.json\n"
                "      source: firmware\n"
                "      commands:\n"
                "        - make idf-build\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n",
                encoding="utf-8",
            )
            write(
                root / "build/lint/userspace/compile_commands.json",
                "[]\n",
            )
            self.assertEqual(
                compile_db_util.verify_required_compile_commands(root, include_firmware=False),
                0,
            )

    def test_clang_tidy_config_enforces_google_naming_and_openssf_checks(self) -> None:
        c_text = (CONFIG_DIR / ".clang-tidy-c").read_text(encoding="utf-8")
        cxx_text = (CONFIG_DIR / ".clang-tidy-cxx").read_text(encoding="utf-8")
        shared_text = (CONFIG_DIR / ".clang-tidy-shared-c-cxx").read_text(encoding="utf-8")
        overlays_md = (CONFIG_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html", overlays_md)
        self.assertIn("google.github.io/styleguide/cppguide.html", overlays_md)
        self.assertIn("best.openssf.org/Compiler-Hardening-Guides", overlays_md)
        for text in (c_text, cxx_text, shared_text):
            self.assertIn("config/README.md", text)
            self.assertIn("misc-misleading-bidirectional", text)
            self.assertIn("readability-identifier-naming", text)
            self.assertRegex(text, r'(?m)^WarningsAsErrors:\s*[\'"]?\*[\'"]?\s*$')
            self.assertNotIn("-readability-magic-numbers,", text)
            self.assertNotIn("-cppcoreguidelines-avoid-magic-numbers,", text)
            self.assertIn("readability-magic-numbers.IgnoredIntegerValues", text)
            self.assertNotRegex(text, r"(?m)^\s*- key: readability-identifier-naming\.MacroDefinitionIgnoredRegexp")
        for check in (
            "cppcoreguidelines-pro-bounds-pointer-arithmetic",
            "cppcoreguidelines-pro-bounds-array-to-pointer-decay",
            "cppcoreguidelines-pro-bounds-constant-array-index",
            "modernize-redundant-void-arg",
            "modernize-deprecated-headers",
        ):
            self.assertIn(f"-{check},", c_text)
            self.assertIn(f"-{check},", shared_text)
            self.assertNotIn(f"-{check},", cxx_text)
        self.assertIn("FunctionCase\n    value: lower_case", c_text)
        self.assertIn("TypedefCase\n    value: lower_case", c_text)
        self.assertIn("TypedefSuffix\n    value: '_t'", c_text)
        self.assertIn("StructCase\n    value: lower_case", c_text)
        self.assertIn("UnionCase\n    value: lower_case", c_text)
        self.assertIn("EnumCase\n    value: lower_case", c_text)
        self.assertIn("EnumConstantCase\n    value: UPPER_CASE", c_text)
        self.assertIn("GlobalConstantCase\n    value: UPPER_CASE", c_text)
        self.assertIn("StaticConstantCase\n    value: UPPER_CASE", c_text)
        self.assertNotIn("GlobalConstantPrefix", c_text)
        self.assertNotIn("StaticConstantPrefix", c_text)
        self.assertNotIn("EnumIgnoredRegexp", c_text)
        self.assertNotIn("StructIgnoredRegexp", c_text)
        self.assertIn("LocalConstantCase\n    value: lower_case", c_text)
        self.assertNotIn("LocalConstantPrefix", c_text)
        self.assertNotIn("EnumConstantPrefix", c_text)
        self.assertNotIn("PublicMemberSuffix", c_text)
        self.assertIn("FunctionCase\n    value: CamelCase", cxx_text)
        self.assertIn("MethodCase\n    value: CamelCase", cxx_text)
        self.assertIn("EnumConstantPrefix\n    value: k", cxx_text)
        self.assertIn("GlobalConstantPrefix\n    value: k", cxx_text)
        self.assertIn("ProtectedMemberSuffix", cxx_text)
        self.assertIn("ScopedEnumConstantPrefix", cxx_text)
        self.assertIn("FunctionCase\n    value: CamelCase", shared_text)
        for text in (c_text, cxx_text, shared_text):
            self.assertIn("-bugprone-unsafe-functions,", text)
        unsafe_c = (CONFIG_DIR / ".clang-tidy-unsafe-c").read_text(encoding="utf-8")
        unsafe_cxx = (CONFIG_DIR / ".clang-tidy-unsafe-cxx").read_text(encoding="utf-8")
        for text in (unsafe_c, unsafe_cxx):
            self.assertIn("bugprone-unsafe-functions", text)
            self.assertIn("bugprone-unsafe-functions.CustomFunctions", text)
            self.assertIn("^malloc$", text)
            self.assertIn("cert-err33-c", text)
            self.assertIn("clang-analyzer-security.insecureAPI.UncheckedReturn", text)
            self.assertIn("clang-analyzer-security.insecureAPI.strcpy", text)
            self.assertIn("clang-analyzer-security.insecureAPI.vfork", text)
            self.assertIn(
                "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling",
                text,
            )
            self.assertNotIn("clang-analyzer-security.insecureAPI.*", text)
            checks_block = text.split("Checks:", 1)[1].split("\n\n", 1)[0]
            self.assertNotRegex(checks_block, r"(?m)^\s+-")
            self.assertRegex(text, r'(?m)^WarningsAsErrors:\s*[\'"]?\*[\'"]?\s*$')
            self.assertIn("ReportDefaultFunctions", text)
            self.assertIn("ReportMoreUnsafeFunctions", text)
            self.assertNotRegex(text, r"ReportMoreUnsafeFunctions\n\s+value: 'false'")
        self.assertIn("cppcoreguidelines-no-malloc", unsafe_cxx)
        self.assertIn("cppcoreguidelines-no-malloc.Allocations", unsafe_cxx)
        self.assertNotIn("cppcoreguidelines-no-malloc", unsafe_c)

    def test_compile_db_path_mapping_rebases_foreign_firmware_prefix(self) -> None:
        import compile_db_util
        from scan_policy import bootstrap_scan_manifest

        with tempfile.TemporaryDirectory() as tmp:
            container_root = Path(tmp) / "src"
            container_root.mkdir()
            bootstrap_scan_manifest(container_root, source_roots=("core", "port", "esp-idf"))
            # Must not use /src/ or /workspace/ prefixes (those are container remaps).
            host_prefix = "/opt/foreign-checkout/sample-firmware"
            raw_entry = {
                "directory": host_prefix,
                "command": (
                    f"{host_prefix}/third-party/toolchain/bin/riscv32-esp-elf-gcc "
                    f"-I{host_prefix}/third-party/esp-idf/components/driver/include "
                    f"-c {host_prefix}/port/port_sys_esp32.c"
                ),
                "file": f"{host_prefix}/port/port_sys_esp32.c",
            }
            self.assertEqual(
                compile_db_util.compile_file_repo_rel(raw_entry["file"], container_root),
                "port/port_sys_esp32.c",
            )
            self.assertEqual(
                compile_db_util.foreign_repo_prefix_for_file(raw_entry["file"], container_root),
                host_prefix,
            )
            normalized = compile_db_util.canonical_compile_entry(
                raw_entry,
                container_root,
                foreign_prefix=host_prefix,
            )
            self.assertIsNotNone(normalized)
            assert normalized is not None
            container_prefix = container_root.resolve().as_posix()
            self.assertEqual(normalized.pop("storage_key"), "port/port_sys_esp32.c")
            self.assertTrue(normalized["file"].startswith(container_prefix))
            self.assertNotIn(host_prefix, normalized["command"])
            self.assertIn(f"{container_prefix}/third-party/esp-idf", normalized["command"])

    def test_clang_tidy_batches_split_c_and_cxx_sources_by_overlay(self) -> None:
        from scan_policy import bootstrap_scan_manifest

        helper = load_helper("compile_db/compile_db_lint.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap_scan_manifest(root, source_roots=("core", "userspace"))
            write(root / "core/app.c", "void app(void) {}\n")
            write(root / "core/app.h", "#pragma once\nvoid app(void);\n")
            write(root / "userspace/tool.cpp", "void ToolMain() {}\n")
            write(root / "userspace/bypass.CXX", "void BypassMain() {}\n")
            merge_dir = root / "build" / "clang-tidy-compile-db"
            source_paths = central_job_paths(root, "source")
            unsafe_paths = central_job_paths(root, "unsafe_api")
            self.assertTrue(
                helper.merge_compile_commands(
                    root,
                    merge_dir / "compile_commands.json",
                    scan_paths=source_paths,
                )
            )
            sources = helper.filter_clang_tidy_sources(
                helper.MergedCompileDatabase.from_json(
                    merge_dir / "compile_commands.json",
                    root,
                ),
                scan_paths=source_paths,
            )
            overlays = [
                {"id": "c", "language": "c", "suffixes": [".c"], "config": ".clang-tidy-c"},
                {"id": "cxx", "language": "cxx", "suffixes": [".cpp", ".cc", ".cxx"], "config": ".clang-tidy-cxx"},
            ]
            c_files = {
                path.relative_to(root).as_posix()
                for path in helper._sources_for_overlay(sources, overlays[0])
            }
            cxx_files = {
                path.relative_to(root).as_posix()
                for path in helper._sources_for_overlay(sources, overlays[1])
            }
        self.assertEqual(c_files, {"core/app.c"})
        self.assertEqual(
            cxx_files,
            {"userspace/bypass.CXX", "userspace/tool.cpp"},
        )
        # Headers stay in compile-DB coverage, not clang-tidy argv.
        self.assertIn(
            "core/app.h",
            {
                path.relative_to(root).as_posix()
                for path in helper.clang_tidy_scan_targets(source_paths)
            },
        )

    def test_clang_tidy_batches_support_header_only_projects(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from scan_policy import bootstrap_scan_manifest

        helper = load_helper("compile_db/compile_db_lint.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap_scan_manifest(root, source_roots=("include",))
            write(root / "include/sample.h", "#pragma once\nint sample(void);\n")
            source_paths = central_job_paths(root, "source")
            unsafe_paths = central_job_paths(root, "unsafe_api")
            merge_dir = root / "build/clang-tidy-compile-db"
            self.assertTrue(
                helper.merge_compile_commands(
                    root,
                    merge_dir / "compile_commands.json",
                    scan_paths=source_paths,
                )
            )
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                result = helper.print_clang_tidy_batches(
                    root,
                    LINT_KIT,
                    source_paths=source_paths,
                    unsafe_api_paths=unsafe_paths,
                )
        self.assertEqual(result, 0, output.getvalue())
        self.assertIn("sample.h", output.getvalue())

    def test_hardening_cmake_roots_discovered_from_cmake_lists(self) -> None:
        from consumer_manifest import discover_hardening_cmake_roots

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(
                root / "userspace/CMakeLists.txt",
                'include("../cmake/Hardening.cmake")\n'
                "define_hardening(\n  TARGET hardening\n  C_STANDARD 23)\n"
                "target_link_libraries(app PRIVATE hardening)\n",
            )
            write(
                root / "esp-idf/main/CMakeLists.txt",
                "idf_component_register(SRCS app.c)\n"
                'include("../../cmake/Hardening.cmake")\n'
                "define_hardening(\n  TARGET hardening\n  C_STANDARD 17)\n"
                "target_link_libraries(${COMPONENT_LIB} PRIVATE hardening)\n",
            )
            roots = {item["file"]: item for item in discover_hardening_cmake_roots(root)}
        self.assertEqual(
            roots["userspace/CMakeLists.txt"]["c_standard"],
            "23",
        )
        self.assertEqual(
            roots["esp-idf/main/CMakeLists.txt"]["c_standard"],
            "17",
        )

    def test_hardeninglint_cmake_ok_lists_each_root_and_standard(self) -> None:
        helper = load_helper("policy/hardening_verify.py")
        config = {
            "cmake_roots": [
                {"file": "esp-idf/main/CMakeLists.txt", "c_standard": "17", "cxx_standard": ""},
                {"file": "userspace/CMakeLists.txt", "c_standard": "23", "cxx_standard": "23"},
            ]
        }
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            helper._print_hardeninglint_cmake_ok(config)
        self.assertEqual(
            buf.getvalue(),
            "hardeninglint (cmake): OK — 2 CMake project root(s)\n"
            "  role: OpenSSF flags in CMakeLists (define_hardening); not compile_db JSON inputs\n"
            "  esp-idf/main/CMakeLists.txt: C17\n"
            "  userspace/CMakeLists.txt: C23, CXX23\n",
        )

    def test_lint_kit_reads_manifest_compile_db_lists_and_overlays(self) -> None:
        from consumer_manifest import (
            clang_tidy_overlays,
            compile_db_firmware_build_commands,
            compile_db_projects,
            cppcheck_config,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core, port, tests, userspace, include, esp-idf]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: esp-idf/build/compile_commands.json\n"
                "      source: esp-idf\n"
                "      commands:\n"
                "        - make idf-build\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/tests/compile_commands.json\n"
                "      source: tests\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n",
            )
            write(root / "include/sample/limits.h", "#define SAMPLE_CAP 1u\n")
            write(root / "core/a.c", "int a;\n")

            projects = compile_db_projects(root)
            self.assertEqual([item["name"] for item in projects], ["tests", "userspace"])
            cfg = cppcheck_config(root, lint_kit=LINT_KIT)
            self.assertIn("core", cfg["include_dirs"])
            self.assertIn("include/sample", cfg["include_dirs"])
            self.assertEqual(cfg["compile_db_from"], ["tests", "userspace"])
            overlay_ids = [item["id"] for item in clang_tidy_overlays(root)]
            self.assertEqual(
                overlay_ids,
                ["c", "cxx"],
            )
            from consumer_manifest import clang_tidy_unsafe_overlays

            unsafe_overlay_ids = [item["id"] for item in clang_tidy_unsafe_overlays(root)]
            self.assertEqual(unsafe_overlay_ids, ["unsafe-c", "unsafe-cxx"])
            self.assertEqual(compile_db_firmware_build_commands(root), ["make idf-build"])

    def test_compile_db_userspace_list_reads_manifest_paths(self) -> None:
        from consumer_manifest import compile_db_projects

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [apps, custom-fw, tests, userspace]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: custom-fw/build/compile_commands.json\n"
                "      source: firmware\n"
                "      commands:\n"
                "        - make firmware-build\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/apps-demo/compile_commands.json\n"
                "      source: apps/demo\n"
                "    - compile_commands_json: build/lint/tests/compile_commands.json\n"
                "      source: tests\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n",
            )

            projects = compile_db_projects(root)
            self.assertEqual(
                [item["name"] for item in projects],
                ["apps-demo", "tests", "userspace"],
            )
            self.assertEqual(
                [item["source"] for item in projects],
                ["apps/demo", "tests", "userspace"],
            )

    def test_compile_db_without_manifest_block_has_no_required_paths(self) -> None:
        from consumer_manifest import compile_db_projects, compile_db_required_compile_command_paths

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [custom-fw, tests]\n",
            )

            self.assertEqual(compile_db_projects(root), [])
            self.assertEqual(compile_db_required_compile_command_paths(root), [])

    def test_compile_db_cmake_coverage_requires_manifest_entry_per_root(self) -> None:
        from consumer_manifest import compile_db_cmake_coverage_issues, verify_compile_db_cmake_coverage

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [tests, userspace]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: fw/build/compile_commands.json\n"
                "      source: firmware\n"
                "      commands:\n"
                "        - make idf-build\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n",
            )
            write(root / "tests/CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\nproject(t C)\n")
            write(root / "userspace/CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\nproject(u C)\n")
            issues = compile_db_cmake_coverage_issues(root)
            self.assertEqual(len(issues), 1)
            self.assertIn("tests", issues[0])
            self.assertEqual(verify_compile_db_cmake_coverage(root), 1)

    def test_compile_db_cmake_coverage_arduino_firmware_adoption_root(self) -> None:
        """firmware/ CMakeLists + out-of-tree build/lint/firmware compile DB (NFC shape)."""
        from consumer_manifest import compile_db_cmake_coverage_issues, verify_compile_db_cmake_coverage

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [firmware, tests, userspace]\n"
                "policy:\n  shared_c_cxx_source_roots: [firmware]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: build/lint/firmware/compile_commands.json\n"
                "      source: firmware\n"
                "      commands:\n"
                "        - make firmware-compile-db\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/tests/compile_commands.json\n"
                "      source: tests\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n",
            )
            write(
                root / "firmware/CMakeLists.txt",
                "cmake_minimum_required(VERSION 3.20)\n"
                "project(fw C CXX)\n"
                "include(../cmake/Hardening.cmake)\n"
                "define_hardening(TARGET hardening C_STANDARD 17 CXX_STANDARD 17)\n",
            )
            write(root / "tests/CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\nproject(t C)\n")
            write(root / "userspace/CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\nproject(u C)\n")
            self.assertEqual(compile_db_cmake_coverage_issues(root), [])
            self.assertEqual(verify_compile_db_cmake_coverage(root), 0)

    def test_manifest_validate_requires_firmware_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  exclude_gitignore: true\n"
                "  source_roots: [firmware]\n"
                "compile_db:\n  firmware:\n"
                "    - compile_commands_json: build/fw/compile_commands.json\n"
                "      commands: [make fw]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  constants_headers: [limits.h]\n"
                + _NULL_OVERRIDES_YAML.replace(
                    "  resource_lifetime: null\n", "  resource_lifetime: null\n  unsafe_api: null\n"
                ),
            )
            result = subprocess.run(
                [sys.executable, str(CORE_DIR / "manifest" / "manifest_validate.py"), "--repo-root", str(root)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("compile_db.firmware[0].source is required", result.stderr)

    def test_generate_hardening_flags_mk_language_order_and_libcpp(self) -> None:
        from hardening_verify import generate_hardening_flags_mk, load_hardening_manifest
        from policy_overrides import apply_openssf_coverage_flag_overrides

        kit = load_hardening_manifest(LINT_KIT)
        coverage_flags = list(kit["coverage"]["flags"])
        dialed = apply_openssf_coverage_flag_overrides(kit, add=None, remove=None)
        with tempfile.TemporaryDirectory() as tmp:
            license_root = Path(tmp)
            write_license_only_manifest(license_root)
            body = generate_hardening_flags_mk(dialed, repo_root=license_root)
        c_line = next(line for line in body.splitlines() if line.startswith("NERO_OPENSSF_CFLAGS"))
        cxx_line = next(line for line in body.splitlines() if line.startswith("NERO_OPENSSF_CXXFLAGS"))
        cpp_line = next(line for line in body.splitlines() if line.startswith("NERO_OPENSSF_CPPFLAGS"))
        c_flags = c_line.split(":=", 1)[1].strip().split()
        cxx_flags = cxx_line.split(":=", 1)[1].strip().split()
        self.assertIn("-Werror=implicit", c_flags)
        self.assertNotIn("-Werror=implicit", cxx_flags)
        self.assertLess(
            c_flags.index("-Wall") if "-Wall" in c_flags else 0,
            c_flags.index("-Wextra") if "-Wextra" in c_flags else 0,
        )
        ordered = [item for item in coverage_flags if item in c_flags]
        self.assertEqual(
            [item for item in c_flags if item in coverage_flags],
            ordered,
        )
        defs = cpp_line.split(":=", 1)[1].strip()
        # Flat Make must not emit mutually exclusive libc++ hardening modes together.
        self.assertNotIn("_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST", defs)
        self.assertNotIn("_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE", defs)
        self.assertNotIn("_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG", defs)

    def test_openssf_audit_honors_provenance_and_preferred_compile_db(self) -> None:
        from unittest.mock import patch

        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        sys.path.insert(0, str(HELPERS_DIR / "policy"))
        import compile_db_util
        from hardening_verify import verify_compile_commands_openssf
        from policy_overrides import openssf_override_dials_for_source

        arduino_db = "build/lint/firmware/arduino/compile_commands.json"
        nucleo_db = "build/lint/firmware/nucleo/compile_commands.json"
        werror = ("-Werror", "-Werror=format-security")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include/sample\n  source_roots: [firmware]\n"
                "compile_db:\n  firmware:\n"
                f"    - compile_commands_json: {arduino_db}\n      source: firmware\n"
                f"    - compile_commands_json: {nucleo_db}\n      source: firmware\n"
                "  userspace: []\n"
                "policy:\n  overrides:\n    openssf-hardening:\n"
                "      add: null\n      remove: null\n"
                "      by_compile_db:\n"
                f"        - compile_commands_json: {arduino_db}\n"
                "          add: null\n"
                "          remove:\n"
                + "".join(f"            - {flag}\n" for flag in werror)
                + f"        - compile_commands_json: {nucleo_db}\n"
                "          add: null\n          remove: null\n",
            )
            write(root / "firmware/shared.c", "void shared(void) {}\n")
            host_flags = (
                "-Wall -Wextra -Wformat -Wformat=2 -Wconversion -Wsign-conversion "
                "-Wimplicit-fallthrough -Werror -Werror=format-security "
                "-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing "
                "-fstack-protector-strong -Whardened -O2 -fexceptions"
            )
            for db in (arduino_db, nucleo_db):
                path = root / db
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(
                        [
                            {
                                "directory": str(root),
                                "command": f"arm-none-eabi-gcc {host_flags} -c {(root / 'firmware/shared.c').resolve()}",
                                "file": str((root / "firmware/shared.c").resolve()),
                            }
                        ]
                    ),
                    encoding="utf-8",
                )
            entry = {
                "directory": str(root),
                "command": f"arm-none-eabi-gcc {host_flags} -c {(root / 'firmware/shared.c').resolve()}",
                "file": str((root / "firmware/shared.c").resolve()),
                compile_db_util.PROVENANCE_KEY: [arduino_db, nucleo_db],
            }
            add, remove = openssf_override_dials_for_source(
                root,
                "firmware/shared.c",
                preferred_compile_db=arduino_db,
                provenance=[arduino_db, nucleo_db],
            )
            self.assertTrue(remove)
            self.assertIn("-Werror", remove)
            _add2, remove2 = openssf_override_dials_for_source(
                root,
                "firmware/shared.c",
                preferred_compile_db=nucleo_db,
                provenance=[arduino_db, nucleo_db],
            )
            self.assertIsNone(remove2)

            def mock_host_triple() -> str:
                return "x86_64-host"

            def mock_compiler_target(compiler: Path) -> str | None:
                return "arm-none-eabi" if "arm-none" in compiler.name else "x86_64-host"

            with patch.object(compile_db_util, "host_target_triple", mock_host_triple), patch.object(
                compile_db_util, "compiler_target_triple", side_effect=mock_compiler_target
            ):
                issues = verify_compile_commands_openssf(
                    root,
                    LINT_KIT,
                    entries_by_key={"firmware/shared.c": entry},
                    source_paths=[root / "firmware/shared.c"],
                )
            self.assertEqual(issues, [], issues)

    def test_spec_traceability_path_reads_manifest_field(self) -> None:
        from consumer_manifest import spec_traceability_path

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core]\n"
                "spec_traceability:\n  manifest: docs/spec-traceability.yaml\n",
            )
            write(root / "docs/spec-traceability.yaml", "constants: []\n")
            path = spec_traceability_path(root)
            self.assertEqual(path, root / "docs/spec-traceability.yaml")


class PolicyLinterSimulations(unittest.TestCase):
    def test_bounds_constants_flags_placement_stack_and_format_macro_gaps(self) -> None:
        helper = load_helper("policy/magic_literals.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(
                root / "userspace/bad.cpp",
                "void f(void) {\n"
                "  for (int depth = 0; depth < 8; ++depth) {}\n"
                "  if (x <= 225) { (void)x; }\n"
                "}\n",
            )
            write(
                root / "userspace/good.cpp",
                "static constexpr int kProbeDepthMax = 8;\n"
                "void f(void) {\n"
                "  for (int depth = 0; depth < kProbeDepthMax; ++depth) {}\n"
                "}\n",
            )
            write(root / "userspace/bad_hex.cpp", "void f(void) { unsigned x = 0x22u; (void)x; }\n")
            write(
                root / "userspace/good_const.cpp",
                "static constexpr unsigned kValue = 0x22u;\nvoid f(void) { (void)kValue; }\n",
            )
            write(root / "userspace/solo.h", "#define SOLO_ONLY 99u\n")
            write(
                root / "userspace/solo.cpp",
                '#include "solo.h"\nvoid f(void) { (void)SOLO_ONLY; }\n',
            )
            write(
                root / "include/sample/bad_printf.h",
                "SAMPLE_PRINTF(4, 5)\nbool sample_appendf(char *buf, size_t cap, size_t *off, const char *fmt, ...);\n",
            )
            errors = policy_lint("magic_literals.py", root, "source")
            reported = reported_basenames(errors)
        self.assertNotIn("bad.cpp", reported)
        self.assertNotIn("bad_hex.cpp", reported)
        self.assertNotIn("good.cpp", reported)
        self.assertNotIn("good_const.cpp", reported)
        self.assertIn("bad_printf.h", reported)
        self.assertTrue(any("SOLO_ONLY" in error and "move to that .c/.cpp" in error for error in errors), errors)

    def test_cross_compile_detection_uses_dumpmachine_not_vendor_regex(self) -> None:
        from unittest.mock import patch

        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_util

        compile_db_util.clear_cross_target_cache()
        with tempfile.TemporaryDirectory() as tmp:
            host_cc = Path(tmp) / "cc"
            cross_cc = Path(tmp) / "vendor-gcc"
            host_cc.write_text("#!/bin/sh\n", encoding="utf-8")
            cross_cc.write_text("#!/bin/sh\n", encoding="utf-8")
            host_cc.chmod(0o755)
            cross_cc.chmod(0o755)
            host_cmd = f"{host_cc} -std=c11 -c core/app.c"
            cross_cmd = f"{cross_cc} -c port/board.c"

            def mock_compiler_target(compiler: Path) -> str:
                resolved = compiler.resolve()
                if resolved == host_cc.resolve():
                    return "x86_64-host"
                return "brand-new-triple"

            with patch.object(compile_db_util, "host_target_triple", return_value="x86_64-host"), patch.object(
                compile_db_util,
                "compiler_target_triple",
                side_effect=mock_compiler_target,
            ):
                self.assertFalse(compile_db_util.is_cross_compile_command(host_cmd))
                self.assertTrue(compile_db_util.is_cross_compile_command(cross_cmd))
                self.assertEqual(
                    compile_db_util._normalize_target_triple("x86_64-redhat-linux-gnu"),
                    compile_db_util._normalize_target_triple("x86_64-redhat-linux"),
                )
                self.assertEqual(
                    compile_db_util.clang_target_for_command(
                        "clang --target=arm-none-eabi -c x.c"
                    ),
                    "arm-none-eabi",
                )

    def test_compile_db_expands_at_response_and_iprefix_includes(self) -> None:
        """Arduino-style @includes.txt + -iprefix must become plain -I for clang-tidy."""
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            platform = root / "platform"
            variant_inc = platform / "variants" / "BOARD" / "includes" / "ra" / "fsp" / "inc" / "api"
            variant_inc.mkdir(parents=True)
            (variant_inc / "bsp_api.h").write_text("/* bsp */\n", encoding="utf-8")
            includes_txt = platform / "variants" / "BOARD" / "includes.txt"
            includes_txt.write_text(
                "-iwithprefixbefore/variants/BOARD/includes/ra/fsp/inc/api\n",
                encoding="utf-8",
            )
            defines_txt = platform / "variants" / "BOARD" / "defines.txt"
            defines_txt.write_text("-D_BOARD_VARIANT=1\n", encoding="utf-8")
            command = (
                f"arm-none-eabi-gcc @{defines_txt} -I{root}/cores "
                f"-iprefix{platform} @{includes_txt} -c {root}/sketch.cpp"
            )
            flags = compile_db_lint._extract_compile_flags(command)
            expected_i = f"-I{platform}/variants/BOARD/includes/ra/fsp/inc/api"
            self.assertIn(expected_i, flags, flags)
            self.assertIn("-D_BOARD_VARIANT=1", flags, flags)
            self.assertTrue(
                any(f.startswith("-I") and f.endswith("/cores") for f in flags),
                flags,
            )

    def test_scrub_preserves_define_values_ending_in_cpp(self) -> None:
        """-DNFC_BOARD_FOO=bar.cpp must not be dropped as a source-file arg."""
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "firmware" / "nfc_hal.cpp"
            src.parent.mkdir(parents=True)
            src.write_text("void x() {}\n", encoding="utf-8")
            command = (
                f"arm-none-eabi-g++ -DNFC_BOARD_NFC_HAL_INC=nfc_hal_board.cpp "
                f"-c {src}"
            )
            with patch.object(
                compile_db_lint, "clang_target_for_command", return_value="arm-none-eabi"
            ), patch.object(
                compile_db_lint, "is_cross_compile_command", return_value=True
            ), patch.object(
                compile_db_lint,
                "compile_driver_path",
                return_value=Path("/usr/bin/arm-none-eabi-g++"),
            ), patch.object(
                compile_db_lint, "_cross_toolchain_include_paths", return_value=[]
            ), patch.object(
                compile_db_lint,
                "_compiler_isystem_flags",
                return_value=["-isystem", "/opt/arm/include"],
            ), patch.object(
                compile_db_lint,
                "_cross_sysroot",
                return_value=Path("/opt/arm/sysroot"),
            ):
                scrubbed = compile_db_lint._scrub_cross_compile_command(
                    command, source_file=str(src)
                )
            self.assertIn("-DNFC_BOARD_NFC_HAL_INC=nfc_hal_board.cpp", scrubbed)
            self.assertIn("--target=arm-none-eabi", scrubbed)
            self.assertIn("--sysroot=/opt/arm/sysroot", scrubbed)
            self.assertIn("-isystem /opt/arm/include", scrubbed)
            self.assertEqual(scrubbed.count("--target=arm-none-eabi"), 1)

    def test_scrub_preserves_gnu_std_and_specs_isystem_query(self) -> None:
        """Cross scrub must keep compile-DB ``-std=gnu*`` and query isystem with ``-specs=``."""
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "esp-idf" / "main" / "app_main.c"
            src.parent.mkdir(parents=True)
            src.write_text("void app_main(void) {}\n", encoding="utf-8")
            specs = root / "build" / "specs" / "picolibc.specs"
            specs.parent.mkdir(parents=True)
            specs.write_text("*cpp:\n", encoding="utf-8")
            cflags = root / "build" / "toolchain" / "cflags"
            cflags.parent.mkdir(parents=True)
            cflags.write_text(
                f"-march=rv32imac\n\"-specs={specs}\"\n",
                encoding="utf-8",
            )
            command = (
                f"/opt/riscv/bin/riscv32-esp-elf-gcc @{cflags} -std=gnu23 "
                f"-c {src}"
            )
            captured: dict[str, object] = {}

            def _fake_isystem(compiler, *, language, extra_flags=None):
                captured["extra_flags"] = list(extra_flags or ())
                return ["-isystem", "/opt/riscv/picolibc/include"]

            with patch.object(
                compile_db_lint, "clang_target_for_command", return_value="riscv32-esp-elf"
            ), patch.object(
                compile_db_lint, "is_cross_compile_command", return_value=True
            ), patch.object(
                compile_db_lint,
                "compile_driver_path",
                return_value=Path("/opt/riscv/bin/riscv32-esp-elf-gcc"),
            ), patch.object(
                compile_db_lint, "_cross_toolchain_include_paths", return_value=[]
            ), patch.object(
                compile_db_lint, "_compiler_isystem_flags", side_effect=_fake_isystem
            ), patch.object(
                compile_db_lint,
                "_cross_sysroot",
                return_value=Path("/opt/riscv/sysroot"),
            ):
                scrubbed = compile_db_lint._scrub_cross_compile_command(
                    command, source_file=str(src)
                )
            self.assertIn("-std=gnu23", scrubbed)
            self.assertNotIn("-std=c11", scrubbed)
            self.assertEqual(
                captured.get("extra_flags"),
                ["-march=rv32imac", f"-specs={specs}"],
            )
            self.assertIn("-isystem /opt/riscv/picolibc/include", scrubbed)
            self.assertNotIn("-specs=", scrubbed)

    def test_expand_at_response_repairs_foreign_specs_path(self) -> None:
        """Bind-mounted ``@cflags`` must rewrite host ``-specs=`` onto the real tree."""
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            specs = root / "esp-idf" / "build" / "specs" / "picolibc.specs"
            specs.parent.mkdir(parents=True)
            specs.write_text("*cpp:\n", encoding="utf-8")
            cflags = root / "esp-idf" / "build" / "toolchain" / "cflags"
            cflags.parent.mkdir(parents=True)
            foreign = (
                "/opt/foreign-checkout/sample-firmware/"
                "esp-idf/build/specs/picolibc.specs"
            )
            cflags.write_text(
                f"-march=rv32imac\n\"-specs={foreign}\"\n",
                encoding="utf-8",
            )
            expanded = compile_db_lint._expand_at_response_tokens([f"@{cflags}"])
            self.assertIn("-march=rv32imac", expanded)
            self.assertIn(f"-specs={specs}", expanded)
            self.assertNotIn(foreign, " ".join(expanded))

    def test_scrub_picolibc_fallback_when_specs_isystem_query_fails(self) -> None:
        """Unusable ``-specs=`` must still yield picolibc-first ``-isystem`` order."""
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "core" / "nero_lifi_io.c"
            src.parent.mkdir(parents=True)
            src.write_text("void f(void) {}\n", encoding="utf-8")
            command = (
                "/opt/riscv/bin/riscv32-esp-elf-gcc -march=rv32imac "
                "-specs=/missing/host/picolibc.specs -std=gnu23 "
                f"-c {src}"
            )
            calls: list[list[str]] = []

            def _fake_isystem(compiler, *, language, extra_flags=None):
                flags = list(extra_flags or ())
                calls.append(flags)
                if any(flag.startswith("-specs=") for flag in flags):
                    return []
                return ["-isystem", "/opt/riscv/newlib/include"]

            with patch.object(
                compile_db_lint, "clang_target_for_command", return_value="riscv32-esp-elf"
            ), patch.object(
                compile_db_lint, "is_cross_compile_command", return_value=True
            ), patch.object(
                compile_db_lint,
                "compile_driver_path",
                return_value=Path("/opt/riscv/bin/riscv32-esp-elf-gcc"),
            ), patch.object(
                compile_db_lint,
                "_cross_toolchain_include_paths",
                return_value=[Path("/opt/riscv/picolibc/include")],
            ), patch.object(
                compile_db_lint, "_compiler_isystem_flags", side_effect=_fake_isystem
            ), patch.object(
                compile_db_lint,
                "_cross_sysroot",
                return_value=Path("/opt/riscv/sysroot"),
            ):
                scrubbed = compile_db_lint._scrub_cross_compile_command(
                    command, source_file=str(src)
                )
            self.assertGreaterEqual(len(calls), 2)
            self.assertIn("-isystem /opt/riscv/picolibc/include", scrubbed)
            self.assertIn("-isystem /opt/riscv/newlib/include", scrubbed)
            self.assertLess(
                scrubbed.index("-isystem /opt/riscv/picolibc/include"),
                scrubbed.index("-isystem /opt/riscv/newlib/include"),
            )
            self.assertNotIn("-specs=", scrubbed)

    def test_scrub_cxx_appends_libc_isystem_after_libstdcxx(self) -> None:
        """Arduino-style C++ scrub must not put libc ahead of libstdc++ (include_next)."""
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "firmware" / "nfc" / "src" / "reader_ccid_impl.cpp"
            src.parent.mkdir(parents=True)
            src.write_text("void x() {}\n", encoding="utf-8")
            command = f"arm-none-eabi-g++ -std=gnu++17 -c {src}"
            with patch.object(
                compile_db_lint, "clang_target_for_command", return_value="arm-none-eabi"
            ), patch.object(
                compile_db_lint, "is_cross_compile_command", return_value=True
            ), patch.object(
                compile_db_lint,
                "compile_driver_path",
                return_value=Path("/usr/bin/arm-none-eabi-g++"),
            ), patch.object(
                compile_db_lint,
                "_cross_toolchain_include_paths",
                # Distinct spelling of libc include (Arduino scrub used to prepend this).
                return_value=[Path("/opt/arm-none-eabi/include")],
            ), patch.object(
                compile_db_lint,
                "_compiler_isystem_flags",
                return_value=[
                    "-isystem",
                    "/opt/arm/include/c++/7.2.1",
                    "-isystem",
                    "/opt/arm/arm-none-eabi/include",
                ],
            ), patch.object(
                compile_db_lint,
                "_cross_sysroot",
                return_value=Path("/opt/arm/sysroot"),
            ):
                scrubbed = compile_db_lint._scrub_cross_compile_command(
                    command, source_file=str(src)
                )
            cxx = scrubbed.index("-isystem /opt/arm/include/c++/7.2.1")
            libc_gcc = scrubbed.index("-isystem /opt/arm/arm-none-eabi/include")
            libc_extra = scrubbed.index("-isystem /opt/arm-none-eabi/include")
            self.assertLess(cxx, libc_gcc)
            self.assertLess(cxx, libc_extra)
            self.assertLess(libc_gcc, libc_extra)

    def test_firmware_template_preferred_over_same_dir_host(self) -> None:
        """Host unit-test entries in firmware/ must not beat a cross template for synthesis."""
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint
        import compile_db_util
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_entry = {
                "directory": str(root),
                "command": f"g++ -std=c++17 -c {root}/firmware/src/foo.cpp",
                "file": str(root / "firmware/src/foo.cpp"),
            }
            cross_entry = {
                "directory": str(root),
                "command": (
                    f"arm-none-eabi-g++ -DNFC_FRONTEND_ID=1 -I{root}/cores/arduino "
                    f"-c {root}/firmware/sketch.cpp"
                ),
                "file": str(root / "firmware/sketch.cpp"),
            }
            by_file = {
                "firmware/src/foo.cpp": host_entry,
                "firmware/sketch.cpp": cross_entry,
            }
            target = root / "firmware/src/bar.cpp"
            target.parent.mkdir(parents=True)
            target.write_text("void bar(void) {}\n", encoding="utf-8")

            def _is_cross(cmd: str) -> bool:
                return "arm-none-eabi" in cmd

            with patch.object(
                compile_db_lint,
                "_target_prefers_firmware_template",
                return_value=True,
            ), patch.object(compile_db_lint, "is_cross_compile_command", side_effect=_is_cross), patch.object(
                compile_db_util, "is_cross_compile_command", side_effect=_is_cross
            ):
                tmpl = compile_db_lint._template_for_target(
                    by_file,
                    target,
                    root,
                    host_templates=(host_entry,),
                    cross_templates=(cross_entry,),
                )
                self.assertIs(tmpl, cross_entry)
                # Same path already has a host row — still must pick cross for tidy rewrite.
                tmpl_existing = compile_db_lint._template_for_target(
                    by_file,
                    root / "firmware/src/foo.cpp",
                    root,
                    host_templates=(host_entry,),
                    cross_templates=(cross_entry,),
                )
                self.assertIs(tmpl_existing, cross_entry)

    def test_header_role_defaults_posix_uapi_model(self) -> None:
        """``.h`` is c_compatible (C surface); ``.hpp`` is cxx_only."""
        from consumer_manifest import (
            clang_tidy_header_filter_regex,
            header_role_for_path,
        )
        from scan_policy import bootstrap_scan_manifest

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap_scan_manifest(root, source_roots=("include", "userspace"))
            write(root / "include/sample/api.h", "#pragma once\n")
            write(root / "userspace/widget.hpp", "#pragma once\n")
            self.assertEqual(header_role_for_path(root / "include/sample/api.h", root), "c_compatible")
            self.assertEqual(header_role_for_path(root / "userspace/widget.hpp", root), "cxx_only")
            c_rx = re.compile(clang_tidy_header_filter_regex(root, role="c_compatible"))
            cxx_rx = re.compile(clang_tidy_header_filter_regex(root, role="cxx_only"))
            api = str((root / "include/sample/api.h").resolve())
            widget = str((root / "userspace/widget.hpp").resolve())
            self.assertTrue(c_rx.search(api))
            self.assertFalse(c_rx.search(widget))
            self.assertTrue(cxx_rx.search(widget))
            self.assertFalse(cxx_rx.search(api))

    def test_header_role_fail_closed_requires_hpp_rename(self) -> None:
        """C++ surface in .h fails closed; rename to .hpp (no path overrides)."""
        from consumer_manifest import (
            cxx_in_c_compatible_header_violations,
            header_role_for_path,
        )
        from scan_policy import bootstrap_scan_manifest

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap_scan_manifest(root, source_roots=("include", "userspace"))
            write(root / "include/sample/api.h", "#pragma once\nvoid api(void);\n")
            write(
                root / "userspace/app/widget.h",
                "#pragma once\nnamespace sample { class Widget {}; }\n",
            )
            write(
                root / "userspace/orphan.h",
                "#pragma once\nnamespace leak { void f(); }\n",
            )
            self.assertEqual(
                header_role_for_path(root / "userspace/app/widget.h", root), "c_compatible"
            )
            scan = [
                root / "include/sample/api.h",
                root / "userspace/app/widget.h",
                root / "userspace/orphan.h",
            ]
            violations = cxx_in_c_compatible_header_violations(scan, root)
            self.assertEqual(len(violations), 2, violations)
            hit = " ".join(violations)
            self.assertIn("userspace/app/widget.h", hit)
            self.assertIn("userspace/orphan.h", hit)
            self.assertIn("rename to .hpp", hit)

    def test_cxx_in_c_compatible_detects_common_cpp_surface(self) -> None:
        """Fail-closed patterns beyond namespace/class (C++ headers, using, casts, auto)."""
        from consumer_manifest import cxx_in_c_compatible_header_violations
        from scan_policy import bootstrap_scan_manifest

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap_scan_manifest(root, source_roots=("include",))
            cases = {
                "include/c_header.h": "#pragma once\n#include <cstdint>\n",
                "include/using_alias.h": "#pragma once\nusing cb_t = void (*)(void);\n",
                "include/enum_base.h": "#pragma once\nenum kind_t : int { KIND_A = 0 };\n",
                "include/static_cast.h": "#pragma once\nstatic inline void* f(int* p) { return static_cast<void*>(p); }\n",
                "include/const_auto.h": "#pragma once\nstatic inline int f(void) { const auto x = 1; return x; }\n",
                "include/plain_c.h": "#pragma once\n#include <stdint.h>\nvoid f(uint8_t x);\n",
            }
            for rel, body in cases.items():
                write(root / rel, body)
            scan = [root / rel for rel in cases]
            violations = cxx_in_c_compatible_header_violations(scan, root)
            hit = " ".join(violations)
            for rel in (
                "include/c_header.h",
                "include/using_alias.h",
                "include/enum_base.h",
                "include/static_cast.h",
                "include/const_auto.h",
            ):
                self.assertTrue(any(rel in v for v in violations), f"missing {rel}: {violations}")
            self.assertFalse(any("include/plain_c.h" in v for v in violations), hit)

    def test_synthesize_compile_entry_respects_header_role(self) -> None:
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import compile_db_lint

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n  source_roots: [include, userspace]\n",
            )
            c_hdr = root / "include/api.h"
            cxx_hdr = root / "userspace/widget.hpp"
            write(c_hdr, "#pragma once\n")
            write(cxx_hdr, "#pragma once\n")
            c_entry = compile_db_lint._synthesize_compile_entry(root, c_hdr, None, [])
            cxx_entry = compile_db_lint._synthesize_compile_entry(root, cxx_hdr, None, [])
            self.assertIn("-x c-header", c_entry["command"])
            self.assertIn("-x c++-header", cxx_entry["command"])
            self.assertTrue(c_entry["command"].startswith("clang "))
            self.assertTrue(cxx_entry["command"].startswith("clang++ "))

    def test_firmware_compile_source_roots_unifies_nfc_and_lifi(self) -> None:
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        from consumer_manifest import firmware_compile_source_roots
        from compile_db_util import storage_key_prefers_firmware_compile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n"
                "  source_roots: [firmware, esp-idf, userspace, tests]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: build/lint/firmware/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make firmware-compile-db]\n"
                "    - compile_commands_json: esp-idf/build/compile_commands.json\n"
                "      source: esp-idf\n"
                "      commands: [make idf-build]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  shared_c_cxx_source_roots: [firmware, tests/firmware]\n",
            )
            roots = firmware_compile_source_roots(root)
            self.assertIn("firmware", roots)
            self.assertIn("esp-idf", roots)
            self.assertNotIn("tests/firmware", roots)
            self.assertTrue(storage_key_prefers_firmware_compile("firmware/src/x.c", root))
            self.assertTrue(
                storage_key_prefers_firmware_compile("esp-idf/main/app_main.c", root)
            )
            self.assertFalse(
                storage_key_prefers_firmware_compile("userspace/app.cpp", root)
            )
            self.assertFalse(
                storage_key_prefers_firmware_compile("tests/firmware/test_x.cpp", root)
            )

    def test_firmware_compile_source_roots_decoupled_from_shared_c_cxx(self) -> None:
        """Cross-template roots come from firmware source even when shared_c_cxx is null."""
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        from consumer_manifest import firmware_compile_source_roots, shared_c_cxx_source_roots
        from compile_db_util import storage_key_prefers_firmware_compile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n"
                "  source_roots: [firmware, userspace, tests]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: build/lint/firmware/uno/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make uno-db]\n"
                "    - compile_commands_json: build/lint/firmware/wba/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make wba-db]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  shared_c_cxx_source_roots: null\n",
            )
            self.assertEqual(shared_c_cxx_source_roots(root), ())
            self.assertEqual(firmware_compile_source_roots(root), ("firmware",))
            self.assertTrue(storage_key_prefers_firmware_compile("firmware/src/x.c", root))

    def test_shared_c_cxx_overlay_partitions_host_and_interop_cpp(self) -> None:
        from consumer_manifest import clang_tidy_overlays

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n  source_roots: [firmware, userspace]\n"
                "policy:\n  shared_c_cxx_source_roots: [firmware]\n",
            )
            write(root / "firmware/a.cpp", "void a() {}\n")
            write(root / "userspace/b.cpp", "void b() {}\n")
            by_id = {item["id"]: item for item in clang_tidy_overlays(root)}
            self.assertEqual(set(by_id), {"c", "cxx", "shared-c-cxx"})
            self.assertEqual(by_id["c"]["config"], ".clang-tidy-c")
            self.assertNotIn("exclude_paths", by_id["c"])
            self.assertEqual(by_id["cxx"]["exclude_paths"], ["firmware"])
            self.assertEqual(by_id["shared-c-cxx"]["paths"], ["firmware"])
            self.assertEqual(by_id["shared-c-cxx"]["config"], ".clang-tidy-shared-c-cxx")
            self.assertNotIn("disabled_checks", by_id["shared-c-cxx"])
            self.assertNotIn("base_config", by_id["shared-c-cxx"])

    def test_openssf_compile_db_audit_covers_firmware_and_host_entries(self) -> None:
        from unittest.mock import patch

        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        _policy = HELPERS_DIR / "policy"
        if str(_policy) not in sys.path:
            sys.path.insert(0, str(_policy))
        import compile_db_util
        from hardening_verify import compile_db_openssf_audit_scope, verify_compile_commands_openssf

        kit = LINT_KIT
        manifest_path = kit / "config/openssf-hardening-manifest.yaml"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
                "  source_roots: [core, esp-idf]\n"
                "compile_db:\n"
                "  firmware:\n"
                "    - compile_commands_json: esp-idf/build/compile_commands.json\n"
                "      source: esp-idf\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/tests/compile_commands.json\n"
                "      source: tests\n",
            )
            (root / "core").mkdir()
            (root / "esp-idf/main").mkdir(parents=True)
            (root / "core/app.c").write_text("void app(void) {}\n", encoding="utf-8")
            (root / "esp-idf/main/app_main.c").write_text("void app_main(void) {}\n", encoding="utf-8")
            host_cache = root / "build/lint/tests/CMakeCache.txt"
            host_cache.parent.mkdir(parents=True)
            # Empty / unconfigured probe set: probe-gated flags are not silently required.
            host_cache.write_text("# no HAVE_* probes yet\n", encoding="utf-8")
            cross_cache = root / "esp-idf/build/CMakeCache.txt"
            cross_cache.parent.mkdir(parents=True)
            cross_cache.write_text("# no HAVE_* probes yet\n", encoding="utf-8")
            host_flags = (
                "-Wall -Wextra -Wformat -Wformat=2 -Wconversion -Wsign-conversion "
                "-Wimplicit-fallthrough -Werror -Werror=format-security "
                "-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing "
                "-fstack-protector-strong -fhardened -fcf-protection=full -O2 -fexceptions"
            )
            cross_flags = host_flags.replace("-fhardened", "-Whardened")
            esp_db = root / "esp-idf/build/compile_commands.json"
            esp_db.write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "command": (
                                f"/opt/riscv32-esp-elf-gcc {cross_flags} -c "
                                f"{root / 'esp-idf/main/app_main.c'}"
                            ),
                            "file": str((root / "esp-idf/main/app_main.c").resolve()),
                        }
                    ]
                ),
                encoding="utf-8",
            )
            entries = {
                "core/app.c": {
                    "directory": str(root),
                    "command": f"/usr/bin/cc {host_flags} -c {root / 'core/app.c'}",
                    "file": str((root / "core/app.c").resolve()),
                },
                "esp-idf/main/app_main.c": {
                    "directory": str(root),
                    "command": (
                        f"/opt/riscv32-esp-elf-gcc {cross_flags} -c "
                        f"{root / 'esp-idf/main/app_main.c'}"
                    ),
                    "file": str((root / "esp-idf/main/app_main.c").resolve()),
                },
            }
            sources = [
                root / "core/app.c",
                root / "esp-idf/main/app_main.c",
            ]

            def mock_host_triple() -> str:
                return "x86_64-host"

            def mock_compiler_target(compiler: Path) -> str | None:
                name = compiler.name
                if "riscv" in name or "esp" in name:
                    return "riscv32-esp-elf"
                return "x86_64-host"

            with patch.object(compile_db_util, "host_target_triple", mock_host_triple), patch.object(
                compile_db_util, "compiler_target_triple", side_effect=mock_compiler_target
            ):
                scope = compile_db_openssf_audit_scope(
                    root,
                    kit,
                    source_paths=sources,
                    entries_by_key=entries,
                )
                self.assertEqual(scope.audited_cc_files, 2)
                self.assertEqual(scope.host_native_files, 1)
                self.assertEqual(scope.cross_compile_files, 1)
                issues = verify_compile_commands_openssf(
                    root,
                    kit,
                    entries_by_key=entries,
                    source_paths=sources,
                )
            self.assertEqual(issues, [], issues)

    def test_clang_tidy_file_filter_handles_repo_and_container_paths(self) -> None:
        from scan_policy import bootstrap_scan_manifest

        helper = load_helper("compile_db/compile_db_lint.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap_scan_manifest(
                root,
                source_roots=("core", "port", "include", "esp-idf", "userspace", "tests"),
            )
            (root / "core").mkdir(parents=True)
            (root / "port").mkdir(parents=True)
            (root / "include" / "sample").mkdir(parents=True)
            (root / "userspace").mkdir(parents=True)
            (root / "tests" / "core").mkdir(parents=True)
            write(root / "core/reader_tags.cpp", "void reader_tags(void) {}\n")
            write(root / "port/board.c", "void board(void) {}\n")
            write(root / "include/sample/api.h", "#pragma once\n")
            write(root / "userspace/x.cpp", "void x(void) {}\n")
            write(root / "tests/core/test_x.cpp", "void test_x(void) {}\n")
            merge_dir = root / "build" / "clang-tidy-compile-db"
            source_paths = central_job_paths(root, "source")
            unsafe_paths = central_job_paths(root, "unsafe_api")
            self.assertTrue(
                helper.merge_compile_commands(
                    root,
                    merge_dir / "compile_commands.json",
                    scan_paths=source_paths,
                )
            )
            merged_db = helper.MergedCompileDatabase.from_json(
                merge_dir / "compile_commands.json",
                root,
            )
            all_sources = {
                path.relative_to(root).as_posix()
                for path in helper.filter_clang_tidy_sources(
                    merged_db,
                    scan_paths=source_paths,
                )
            }
            unsafe_sources = {
                path.relative_to(root).as_posix()
                for path in helper.filter_clang_tidy_sources(
                    merged_db,
                    scan_paths=unsafe_paths,
                )
            }
        self.assertEqual(
            all_sources,
            {
                "core/reader_tags.cpp",
                "port/board.c",
                "tests/core/test_x.cpp",
                "userspace/x.cpp",
            },
        )
        self.assertIn(
            "include/sample/api.h",
            {
                path.relative_to(root).as_posix()
                for path in helper.clang_tidy_scan_targets(source_paths)
            },
        )

    def test_clang_tidy_scan_targets_match_unsafe_api_job(self) -> None:
        from scan_policy import JOB_UNSAFE_API

        helper = load_helper("compile_db/compile_db_lint.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/a.c", "void a(void) {}\n")
            write(root / "port/b.c", "void b(void) {}\n")
            write(root / "include/sample/c.h", "#pragma once\n")
            write(root / "include/sample/mem_util.h", "#pragma once\nstatic inline void w(void *p){(void)p;}\n")
            unsafe_paths = central_job_paths(root, JOB_UNSAFE_API)
            targets = {path.relative_to(root).as_posix() for path in helper.clang_tidy_scan_targets(unsafe_paths)}
            enforced = {path.relative_to(root).as_posix() for path in unsafe_paths}
        self.assertEqual(targets, enforced)
        self.assertIn("include/sample/mem_util.h", targets)

    def test_unsafe_scan_keeps_wrappers_for_nonwaivable_checks(self) -> None:
        from scan_policy import JOB_SOURCE, JOB_UNSAFE_API

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/app.c", "void app(void) {}\n")
            write(root / "include/sample/mem_util.h", "#pragma once\nvoid w(void);\n")
            full = {p.relative_to(root).as_posix() for p in central_job_paths(root, JOB_SOURCE)}
            strict = {p.relative_to(root).as_posix() for p in central_job_paths(root, JOB_UNSAFE_API)}
        self.assertIn("include/sample/mem_util.h", full)
        self.assertIn("include/sample/mem_util.h", strict)
        self.assertIn("core/app.c", strict)

    def test_duplicate_definitions_flags_header_exposed_shadow_constant(self) -> None:
        helper = load_helper("policy/shared_constant_dupes.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "include/sample/canonical.h", "enum { SAMPLE_FOO = 0xA4u };\n")
            write(root / "userspace/shadow.cpp", "#define SAMPLE_FOO 0xA4u\n")
            write(root / "userspace/local_a.cpp", "#define SAMPLE_LOCAL 5u\n")
            write(root / "userspace/local_b.cpp", "#define SAMPLE_LOCAL 5u\n")
            errors = policy_lint("shared_constant_dupes.py", root, "source")
        self.assertTrue(any("SAMPLE_FOO" in error for error in errors), errors)
        self.assertTrue(any("SAMPLE_LOCAL" in error for error in errors), errors)

    def test_duplicate_includes_catches_mixed_angle_and_quote_duplicates(self) -> None:
        helper = load_helper("policy/duplicate_includes.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/bad.c", '#include <foo.h>\n#include "foo.h"\n')
            write(root / "core/good.c", 'const char *s = "#include \\"foo.h\\"";\n#include "foo.h"\n')
            write(root / "core/exact_dup.c", '#include "foo.h"\n#include "foo.h"\n')
            write(root / "core/good.h", "// license\n\n#pragma once\n#include \"foo.h\"\n")
            write(root / "core/missing_pragma.h", "#include \"foo.h\"\n")
            reported = reported_basenames(policy_lint("duplicate_includes.py", root, "source"))
        assert_simulation_reported(
            self,
            reported,
            violations=["bad.c"],
            clean=["good.c", "good.h", "exact_dup.c"],
        )
        self.assertIn("missing_pragma.h", reported)

    def test_early_return_flags_wrapped_success_but_allows_dispatch(self) -> None:
        helper = load_helper("policy/guard_clause_style.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(
                root / "core/bad.c",
                "static bool f(int x) {\n"
                "  if (x > 0) {\n"
                "    return true;\n"
                "  }\n"
                "  return false;\n"
                "}\n",
            )
            write(
                root / "core/good.c",
                "static bool f(int k) {\n"
                "  if (k == 1) { return true; }\n"
                "  if (k == 2) { return true; }\n"
                "  return false;\n"
                "}\n",
            )
            reported = reported_basenames(policy_lint("guard_clause_style.py", root, "source"))
        assert_simulation_reported(self, reported, violations=["bad.c"], clean=["good.c"])
        helper = load_helper("policy/banned_libc_io.py")
        from scan_policy import BANNED_C_API_NAMES, BANNED_OUTPUT_C_API_NAMES

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            for func in BANNED_OUTPUT_C_API_NAMES:
                write(root / "core" / f"bad_{func}.c", f"void f(void) {{ {func}(x); }}\n")
            write(
                root / "core/sample_io.c",
                "namespace sample { void sample_stdout_line(const char *) {} }\n",
            )
            reported = reported_basenames(
                policy_lint("banned_libc_io.py", root, "unsafe_api")
            )
        for func in BANNED_OUTPUT_C_API_NAMES:
            self.assertIn(f"bad_{func}.c", reported, func)
        self.assertNotIn("sample_io.c", reported)
        self.assertTrue(BANNED_OUTPUT_C_API_NAMES <= frozenset(BANNED_C_API_NAMES))

    def test_unsafe_api_allows_only_wrapper_sink_files(self) -> None:
        helper = load_helper("policy/banned_libc_io.py")
        bad = "void f(void) { std::println(\"x\"); }\n"
        allowed = "void f(void) { std::println(\"{}\", s); std::fflush(stdout); }\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/bad.cpp", bad)
            write(root / "core/sample_io.c", allowed)
            reported = reported_basenames(
                policy_lint("banned_libc_io.py", root, "unsafe_api")
            )
        self.assertIn("bad.cpp", reported)
        self.assertNotIn("sample_io.c", reported)

    def test_unsafe_api_flags_integer_parse_and_ignores_comments_and_canonical_impl(self) -> None:
        helper = load_helper("policy/banned_libc_io.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(
                root / "core/bad.cpp",
                "void f(const char *s) { (void)strtol\n(s, 0, 10); }\n",
            )
            write(root / "core/good.cpp", "/* strtol(s, 0, 10) */ void f(void) {}\n")
            write(
                root / "core/sample_parse.h",
                "long f(const char *s) { return strtol(s, 0, 10); }\n",
            )
            reported = reported_basenames(
                policy_lint("banned_libc_io.py", root, "unsafe_api")
            )
        self.assertIn("bad.cpp", reported)
        self.assertNotIn("good.cpp", reported)
        self.assertNotIn("sample_parse.h", reported)

    def test_license_header_repair_is_idempotent_and_prunes_vendor_dirs(self) -> None:
        helper = load_helper("policy/spdx_headers.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            helper.configure_from_manifest(root)
            repaired, changed = helper.repair_hash("#!/usr/bin/env bash\necho ok\n", 2026)
            self.assertTrue(changed)
            self.assertTrue(repaired.startswith("#!/usr/bin/env bash\n# SPDX-License-Identifier:"))
            rerepaired, changed_again = helper.repair_hash(repaired, 2026)
            self.assertFalse(changed_again)
            self.assertEqual(repaired, rerepaired)
            write(
                root / ".github/lint-c-cpp.yaml",
                "license_header: |\n"
                "  # SPDX-License-Identifier: Apache-2.0\n"
                "  #\n"
                "  # Copyright (C) 2026 Nero Duality, LLC.\n"
                "scan:\n  source_roots:\n    - .\n",
            )
            write(root / ".gitignore", "third-party/\n")
            write(root / "third-party/vendor.c", "int vendor;\n")
            write(root / "src.c", "int project;\n")
            helper.configure_from_manifest(root)
            targets = {
                path.relative_to(root).as_posix()
                for path in helper.iter_targets(central_job_paths(root, "license"))
            }
        self.assertIn("src.c", targets)
        self.assertNotIn("third-party/vendor.c", targets)

    def test_null_nodiscard_flags_violations_and_skips_clean_files(self) -> None:
        helper = load_helper("policy/null_nodiscard.py")
        cases = {
            "raw_null.c": "void f(void *p) { if (p == NULL) {} }\n",
            "legacy_old_null.c": "void f(void *p) { if (p == OLD_NULL) {} }\n",
            "cast_null.c": "const void *p = (const uint8_t *)0;\n",
            "source_nullptr.cpp": "void f(const char *s) { if (s == nullptr) {} }\n",
            "missing_nodiscard.h": "#pragma once\nbool probe_no_nodiscard(void);\n",
            "nodiscard_field.h": "struct S { SAMPLE_NODISCARD bool flag{}; };\n",
            "missing_null_include.c": "void f(void *p) { if (p == SAMPLE_NULL) {} }\n",
            "missing_include.c": "void f(void *p) { if (p == SAMPLE_NULL) {} }\n",
            "field.h": "struct S { SAMPLE_NODISCARD bool flag{}; };\n",
            "comment_ok.c": "/* NULL nullptr SAMPLE_NULL */ void f(void) {}\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(
                root / "include/sample/sample_null.h",
                "#define SAMPLE_NULL nullptr\n",
            )
            for name, body in cases.items():
                write(root / "core" / name, body)
            reported = reported_basenames(
                policy_lint("null_nodiscard.py", root, "unsafe_api")
            )
        assert_simulation_reported(
            self,
            reported,
            violations=[name for name in cases if name != "comment_ok.c"],
            clean=["comment_ok.c"],
        )

    def test_relative_includes_rejects_parent_traversal(self) -> None:
        helper = load_helper("policy/relative_includes.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/bad.c", '#include "../generated.h"\n')
            write(root / "core/good.c", '/* #include "../hidden.h" */\n#include "ok.h"\n')
            reported = reported_basenames(policy_lint("relative_includes.py", root, "source"))
        assert_simulation_reported(self, reported, violations=["bad.c"], clean=["good.c"])

    def test_nolint_audit_reports_and_rejects_suppressions(self) -> None:
        helper = load_helper("policy/nolint_audit.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/clean.c", "int ok(void) { return 0; }\n")
            write(root / "core/bad_nextline.c", "// NOLINTNEXTLINE(foo)\nint bad(void) { return 1; }\n")
            write(root / "core/bad_nolint.c", "int x; // NOLINT(readability)\n")
            write(root / "core/bad_begin.c", "// NOLINTBEGIN\nint a = 1;\n// NOLINTEND\n")
            write(
                root / "core/bad_cppcheck.c",
                "int x; // cppcheck-suppress constParameterPointer\n",
            )
            write(
                root / "core/bad_cppcheck_begin.c",
                "// cppcheck-suppress-begin uninitvar\nint a = 0;\n"
                "// cppcheck-suppress-end uninitvar\n",
            )
            write(
                root / "include/sample/sample_null.h",
                "// NOLINTNEXTLINE(ok-here)\n#pragma once\n",
            )
            findings = policy_lint("nolint_audit.py", root, "nolint")
        reported = reported_basenames(findings)
        assert_simulation_reported(
            self,
            reported,
            violations=[
                "bad_nextline.c",
                "bad_nolint.c",
                "bad_begin.c",
                "bad_cppcheck.c",
                "bad_cppcheck_begin.c",
            ],
            clean=["clean.c", "sample_null.h"],
        )

    def test_resource_lifetime_flags_split_manual_pairs_and_allows_canonical_wrappers(self) -> None:
        helper = load_helper("policy/raii_lifetime.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "userspace/bad.c", "void f(void) { FILE *fp = fopen\n(\"x\", \"r\"); fclose(fp); }\n")
            write(
                root / "include/sample/sample_file_raii.h",
                "void f(void) { FILE *fp = fopen(\"x\", \"r\"); fclose(fp); }\n",
            )
            reported = reported_basenames(
                policy_lint("raii_lifetime.py", root, "unsafe_api")
            )
        assert_simulation_reported(self, reported, violations=["bad.c"], clean=["sample_file_raii.h"])

    def test_safe_indexing_flags_unchecked_external_buffer_access(self) -> None:
        helper = load_helper("policy/pointer_bounds.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/bad.c", "uint8_t f(const uint8_t *apdu) { return apdu[5]; }\n")
            write(
                root / "core/good.c",
                "uint8_t f(const uint8_t *apdu, size_t apdu_len) {\n"
                "  if (apdu_len <= 5) { return 0; }\n"
                "  return apdu[5];\n"
                "}\n",
            )
            reported = reported_basenames(policy_lint("pointer_bounds.py", root, "source"))
        assert_simulation_reported(self, reported, violations=["bad.c"], clean=["good.c"])

    def test_spec_traceability_check_detects_missing_mismatch_and_impl_policy_drift(self) -> None:
        helper = load_helper("policy/spec_traceability.py")
        sample = (
            "#define SAMPLE_OK 0xA4u\n"
            "#define SAMPLE_MISMATCH 5u\n"
            "#define SAMPLE_RETRY_ATTEMPTS 3u\n"
        )
        defs = helper._load_defines_from_text(sample)
        self.assertEqual(defs["SAMPLE_OK"], "0xA4u")
        self.assertEqual(helper.normalize_value("0xA4u")[0], 0xA4)
        errors: list[str] = []
        helper.validate_policy_comment("T2T", "SAMPLE_RETRY_ATTEMPTS", "", sample, errors)
        self.assertTrue(errors)
        self.assertNotEqual(helper.normalize_value("6u")[0], helper.normalize_value(defs["SAMPLE_MISMATCH"])[0])

    def test_spec_traceability_main_flags_missing_symbol_and_value_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "include/sample/limits.h", "/* [ISO14443-3] section 1 */\n#define SAMPLE_PRESENT 4u\n")
            manifest = write(
                root / "docs/spec-traceability.yaml",
                "constants:\n"
                "  - spec_prefix: ISO14443-3\n"
                "    symbol: SAMPLE_PRESENT\n"
                "    spec_value: \"5\"\n"
                "    ref: \"section 1\"\n"
                "    source: include/sample/limits.h\n"
                "  - spec_prefix: ISO14443-3\n"
                "    symbol: SAMPLE_MISSING\n"
                "    spec_value: \"4\"\n"
                "    ref: \"section 1\"\n"
                "    source: include/sample/limits.h\n",
            )
            paths_file = root / "source.paths"
            write_paths_file(root, "source", paths_file)
            result = subprocess.run(
                policy_runner_cmd(
                    "spec_traceability.py",
                    root,
                    paths_file=paths_file,
                    extras=["--traceability", str(manifest)],
                ),
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("SAMPLE_PRESENT: spec=5 code=4", result.stderr)
        self.assertIn("SAMPLE_MISSING: source literal not found", result.stderr)

    def test_spec_traceability_main_flags_missing_source_prefix_and_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "include/sample/limits.h", "#define SAMPLE_PRESENT 4u\n")
            manifest = write(
                root / "docs/spec-traceability.yaml",
                "constants:\n"
                "  - spec_prefix: ISO14443-3\n"
                "    symbol: SAMPLE_PRESENT\n"
                "    spec_value: \"4\"\n"
                "    source: include/sample/limits.h\n",
            )
            paths_file = root / "source.paths"
            write_paths_file(root, "source", paths_file)
            result = subprocess.run(
                policy_runner_cmd(
                    "spec_traceability.py",
                    root,
                    paths_file=paths_file,
                    extras=["--traceability", str(manifest)],
                ),
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("SAMPLE_PRESENT: ref must be non-empty", result.stderr)
        self.assertIn("SAMPLE_PRESENT: spec_prefix is not cited", result.stderr)

    def test_yamllint_requires_schema_and_canonical_sort(self) -> None:
        helper = load_helper("policy/yaml_manifest.py")
        bad = {"constants": [{"spec_prefix": "P", "symbol": "SAMPLE_X", "source": "a.h"}]}
        self.assertTrue(any("spec_value" in error for error in helper.validate_manifest(bad)))
        data = {
            "constants": [
                {"spec_prefix": "Z", "symbol": "B", "spec_value": "1", "ref": "section 1", "source": "b.h"},
                {"spec_prefix": "A", "symbol": "A", "spec_value": "2", "ref": "section 2", "source": "a.h"},
            ]
        }
        rendered = helper.canonical_text("", data)
        self.assertLess(rendered.index("symbol: A"), rendered.index("symbol: B"))

    def test_yamllint_uses_manifest_files_outside_source_roots(self) -> None:
        from consumer_manifest import yamllint_manifest_paths

        helper = load_helper("policy/yaml_manifest.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            paths, errors = yamllint_manifest_paths(root)
            self.assertEqual(errors, [])
            self.assertIn(".github/lint-c-cpp.yaml", [p.relative_to(root).as_posix() for p in paths])
            scan_only = {
                p.relative_to(root).as_posix()
                for p in central_job_paths(root, "yaml")
            }
            self.assertIn(".github/lint-c-cpp.yaml", scan_only)
        self.assertEqual(helper.yamllint_ok_message(0), "yamllint: OK (0 scanned, 0 auto-formatted)")
        self.assertEqual(helper.yamllint_ok_message(2), "yamllint: OK (2 scanned, 0 auto-formatted)")

    def test_unsafe_api_flags_each_banned_c_api(self) -> None:
        helper = load_helper("policy/banned_libc_io.py")
        from scan_policy import BANNED_C_API_NAMES, JOB_UNSAFE_API

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            for api in BANNED_C_API_NAMES:
                write(root / "core" / f"bad_{api}.c", f"void f(void) {{ {api}(a, b); }}\n")
                write(root / "core" / f"ignored_{api}.ino", f"void f(void) {{ {api}(a, b); }}\n")
            reported = reported_basenames(policy_lint("banned_libc_io.py", root, JOB_UNSAFE_API))
        for api in BANNED_C_API_NAMES:
            self.assertIn(f"bad_{api}.c", reported, api)
            self.assertNotIn(f"ignored_{api}.ino", reported, api)

    def test_unsafe_api_fallback_catches_split_banned_calls_in_port(self) -> None:
        helper = load_helper("policy/banned_libc_io.py")
        from scan_policy import JOB_UNSAFE_API
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(root / "core/ignored.ino", "void f(char *d, const char *s) { strcpy\n(d, s); }\n")
            write(root / "port/board/bad.c", "void f(void) { system\n(\"true\"); }\n")
            reported = reported_basenames(policy_lint("banned_libc_io.py", root, JOB_UNSAFE_API))
        self.assertNotIn("ignored.ino", reported)
        self.assertIn("bad.c", reported)

    def test_cxx_heap_policy_flags_new_delete_and_skips_wrapper_sink(self) -> None:
        helper = load_helper("policy/banned_cxx_heap.py")
        cases = {
            "new": "struct S {}; void f(void) { auto *p = new S; delete p; }\n",
            "placement": "struct S {}; void f(void *a) { auto *p = new (a) S; (void)p; }\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_policy_test_manifest(root)
            write(
                root / "userspace/sample_file_raii.h",
                "struct S {}; void f(void) { auto *p = new S; delete p; }\n",
            )
            for name, body in cases.items():
                write(root / "core" / f"bad_{name}.cpp", body)
            write(root / "core/bad.cpp", "struct S {}; void f(void) { auto *p = new\n S; delete p; }\n")
            write(root / "core/malloc_ok.c", "void f(void) { void *p = malloc(16); free(p); }\n")
            reported = reported_basenames(
                policy_lint("banned_cxx_heap.py", root, "unsafe_api")
            )
        violations = [f"bad_{name}.cpp" for name in cases] + ["bad.cpp"]
        assert_simulation_reported(
            self, reported, violations=violations, clean=["sample_file_raii.h", "malloc_ok.c"]
        )

    def test_firmware_compile_db_source_required_and_accepted(self) -> None:
        from manifest_validate import validate_compile_db

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / ".github/lint-c-cpp.yaml"
            write(
                missing,
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n  source_roots: [firmware]\n"
                "compile_db:\n  firmware:\n"
                "    - compile_commands_json: build/fw/compile_commands.json\n"
                "      commands: [make fw]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/us/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML,
            )
            import yaml as _yaml

            data = _yaml.safe_load(missing.read_text(encoding="utf-8"))
            issues = validate_compile_db(data, missing)
            self.assertTrue(any(".source is required" in item for item in issues), issues)

            write(
                missing,
                "license_header: |\n  # test\n"
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n  source_roots: [firmware]\n"
                "compile_db:\n  firmware:\n"
                "    - compile_commands_json: build/fw/compile_commands.json\n"
                "      commands: [make fw]\n"
                "      source: firmware\n"
                "  userspace:\n"
                "    - compile_commands_json: build/us/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  constants_headers: [limits.h]\n" + _NULL_OVERRIDES_YAML,
            )
            data = _yaml.safe_load(missing.read_text(encoding="utf-8"))
            issues = validate_compile_db(data, missing)
            self.assertFalse(any("firmware" in item and "source" in item for item in issues), issues)

        from consumer_manifest import compile_db_firmware_entries

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n  source_roots: [firmware]\n"
                "compile_db:\n  firmware:\n"
                "    - compile_commands_json: build/fw/compile_commands.json\n"
                "      commands: [make fw]\n"
                "      source: firmware\n"
                "  userspace:\n"
                "    - compile_commands_json: build/us/compile_commands.json\n"
                "      source: userspace\n",
            )
            entries = compile_db_firmware_entries(root)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["source"], "firmware")

    def test_duplicate_source_compile_db_provenance_preserved(self) -> None:
        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        import json

        from compile_db_util import (
            PROVENANCE_KEY,
            entry_compile_db_provenance,
            load_compile_entries_by_db,
            load_richest_compile_entries,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n  source_roots: [firmware]\n"
                "compile_db:\n  firmware:\n"
                "    - compile_commands_json: build/lint/firmware/uno/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make uno]\n"
                "    - compile_commands_json: build/lint/firmware/wba/compile_commands.json\n"
                "      source: firmware\n"
                "      commands: [make wba]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n",
            )
            src = root / "firmware/shared.c"
            write(src, "void shared(void) {}\n")
            uno = root / "build/lint/firmware/uno/compile_commands.json"
            wba = root / "build/lint/firmware/wba/compile_commands.json"
            for db_path, compiler in (
                (uno, "/opt/arm-uno-gcc"),
                (wba, "/opt/arm-wba-gcc"),
            ):
                db_path.parent.mkdir(parents=True, exist_ok=True)
                db_path.write_text(
                    json.dumps(
                        [
                            {
                                "directory": str(root),
                                "command": f"{compiler} -c {src.resolve()}",
                                "file": str(src.resolve()),
                            }
                        ]
                    ),
                    encoding="utf-8",
                )
            by_db = load_compile_entries_by_db(root)
            self.assertIn("build/lint/firmware/uno/compile_commands.json", by_db)
            self.assertIn("build/lint/firmware/wba/compile_commands.json", by_db)
            self.assertIn("firmware/shared.c", by_db["build/lint/firmware/uno/compile_commands.json"])
            self.assertIn("firmware/shared.c", by_db["build/lint/firmware/wba/compile_commands.json"])
            richest = load_richest_compile_entries(root)
            prov = entry_compile_db_provenance(richest["firmware/shared.c"])
            self.assertEqual(
                set(prov),
                {
                    "build/lint/firmware/uno/compile_commands.json",
                    "build/lint/firmware/wba/compile_commands.json",
                },
            )
            self.assertEqual(richest["firmware/shared.c"][PROVENANCE_KEY], prov)

            # Emit contract matches pre-0.2.0: clang/cppcheck JSON has only public keys.
            # Provenance stays on in-memory merge entries for override/OpenSSF ownership.
            from compile_db_lint import (
                MergedCompileDatabase,
                _compile_db_provenance_for_source,
                scrub_compile_entry_for_clang_tidy,
                write_clang_tidy_compile_commands,
            )
            from compile_db_util import public_compile_entry

            in_memory = richest["firmware/shared.c"]
            self.assertIn(PROVENANCE_KEY, in_memory)
            scrubbed = scrub_compile_entry_for_clang_tidy(in_memory)
            self.assertNotIn(PROVENANCE_KEY, scrubbed)
            self.assertTrue(set(scrubbed.keys()) <= {"directory", "file", "command", "arguments", "output"})
            self.assertEqual(public_compile_entry(in_memory), scrubbed)
            # In-memory provenance must survive scrub (scrub copies).
            self.assertIn(PROVENANCE_KEY, in_memory)

            merge_dir = root / "build/clang-tidy-compile-db"
            merge_dir.mkdir(parents=True, exist_ok=True)
            db = MergedCompileDatabase(
                root.resolve(),
                richest,
                MergedCompileDatabase.host_template_pool(richest, root.resolve()),
            )
            write_clang_tidy_compile_commands(
                db, merge_dir / "compile_commands.json", scan_paths=[src]
            )
            written = json.loads(
                (merge_dir / "compile_commands.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(written), 1)
            self.assertNotIn(PROVENANCE_KEY, written[0])
            for key in written[0]:
                self.assertIn(key, {"directory", "file", "command", "arguments", "output"})
            self.assertEqual(
                set(
                    _compile_db_provenance_for_source(
                        root,
                        "firmware/shared.c",
                        written[0],
                    )
                ),
                {
                    "build/lint/firmware/uno/compile_commands.json",
                    "build/lint/firmware/wba/compile_commands.json",
                },
            )
            # Memory model unchanged after write.
            self.assertEqual(
                entry_compile_db_provenance(db.by_key["firmware/shared.c"]),
                prov,
            )

    def test_openssf_audits_each_firmware_db_separately(self) -> None:
        from unittest.mock import patch
        import json

        if str(COMPILE_DB_DIR) not in sys.path:
            sys.path.insert(0, str(COMPILE_DB_DIR))
        _policy = HELPERS_DIR / "policy"
        if str(_policy) not in sys.path:
            sys.path.insert(0, str(_policy))
        import compile_db_util
        from hardening_verify import verify_compile_commands_openssf
        from policy_overrides import openssf_manifest_for_audit, override_dials_for_compile_db

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            uno_json = "build/lint/firmware/uno/compile_commands.json"
            wba_json = "build/lint/firmware/wba/compile_commands.json"
            write(
                root / ".github/lint-c-cpp.yaml",
                "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n"
                "  public_headers_dir: include\n  source_roots: [firmware]\n"
                "compile_db:\n  firmware:\n"
                f"    - compile_commands_json: {uno_json}\n"
                "      source: firmware\n"
                "      commands: [make uno]\n"
                f"    - compile_commands_json: {wba_json}\n"
                "      source: firmware\n"
                "      commands: [make wba]\n"
                "  userspace:\n"
                "    - compile_commands_json: build/lint/userspace/compile_commands.json\n"
                "      source: userspace\n"
                "policy:\n  constants_headers: [limits.h]\n"
                "  nolint_allowed: null\n  resource_lifetime: null\n"
                "  shared_c_cxx_source_roots: null\n"
                "  unsafe_api:\n    header: sample_null.h\n"
                "    include_headers: [attrs.h]\n"
                "    wrapper_files: [include/sample_null.h]\n"
                "  overrides:\n"
                "    clang-format: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-c: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-shared-c-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-unsafe-c: {add: null, remove: null, by_compile_db: null}\n"
                "    clang-tidy-unsafe-cxx: {add: null, remove: null, by_compile_db: null}\n"
                "    cppcheck: {add: null, remove: null, by_compile_db: null}\n"
                "    openssf-hardening:\n"
                "      add: null\n"
                "      remove: null\n"
                "      by_compile_db:\n"
                f"        - compile_commands_json: {uno_json}\n"
                "          add: null\n"
                "          remove: [-Werror]\n"
                f"        - compile_commands_json: {wba_json}\n"
                "          add: null\n"
                "          remove: [-Wall]\n",
            )
            src = root / "firmware/shared.c"
            write(src, "void shared(void) {}\n")
            base_flags = (
                "-Wall -Wextra -Wformat -Wformat=2 -Wconversion -Wsign-conversion "
                "-Wimplicit-fallthrough -Werror -Werror=format-security "
                "-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing "
                "-fstack-protector-strong -Whardened -O2 -fexceptions"
            )
            for rel, compiler in (
                (uno_json, "/opt/arm-uno-gcc"),
                (wba_json, "/opt/arm-wba-gcc"),
            ):
                db_path = root / rel
                db_path.parent.mkdir(parents=True, exist_ok=True)
                db_path.write_text(
                    json.dumps(
                        [
                            {
                                "directory": str(root),
                                "command": f"{compiler} {base_flags} -c {src.resolve()}",
                                "file": str(src.resolve()),
                            }
                        ]
                    ),
                    encoding="utf-8",
                )
                (db_path.parent / "CMakeCache.txt").write_text(
                    "# no HAVE_* probes\n", encoding="utf-8"
                )

            _add, uno_remove = override_dials_for_compile_db(
                root, "openssf-hardening", uno_json
            )
            _add, wba_remove = override_dials_for_compile_db(
                root, "openssf-hardening", wba_json
            )
            self.assertIn("-Werror", uno_remove or ())
            self.assertIn("-Wall", wba_remove or ())
            self.assertNotEqual(uno_remove, wba_remove)

            kit = LINT_KIT
            kit_manifest = __import__(
                "hardening_verify", fromlist=["load_hardening_manifest"]
            ).load_hardening_manifest(kit)
            uno_manifest = openssf_manifest_for_audit(
                root, kit_manifest, lookup_key="firmware/shared.c", preferred_compile_db=uno_json
            )
            wba_manifest = openssf_manifest_for_audit(
                root, kit_manifest, lookup_key="firmware/shared.c", preferred_compile_db=wba_json
            )
            uno_flags = {
                str(item) for item in uno_manifest.get("coverage", {}).get("flags", [])
            }
            wba_flags = {
                str(item) for item in wba_manifest.get("coverage", {}).get("flags", [])
            }
            self.assertNotIn("-Werror", uno_flags)
            self.assertIn("-Wall", uno_flags)
            self.assertNotIn("-Wall", wba_flags)
            self.assertIn("-Werror", wba_flags)

            def mock_host_triple() -> str:
                return "x86_64-host"

            with patch.object(compile_db_util, "host_target_triple", mock_host_triple):
                with patch.object(
                    compile_db_util,
                    "clang_target_for_command",
                    side_effect=lambda cmd: (
                        "arm-uno" if "uno-gcc" in cmd else "arm-wba" if "wba-gcc" in cmd else "x86_64-host"
                    ),
                ):
                    issues = verify_compile_commands_openssf(
                        root,
                        kit,
                        entries_by_key={},
                        source_paths=[src],
                    )
            # UNO dials out -Werror (present in command); WBA dials out -Wall (present).
            # Both should pass their own dialed requirements.
            self.assertEqual(issues, [], issues)
            # Remove a non-waived WBA requirement to prove that profile is
            # audited independently and identified in the failure.
            wba_path = root / wba_json
            wba_path.write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "command": (
                                f"/opt/arm-wba-gcc {base_flags.replace('-Wextra ', '')} "
                                f"-c {src.resolve()}"
                            ),
                            "file": str(src.resolve()),
                        }
                    ]
                ),
                encoding="utf-8",
            )
            with patch.object(compile_db_util, "host_target_triple", mock_host_triple):
                with patch.object(
                    compile_db_util,
                    "clang_target_for_command",
                    side_effect=lambda cmd: (
                        "arm-uno" if "uno-gcc" in cmd else "arm-wba" if "wba-gcc" in cmd else "x86_64-host"
                    ),
                ):
                    issues = verify_compile_commands_openssf(
                        root,
                        kit,
                        entries_by_key={},
                        source_paths=[src],
                    )
            labeled = " ".join(issues)
            self.assertIn(f"[{wba_json}]", labeled)
            self.assertIn("-Wextra", labeled)
            self.assertNotIn(f"[{uno_json}]", labeled)

    def test_hardening_flags_mk_preserves_order_and_language_split(self) -> None:
        from hardening_verify import (
            generate_hardening_flags_mk,
            load_hardening_manifest,
            _ordered_language_coverage_flags,
            _ordered_make_definitions,
        )

        manifest = load_hardening_manifest(LINT_KIT)
        with tempfile.TemporaryDirectory() as tmp:
            license_root = Path(tmp)
            write_license_only_manifest(license_root)
            body = generate_hardening_flags_mk(manifest, repo_root=license_root)
        c_flags = _ordered_language_coverage_flags(manifest, "C")
        cxx_flags = _ordered_language_coverage_flags(manifest, "CXX")
        self.assertIn("NERO_OPENSSF_CFLAGS := " + " ".join(c_flags), body)
        self.assertIn("NERO_OPENSSF_CXXFLAGS := " + " ".join(cxx_flags), body)
        # C-only flags must not appear on CXXFLAGS; CXX-only defs handling below.
        self.assertIn("-Werror=implicit", c_flags)
        self.assertNotIn("-Werror=implicit", cxx_flags)
        # Order matches coverage.flags, not lexicographic sort.
        coverage_flags = [
            str(item) for item in manifest.get("coverage", {}).get("flags", []) if item
        ]
        c_positions = [coverage_flags.index(flag) for flag in c_flags if flag in coverage_flags]
        self.assertEqual(c_positions, sorted(c_positions))
        # Mutually exclusive libc++ modes must not all be emitted together.
        defs = _ordered_make_definitions(manifest)
        libcpp = [item for item in defs if item.startswith("_LIBCPP_HARDENING_MODE=")]
        self.assertEqual(libcpp, [])
        self.assertNotIn("_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST", body)
        self.assertNotIn("_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE", body)
        self.assertNotIn("_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG", body)


if __name__ == "__main__":
    unittest.main(testRunner=NumberedTextTestRunner, verbosity=2)
