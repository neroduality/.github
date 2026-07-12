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

"""Verify host lint tools for the org C/C++ lint kit (always strict)."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_LINT_KIT = Path(__file__).resolve().parents[3]
_MANIFEST = _DEFAULT_LINT_KIT / "config" / "tool-versions.yaml"

FULL_PROFILE = (
    "python3",
    "cmake",
    "make",
    "cppcheck",
    "codespell",
    "shellcheck",
    "shfmt",
    "clang_format",
    "clang_tidy",
    "markdownlint",
    "node",
)
WORKFLOW_PROFILE = ("python3",)


@dataclass(frozen=True)
class ToolIssue:
    tool: str
    message: str


def _load_tools() -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise SystemExit("error: PyYAML is required to read tool-versions.yaml") from exc
    if not _MANIFEST.is_file():
        raise SystemExit(f"error: missing tool manifest: {_MANIFEST}")
    data = yaml.safe_load(_MANIFEST.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"error: {_MANIFEST} must define a mapping at top level")
    unknown = sorted(key for key in data if key != "tools")
    if unknown:
        raise SystemExit(
            f"error: {_MANIFEST.name}: unknown top-level keys: {', '.join(unknown)} (allowed: tools)"
        )
    tools = data.get("tools")
    if not isinstance(tools, dict):
        raise SystemExit(f"error: {_MANIFEST} must define tools mapping")
    return tools


def parse_version(raw: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", raw)
    return tuple(int(part) for part in parts) if parts else (0,)


def version_ge(have: str, want: str) -> bool:
    left = parse_version(have)
    right = parse_version(want)
    width = max(len(left), len(right))
    left = left + (0,) * (width - len(left))
    right = right + (0,) * (width - len(right))
    return left >= right


def _run(argv: list[str], *, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def resolve_binary(tool_key: str, spec: dict) -> str | None:
    if tool_key == "node":
        return shutil.which("node") or shutil.which("nodejs")
    names = spec.get("binaries")
    if isinstance(names, list) and names:
        for name in names:
            if isinstance(name, str) and name.strip():
                path = shutil.which(name.strip())
                if path:
                    return path
        return None
    return shutil.which(tool_key.replace("_", "-")) or shutil.which(tool_key)


def probe_version(tool_key: str, binary: str) -> str | None:
    if tool_key == "python3":
        result = _run([binary, "-c", "import platform; print(platform.python_version())"])
        return result.stdout.strip() if result.returncode == 0 else None
    if tool_key == "cmake":
        result = _run([binary, "--version"])
        if result.returncode != 0:
            return None
        match = re.search(r"(\d+\.\d+(?:\.\d+)*)", result.stdout)
        return match.group(1) if match else None
    if tool_key == "cppcheck":
        result = _run([binary, "--version"])
        if result.returncode != 0:
            return None
        match = re.search(r"Cppcheck\s+(\d+\.\d+(?:\.\d+)*)", result.stdout)
        return match.group(1) if match else None
    if tool_key == "codespell":
        result = _run([binary, "--version"])
        if result.returncode != 0:
            return None
        match = re.search(r"(\d+\.\d+(?:\.\d+)*)", result.stdout)
        return match.group(1) if match else None
    if tool_key == "markdownlint":
        result = _run([binary, "--version"])
        if result.returncode != 0:
            return None
        match = re.search(r"(\d+\.\d+(?:\.\d+)*)", result.stdout)
        return match.group(1) if match else None
    if tool_key == "make":
        result = _run([binary, "--version"])
        if result.returncode != 0:
            return None
        match = re.search(r"GNU Make\s+(\d+\.\d+(?:\.\d+)*)", result.stdout)
        if match:
            return match.group(1)
        match = re.search(r"(\d+\.\d+(?:\.\d+)*)", result.stdout)
        return match.group(1) if match else None
    if tool_key == "shellcheck":
        result = _run([binary, "--version"])
        if result.returncode != 0:
            return None
        match = re.search(r"version:\s*(\d+\.\d+(?:\.\d+)*)", result.stdout)
        return match.group(1) if match else None
    if tool_key == "shfmt":
        result = _run([binary, "--version"])
        text = f"{result.stdout}\n{result.stderr}"
        match = re.search(r"v?(\d+\.\d+(?:\.\d+)*)", text)
        if match:
            return match.group(1)
        try:
            blob = Path(binary).read_bytes()
        except OSError:
            return None
        match = re.search(rb"mvdan\.cc/sh/v3/version=(\d+\.\d+(?:\.\d+)*)", blob)
        return match.group(1).decode("ascii") if match else None
    if tool_key in {"clang_format", "clang_tidy"}:
        result = _run([binary, "--version"])
        if result.returncode != 0:
            return None
        match = re.search(
            r"(?:LLVM version|clang-(?:format|tidy) version)\s+(\d+\.\d+(?:\.\d+)*)",
            result.stdout,
        )
        if match:
            return match.group(1)
        match = re.search(r"(\d+\.\d+(?:\.\d+)*)", result.stdout)
        return match.group(1) if match else None
    if tool_key == "node":
        result = _run([binary, "-p", 'process.versions.node.split(".")[0]'])
        return result.stdout.strip() if result.returncode == 0 else None
    return "0"


def verify_tool(tool_key: str, spec: dict) -> list[ToolIssue]:
    issues: list[ToolIssue] = []
    binary = resolve_binary(tool_key, spec)
    if binary is None:
        label = tool_key.replace("_", "-")
        if isinstance(spec.get("binaries"), list):
            label = " or ".join(str(name) for name in spec["binaries"])
        issues.append(ToolIssue(tool_key, f"required lint tool not found: {label}"))
        return issues

    min_raw = spec.get("min")
    if min_raw is None:
        return issues

    want = str(min_raw)

    have = probe_version(tool_key, binary)
    if not have:
        issues.append(ToolIssue(tool_key, f"could not read version from {binary}"))
        return issues

    if tool_key == "node":
        if int(have) < int(parse_version(want)[0]):
            issues.append(
                ToolIssue(tool_key, f"node {have} < required {want} ({_MANIFEST.name})")
            )
        return issues

    if not version_ge(have, want):
        issues.append(
            ToolIssue(tool_key, f"{tool_key.replace('_', '-')} {have} < required {want} ({_MANIFEST.name})")
        )
        return issues

    pin = spec.get("pin")
    if pin is not None and str(have) != str(pin):
        issues.append(
            ToolIssue(
                tool_key,
                f"{tool_key.replace('_', '-')} {have} != pinned {pin} ({_MANIFEST.name})",
            )
        )

    if tool_key == "codespell":
        result = _run([binary, "--help"])
        if "--ignore-multiline-regex" not in result.stdout:
            issues.append(
                ToolIssue(
                    tool_key,
                    f"codespell {have} lacks --ignore-multiline-regex ({_MANIFEST.name})",
                )
            )

    return issues


def verify_profile(profile: tuple[str, ...]) -> list[ToolIssue]:
    tools = _load_tools()
    issues: list[ToolIssue] = []
    for tool_key in profile:
        spec = tools.get(tool_key)
        if not isinstance(spec, dict):
            issues.append(ToolIssue(tool_key, f"unknown tool key in profile: {tool_key}"))
            continue
        issues.extend(verify_tool(tool_key, spec))
    return issues


def verify(args: argparse.Namespace) -> int:
    profile = WORKFLOW_PROFILE if args.workflow else FULL_PROFILE
    issues = verify_profile(profile)
    if args.workflow:
        try:
            __import__("yaml")
        except ImportError:
            issues.append(ToolIssue("python3-yaml", "PyYAML is required for workflow lint"))
    if issues:
        for issue in issues:
            print(f"error: {issue.message}", file=sys.stderr)
        return 1
    print("tool-versions: OK")
    return 0


def resolve(args: argparse.Namespace) -> int:
    tools = _load_tools()
    for tool in args.tools:
        spec = tools.get(tool.replace("-", "_"))
        if not isinstance(spec, dict):
            spec = {}
        print(resolve_binary(tool.replace("-", "_"), spec) or "")
    return 0


def run_self_test() -> int:
    failures: list[str] = []

    if not version_ge("21.0.0", "20.0.0"):
        failures.append("version comparator must treat 21.0.0 >= 20.0.0")
    if version_ge("1.0.0", "2.4.2"):
        failures.append("version comparator must reject 1.0.0 >= 2.4.2")

    with tempfile.TemporaryDirectory() as tmp:
        bindir = Path(tmp) / "bin"
        bindir.mkdir()
        fake = bindir / "cppcheck"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ ${1:-} == '--version' ]]; then echo 'Cppcheck 1.0.0'; exit 0; fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        env = {**dict(**os.environ), "PATH": f"{bindir}:{os.environ.get('PATH', '')}"}
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "verify"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        if result.returncode == 0:
            failures.append("verify must fail when cppcheck is too old")
        if "cppcheck 1.0.0 < required" not in result.stderr:
            failures.append("verify must report under-version cppcheck")

    if failures:
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print("tool-versions self-test failures:", file=sys.stderr)
        return 1
    print("tool-versions self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run internal regression checks")
    sub = parser.add_subparsers(dest="cmd")
    verify_parser = sub.add_parser("verify", help="Fail unless every required tool is present and new enough")
    verify_parser.add_argument(
        "--workflow",
        action="store_true",
        help="Verify workflow-lint subset only (python3 + PyYAML)",
    )
    verify_parser.set_defaults(func=verify)
    resolve_parser = sub.add_parser("resolve")
    resolve_parser.add_argument("tools", nargs="+")
    resolve_parser.set_defaults(func=resolve)
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    if not args.cmd:
        parser.error("command is required unless --self-test is set")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
