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

"""Drop intentional wrapper diagnostics from the unsafe-api clang-tidy pass.

Wrapper paths do not waive heap policy, unrelated checks, or tool failures.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
import tempfile
from pathlib import Path

_LINT_LIB = Path(__file__).resolve().parents[2]
if str(_LINT_LIB) not in sys.path:
    sys.path.insert(0, str(_LINT_LIB))
from lint_pythonpath import bootstrap as _bootstrap_lint_pythonpath

_bootstrap_lint_pythonpath()
from scan_policy import bootstrap_scan_manifest, path_is_unsafe_wrapper

_DIAG = re.compile(r"^(.+?):(\d+):(\d+): (error|warning|note):")
_CHECK = re.compile(r"\[([^\]]+)\]\s*$")
_INSECURE_BUFFER_NOTE = re.compile(
    r"Call to function '[^']+' is insecure as it does not provide security "
    r"checks introduced in the C11 standard\."
)
_INFRA_FAILURE = re.compile(
    r"(?:LLVM ERROR|PLEASE submit a bug report|Segmentation fault|"
    r"Error while processing|unable to (?:load|read) compilation database|"
    r"clang-tidy: error:|Traceback \(most recent call last\))",
    re.IGNORECASE,
)
_PROGRESS = re.compile(r"^\[ ?\d+/\d+\]")
_SUMMARY = re.compile(
    r"^(?:\d+ warnings?(?: treated as errors)? generated\.|"
    r"Suppressed \d+ warnings|Use -header-filter=|Running clang-tidy)"
)


def diagnostic_file(line: str) -> Path | None:
    match = _DIAG.match(line)
    if match is None:
        return None
    return Path(match.group(1))


def _waivable_wrapper_diagnostic(line: str) -> bool:
    check_match = _CHECK.search(line)
    if "heap forbidden" in line:
        return False
    if check_match is None:
        return _INSECURE_BUFFER_NOTE.search(line) is not None
    check = check_match.group(1).split(",", 1)[0]
    return check == "bugprone-unsafe-functions" or check.startswith(
        "clang-analyzer-security.insecureAPI."
    )


def _process_line(
    line: str,
    *,
    repo_root: Path,
    skip_block: bool,
    failed: bool,
) -> tuple[bool, bool, bool, str | None]:
    if _INFRA_FAILURE.search(line):
        return False, True, False, line
    path = diagnostic_file(line)
    if path is not None:
        if path_is_unsafe_wrapper(path, repo_root) and _waivable_wrapper_diagnostic(line):
            return True, failed, True, None
        if ": error:" in line or ": warning:" in line:
            failed = True
        return False, failed, False, line
    if skip_block:
        if _PROGRESS.match(line):
            skip_block = False
            return skip_block, failed, False, line
        return skip_block, failed, False, None
    if _PROGRESS.match(line):
        return skip_block, failed, False, line
    if _SUMMARY.match(line) and not failed:
        return skip_block, failed, False, None
    return skip_block, failed, False, line


def filter_clang_tidy_output(text: str, repo_root: Path) -> tuple[list[str], bool]:
    """Return kept lines and whether any non-wrapper error|warning remains."""
    repo_root = repo_root.resolve()
    kept: list[str] = []
    failed = False
    skip_block = False
    for line in text.splitlines():
        skip_block, failed, _wrapper_seen, kept_line = _process_line(
            line, repo_root=repo_root, skip_block=skip_block, failed=failed
        )
        if kept_line is not None:
            kept.append(kept_line)
    return kept, failed


def stream_clang_tidy_output(
    repo_root: Path, stream: io.TextIOBase
) -> tuple[bool, bool]:
    """Pass progress through live; return (failed, waived_wrapper_diagnostic_seen)."""
    repo_root = repo_root.resolve()
    failed = False
    wrapper_seen = False
    skip_block = False
    for line in stream:
        line = line.rstrip("\n")
        skip_block, failed, line_wrapper_seen, kept_line = _process_line(
            line, repo_root=repo_root, skip_block=skip_block, failed=failed
        )
        wrapper_seen = wrapper_seen or line_wrapper_seen
        if kept_line is not None:
            print(kept_line, flush=True)
    return failed, wrapper_seen


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".github").mkdir()
        (root / ".github" / "lint-c-cpp.yaml").write_text(
            "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
            "  source_roots: [core, include]\n"
            "policy:\n  unsafe_api:\n    header: sample_null.h\n"
            "    include_headers: [attrs.h]\n"
            "    wrapper_files:\n      - include/sample/mem_util.h\n",
            encoding="utf-8",
        )
        bootstrap_scan_manifest(root)
        wrapper = root / "include/sample/mem_util.h"
        wrapper.parent.mkdir(parents=True)
        app = root / "core/app.c"
        app.parent.mkdir(parents=True)
        rel_wrapper = (app.parent / "../include/sample/mem_util.h").resolve()
        out = "\n".join(
            [
                "[ 1/3][0.0s] clang-tidy wrapper.c",
                f"{wrapper}:1:1: error: wrapper error [bugprone-unsafe-functions]",
                "  1 | bad();",
                "      | ^",
                "[ 2/3][0.1s] clang-tidy rel-wrapper.c",
                f"{rel_wrapper}:2:1: note: wrapper note [bugprone-unsafe-functions]",
                "  2 | more();",
                "      | ^",
                "[ 3/3][0.2s] clang-tidy app.c",
                f"{app}:3:1: error: app error [bugprone-unsafe-functions]",
                "  3 | oops();",
                "3 warnings generated.",
            ]
        )
        kept, failed = filter_clang_tidy_output(out, root)
        text = "\n".join(kept)
        if "wrapper error" in text or "wrapper note" in text or "bad();" in text or "more();" in text:
            print("self-test FAIL: wrapper diagnostics were not dropped", file=sys.stderr)
            return 1
        if "app error" not in text or not failed:
            print("self-test FAIL: non-wrapper diagnostics must be kept", file=sys.stderr)
            return 1
        if "[ 1/3]" not in text or "[ 3/3]" not in text:
            print("self-test FAIL: progress lines must be kept", file=sys.stderr)
            return 1

        wrapper_only = "\n".join(
            [
                "[ 1/1][0.0s] clang-tidy wrapper.c",
                f"{wrapper}:1:1: error: wrapper error [bugprone-unsafe-functions]",
                "  1 | bad();",
                "3 warnings generated.",
            ]
        )
        wrapper_kept, wrapper_failed = filter_clang_tidy_output(wrapper_only, root)
        wrapper_text = "\n".join(wrapper_kept)
        if wrapper_failed or "wrapper error" in wrapper_text:
            print("self-test FAIL: wrapper-only batch must drop wrapper diagnostics", file=sys.stderr)
            return 1
        if "3 warnings generated." in wrapper_text:
            print("self-test FAIL: wrapper-only summary must be dropped", file=sys.stderr)
            return 1

        analyzer_note = (
            f"{wrapper}:4:1: note: Call to function 'memcpy' is insecure as it does not "
            "provide security checks introduced in the C11 standard. Replace it "
            "with a bounded wrapper"
        )
        analyzer_kept, analyzer_failed = filter_clang_tidy_output(analyzer_note, root)
        if analyzer_failed or analyzer_kept:
            print(
                "self-test FAIL: wrapper analyzer notes without check names must be dropped",
                file=sys.stderr,
            )
            return 1

        stream_in = io.StringIO(out + "\n")
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            stream_failed, stream_wrapper_seen = stream_clang_tidy_output(root, stream_in)
        if not stream_failed:
            print("self-test FAIL: stream mode must fail on non-wrapper diagnostics", file=sys.stderr)
            return 1
        if not stream_wrapper_seen:
            print("self-test FAIL: stream mode must report waived wrapper diagnostics", file=sys.stderr)
            return 1
        crash = f"{wrapper}:1:1: error: wrapper error [bugprone-unsafe-functions]\nLLVM ERROR: boom\n"
        crash_kept, crash_failed = filter_clang_tidy_output(crash, root)
        if not crash_failed or not any("LLVM ERROR" in line for line in crash_kept):
            print("self-test FAIL: wrapper diagnostics must not hide tool crashes", file=sys.stderr)
            return 1
        heap = f"{wrapper}:1:1: error: heap forbidden [bugprone-unsafe-functions]\n"
        heap_kept, heap_failed = filter_clang_tidy_output(heap, root)
        if not heap_failed or not any("heap forbidden" in line for line in heap_kept):
            print("self-test FAIL: wrappers must not waive heap policy", file=sys.stderr)
            return 1
        stream_text = capture.getvalue()
        if "[ 1/3]" not in stream_text or "[ 3/3]" not in stream_text:
            print("self-test FAIL: stream mode must pass progress lines through", file=sys.stderr)
            return 1
    print("clang-tidy wrapper filter self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--stream", action="store_true", help="Filter stdin line-by-line for live progress")
    parser.add_argument(
        "--wrapper-status",
        action="store_true",
        help="Return 2 when otherwise clean output waived a wrapper diagnostic",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    if args.repo_root is None:
        parser.error("--repo-root is required unless --self-test is set")
    repo_root = args.repo_root.resolve()
    bootstrap_scan_manifest(repo_root)
    if args.stream:
        failed, wrapper_seen = stream_clang_tidy_output(repo_root, sys.stdin)
        if failed:
            return 1
        return 2 if args.wrapper_status and wrapper_seen else 0
    kept, failed = filter_clang_tidy_output(sys.stdin.read(), repo_root)
    for line in kept:
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
