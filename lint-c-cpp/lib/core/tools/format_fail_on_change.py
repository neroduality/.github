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
#
# Shared apply-in-place + fail-if-changed gate for lint formatters.

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

FAIL_ON_CHANGE_TAIL = "commit the updates and re-run"


def fail_on_change_error(detail: str) -> str:
    return f"error: {detail}; {FAIL_ON_CHANGE_TAIL}"


def file_checksums(paths: Iterable[Path]) -> dict[str, str]:
    digest: dict[str, str] = {}
    for path in sorted(paths, key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        digest[path.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest


def _fail(detail: str) -> int:
    print(fail_on_change_error(detail), file=sys.stderr)
    return 1


def apply_with_fail_on_change(
    paths: Iterable[Path],
    apply: Callable[[], None],
    *,
    detail: str,
) -> int:
    """Apply an in-place formatter; exit 1 if any file checksum changed."""
    targets = [path for path in paths if path.is_file()]
    if not targets:
        return 0
    before = file_checksums(targets)
    apply()
    if before != file_checksums(targets):
        return _fail(detail)
    return 0


def formatter_ok_message(tool: str, scanned: int, reformatted: int = 0) -> str:
    return f"{tool}: OK ({scanned} scanned, {reformatted} auto-formatted)"


def fail_if_repaired(*, detail: str, changed_count: int) -> int:
    """Fail when a repair pass changed one or more files (count-based gate)."""
    return _fail(detail) if changed_count else 0


def self_test() -> int:
    with __import__("tempfile").TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / "sample.txt"
        path.write_text("before\n", encoding="utf-8")

        def rewrite() -> None:
            path.write_text("after\n", encoding="utf-8")

        if apply_with_fail_on_change([path], rewrite, detail="sample rewrite") == 0:
            print("self-test miss: expected checksum gate failure", file=sys.stderr)
            return 1

        path.write_text("stable\n", encoding="utf-8")
        if apply_with_fail_on_change([path], lambda: None, detail="sample noop") != 0:
            print("self-test miss: expected stable file to pass", file=sys.stderr)
            return 1

        if fail_if_repaired(detail="sample repair", changed_count=1) != 1:
            print("self-test miss: expected count-based failure", file=sys.stderr)
            return 1
        if fail_if_repaired(detail="sample repair", changed_count=0) != 0:
            print("self-test miss: expected zero changes to pass", file=sys.stderr)
            return 1

    print("format-fail-on-change self-test: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test())
