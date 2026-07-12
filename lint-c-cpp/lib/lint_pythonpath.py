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

"""Insert lint-c-cpp core package paths for helper scripts run outside lint.sh."""

from __future__ import annotations

import sys
from pathlib import Path


def bootstrap() -> None:
    lint_lib = Path(__file__).resolve().parent
    core = lint_lib / "core"
    for sub in ("manifest", "scan", "tools", "workflow"):
        entry = str(core / sub)
        if entry not in sys.path:
            sys.path.insert(0, entry)
    compile_db = str(lint_lib / "helpers" / "compile_db")
    if compile_db not in sys.path:
        sys.path.insert(0, compile_db)
