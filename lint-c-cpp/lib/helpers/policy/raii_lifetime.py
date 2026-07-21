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

"""RAII for configured acquire/release API pairs (unsafe_api scan job)."""

from __future__ import annotations

import sys
from pathlib import Path

from policy_config import PolicyConfig, RaiiPair
from scan_policy import is_preprocessor_at, line_number_at, strip_comments_and_strings

LINT_TITLE = "RAII lifetime policy"
LINT_FIX_HINT = "Use project RAII wrappers for acquire/release pairs."


def scan_text(path: Path, code: str, pairs: tuple[RaiiPair, ...]) -> list[str]:
    issues: list[str] = []
    for pair in pairs:
        if path.resolve() in pair.canonical_files:
            continue
        for rx in pair.acquire_rx:
            for match in rx.finditer(code):
                if is_preprocessor_at(code, match.start()):
                    continue
                issues.append(
                    f"{path}:{line_number_at(code, match.start())}: manual {pair.label} acquire "
                    f"(use RAII; {pair.hint})"
                )
        for rx in pair.release_rx:
            for match in rx.finditer(code):
                if is_preprocessor_at(code, match.start()):
                    continue
                issues.append(
                    f"{path}:{line_number_at(code, match.start())}: manual {pair.label} release "
                    f"(use RAII; {pair.hint})"
                )
    return sorted(set(issues))


def scan_file(path: Path, config: PolicyConfig) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return scan_text(path, strip_comments_and_strings(text), config.raii_pairs)


def lint(paths: list[Path], config: PolicyConfig) -> list[str]:
    return [issue for path in paths for issue in scan_file(path, config)]


def prepare_self_test_repo(root: Path) -> None:
    glob_canonical = "sample_glob_raii.h"
    file_canonical = "sample_file_raii.h"
    dir_canonical = "sample_dir_raii.h"
    dl_canonical = "sample_dl_raii.h"
    pcsc_canonical = "sample_pcsc_connect.cpp"
    serial_canonical = "sample_serial.cpp"
    cases = {
        "glob_ok.cpp": ('#include "sample_glob_raii.h"\nvoid f(){ sample::GlobResult gr; (void)gr.match("/dev/tty*"); }\n', set()),
        "glob_bad.cpp": ("#include <glob.h>\nvoid f(){ glob_t g{}; (void)glob(\"/dev/tty*\",0,0,&g); globfree(&g); }\n", {"glob_bad.cpp"}),
        "fopen_bad.c": ("void f(void){ FILE *fp=fopen(\"/tmp/x\",\"r\"); if(fp){fclose(fp);} }\n", {"fopen_bad.c"}),
        "fopen_ok.cpp": ('#include "sample_file_raii.h"\nvoid f(){ sample::FileHandle fh; (void)fh.open("/tmp/x", "r"); }\n', set()),
        "opendir_bad.c": ("void f(void){ DIR *d=opendir(\"/tmp\"); if(d){closedir(d);} }\n", {"opendir_bad.c"}),
        "dlopen_bad.cpp": ("void f(){ void *h=dlopen(\"libm.so\",0); if(h){dlclose(h);} }\n", {"dlopen_bad.cpp"}),
        "pcsc_bad.cpp": ("void f(){ SCARDCONTEXT ctx{}; (void)SCardEstablishContext(0,0,0,&ctx); (void)SCardReleaseContext(ctx); }\n", {"pcsc_bad.cpp"}),
        "open_bad.cpp": ("#include <fcntl.h>\nvoid f(){ int fd=open(\"/dev/null\",O_RDONLY); close(fd); }\n", {"open_bad.cpp"}),
        "comment_ok.c": ("/* glob(pattern, 0, NULL, &g) then globfree(&g) */ void f(void){}\n", set()),
        "raw_glob_bad.c": ("void f(){ glob_t g{}; glob(\"/dev/tty*\",0,0,&g); }\n", {"raw_glob_bad.c"}),
        "split_glob_bad.c": ("void f(){ glob_t g{}; glob\n(\"/dev/tty*\",0,0,&g); }\n", {"split_glob_bad.c"}),
    }
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "lint-c-cpp.yaml").write_text(
        "scan:\n  c_api_prefix: sample\n  c_macro_prefix: SAMPLE\n  public_headers_dir: include/sample\n"
        "  source_roots: [userspace]\n"
        "policy:\n  resource_lifetime:\n    pairs:\n"
        "      - label: glob/globfree\n        acquire: [\"\\\\bglob\\\\s*\\\\(\"]\n        release: [\"\\\\bglobfree\\\\s*\\\\(\"]\n"
        "        canonical_files: [userspace/app/sample_glob_raii.h]\n        hint: GlobResult (sample_glob_raii.h)\n"
        "      - label: fopen/fclose\n        acquire: [\"\\\\bfopen\\\\s*\\\\(\"]\n        release: [\"\\\\bfclose\\\\s*\\\\(\"]\n"
        "        canonical_files: [userspace/app/sample_file_raii.h]\n        hint: FileHandle (sample_file_raii.h)\n"
        "      - label: opendir/closedir\n        acquire: [\"\\\\bopendir\\\\s*\\\\(\"]\n        release: [\"\\\\bclosedir\\\\s*\\\\(\"]\n"
        "        canonical_files: [userspace/app/sample_dir_raii.h]\n        hint: DirHandle (sample_dir_raii.h)\n"
        "      - label: dlopen/dlclose\n        acquire: [\"\\\\bdlopen\\\\s*\\\\(\"]\n        release: [\"\\\\bdlclose\\\\s*\\\\(\"]\n"
        "        canonical_files: [userspace/app/sample_dl_raii.h]\n        hint: DlHandle (sample_dl_raii.h)\n"
        "      - label: open/close (fd)\n        acquire: [\"(?<![:\\\\w])open\\\\s*\\\\([^;)]*,\\\\s*O_[A-Z_]\"]\n        release: [\"\\\\bclose\\\\s*\\\\(\\\\s*[^)\\\\s]\"]\n"
        "        canonical_files: [userspace/app/sample_serial.cpp]\n        hint: serial_open helpers (sample_serial.cpp)\n"
        "      - label: SCardEstablishContext/SCardReleaseContext\n        acquire: [\"\\\\bSCardEstablishContext\\\\s*\\\\(\"]\n        release: [\"\\\\bSCardReleaseContext\\\\s*\\\\(\"]\n"
        "        canonical_files: [userspace/app/sample_pcsc_connect.cpp]\n        hint: PcscCard (sample_pcsc_connect.cpp)\n"
        "  unsafe_api:\n    wrapper_files:\n"
        f"      - userspace/app/{glob_canonical}\n      - userspace/app/{file_canonical}\n"
        f"      - userspace/app/{dir_canonical}\n      - userspace/app/{dl_canonical}\n"
        f"      - userspace/app/{serial_canonical}\n      - userspace/app/{pcsc_canonical}\n",
        encoding="utf-8",
    )
    app = root / "userspace" / "app"
    app.mkdir(parents=True)
    (app / glob_canonical).write_text("class GlobResult{~GlobResult(){globfree(&g_);} int match(const char*p){return glob(p,0,0,&g_);} glob_t g_;};\n", encoding="utf-8")
    (app / file_canonical).write_text("class FileHandle{~FileHandle(){if(fp_)fclose(fp_);} FILE*open(const char*p,const char*m){return fp_=fopen(p,m);} FILE*fp_;};\n", encoding="utf-8")
    (app / dir_canonical).write_text("class DirHandle{~DirHandle(){if(dir_)closedir(dir_);} DIR*open(const char*p){return dir_=opendir(p);} DIR*dir_;};\n", encoding="utf-8")
    (app / dl_canonical).write_text("class DlHandle{~DlHandle(){if(h_)dlclose(h_);} void*open(const char*p,int f){return h_=dlopen(p,f);} void*h_;};\n", encoding="utf-8")
    (app / pcsc_canonical).write_text("void list_readers_impl(){ SCARDCONTEXT ctx{}; SCardEstablishContext(0,0,0,&ctx); SCardReleaseContext(ctx); }\n", encoding="utf-8")
    (app / serial_canonical).write_text("int serial_open(const char*p){ int fd=open(p,O_RDONLY); if(fd<0)return fd; close(fd); return fd; }\n", encoding="utf-8")
    duplicate = app / "duplicate"
    duplicate.mkdir()
    (duplicate / glob_canonical).write_text(
        'void f(){ glob_t g{}; glob("*",0,0,&g); globfree(&g); }\n',
        encoding="utf-8",
    )
    for name, (content, _) in cases.items():
        (app / name).write_text(content, encoding="utf-8")
    prepare_self_test_repo._cases = cases  # type: ignore[attr-defined]


def verify_self_test(errors: list[str]) -> int:
    cases = prepare_self_test_repo._cases  # type: ignore[attr-defined]
    reported = {Path(err.split(":", 2)[0]).name for err in errors}
    for name, (_, expected) in cases.items():
        if expected and name not in reported:
            print(f"self-test miss: {name}", file=sys.stderr)
            return 1
        if not expected and name in reported:
            print(f"self-test false positive: {name}", file=sys.stderr)
            return 1
    if not any("/duplicate/sample_glob_raii.h:" in err for err in errors):
        print("self-test miss: canonical basename must not exempt another path", file=sys.stderr)
        return 1
    print("resource lifetime self-test: OK")
    return 0
