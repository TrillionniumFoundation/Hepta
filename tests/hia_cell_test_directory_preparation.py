"""Explicit test-only directory preparation for the fixed original Cell suite.

The original module, method bodies, arguments and child budgets remain intact.
Only its single TemporaryDirectory(prefix="hia-cell-native-", dir="/dev/shm")
setup call is redirected to a separately owned private directory.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib
import json
from pathlib import Path
import os
import runpy
import stat
import sys
import tempfile
import traceback

ORIGINAL_SHA256 = "f6cef59a2437140dd7bf25c84ad274b2bbbc51cf19a9770bc0810bb0fda2e1cd"
SELF = Path(__file__).resolve()
SELF_BYTES = SELF.read_bytes()
MODULES = ("tools.qualify_cell_bridge_continuation", "tools.qualify_hia_cell_bridge_native")


def _directory_identity(path):
    path = Path(path).absolute()
    st = path.lstat()
    if (path.resolve(strict=True) != path or not stat.S_ISDIR(st.st_mode)
            or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.getuid()):
        raise ValueError("Cell test directory must be a physical owned 0700 directory")
    return (st.st_dev, st.st_ino, stat.S_IMODE(st.st_mode), st.st_uid)


class _PreparedTempfile:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        self.identity = _directory_identity(self.directory)
        self.calls = []
        self.original = tempfile.TemporaryDirectory

    def __getattr__(self, name):
        return getattr(tempfile, name)

    def verify(self):
        if (_directory_identity(self.directory) != self.identity
                or tempfile.TemporaryDirectory is not self.original):
            raise ValueError("Cell test directory preparation changed")

    def TemporaryDirectory(self, *args, **kwargs):
        if args or kwargs != {"prefix": "hia-cell-native-", "dir": "/dev/shm"}:
            raise ValueError("Cell test preparation only admits the fixed original setup call")
        self.verify()
        result = self.original(prefix=kwargs["prefix"], dir=str(self.directory))
        actual = Path(result.name)
        if actual.parent != self.directory or _directory_identity(actual)[2] != 0o700:
            result.cleanup()
            raise ValueError("Cell test temporary directory escaped its prepared root")
        self.calls.append({"requested": dict(kwargs), "actual": str(actual),
                           "actual_identity": list(_directory_identity(actual))})
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--module", choices=MODULES, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    arguments = list(args.arguments)
    if arguments[:1] == ["--"]:
        arguments.pop(0)
    root = Path.cwd().resolve()
    original_path = root / "tests/test_hia_cell_bridge.py"
    original_bytes = original_path.read_bytes()
    if sha256(original_bytes).hexdigest() != ORIGINAL_SHA256:
        raise ValueError("Cell test preparation requires the complete fixed original source")
    if SELF.read_bytes() != SELF_BYTES:
        raise ValueError("Cell test preparation source changed after import")
    if args.receipt.exists():
        raise ValueError("Cell test preparation receipt already exists")
    prepared = _PreparedTempfile(args.directory)
    sys.path.insert(0, str(root))
    module_name = "tests.test_hia_cell_bridge"
    if args.module == "tools.qualify_cell_bridge_continuation":
        # The unchanged original CLI uses unittest.discover, whose module name
        # is unqualified. Prepare that exact module without aliasing its class.
        sys.path.insert(0, str(root / "tests"))
        module_name = "test_hia_cell_bridge"
    module = importlib.import_module(module_name)
    if Path(module.__file__).resolve() != original_path or module.tempfile is not tempfile:
        raise ValueError("Cell test preparation imported a different original test module")
    original_argv = list(sys.argv)
    original_tempfile = module.tempfile
    code, raised, stable = 1, None, False
    try:
        module.tempfile = prepared
        sys.argv = [args.module, *arguments]
        try:
            runpy.run_module(args.module, run_name="__main__", alter_sys=True)
            code = 0
        except SystemExit as exc:
            code = 0 if exc.code is None else exc.code if type(exc.code) is int else 1
        except BaseException:
            raised = traceback.format_exc()
        prepared.verify()
        stable = (module.tempfile is prepared
                  and original_path.read_bytes() == original_bytes
                  and SELF.read_bytes() == SELF_BYTES)
    finally:
        module.tempfile = original_tempfile
        sys.argv = original_argv
    passed = code == 0 and raised is None and stable and len(prepared.calls) == 1
    report = {
        "schema": "hepta.cell-fixed-test-directory-preparation.v1",
        "status": "PREPARED_TEST_PASS" if passed else "HOLD",
        "module": args.module, "original_test_module": module_name, "original_arguments": arguments,
        "original_source": str(original_path), "original_source_bytes": len(original_bytes),
        "original_source_sha256": ORIGINAL_SHA256,
        "preparation_source": str(SELF), "preparation_source_bytes": len(SELF_BYTES),
        "preparation_source_sha256": sha256(SELF_BYTES).hexdigest(),
        "actual_directory": str(prepared.directory),
        "directory_identity": list(prepared.identity), "calls": prepared.calls,
        "source_stable": stable, "returncode": code, "raised": raised,
        "original_method_source_unchanged": stable,
        "original_child_limits_changed": False, "global_tempfile_changed": False,
        "global_mount_changed": False, "native_cold_qualification_claimed": False,
        "whole_stack_qualified": False,
    }
    args.receipt.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    if raised:
        print(raised, file=sys.stderr, end="")
    print(json.dumps({"test_preparation": report["status"], "receipt": str(args.receipt)}))
    return 0 if passed else code if type(code) is int and code != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
