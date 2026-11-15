"""Separate fresh-child checks of actual v5 admission and real linker boundaries.

The parent first verifies a real built image and copies an exact private package.
No control writes a shared product file, supplies expected observations to the
candidate, or turns an original v1 Native6 result into v5 qualification.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import traceback

CASES = [["ordinary-import",None,False],["unselected-refusal","ValueError:mechanical executable is outside the pinned worker bundle",False],["healthy",None,True],["wrong-expected","ValueError:native helper bundle identity mismatch",False],["v1-has-no-bridge","ValueError:mechanical executable is outside the pinned worker bundle",False],["extra-outer","ValueError:unsupported mechanical worker capsule schema",False],["duplicate-bridge","ValueError:unsupported mechanical worker capsule schema",False],["wrong-abi","ValueError:administrator mechanical ABI/profile differs",False],["wrong-profile","ValueError:administrator mechanical ABI/profile differs",False],["wrong-package-path","ValueError:administrator mechanical package path differs",False],["wrong-receipt-pin","ValueError:administrator mechanical executable/source/receipt pin differs",False],["wrong-binary-pin","ValueError:administrator mechanical executable/source/receipt pin differs",False],["wrong-c-source-pin","ValueError:administrator mechanical executable/source/receipt pin differs",False],["wrong-source-path","ValueError:administrator mechanical executable/source/receipt pin differs",False],["receipt-drift","ValueError:administrator mechanical executable/source/receipt pin differs",False],["binary-drift","ValueError:Slot mechanical executable changed",False],["c-source-drift","ValueError:Slot mechanical source changed",False],["receipt-last-boundary-drift","ValueError:mechanical capsule changed",False],["write-failure","OSError:mechanical-test-write-failure",False],["seal-readback-failure","ValueError:mechanical executable descriptor differs before linker load",False],["close-failure-no-retry","OSError:mechanical-test-close-unconfirmed",False],["live-export-drift","ValueError:mechanical executed export changed",True],["live-source-drift","ValueError:Slot mechanical source changed",True],["cross-thread","ValueError:",True],["stale-owner","ValueError:",True]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "package", "base-v1", "source-capsule", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--base-sha256", required=True)
    parser.add_argument("--source-capsule-sha256", required=True)
    parser.add_argument("--case", choices=[row[0] for row in CASES], required=True)
    args = parser.parse_args()
    output = args.evidence.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = args.root.resolve(strict=True)
    sys.path.insert(0, str(root))
    from tests.hia_slot_operations_qualification_support import canonical, regular_bytes, pin, write_json
    from tools.build_hia_slot_mechanical_bundle import create
    original_package = args.package.resolve(strict=True)
    source_capsule_raw = regular_bytes(args.source_capsule)
    assert sha256(source_capsule_raw).hexdigest() == args.source_capsule_sha256
    source_capsule = json.loads(source_capsule_raw)
    source_bridge, = source_capsule["bridges"]
    assert source_capsule["schema"] == "hepta.hia.native-helpers.v5"
    assert source_bridge["package_path"] == str(original_package)
    source_inputs = [source_bridge["build_receipt"], source_bridge["binary"],
                     *source_bridge["sources"].values()]
    for source_input in source_inputs:
        assert pin(source_input["path"]) == {k: source_input[k] for k in ("bytes", "sha256")}
    package = output / "package/hepta"
    package.parent.mkdir()
    shutil.copytree(original_package, package, ignore=shutil.ignore_patterns("__pycache__"))
    base_raw = regular_bytes(args.base_v1)
    assert sha256(base_raw).hexdigest() == args.base_sha256
    receipt = package / "_slot_mechanical_build.json"
    capsule = output / "v5.json"
    administrator = create(package, args.base_v1, args.base_sha256, pin(receipt)["sha256"], capsule)
    capsule_raw = regular_bytes(capsule)
    original = json.loads(capsule_raw)
    actual_bridge, = original["bridges"]
    for field in ("binary", "build_receipt"):
        assert {k: actual_bridge[field][k] for k in ("bytes", "sha256")} == {
            k: source_bridge[field][k] for k in ("bytes", "sha256")}
    assert set(actual_bridge["sources"]) == set(source_bridge["sources"])
    for name in actual_bridge["sources"]:
        assert {k: actual_bridge["sources"][name][k] for k in ("bytes", "sha256")} == {
            k: source_bridge["sources"][name][k] for k in ("bytes", "sha256")}
    selected = json.loads(capsule_raw)
    binary = package / original["bridges"][0]["binary"]["name"]
    c_source = package / "native/slot_mechanical.c"
    originals = {path: regular_bytes(path) for path in (receipt, binary, c_source)}
    sys.path.insert(0, str(package.parent))
    assert not any(name == "hepta" or name.startswith("hepta.") for name in sys.modules)
    import _imp
    calls, closes = [], []
    create_dynamic = _imp.create_dynamic
    def counted(spec, *a, **kw):
        if spec.name == "hepta._hia_slot_mechanical":
            calls.append({"name": spec.name, "origin": spec.origin})
        return create_dynamic(spec, *a, **kw)
    _imp.create_dynamic = counted
    from hepta import hia_native_helpers as helpers, hia_slot_mechanical as mechanical
    assert Path(mechanical.__file__).resolve().parent == package
    assert mechanical._EXTENSION is None and calls == []
    expected = administrator["sha256"]
    chosen = capsule
    mode, expected_error, expect_loaded = next(row for row in CASES if row[0] == args.case)
    target = selected["bridges"][0]
    restore = []
    terminal = None
    caught = None
    live = None

    def swap(obj, name, value):
        old = getattr(obj, name)
        restore.append((obj, name, old))
        setattr(obj, name, value)
        return old

    def read_back_error(operation):
        nonlocal caught
        try:
            operation()
        except BaseException as error:
            caught = {"type": type(error).__module__ + "." + type(error).__qualname__,
                      "message": str(error), "traceback": traceback.format_exc()}
            if expected_error is None:
                raise
            kind, text = expected_error.split(":", 1)
            assert type(error).__name__ == kind, caught
            assert text in str(error), caught
        else:
            assert expected_error is None, "expected actual refusal did not happen"

    try:
        if mode == "wrong-expected":
            expected = "0" * 64 if expected != "0" * 64 else "1" * 64
        elif mode == "v1-has-no-bridge":
            chosen, expected = args.base_v1, args.base_sha256
        elif mode == "extra-outer":
            selected["unexpected"] = True
        elif mode == "duplicate-bridge":
            selected["bridges"].append(dict(target))
        elif mode == "wrong-abi":
            target["abi"] += "-different"
        elif mode == "wrong-profile":
            target["profile"]["python"][2] += 1
        elif mode == "wrong-package-path":
            # It is a real byte-identical copy, not a nonexistent basename.
            twin = output / "same-bytes/hepta"
            twin.parent.mkdir()
            shutil.copytree(package, twin)
            assert regular_bytes(twin / "native/slot_mechanical.c") == originals[c_source]
            target["package_path"] = str(twin)
        elif mode == "wrong-receipt-pin":
            target["build_receipt"]["sha256"] = "0" * 64
        elif mode == "wrong-binary-pin":
            target["binary"]["sha256"] = "0" * 64
        elif mode == "wrong-c-source-pin":
            target["sources"]["hepta/native/slot_mechanical.c"]["sha256"] = "0" * 64
        elif mode == "wrong-source-path":
            target["sources"]["hepta/native/slot_mechanical.c"]["path"] += ".same-hash"
        if selected != original:
            capsule.write_bytes(canonical(selected) + b"\n")
            expected = sha256(regular_bytes(capsule)).hexdigest()
        if mode == "receipt-drift":
            receipt.write_bytes(originals[receipt] + b"\n")
        elif mode == "binary-drift":
            raw = originals[binary]
            binary.write_bytes(raw[:-1] + bytes((raw[-1] ^ 1,)))
        elif mode == "c-source-drift":
            c_source.write_bytes(originals[c_source] + b"\n")
        elif mode == "receipt-last-boundary-drift":
            original_spec = importlib.util.spec_from_file_location
            def drift(name, path, *a, **kw):
                spec = original_spec(name, path, *a, **kw)
                if name == "hepta._hia_slot_mechanical":
                    receipt.write_bytes(originals[receipt] + b"\n")
                return spec
            swap(importlib.util, "spec_from_file_location", drift)
        if mode in ("write-failure", "seal-readback-failure", "receipt-last-boundary-drift", "close-failure-no-retry"):
            real_close = os.close
            def close(fd):
                ours = any(row[0] == fd and not row[3] in ("CLOSED", "NOT_CREATED")
                           for row in mechanical._LOADER_CUSTODY)
                if ours:
                    closes.append(fd)
                result = real_close(fd)
                if ours and mode == "close-failure-no-retry":
                    raise OSError("mechanical-test-close-unconfirmed")
                return result
            swap(os, "close", close)
        if mode in ("write-failure", "close-failure-no-retry"):
            actual_write = os.write
            partial_writes = []
            def failed_write(fd, data):
                if not partial_writes:
                    result = actual_write(fd, data[:1])
                    partial_writes.append(result)
                    return result
                raise OSError("mechanical-test-write-failure")
            swap(os, "write", failed_write)
        elif mode == "seal-readback-failure":
            real_fcntl = mechanical.fcntl.fcntl
            def wrong_seals(fd, command, *a):
                result = real_fcntl(fd, command, *a)
                return 0 if command == mechanical.fcntl.F_GET_SEALS else result
            swap(mechanical.fcntl, "fcntl", wrong_seals)

        def run():
            nonlocal terminal, live
            if mode == "ordinary-import":
                assert mechanical._EXTENSION is None
                assert mechanical.preload_if_present() is None and calls == []
                return
            if mode == "unselected-refusal":
                with helpers.native_helpers_scope(None, None):
                    mechanical.extension()
                return
            if mode == "stale-owner":
                with helpers.native_helpers_scope(str(chosen), expected):
                    owner = helpers.pinned_mechanical_bridge("slot-mechanical", mechanical.ABI)
                    captured = mechanical._bundle()
                    mechanical.extension()
                owner.current(captured)
                return
            with helpers.native_helpers_scope(str(chosen), expected):
                module = mechanical.extension()
                live = {"binary": {k: target["binary"][k] for k in ("bytes", "sha256")},
                        "module_file": module.__file__, "abi": module.ABI,
                        "modes": module.MODES, "ports": module.PORTS,
                        "seals": mechanical.fcntl.fcntl(mechanical._SEALED[0],
                                                      mechanical.fcntl.F_GET_SEALS)}
                assert mechanical.extension() is module
                if mode == "live-export-drift":
                    saved = module.ack
                    module.ack = module.begin
                    try:
                        mechanical.extension()
                    finally:
                        module.ack = saved
                elif mode == "live-source-drift":
                    c_source.write_bytes(originals[c_source] + b"\n")
                    try:
                        mechanical.extension()
                    finally:
                        c_source.write_bytes(originals[c_source])
                elif mode == "cross-thread":
                    found = []
                    def other_thread():
                        try:
                            mechanical.extension()
                        except BaseException as error:
                            found.append(error)
                    worker = threading.Thread(target=other_thread)
                    worker.start()
                    worker.join(5)
                    assert not worker.is_alive() and len(found) == 1
                    raise found.pop()
                terminal = helpers.native_helpers_identity()
        read_back_error(run)
        assert (mechanical._EXTENSION is not None) is expect_loaded
        assert len(calls) == (1 if expect_loaded else 0), calls
        assert (caught is not None) is (expected_error is not None)
        if mode in ("write-failure", "seal-readback-failure", "receipt-last-boundary-drift", "close-failure-no-retry"):
            assert len(closes) == 1
            owned, = mechanical._LOADER_CUSTODY
            assert owned[0] == closes[0] and owned[2] is True
            assert owned[3] == ("CLOSE_UNCONFIRMED" if mode == "close-failure-no-retry" else "CLOSED")
            if mode == "close-failure-no-retry":
                try:
                    mechanical._close_loader_descriptor(owned)
                except RuntimeError as error:
                    assert str(error) == "mechanical descriptor close was already attempted"
                else:
                    raise AssertionError("uncertain descriptor close was retried")
                assert len(closes) == 1
            try:
                os.fstat(owned[0])
            except OSError as error:
                import errno
                assert error.errno == errno.EBADF
            else:
                raise AssertionError("owned descriptor remains open")
        if mode == "healthy":
            assert terminal == {"native_helpers_sha256": expected}
            assert live["seals"] == 15 and live["modes"] == 15 and live["ports"] == 136
        result = {"schema": "hepta.slot.mechanical.admission-case.v1", "status": "PASS",
            "case": mode, "expected_error": expected_error, "expected_loaded": expect_loaded,
            "error": caught, "linker_calls": calls, "close_calls": closes, "live": live,
            "terminal": terminal, "base_bundle": {"path": str(args.base_v1), **pin(args.base_v1)},
            "source_capsule": {"path": str(args.source_capsule), "bytes": len(source_capsule_raw),
                               "sha256": args.source_capsule_sha256},
            "original_capsule": administrator, "attempted_capsule": {"path": str(chosen), **pin(chosen)},
            "supplied_expected_sha256": expected,
            "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp(),
            "argv": list(sys.argv), "fixture_admin_pins_explicit": True,
            "original_Native6_replaced": False, "whole_native_stack_qualified": False}
    finally:
        for obj, name, value in reversed(restore):
            setattr(obj, name, value)
        for path, raw in originals.items():
            path.write_bytes(raw)
        _imp.create_dynamic = create_dynamic
        assert regular_bytes(args.base_v1) == base_raw
        assert regular_bytes(args.source_capsule) == source_capsule_raw
        for source_input in source_inputs:
            assert pin(source_input["path"]) == {k: source_input[k] for k in ("bytes", "sha256")}
    write_json(output / "report.json", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
