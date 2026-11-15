"""Owned-child actual route controls; no C compilation and no expected oracle import."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
import sys
import threading
import time
import traceback
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    admit_product, canonical, regular_bytes, write_json)
from hepta import hia_native_helpers as helpers
from hepta import hia_slot_operations_native as native
from hepta import hia_slot_operations_selection as selection
from hepta.hia_slot_ledger_native import NativeSlotLedgerStore as Store
from hepta.hia_native_delivery import current_record

CASES = (
    "direct-env", "explicit-owner", "v1-scope", "v1-unprimed-to-v5",
    "v1-primed-to-v5", "v5-live", "v5-closed", "v5-equivalent-scope",
    "v5-thread", "v5-fork", "v5-bundle-drift", "v5-bad-digest",
    "raw-frame-legacy", "new-v1-after-v5", "v5-argument-binding",
    "v5-real-receipt-loss", "v5-original-provider-error",
)

def require(value, message):
    if not value:
        raise AssertionError(message)

def error_record(error):
    return {"type": type(error).__module__ + "." + type(error).__qualname__,
            "message": str(error)}

def counters():
    module = sys.modules.get("hepta.hia_slot_mechanical")
    loaded = None if module is None else module._EXTENSION
    if loaded is None:
        return None
    module._check_exports(loaded)
    return loaded.execution_counters()

def no_new_initialization(before, after):
    if before is None:
        require(after is None or sum(after["initialized"]) == 0, "refusal initialized C/HIA")
    else:
        require(after["pid"] == before["pid"]
                and after["initialized"] == before["initialized"], "refusal initialized C/HIA")

@contextmanager
def direct(path):
    missing = object()
    old = os.environ.get(selection.SELECTOR, missing)
    os.environ[selection.SELECTOR] = str(path)
    try:
        yield
    finally:
        if old is missing:
            os.environ.pop(selection.SELECTOR, None)
        else:
            os.environ[selection.SELECTOR] = old

@contextmanager
def watch(path, events, *, lost=None, records=None):
    image = native.installed_slot_operations(path)
    saved = image._entry
    def actual(*args):
        result = saved(*args)
        events.append({"actual_entry_returned": True})
        if lost is not None:
            records.append(current_record())
            raise lost
        return result
    image._entry = actual
    try:
        yield image
    finally:
        image._entry = saved

@contextmanager
def deny_legacy_finish(events):
    saved = native.SlotOperationsFrame.finish
    def denied(self):
        events.append("legacy-finish-after-v5")
        raise AssertionError("v5 silently fell back to the original HIA bridge")
    native.SlotOperationsFrame.finish = denied
    try:
        yield
    finally:
        native.SlotOperationsFrame.finish = saved

def receiver(trace, fault=None):
    def provider(*args, **kw):
        trace.append({"args": list(args), "kwargs": kw})
        if fault is not None:
            raise fault
        return types.SimpleNamespace(values=(17,))
    return types.SimpleNamespace(_call=provider)

def invoke(function, trace, fault=None):
    return function(receiver(trace, fault), 17, "generation")

def rejected(function, kind, trace):
    try:
        invoke(function, trace)
    except BaseException as error:
        require(type(error) is kind, ("wrong actual refusal", error_record(error)))
        return error_record(error)
    raise AssertionError("expected refusal returned")

def fork_call(function):
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            trace = []
            error = rejected(function, ValueError, trace)
            report = {"error": error, "trace": trace, "counters": counters(),
                      "pid": os.getpid()}
            os.write(write_fd, canonical(report) + b"\n")
            os.close(write_fd)
            os._exit(0)
        except BaseException:
            traceback.print_exc()
            os._exit(1)
    os.close(write_fd)
    reaped = False
    try:
        deadline = time.monotonic() + 5
        raw = bytearray()
        status = None
        while time.monotonic() < deadline:
            ready, _, _ = select.select([read_fd], [], [], min(.05, max(0, deadline-time.monotonic())))
            if ready:
                part = os.read(read_fd, 16384)
                raw.extend(part)
            waited, value = os.waitpid(pid, os.WNOHANG)
            if waited:
                reaped = True
                status = value
                while True:
                    part = os.read(read_fd, 16384)
                    if not part:
                        break
                    raw.extend(part)
                break
        require(reaped and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                "owned fork refusal did not naturally finish")
        value = json.loads(raw)
        require(value["pid"] == pid and value["trace"] == []
                and value["counters"]["pid"] == pid
                and sum(value["counters"]["initialized"]) == 0,
                "fork inherited authorization or parent counters")
        return {"pid": pid, "reaped": True, "exit_code": 0, "raw": raw.decode()}
    finally:
        os.close(read_fd)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)

def run_case(name, controller, base, base_sha, bundle, bundle_sha, directory):
    # Actual retained method first, only for this new mechanical route witness.
    # The complete original248/derived7574/public84/handled12 remain separate.
    old = Store._hia_slot_reference_methods["validate_u64"]
    expected_trace = []
    expected = invoke(old, expected_trace)
    require(expected == 17, "retained route witness did not return its result")
    trace, entries, forbidden = [], [], []
    detail = {"reference_result": expected, "reference_trace": expected_trace,
              "initial_counters": counters(), "case": name}
    v5 = lambda: helpers.native_helpers_scope(str(bundle), bundle_sha)
    v1 = lambda: helpers.native_helpers_scope(str(base), base_sha)
    def healthy(function, c_route):
        require((type(function) is types.FunctionType) is (not c_route),
                "captured callable selected the wrong explicit route")
        before = counters()
        with watch(controller, entries):
            actual = invoke(function, trace)
        after = counters()
        require(actual == expected and trace == expected_trace and entries,
                "actual HIA route differs from the retained provider trace")
        if c_route:
            require(after["initialized"][5] > before["initialized"][5]
                    and after["public_calls"][5] > before["public_calls"][5]
                    and after["raw_frame_calls"] == before["raw_frame_calls"],
                    "selected public callable did not enter C/HIA")
        else:
            no_new_initialization(before, after)
        detail["route_before"], detail["route_after"] = before, after

    if name == "direct-env":
        with direct(controller):
            healthy(Store.validate_u64, False)
        require(counters() is None, "direct env loaded an unauthorized C extension")
    elif name == "explicit-owner":
        with selection.slot_operations_owner(controller):
            healthy(Store.validate_u64, False)
        require(counters() is None, "original owner loaded C")
    elif name == "v1-scope":
        with v1():
            require(helpers.selected_mechanical_bridge("slot-mechanical",
                    "hepta.slot.mechanical.cpython-gil-linux.v1") is None, "v1 became v5")
            healthy(Store.validate_u64, False)
        require(counters() is None, "v1 loaded C")
    elif name in ("v1-unprimed-to-v5", "v1-primed-to-v5"):
        with v1():
            function = Store.validate_u64
            if name == "v1-primed-to-v5":
                healthy(function, False)
                trace.clear(); entries.clear()
        with v5():
            before = counters()
            require(type(function) is types.FunctionType, "v1 callable changed type")
            if name == "v1-unprimed-to-v5":
                healthy(function, False)
            else:
                with watch(controller, entries):
                    detail["error"] = rejected(function, native.SlotOperationsUnknown, trace)
                require(trace == [] and entries == [], "old captured-image refusal ran provider")
            no_new_initialization(before, counters())
    elif name == "raw-frame-legacy":
        image = native.installed_slot_operations(controller)
        before = counters()
        frame = native.SlotOperationsFrame(image, 5,
            {"self": receiver(trace), "value": 17, "label": "generation"})
        with watch(controller, entries):
            actual = frame.finish()
        require(actual == expected and trace == expected_trace and entries,
                "raw Frame changed its original HIA finish")
        no_new_initialization(before, counters())
        require(counters() is None, "raw Frame implicitly authorized a linker load")
    elif name == "new-v1-after-v5":
        with v5():
            require(counters() is not None, "v5 did not load its authorized C image")
        with v1():
            healthy(Store.validate_u64, False)
    elif name == "v5-bad-digest":
        wrong = ("0" if bundle_sha[0] != "0" else "1") + bundle_sha[1:]
        try:
            with helpers.native_helpers_scope(str(bundle), wrong):
                raise AssertionError("wrong administrator digest acquired authority")
        except ValueError as error:
            detail["error"] = error_record(error)
        require(counters() is None and trace == [] and entries == [],
                "failed v5 load fell back or entered C")
    elif name == "v5-closed":
        with v5():
            function = Store.validate_u64
        before = counters()
        with deny_legacy_finish(forbidden):
            detail["error"] = rejected(function, ValueError, trace)
        no_new_initialization(before, counters())
        require(trace == [], "closed v5 ran a provider")
    elif name == "v5-equivalent-scope":
        with v5() as first:
            function = Store.validate_u64
        with v5() as second:
            require(second is not first and second.sha256 == first.sha256,
                    "equivalent authority control did not create a new instance")
            before = counters()
            with deny_legacy_finish(forbidden):
                detail["error"] = rejected(function, ValueError, trace)
            no_new_initialization(before, counters())
            require(trace == [], "new scope authorized the captured old C callable")
            healthy(Store.validate_u64, True)
    elif name == "v5-bundle-drift":
        copy = directory / "same-content-v5.json"
        original = regular_bytes(bundle)
        copy.write_bytes(original)
        with helpers.native_helpers_scope(str(copy), bundle_sha):
            function = Store.validate_u64
            before = counters()
            try:
                copy.write_bytes(original + b"\n")
                with deny_legacy_finish(forbidden):
                    detail["error"] = rejected(function, ValueError, trace)
                no_new_initialization(before, counters())
                require(trace == [], "changed pinned bundle ran a provider")
                detail["actual_mutation_sha256"] = sha256(regular_bytes(copy)).hexdigest()
            finally:
                copy.write_bytes(original)
            require(regular_bytes(copy) == original, "copied bundle was not restored")
    else:
        with v5():
            function = Store.validate_u64
            before = counters()
            with deny_legacy_finish(forbidden):
                if name == "v5-live":
                    healthy(function, True)
                elif name == "v5-thread":
                    found = []
                    def child():
                        try:
                            found.append({"error": rejected(function, ValueError, trace)})
                        except BaseException as error:
                            found.append({"unexpected": error_record(error)})
                    worker = threading.Thread(target=child, daemon=True)
                    worker.start(); worker.join(5)
                    require(not worker.is_alive() and len(found) == 1
                            and set(found[0]) == {"error"} and trace == [],
                            "foreign-thread callable was authorized or not joined")
                    detail["thread"] = found[0]
                    no_new_initialization(before, counters())
                elif name == "v5-fork":
                    detail["fork"] = fork_call(function)
                    no_new_initialization(before, counters())
                elif name == "v5-argument-binding":
                    try:
                        function(receiver(trace))
                    except TypeError as error:
                        detail["error"] = error_record(error)
                    else:
                        raise AssertionError("original signature accepted missing arguments")
                    require(trace == [], "invalid binding ran provider")
                    no_new_initialization(before, counters())
                elif name == "v5-original-provider-error":
                    fault = RuntimeError("independent route provider error")
                    try:
                        with watch(controller, entries):
                            invoke(function, trace, fault)
                    except BaseException as error:
                        require(error is fault, "confirmed provider error identity changed")
                        detail["error"] = error_record(error)
                    else:
                        raise AssertionError("provider error was swallowed")
                    require(trace == expected_trace and entries, "provider trace changed")
                    require(counters()["final_receipts"][5] > before["final_receipts"][5],
                            "ordinary provider error lacks its actual final receipt")
                elif name == "v5-real-receipt-loss":
                    fault = ValueError("actual Slot entry returned; its receipt was withheld")
                    records = []
                    try:
                        with watch(controller, entries, lost=fault, records=records):
                            invoke(function, trace)
                    except native.SlotOperationsUnknown as error:
                        detail["error"] = error_record(error)
                    else:
                        raise AssertionError("real native receipt loss returned")
                    require(entries and trace == [] and records
                            and records[0] is not None and records[0].loss is not None
                            and records[0].loss.error is fault,
                            "loss was not recorded by the actual native handoff")
                    detail["actual_record_loss_is_injected_fault"] = True
                    require(counters()["final_receipts"] == before["final_receipts"],
                            "lost initialization receipt falsely finalized")
                else:
                    raise ValueError("unknown route control")
    require(forbidden == [], "v5 used original finish fallback")
    detail.update({"provider_trace": trace, "actual_entries": entries,
        "forbidden_legacy_finish": forbidden, "final_counters": counters(),
        "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp(),
        "argv": list(sys.argv), "status": "PASS"})
    return detail

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("controller", "base-v1", "bridge-bundle", "product-freeze", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("base-sha256", "expected-bridge-sha256", "product-freeze-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = admit_product(ROOT, args.product_freeze, args.product_freeze_sha256)
    before = {str(p): regular_bytes(p) for p in (args.controller, args.base_v1, args.bridge_bundle)}
    require(sha256(before[str(args.base_v1)]).hexdigest() == args.base_sha256
            and sha256(before[str(args.bridge_bundle)]).hexdigest() == args.expected_bridge_sha256,
            "external administrator input changed")
    report = {"schema": "hepta.slot.mechanical.route-control.v1", "case": args.case,
              "status": "HOLD", "source_before": sources}
    try:
        report["detail"] = run_case(args.case, args.controller, args.base_v1,
            args.base_sha256, args.bridge_bundle, args.expected_bridge_sha256, args.output)
        require(admit_product(ROOT, args.product_freeze, args.product_freeze_sha256) == sources,
                "product sources changed")
        require(all(regular_bytes(p) == raw for p, raw in before.items()), "route input changed")
        report["source_after"] = sources
        report["status"] = "PASS"
    except BaseException as error:
        report["error"] = error_record(error)
        report["traceback"] = traceback.format_exc()
        raise
    finally:
        write_json(args.output / "report.json", report)
    terminal_raw = regular_bytes(args.output / "report.json")
    print(json.dumps({"case": args.case, "status": "PASS", "report": {
        "bytes": len(terminal_raw), "sha256": sha256(terminal_raw).hexdigest()}}, sort_keys=True))
    require(regular_bytes(args.output / "report.json") == terminal_raw,
            "terminal route report changed after its stdout pin")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
