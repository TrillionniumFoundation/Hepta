"""DEF-21 first-load fork/epoch proposal; STATIC, never executed by author.

Call run_epoch_control only from a separately owned, fresh diagnostic process.
The caller supplies the real current v5 bundle and its exact digest. This does
not replace any original route/admission/finite gate. It neither patches an
epoch nor fabricates a loader exception, close receipt, native call or terminal.
"""
import errno
import json
import os
from pathlib import Path
import select
import signal
import sys
import time
import traceback


def _dump(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def _create(path, raw):
    with open(path, "xb") as stream:
        stream.write(raw)


def _error_graph(error):
    if error is None:
        return {"root": None, "nodes": [], "formatted": ""}
    pending = [error]
    numbers = {id(error): 0}
    nodes = []
    at = 0
    while at < len(pending):
        current = pending[at]
        edges = {}
        for label, related in (("cause", current.__cause__),
                               ("context", current.__context__)):
            if related is None:
                edges[label] = None
            else:
                number = numbers.get(id(related))
                if number is None:
                    number = len(pending)
                    numbers[id(related)] = number
                    pending.append(related)
                edges[label] = number
        frames = []
        cursor = current.__traceback__
        while cursor is not None:
            # No frame.f_locals, frame.clear, clear_frames or traceback mutation.
            frame = cursor.tb_frame
            frames.append({"file": frame.f_code.co_filename,
                           "name": frame.f_code.co_name,
                           "line": cursor.tb_lineno})
            cursor = cursor.tb_next
        nodes.append({"number": at,
                      "module": type(current).__module__,
                      "qualname": type(current).__qualname__,
                      "message": str(current),
                      "suppress_context": current.__suppress_context__,
                      "cause": edges["cause"], "context": edges["context"],
                      "frames": frames})
        at += 1
    return {"root": 0, "nodes": nodes,
            "formatted": "".join(traceback.format_exception(
                type(error), error, error.__traceback__))}


def _counter_delta(before, after, mode):
    problems = []
    if (before.get("schema") != "hepta.slot.mechanical.execution-counters.v1"
            or after.get("schema") != before.get("schema")
            or type(after.get("pid")) is not int
            or before.get("pid") != os.getpid()
            or after.get("pid") != os.getpid()
            or before.get("overflow") is not False
            or after.get("overflow") is not False):
        problems.append("counter header")
    differences = {}
    for name in ("public_calls", "raw_frame_calls", "initialized",
                 "final_receipts"):
        left, right = before.get(name), after.get(name)
        if (type(left) is not list or type(right) is not list
                or len(left) != 16 or len(right) != 16
                or any(type(x) is not int for x in left + right)):
            problems.append("counter shape:" + name)
            continue
        delta = [b - a for a, b in zip(left, right)]
        differences[name] = delta
        wanted = [0] * 16
        if name != "raw_frame_calls":
            wanted[mode] = 1
        if delta != wanted:
            problems.append("counter delta:" + name)
    return differences, problems


def _read_and_reap(child_pid, fd, deadline, limit):
    """Drain while waiting, then prove this actual direct child was reaped."""
    raw = bytearray()
    eof = False
    wait_status = None
    signals = []
    errors = []
    timed_out = False
    try:
        while not (eof and wait_status is not None):
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                break
            if not eof:
                readable, _, _ = select.select([fd], [], [], min(.1, deadline - now))
                if readable:
                    block = os.read(fd, min(65536, limit + 1 - len(raw)))
                    if not block:
                        eof = True
                    else:
                        raw.extend(block)
                        if len(raw) > limit:
                            errors.append("child report exceeds declared IPC limit")
                            break
            else:
                select.select([], [], [], min(.05, deadline - now))
            if wait_status is None:
                actual_pid, status = os.waitpid(child_pid, os.WNOHANG)
                if actual_pid == child_pid:
                    wait_status = status
    finally:
        if wait_status is None:
            # Only this actually forked direct child is targeted; the enclosing
            # diagnostic supervisor continues to own the complete process group.
            try:
                os.kill(child_pid, signal.SIGTERM)
                signals.append("SIGTERM")
            except ProcessLookupError:
                pass
            stop = time.monotonic() + 1.0
            while wait_status is None and time.monotonic() < stop:
                actual_pid, status = os.waitpid(child_pid, os.WNOHANG)
                if actual_pid == child_pid:
                    wait_status = status
                    break
                select.select([], [], [], .02)
            if wait_status is None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                    signals.append("SIGKILL")
                except ProcessLookupError:
                    pass
                actual_pid, wait_status = os.waitpid(child_pid, 0)
                if actual_pid != child_pid:
                    raise AssertionError("waitpid returned another child")
    return {"raw": bytes(raw), "eof": eof, "wait_status": wait_status,
            "returncode": os.waitstatus_to_exitcode(wait_status),
            "reaped": True, "timed_out": timed_out,
            "signals": signals, "errors": errors}


def run_epoch_control(bundle_path, bundle_sha256, output, *,
                      child_seconds, max_report_bytes=262144):
    """Actual owned fork lane; parent asserts after preserving all raw evidence.

    child_seconds is an explicit additional-control limit chosen by its owner.
    It does not change any original Source, Native, route or admission budget.
    The parent begins its fork deadline immediately after the real fork and
    does not issue its healthy call until the child has naturally exited.
    """
    if type(child_seconds) is not int or child_seconds <= 0:
        raise ValueError("DEF-21 requires an exact positive child budget")
    if type(max_report_bytes) is not int or max_report_bytes < 65536:
        raise ValueError("DEF-21 requires an exact bounded report limit")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    if "hepta._hia_slot_mechanical" in sys.modules:
        raise AssertionError("DEF-21 requires a genuinely fresh unloaded process")

    from hepta import hia_slot_ledger_native as ledger

    names = ("__init__", "_execute", "_call", "snapshot", "validate_u64",
             "conditional", "_begin", "admit_evaluation", "admit_net_benefit",
             "adopt", "rollback", "_lease_value", "acquire", "lease", "release")
    definitions = tuple(vars(ledger.NativeSlotLedgerStore)[name]._mechanical_definition
                        for name in names)
    cold = {"pid": os.getpid(), "definitions": len(definitions),
            "extension_in_sys_modules": "hepta._hia_slot_mechanical" in sys.modules,
            "loader_imported_by_ledger": "hepta.hia_slot_mechanical" in sys.modules}
    # Importing the pure ledger definitions must not have loaded the C image.
    # Record loader import separately: an enclosing harness import is not silently
    # relabelled as this required fresh ledger-only boundary.
    if cold["extension_in_sys_modules"] or cold["loader_imported_by_ledger"]:
        raise AssertionError("ledger import crossed DEF-21 fresh loader boundary")

    from hepta import hia_slot_mechanical as mechanical
    from hepta.hia_native_helpers import native_helpers_scope
    if (mechanical._EXTENSION is not None or mechanical._CAPTURED is not None
            or mechanical._SEALED is not None or mechanical._EXPORTED != ()
            or mechanical._LOADING or mechanical._BROKEN_LOAD
            or mechanical._LOADER_CUSTODY):
        raise AssertionError("DEF-21 loader was already used")
    if not hasattr(os, "fork"):
        raise AssertionError("actual admitted fork profile is required")

    original_load = mechanical._load_sealed
    initial_epoch = mechanical._EPOCH
    original_pid = os.getpid()
    read_fd, write_fd = os.pipe()
    open_owned = {read_fd, write_fd}
    closes = []
    state = {"role": "parent", "child_pid": None, "payload": None,
             "load_calls": 0, "fork_monotonic": None}
    parent_error = None
    child_error = None
    healthy = None
    waited = None

    def close_owned(fd):
        if fd not in open_owned:
            raise AssertionError("DEF-21 attempted a second test-fd close")
        open_owned.remove(fd)  # an uncertain close is never retried
        receipt = {"fd": fd, "attempted": True, "confirmed": False}
        closes.append(receipt)
        os.close(fd)
        receipt["confirmed"] = True

    def transparent_load(captured):
        actual = original_load(captured)
        loaded, descriptor_owner, seals = actual
        try:
            if state["load_calls"] != 0:
                raise AssertionError("DEF-21 load unexpectedly repeated")
            state["load_calls"] = 1
            state["payload"] = actual
            child_pid = os.fork()  # actual registered at-fork callbacks run here
            if child_pid == 0:
                state["role"] = "child"
                state["child_pid"] = os.getpid()
                close_owned(read_fd)
            else:
                state["child_pid"] = child_pid
                state["fork_monotonic"] = time.monotonic()
                close_owned(write_fd)
            return actual  # original module/owner/seals, unmodified
        except BaseException:
            # A test-fixture failure after original_load returned cannot leave
            # its real FD unowned merely because extension's tuple assignment
            # has not executed yet. This branch is never a passing epoch result.
            if sys.modules.get("hepta._hia_slot_mechanical") is loaded:
                del sys.modules["hepta._hia_slot_mechanical"]
            if not descriptor_owner[2]:
                mechanical._close_loader_descriptor(descriptor_owner)
            raise

    try:
        mechanical._load_sealed = transparent_load
        try:
            with native_helpers_scope(str(bundle_path), bundle_sha256):
                if state["role"] == "child":
                    raise AssertionError("forked old initializer was accepted")
                if state["child_pid"] is None:
                    raise AssertionError("real loader wrapper did not fork")
                waited = _read_and_reap(
                    state["child_pid"], read_fd,
                    state["fork_monotonic"] + child_seconds, max_report_bytes)
                close_owned(read_fd)
                loaded, descriptor_owner, seals = state["payload"]
                if (mechanical._EPOCH is not initial_epoch
                        or mechanical._EXTENSION is not loaded
                        or mechanical._SEALED != (descriptor_owner[0], seals)
                        or descriptor_owner[2] is not False
                        or descriptor_owner[3] != "MODULE_LIFETIME"):
                    raise AssertionError("parent first-load publication differs")
                parent_fd = os.fstat(descriptor_owner[0])
                from hepta.hia_agent_store import wire
                fields = (ledger._text("epoch-lease"), ledger._text("slot"),
                          ledger._text("generation"), wire(None))
                before = loaded.execution_counters()
                actual = ledger.NativeSlotLedgerStore._lease_value(fields)
                after = loaded.execution_counters()
                delta, counter_errors = _counter_delta(before, after, 12)
                wanted = {"id": "epoch-lease", "slot": "slot",
                          "generation": "generation", "artifact": None}
                if actual != wanted or counter_errors:
                    raise AssertionError("parent actual selected call was not healthy")
                healthy = {"actual": actual, "expected": wanted,
                           "counters_before": before, "counters_after": after,
                           "counter_delta": delta, "counter_errors": counter_errors,
                           "definition_objects_stable": all(
                               vars(ledger.NativeSlotLedgerStore)[name]._mechanical_definition
                               is function for name, function in zip(names, definitions)),
                           "parent_fd": {"fd": descriptor_owner[0],
                                         "dev": parent_fd.st_dev, "ino": parent_fd.st_ino,
                                         "size": parent_fd.st_size,
                                         "owner": list(descriptor_owner)}}
        except BaseException as error:
            if state["role"] == "child":
                child_error = error
            else:
                parent_error = error
        finally:
            mechanical._load_sealed = original_load

        if state["role"] == "child":
            child_exit = 2
            try:
                loaded, descriptor_owner, seals = state["payload"]
                # Observe the real closed descriptor before traceback formatting
                # can open any source files for diagnostics. Never close it again.
                fd_error = None
                try:
                    os.fstat(descriptor_owner[0])
                except OSError as error:
                    fd_error = {"type": type(error).__name__, "errno": error.errno,
                                "message": str(error)}
                graph = _error_graph(child_error)
                epoch_nodes = [
                    item["number"] for item in graph["nodes"]
                    if (item["module"] == "builtins"
                        and item["qualname"] == "ValueError"
                        and item["message"] == "Slot mechanical loaded module/epoch differs"
                        and any(frame["file"] == mechanical.__file__
                                and frame["name"] == "extension"
                                for frame in item["frames"]))]
                counters = loaded.execution_counters()
                checks = {
                    "actual_pid_changed": os.getpid() != original_pid,
                    "actual_atfork_epoch_changed": mechanical._EPOCH is not initial_epoch,
                    "exact_epoch_error_in_actual_chain": len(epoch_nodes) == 1,
                    "no_loader_publication": (mechanical._EXTENSION is None
                        and mechanical._CAPTURED is None and mechanical._SEALED is None
                        and mechanical._EXPORTED == ()),
                    "loaded_module_removed": (
                        sys.modules.get("hepta._hia_slot_mechanical") is not loaded),
                    "one_confirmed_product_fd_close": (
                        descriptor_owner[2] is True and descriptor_owner[3] == "CLOSED"),
                    "descriptor_is_actually_closed": (
                        fd_error is not None and fd_error["errno"] == errno.EBADF),
                    "old_initializer_not_republished": (
                        mechanical._BROKEN_LOAD is True and mechanical._LOADING is False),
                    "no_child_business_entry": (
                        counters["pid"] == os.getpid()
                        and counters["overflow"] is False
                        and all(counters[name] == [0] * 16 for name in
                                ("public_calls", "raw_frame_calls",
                                 "initialized", "final_receipts"))),
                    "one_original_loader_return": state["load_calls"] == 1,
                }
                record = {"schema": "hepta.slot.definition.epoch-child.v1",
                          "status": "PASS" if all(checks.values()) else "HOLD",
                          "pid": os.getpid(), "ppid": os.getppid(),
                          "pgid": os.getpgrp(), "checks": checks,
                          "exception_graph": graph, "epoch_error_nodes": epoch_nodes,
                          "descriptor_owner": list(descriptor_owner),
                          "fd_probe": fd_error, "counters": counters,
                          "owned_test_fd_closes_before_output": list(closes),
                          "scope_owner_error_may_be_top": True}
                raw = _dump(record)
                if len(raw) > max_report_bytes:
                    raise AssertionError("DEF-21 actual exception graph exceeded IPC limit")
                position = 0
                while position < len(raw):
                    wrote = os.write(write_fd, raw[position:])
                    if wrote <= 0:
                        raise OSError("short DEF-21 child report write")
                    position += wrote
                child_exit = 0 if record["status"] == "PASS" else 1
            except BaseException:
                # The outer original child supervisor retains stderr too.
                traceback.print_exc()
            finally:
                try:
                    if write_fd in open_owned:
                        close_owned(write_fd)
                finally:
                    os._exit(child_exit)

        if state["child_pid"] is not None and waited is None:
            waited = _read_and_reap(
                state["child_pid"], read_fd,
                state["fork_monotonic"] + child_seconds, max_report_bytes)
        child_record = None
        errors = []
        if waited is not None:
            _create(output / "epoch-child.raw.json", waited["raw"])
            try:
                child_record = json.loads(waited["raw"])
            except (UnicodeDecodeError, ValueError):
                errors.append("child raw report is not one complete JSON document")
            if (waited["returncode"] != 0 or not waited["reaped"] or not waited["eof"]
                    or waited["timed_out"] or waited["signals"] or waited["errors"]):
                errors.append("child did not naturally complete and reap")
            if type(child_record) is not dict or child_record.get("status") != "PASS":
                errors.append("child epoch evidence failed")
        else:
            errors.append("no actual fork child result")
        if parent_error is not None:
            errors.append("parent load or healthy call failed")
        if healthy is None or not healthy["definition_objects_stable"]:
            errors.append("parent actual healthy mode12 result missing")
        if mechanical._load_sealed is not original_load:
            errors.append("transparent wrapper not restored")
        # The selected parent's sealed executable descriptor remains owned by
        # the real module. Do not close it here or call a loader cleanup twice.
        result = {"schema": "hepta.slot.definition.epoch-parent.v1",
                  "status": "PASS" if not errors else "HOLD",
                  "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp(),
                  "cold": cold, "child_pid": state["child_pid"],
                  "child_seconds": child_seconds, "max_report_bytes": max_report_bytes,
                  "load_calls": state["load_calls"], "healthy": healthy,
                  "owned_test_fd_close_receipts": list(closes),
                  "parent_error": _error_graph(parent_error),
                  "child": child_record,
                  "child_process": None if waited is None else {
                      key: value for key, value in waited.items() if key != "raw"},
                  "errors": errors,
                  "scope": "additional actual DEF-21 diagnostic; no original gate replacement"}
        _create(output / "epoch-parent.json", _dump(result))
        if errors:
            raise AssertionError("DEF-21 actual first-load fork evidence is HOLD")
        return result
    finally:
        mechanical._load_sealed = original_load
        # Handles a pre-fork fixture failure too. Every owned pipe close is
        # attempted once; this never closes/retries the module's executable FD.
        for fd in tuple(open_owned):
            close_owned(fd)
