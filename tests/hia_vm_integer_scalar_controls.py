"""Fresh-child actual-image controls. No manual delivery-loss publication."""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tests.hia_vm_integer_scalar_cases import canonical, pin, source_capture, stable, observe, operation_program, operation_arguments

TRANSPORT = ("missing", "stale", "nonce", "operation", "width", "signed", "lhs",
             "rhs", "version", "completion", "status", "result-high-bits",
             "trap-value", "checksum", "input-canary", "output-canary", "workspace-canary",
             "value-error-after-return", "memory-error-after-return",
             "keyboard-interrupt-after-return", "system-exit-after-return",
             "resource-owner-missing-ack", "partial-ack", "no-receipt")
ADMISSION = ("wrong-manifest-pin", "duplicate-manifest-key", "extra-manifest-key",
             "wrong-image-bytes", "manifest-drift", "image-drift", "image-drift-after-return")
LIVENESS = ("original-operation", "original-invoke", "runtime-global",
            "derived-operation-code", "derived-invoke-code", "derived-execute-code",
            "factory-operation-field", "machine-operation", "public-target",
            "explicit-factory-identity")
CONTEXT = ("thread-refusal", "fork-refusal", "caught-reentry", "unselected-worker-scope")
NEW_OPERATIONS = ("int.shl.checked", "int.shr.checked", "int.neg.checked",
                  "bit.and", "bit.or", "bit.xor", "bit.not")


def _new(manifest, digest):
    from hepta.hia_vm_integer_divrem_runtime import NativeIntegerScalarExecutor
    return NativeIntegerScalarExecutor(manifest, digest)


def _program(resource=False):
    from tests.test_hia_program import arithmetic, m, f, b, i, c, ret
    if not resource:
        return arithmetic("int.mul.checked", "i8"), "calculate", [-7, 3]
    return m(f("owned", [("a", "i8"), ("z", "i8")], ["i8"], ["alloc", "trap"], [
        b("entry", [("a", "i8"), ("z", "i8")], [
            c("size", "usize", 8), i("buffer.new", ["size"], [("owner", "buffer")]),
            i("int.mul.checked", ["a", "z"], [("q", "i8")]),
            i("owner.drop", ["owner"])], ret("q"))])), "owned", [-7, 3]


def _refold(words):
    words[10] = 0
    for index, value in enumerate(words):
        if index != 10:
            words[10] ^= value
    return struct.pack("<12Q", *words)


def transport(name, manifest, digest):
    from hepta import hia_native_delivery as delivery
    from hepta.hia_vm_integer_divrem_native import NativeDivRemUnknown
    from hepta import hia_vm_integer_divrem_protocol as wire
    if name not in TRANSPORT:
        raise ValueError("transport control was not predeclared")
    if delivery.custody_snapshot():
        raise AssertionError("fresh control process has preexisting custody")
    executor = _new(manifest, digest)
    binding, real = executor.binding, executor.binding.image._entry
    actual_entries, completed_returns = 0, 0
    saved = None
    if name == "stale":
        args = _program()
        executor(*args)
        def save(*call):
            nonlocal saved
            result = real(*call)
            saved = ctypes.string_at(call[2], 96)
            return result
        binding.image._entry = save
        executor(*args)
        binding.image._entry = real
        if saved is None:
            raise AssertionError("stale receipt prerequisite did not actually complete")
    injected = None
    if name == "value-error-after-return":
        injected = ValueError("real div/rem return then original injected error")
    elif name == "memory-error-after-return":
        injected = MemoryError("real div/rem return then original injected error")
    elif name == "keyboard-interrupt-after-return":
        injected = KeyboardInterrupt("real div/rem return then original injected error")
    elif name == "system-exit-after-return":
        injected = SystemExit(37)
    def entry(*call):
        nonlocal actual_entries, completed_returns
        actual_entries += 1
        result = real(*call)
        completed_returns += 1
        if injected is not None:
            raise injected
        if name in ("missing", "resource-owner-missing-ack"):
            return 0
        if name == "partial-ack":
            ctypes.memset(ctypes.addressof(call[2]) + 80, 0xa5, 16)
            return 80
        if name == "no-receipt":
            ctypes.memset(call[2], 0xa5, 96)
            return result
        if name == "stale":
            ctypes.memmove(call[2], saved, 96)
            return result
        if name.endswith("-canary"):
            target, offset = {"input-canary": (call[0], 64),
                              "output-canary": (call[2], 96),
                              "workspace-canary": (call[4], 0)}[name]
            ctypes.memset(ctypes.addressof(target) + offset, 0, 1)
            return result
        words = list(struct.unpack("<12Q", ctypes.string_at(call[2], 96)))
        field = {"nonce": 2, "operation": 3, "width": 4, "signed": 5,
                 "lhs": 8, "rhs": 9, "version": 1, "completion": 11}.get(name)
        if field is not None:
            words[field] ^= 1
        elif name == "status":
            words[6] = 4
        elif name == "result-high-bits":
            words[7] = 256
        elif name == "trap-value":
            words[6], words[7] = 3, 1
        elif name == "checksum":
            words[10] ^= 1
            ctypes.memmove(call[2], struct.pack("<12Q", *words), 96)
            return result
        else:
            raise AssertionError("unhandled transport control")
        ctypes.memmove(call[2], _refold(words), 96)
        return result
    binding.image._entry = entry
    primary = None
    try:
        executor(*_program(name == "resource-owner-missing-ack"))
    except BaseException as error:
        primary = error
    if (primary is None or actual_entries != 1 or completed_returns != 1
            or binding._loss is None or binding._loss.native_pending is not True
            or binding._loss.terminal or not delivery.custody_snapshot()):
        raise AssertionError("actual native return did not produce sticky unconfirmed custody")
    if injected is not None and not isinstance(injected, ValueError):
        if primary is not injected:
            raise AssertionError("process-control/MemoryError identity was replaced")
    else:
        if not isinstance(primary, NativeDivRemUnknown):
            raise AssertionError("lost domain receipt was not classified from its actual record")
        if injected is not None and primary.__cause__ is not injected:
            raise AssertionError("original injected ValueError identity was lost")
    owner_resources = None
    if name == "resource-owner-missing-ack":
        actual_owner = binding._loss.owner[1]
        owner_resources = actual_owner.resources()
        if owner_resources["live_owners"] != 1 or owner_resources["live_bytes"] != 8:
            raise AssertionError("real stopped VM owner is not retained by actual delivery custody")
    retry_error = None
    try:
        executor(*_program())
    except BaseException as error:
        retry_error = error
    if not isinstance(retry_error, NativeDivRemUnknown) or actual_entries != 1:
        raise AssertionError("the same actual binding silently retried after loss")
    other = _new(manifest, digest)
    result = other(*_program())
    if (result["result"] != -21 or other.binding.native_returns != 1
            or other.binding.acknowledgements != 1):
        raise AssertionError("independent binding sharing immutable image was poisoned")
    return {"control": name, "actual_entry_calls": actual_entries,
            "actual_entry_returns": completed_returns, "same_binding_retry_entries": 0,
            "stale_prerequisite_confirmed_returns": 2 if name == "stale" else 0,
            "stale_receipt": None if saved is None else pin(saved),
            "other_binding_returns": other.binding.native_returns,
            "primary_type": type(primary).__qualname__,
            "primary_is_injected": primary is injected if injected is not None else None,
            "cause_is_injected": primary.__cause__ is injected if injected is not None else None,
            "custody": list(delivery.custody_snapshot()), "owner_resources": owner_resources,
            "traceback": "".join(traceback.format_exception(type(primary), primary, primary.__traceback__))}


def admission(name, manifest, digest):
    from hepta import hia_native_delivery as delivery
    from hepta.hia_vm_integer_divrem_native import NativeDivRemUnknown
    if name not in ADMISSION or delivery.custody_snapshot():
        raise ValueError("admission control/fresh custody differs")
    source_manifest = Path(manifest)
    raw = source_manifest.read_bytes()
    image_raw = (source_manifest.parent / "vm-integer-scalar.image.bin").read_bytes()
    with tempfile.TemporaryDirectory(prefix="divrem-admission-") as directory:
        selected = Path(directory) / "manifest.json"
        image = Path(directory) / "vm-integer-scalar.image.bin"
        selected.write_bytes(raw)
        image.write_bytes(image_raw)
        selected_digest = digest
        if name == "wrong-manifest-pin":
            selected_digest = "0" * 64 if digest != "0" * 64 else "1" * 64
        elif name == "duplicate-manifest-key":
            value = b'{"schema":"unexpected",' + raw.lstrip()[1:]
            selected.write_bytes(value)
            selected_digest = sha256(value).hexdigest()
        elif name == "extra-manifest-key":
            value = json.loads(raw)
            value["unreviewed"] = True
            data = canonical(value)
            selected.write_bytes(data)
            selected_digest = sha256(data).hexdigest()
        elif name == "wrong-image-bytes":
            image.write_bytes(image_raw + b"\0")
        if name in ADMISSION[:4]:
            try:
                _new(selected, selected_digest)
            except ValueError as error:
                return {"control": name, "rejected_before_call": True,
                        "error": str(error), "custody": list(delivery.custody_snapshot())}
            raise AssertionError("unadmitted executable/manifest was accepted")
        executor = _new(selected, selected_digest)
        real, calls = executor.binding.image._entry, []
        def counted(*args):
            result = real(*args)
            calls.append(result)
            if name == "image-drift-after-return":
                image.write_bytes(image_raw + b"\0")
            return result
        executor.binding.image._entry = counted
        if name == "manifest-drift":
            selected.write_bytes(raw + b"\n")
        elif name == "image-drift":
            image.write_bytes(image_raw + b"\0")
        try:
            executor(*_program())
        except BaseException as error:
            selected.write_bytes(raw)
            image.write_bytes(image_raw)
            if name == "image-drift-after-return":
                if (not isinstance(error, NativeDivRemUnknown) or calls != [96]
                        or not delivery.custody_snapshot()):
                    raise AssertionError("post-return image drift lost actual pending custody")
            elif calls or delivery.custody_snapshot() or not isinstance(error, ValueError):
                raise AssertionError("safe pre-entry admission refusal fabricated a delivery loss")
            return {"control": name, "actual_entry_returns": len(calls),
                    "type": type(error).__qualname__, "custody": list(delivery.custody_snapshot())}
        raise AssertionError("source/image drift was accepted")


def liveness(name, manifest, digest):
    from hepta import hia_program_runtime as original
    from hepta import hia_native_delivery as delivery
    from hepta.hia_vm_integer_divrem_native import NativeDivRemUnknown
    if name not in LIVENESS or delivery.custody_snapshot():
        raise ValueError("live-code control/fresh custody differs")
    executor = _new(manifest, digest)
    factory = executor._factory
    target, attribute = {
        "original-operation": (original._Machine, "operation"),
        "original-invoke": (original._Machine, "invoke"),
        "runtime-global": (original, "_checked"),
        "derived-operation-code": (factory.operation, "__code__"),
        "derived-invoke-code": (factory.invoke, "__code__"),
        "derived-execute-code": (factory.execute, "__code__"),
        "factory-operation-field": (factory, "operation"),
        "machine-operation": (factory.machine_type, "operation"),
        "public-target": (executor, "_target"),
        "explicit-factory-identity": (executor, "_factory"),
    }[name]
    old = getattr(target, attribute)
    replacement = (old.replace(co_filename="<deliberately changed actual code>")
                   if attribute == "__code__" else (lambda *a, **k: None))
    setattr(target, attribute, replacement)
    caught = None
    try:
        executor(*_program())
    except BaseException as error:
        caught = error
    finally:
        setattr(target, attribute, old)
    if (not isinstance(caught, NativeDivRemUnknown) or executor.binding.native_returns != 0
            or delivery.custody_snapshot()):
        raise AssertionError("drifted code/authority was used or fabricated native custody")
    # The original entry remains usable; the native factory did not patch it.
    value = original.execute_program(*_program())
    if value["result"] != -21:
        raise AssertionError("explicit factory altered the original default entry")
    return {"control": name, "rejected_before_native": True,
            "original_default_unchanged": True, "custody": []}


def context(name, manifest, digest):
    from hepta import hia_native_delivery as delivery
    from hepta.hia_vm_integer_divrem_native import NativeDivRemUnknown
    if name not in CONTEXT or delivery.custody_snapshot():
        raise ValueError("context control/fresh custody differs")
    executor = _new(manifest, digest)
    if name == "thread-refusal":
        outcome = []
        def other():
            try:
                executor(*_program())
            except BaseException as error:
                outcome.append(type(error) is NativeDivRemUnknown)
        thread = threading.Thread(target=other)
        thread.start()
        thread.join(5)
        if thread.is_alive() or outcome != [True] or executor.binding.native_returns:
            raise AssertionError("another thread entered the owned binding")
    elif name == "fork-refusal":
        # A diagnostic-only child. The parent never kills a foreign process.
        import signal
        import time
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            code = 1
            try:
                try:
                    executor(*_program())
                except NativeDivRemUnknown:
                    os.write(write_fd, b"rejected-before-entry")
                    code = 0
            finally:
                os.close(write_fd)
                os._exit(code)
        os.close(write_fd)
        reaped, status = False, None
        deadline = time.monotonic() + 5
        try:
            while time.monotonic() < deadline:
                done, value = os.waitpid(pid, os.WNOHANG)
                if done:
                    reaped, status = True, value
                    break
                time.sleep(0.005)
            if not reaped:
                raise AssertionError("new diagnostic fork child exceeded its own five-second limit")
            raw = os.read(read_fd, 64)
            if status != 0 or raw != b"rejected-before-entry":
                raise AssertionError("fork inherited executable authority")
        finally:
            if not reaped:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                cleanup_deadline = time.monotonic() + 2
                while time.monotonic() < cleanup_deadline:
                    done, _ = os.waitpid(pid, os.WNOHANG)
                    if done:
                        reaped = True
                        break
                    time.sleep(0.005)
                if not reaped:
                    raise AssertionError("owned diagnostic child was not reaped after SIGKILL")
            os.close(read_fd)
    elif name == "caught-reentry":
        real = executor.binding.image._entry
        observed = []
        def reenter(*args):
            try:
                executor(*_program())
            except ValueError as error:
                observed.append(str(error))
            return real(*args)
        executor.binding.image._entry = reenter
        executor(*_program())
        if len(observed) != 1 or executor.binding.acknowledgements != 1:
            raise AssertionError("caught same-binding reentry altered the outer native obligation")
        executor.binding.image._entry = real
    elif name == "unselected-worker-scope":
        from hepta.hia_native_helpers import native_helpers_scope
        try:
            with native_helpers_scope():
                executor(*_program())
        except ValueError as error:
            if "pinned worker bundle" not in str(error):
                raise
        else:
            raise AssertionError("standalone div/rem silently joined an unselected worker bundle")
    if delivery.custody_snapshot():
        raise AssertionError("safe context refusal/healthy call left custody")
    # The same original process/thread binding still works after safe refusal.
    result = executor(*_program())
    if result["result"] != -21:
        raise AssertionError("context refusal poisoned a healthy binding")
    return {"control": name, "healthy_after_refusal": True, "custody": []}


def boundaries(manifest, digest):
    from hepta.hia_program_runtime import execute_program
    from tests.test_hia_program import arithmetic, m, f, b, i, c, ret
    executor = _new(manifest, digest)
    plans = []
    operations = ("int.div.checked", "int.rem.checked", "int.add.checked",
                  "int.add.wrap", "int.sub.checked", "int.sub.wrap",
                  "int.mul.checked", "int.mul.wrap")
    for operation in operations:
        for args in ([-7, 3], [1, 0], [-128, -1], [127, 2]):
            for steps in (1, 2, 3):
                plans.append((operation + "." + str(args) + ".steps" + str(steps),
                              arithmetic(operation, "i8"), "calculate", args, {"max_steps": steps}))
        owned = m(f("owned", [("a", "i8"), ("z", "i8")], ["i8"], ["alloc", "trap"], [
            b("entry", [("a", "i8"), ("z", "i8")], [
                c("size", "usize", 8), i("buffer.new", ["size"], [("owner", "buffer")]),
                i(operation, ["a", "z"], [("q", "i8")]),
                i("owner.drop", ["owner"])], ret("q"))]))
        for heap, failure, a, z in ((0, None, -7, 3), (8, 1, -7, 3),
                                    (8, None, 127, 2), (8, None, -7, 3)):
            plans.append((operation + ".owned." + str((heap, failure, a, z)),
                          owned, "owned", [a, z],
                          {"max_heap_bytes": heap, "allocation_fail_at": failure}))
        inner = arithmetic(operation, "i8")["functions"][0]
        outer = f("outer", [("a", "i8"), ("z", "i8")], ["i8"], ["trap"], [
            b("entry", [("a", "i8"), ("z", "i8")],
              [i("call", ["a", "z"], [("q", "i8")], function="calculate")], ret("q"))])
        for depth in (1, 2):
            plans.append((operation + ".nested.depth" + str(depth),
                          m(inner, outer), "outer", [-7, 3], {"max_call_depth": depth}))
    # The original eight-operation 144 plans above are an unchanged prefix.
    for operation in NEW_OPERATIONS:
        unary = operation in ("int.neg.checked", "bit.not")
        parameters = [("a", "i8")] if unary else [("a", "i8"), ("z", "i8")]
        operands = ["a"] if unary else ["a", "z"]
        for pair in ([-7, 3], [1, 0], [-128, -1], [127, 2]):
            args = operation_arguments(operation, *pair)
            for steps in (1, 2, 3):
                plans.append((operation + "." + str(pair) + ".steps" + str(steps),
                              operation_program(operation, "i8"), "calculate", args,
                              {"max_steps": steps}))
        owned = m(f("owned", parameters, ["i8"], ["alloc", "trap"], [
            b("entry", parameters, [
                c("size", "usize", 8), i("buffer.new", ["size"], [("owner", "buffer")]),
                i(operation, operands, [("q", "i8")]),
                i("owner.drop", ["owner"])], ret("q"))]))
        for heap, failure, a, z in ((0, None, -7, 3), (8, 1, -7, 3),
                                    (8, None, 127, 2), (8, None, -7, 3)):
            plans.append((operation + ".owned." + str((heap, failure, a, z)),
                          owned, "owned", operation_arguments(operation, a, z),
                          {"max_heap_bytes": heap, "allocation_fail_at": failure}))
        inner = operation_program(operation, "i8")["functions"][0]
        outer = f("outer", parameters, ["i8"], ["trap"], [
            b("entry", parameters,
              [i("call", operands, [("q", "i8")], function="calculate")], ret("q"))])
        for depth in (1, 2):
            plans.append((operation + ".nested.depth" + str(depth),
                          m(inner, outer), "outer", operation_arguments(operation, -7, 3),
                          {"max_call_depth": depth}))
    frozen = []
    # Every original row and its complete repeated report precedes all native
    # executions in this separate resource/tick domain. No candidate expectations.
    for ident, program, entry, args, limits in plans:
        first, ftb = observe(execute_program, program, entry, args, limits)
        second, stb = observe(execute_program, program, entry, args, limits)
        if canonical(first) != canonical(second) or ftb != stb:
            raise AssertionError(("complete original boundary differs", ident))
        frozen.append((canonical(first), ftb))
    rows = []
    for (ident, program, entry, args, limits), (original_raw, ftb) in zip(plans, frozen):
        first = json.loads(original_raw)
        before = executor.binding.native_returns
        actual, atb = observe(executor, program, entry, args, limits)
        if canonical(actual) != original_raw:
            raise AssertionError(("boundary observation differs", ident, first, actual))
        rows.append({"id": ident, "original": first, "candidate": actual,
                     "native_returns": executor.binding.native_returns - before,
                     "original_traceback": ftb, "candidate_traceback": atb,
                     "raw_tracebacks_equal": ftb == atb})
    if len(rows) != 270:
        raise AssertionError("complete fifteen-operation resource/tick domain differs")
    return {"control": "boundaries", "rows": rows, "count": 270,
            "whole_vm_native": False, "raw_traceback_equivalence_claimed": False}


INSTALLED_PROBE = "\"\"\"Isolated installed explicit-factory probe; no checkout product import.\"\"\"\nimport argparse\nfrom hashlib import sha256\nimport json\nfrom pathlib import Path\nimport sys\nimport traceback\n\nparser = argparse.ArgumentParser()\nparser.add_argument(\"--target\", required=True, type=Path)\nparser.add_argument(\"--manifest\", required=True, type=Path)\nparser.add_argument(\"--manifest-sha256\", required=True)\nparser.add_argument(\"--inputs\", required=True, type=Path)\nparser.add_argument(\"--output\", required=True, type=Path)\nargs = parser.parse_args()\nsys.path.insert(0, str(args.target))\nimport hepta\nfrom hepta.hia_vm_integer_divrem_runtime import NativeIntegerScalarExecutor\nfrom hepta.hia_agent_contract import installation_manifest\nfrom hepta.hia_native_helpers import native_helpers_scope\nfrom hepta.hia_native_delivery import custody_snapshot\nif not Path(hepta.__file__).resolve().is_relative_to(args.target.resolve()):\n    raise AssertionError(\"installed probe imported checkout modules\")\ninputs_raw = args.inputs.read_bytes()\ndata = json.loads(inputs_raw)\nactual_identity = installation_manifest()\nif actual_identity != data[\"installation_manifest\"]:\n    raise AssertionError(\"source and installed complete module/resource identity differ\")\nexecutor = NativeIntegerScalarExecutor(args.manifest, args.manifest_sha256)\nobserved = []\nfor row in data[\"rows\"]:\n    try:\n        value = executor(row[\"program\"], row[\"function\"], row[\"arguments\"])\n        outcome = {\"outcome\": \"returned\", \"report\": value}\n        raw_tb = \"\"\n    except ArithmeticError as error:\n        if type(error).__module__ != \"hepta.hia_program_runtime\":\n            raise\n        outcome = {\"outcome\": \"raised\", \"error\": {\n            \"module\": type(error).__module__, \"type\": type(error).__qualname__,\n            \"args\": list(error.args), \"message\": str(error),\n            \"code\": error.code, \"report\": error.report,\n            \"cause\": None, \"context\": None, \"suppress_context\": error.__suppress_context__}}\n        if error.__cause__ is not None or error.__context__ is not None:\n            raise AssertionError(\"installed trap gained an unobserved exception chain\")\n        raw_tb = \"\".join(traceback.format_exception(type(error), error, error.__traceback__))\n    if outcome != row[\"expected\"]:\n        raise AssertionError((\"installed full observation differs\", row[\"id\"], outcome))\n    observed.append({\"id\": row[\"id\"], \"actual\": outcome, \"raw_traceback\": raw_tb})\nreturns = executor.binding.native_returns\npath = Path(hepta.__file__).parent / \"hia_vm_integer_divrem_protocol.py\"\nsaved = path.read_bytes()\ntry:\n    path.write_bytes(saved + b\"\\n\")\n    try:\n        row = data[\"rows\"][0]\n        executor(row[\"program\"], row[\"function\"], row[\"arguments\"])\n    except ValueError:\n        pass\n    else:\n        raise AssertionError(\"installed component source drift was accepted\")\n    if executor.binding.native_returns != returns or custody_snapshot():\n        raise AssertionError(\"safe installed source refusal entered native or invented loss\")\nfinally:\n    path.write_bytes(saved)\ntry:\n    with native_helpers_scope():\n        row = data[\"rows\"][0]\n        executor(row[\"program\"], row[\"function\"], row[\"arguments\"])\nexcept ValueError as error:\n    if \"pinned worker bundle\" not in str(error):\n        raise\nelse:\n    raise AssertionError(\"unregistered installed component silently joined worker scope\")\nif executor.binding.native_returns != returns or custody_snapshot():\n    raise AssertionError(\"worker scope refusal changed actual call custody\")\nif installation_manifest() != actual_identity or args.inputs.read_bytes() != inputs_raw:\n    raise AssertionError(\"installed source inventory or original input authority changed\")\nreport = {\"schema\": \"hepta.hia.vm-integer-scalar-installed.v1\", \"status\": \"PASS_INSTALLED_SLICE\",\n          \"installation_manifest\": actual_identity, \"rows\": observed,\n          \"native_returns\": executor.binding.native_returns,\n          \"acknowledgements\": executor.binding.acknowledgements,\n          \"source_drift_rejected_before_native\": True,\n          \"unselected_worker_scope_rejected_before_native\": True,\n          \"input_sha256\": sha256(inputs_raw).hexdigest(),\n          \"whole_vm_native\": False, \"raw_traceback_equivalence_claimed\": False}\nwith args.output.open(\"x\") as stream:\n    json.dump(report, stream, sort_keys=True)\n    stream.write(\"\\n\")\n"


def raw_abi(manifest, digest):
    from hepta.hia_native_delivery import NativeCall, custody_snapshot
    from hepta.hia_vm_integer_divrem_native import NativeDivRemBinding
    from hepta import hia_vm_integer_divrem_protocol as wire
    binding = NativeDivRemBinding(manifest, digest, _integer_scalar=True)
    good = wire.scalar_request("int.mul.checked", "i8", -7, 3, 1)
    plans = []
    for source_size in (0, 63, 65):
        plans.append(("source-size-" + str(source_size),
                      (good + b"\0")[:source_size], 96, 0))
    for output_size in (0, 95, 97):
        plans.append(("output-size-" + str(output_size), good, output_size, 0))
    plans.append(("workspace-size-1", good, 96, 1))
    for ident, index, value in (
        ("magic", 0, 0), ("nonce-zero", 1, 0), ("operation-zero", 2, 0),
        ("operation-sixteen", 2, 16), ("width-zero", 3, 0), ("width-seven", 3, 7),
        ("width-sixtyfive", 3, 65), ("signed-two", 4, 2), ("reserved", 7, 1),
        ("lhs-noncanonical-eight", 5, 256), ("rhs-noncanonical-eight", 6, 256)):
        words = list(struct.unpack("<8Q", good))
        words[index] = value
        plans.append((ident, struct.pack("<8Q", *words), 96, 0))
    for width, index in ((16, 5), (32, 6)):
        words = list(struct.unpack("<8Q", good))
        words[3], words[index] = width, 1 << width
        plans.append(("noncanonical-" + str(width), struct.pack("<8Q", *words), 96, 0))
    for operation in ("int.neg.checked", "bit.not"):
        words = list(struct.unpack("<8Q", wire.scalar_request(operation, "i8", -7, 0, 1)))
        words[6] = 1
        plans.append(("unary-unused-rhs-" + operation, struct.pack("<8Q", *words), 96, 0))
    rows = []
    guard = b"RAW-ABI-CANARYv1"
    if len(guard) != 16 or len(plans) != 22:
        raise AssertionError("complete raw ABI control inventory differs")
    for ident, request, output_size, workspace_size in plans:
        source = ctypes.create_string_buffer(request + guard, len(request) + 16)
        output_bytes = b"\xa5" * output_size
        state_bytes = b"\x5a" * workspace_size
        output = ctypes.create_string_buffer(output_bytes + guard, output_size + 16)
        state = ctypes.create_string_buffer(state_bytes + guard, workspace_size + 16)
        binding.check()
        entry = binding.image._entry
        arguments = (source, len(request), output, output_size, state, workspace_size)
        with NativeCall((binding, source, output, state)) as record:
            record.associate(binding)
            record.check()
            record.enter_native()
            returned = entry(*arguments)
            if (returned != 0 or source.raw != request + guard
                    or output.raw != output_bytes + guard or state.raw != state_bytes + guard):
                raise AssertionError(("malformed f0 framing changed output or guards", ident))
            binding.check()
            row = {"id": ident, "source_bytes": len(request), "output_bytes": output_size,
                   "workspace_bytes": workspace_size, "return": returned,
                   "request": pin(request), "all_bytes_unchanged": True}
            record.check()
            record.confirmed(terminal=True)
            rows.append(row)
    if custody_snapshot():
        raise AssertionError("complete raw ABI refusals left unconfirmed custody")
    return {"control": "raw-abi", "rows": rows, "actual_entry_returns": len(rows), "custody": []}


def operation_custody(operation, manifest, digest):
    """One fresh actual lost receipt for each new HIA operation, with a VM owner."""
    from hepta import hia_native_delivery as delivery
    from hepta.hia_vm_integer_divrem_native import NativeDivRemUnknown
    from hepta.hia_program_runtime import execute_program
    from tests.test_hia_program import m, f, b, i, c, ret
    if operation not in NEW_OPERATIONS or delivery.custody_snapshot():
        raise ValueError("new-operation control or initial custody differs")
    unary = operation in ("int.neg.checked", "bit.not")
    parameters = [("a", "i8")] if unary else [("a", "i8"), ("z", "i8")]
    operands = ["a"] if unary else ["a", "z"]
    values = (1, 3) if operation == "int.shl.checked" else (-7, 1) if operation == "int.shr.checked" else (-7, 3)
    arguments = operation_arguments(operation, *values)
    program = m(f("owned", parameters, ["i8"], ["alloc", "trap"], [
        b("entry", parameters, [
            c("size", "usize", 8), i("buffer.new", ["size"], [("owner", "buffer")]),
            i(operation, operands, [("q", "i8")]),
            i("owner.drop", ["owner"])], ret("q"))]))
    first, first_tb = observe(execute_program, program, "owned", arguments)
    second, second_tb = observe(execute_program, program, "owned", arguments)
    if canonical(first) != canonical(second) or first_tb != second_tb or first["outcome"] != "returned":
        raise AssertionError("new-operation original prerequisite differs")
    frozen = canonical(first)
    executor = _new(manifest, digest)
    healthy, healthy_tb = observe(executor, program, "owned", arguments)
    if canonical(healthy) != frozen or executor.binding.acknowledgements != 1:
        raise AssertionError("new-operation healthy actual native result differs")
    binding, real = executor.binding, executor.binding.image._entry
    actual_entries, actual_returns = 0, 0
    def missing(*call):
        nonlocal actual_entries, actual_returns
        actual_entries += 1
        result = real(*call)
        actual_returns += 1
        if result != 96:
            raise AssertionError("new-operation actual native prerequisite did not return a full receipt")
        return 0
    binding.image._entry = missing
    primary = None
    try:
        executor(program, "owned", arguments)
    except BaseException as error:
        primary = error
    if (not isinstance(primary, NativeDivRemUnknown) or actual_entries != 1 or actual_returns != 1
            or binding._loss is None or binding._loss.native_pending is not True
            or binding._loss.terminal or not delivery.custody_snapshot()
            or binding.native_returns != 2 or binding.acknowledgements != 1):
        raise AssertionError("new operation did not preserve its real unacknowledged return")
    actual_owner = binding._loss.owner[1]
    resources = actual_owner.resources()
    if resources["live_owners"] != 1 or resources["live_bytes"] != 8:
        raise AssertionError("new-operation loss retired its actual still-owned VM resource")
    retry_error = None
    try:
        executor(program, "owned", arguments)
    except BaseException as error:
        retry_error = error
    if not isinstance(retry_error, NativeDivRemUnknown) or actual_entries != 1:
        raise AssertionError("new-operation binding retried after actual loss")
    other = _new(manifest, digest)
    other_value, other_tb = observe(other, program, "owned", arguments)
    if (canonical(other_value) != frozen or other.binding.native_returns != 1
            or other.binding.acknowledgements != 1):
        raise AssertionError("new-operation loss poisoned an independent binding")
    return {"control": operation, "original": first, "healthy": healthy,
            "other_binding": other_value, "actual_entry_calls": actual_entries,
            "actual_entry_returns": actual_returns, "same_binding_retry_entries": 0,
            "native_returns": binding.native_returns, "acknowledgements": binding.acknowledgements,
            "owner_resources": resources, "custody": list(delivery.custody_snapshot()),
            "original_traceback": first_tb, "healthy_traceback": healthy_tb,
            "other_traceback": other_tb,
            "primary_traceback": "".join(traceback.format_exception(
                type(primary), primary, primary.__traceback__)),
            "retry_traceback": "".join(traceback.format_exception(
                type(retry_error), retry_error, retry_error.__traceback__))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", choices=("transport", "admission", "liveness", "context", "boundaries", "raw-abi", "operation-custody"), required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    captured = source_capture()
    if args.group == "operation-custody":
        result = operation_custody(args.case, args.manifest, args.manifest_sha256)
    elif args.group == "raw-abi":
        if args.case != "raw-abi":
            raise ValueError("raw ABI control identity differs")
        result = raw_abi(args.manifest, args.manifest_sha256)
    elif args.group == "boundaries":
        if args.case != "boundaries":
            raise ValueError("boundary case identity differs")
        result = boundaries(args.manifest, args.manifest_sha256)
    else:
        function = {"transport": transport, "admission": admission,
                    "liveness": liveness, "context": context}[args.group]
        result = function(args.case, args.manifest, args.manifest_sha256)
    stable(captured)
    result.update({"schema": "hepta.hia.vm-integer-scalar-control.v1",
                   "status": "PASS_CONTROL", "source_pins": {k: pin(v) for k, v in captured.items()},
                   "whole_vm_native": False})
    with args.output.open("xb") as stream:
        stream.write(canonical(result))
    print(json.dumps({"status": result["status"], "control": result["control"]}))


if __name__ == "__main__":
    main()
