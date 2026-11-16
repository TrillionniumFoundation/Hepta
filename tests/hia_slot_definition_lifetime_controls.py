"""Additional owned Slot definition diagnostics; no existing gate is replaced.

The main process records all planned checks and complete typed observations.
The separate reader decides their result. No GC scheduling, traceback clearing,
user-object cache, or observation normalization is used by these controls.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from hashlib import sha256
import inspect
import json
import math
import os
from pathlib import Path
import shutil
import sys
import traceback
import types
import weakref

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    admit_product, canonical, clean_environment, pin, read_json, regular_bytes,
    run_owned, successful_exit, unique_pairs, write_json)

FIXTURE = "tests/fixtures/slot_definition_lifetime_controls.json"
COUNTERS = ("public_calls", "raw_frame_calls", "initialized", "final_receipts")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def wire(value):
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) is bytes:
        return {"bytes_hex": value.hex()}
    if type(value) is dict:
        return {"type": "dict", "items": [[wire(k), wire(v)] for k, v in value.items()]}
    if type(value) in (list, tuple):
        return {"type": type(value).__name__, "items": [wire(x) for x in value]}
    raise TypeError("unsupported actual definition-control observation")


def same(left, right):
    return canonical(wire(left)) == canonical(wire(right))


def error_graph(error):
    from tests.hia_slot_definition_epoch_control import _error_graph
    return _error_graph(error)


def count():
    module = sys.modules.get("hepta.hia_slot_mechanical")
    loaded = None if module is None else module._EXTENSION
    return None if loaded is None else loaded.execution_counters()


def counter_check(before, after, mode, amount=1):
    require(type(before) is dict and type(after) is dict, "actual C counters absent")
    require(before["pid"] == after["pid"] == os.getpid()
            and before["overflow"] is False and after["overflow"] is False,
            "actual C counter owner/overflow differs")
    for key in COUNTERS:
        wanted = [0] * 16
        if key != "raw_frame_calls":
            wanted[mode] = amount
        require([b-a for a, b in zip(before[key], after[key])] == wanted,
                "actual C/HIA entry/final receipt count differs: " + key)


def product():
    # This is deliberately delayed. DEF-21 and DEF-22 observe the cold import
    # boundary before this helper imports any product module.
    from hepta import hia_slot_ledger_native as ledger
    from hepta import hia_slot_operations_selection as selection
    from hepta import hia_native_helpers as helpers
    from tests import hia_slot_mechanical_route_controls as routes
    return types.SimpleNamespace(ledger=ledger, selection=selection, helpers=helpers,
        routes=routes, Store=ledger.NativeSlotLedgerStore,
        references=ledger.NativeSlotLedgerStore._hia_slot_reference_methods)


class Recorder:
    def __init__(self, args, fixture, case):
        self.args, self.fixture, self.case = args, fixture, case
        self.rows = []
        self.plan = case["steps"]
        if args.lane:
            self.plan = next(x["steps"] for x in case["lanes"] if x["id"] == args.lane)
        self.progress = args.output / "progress.jsonl"

    def record(self, name, value):
        at = len(self.rows)
        require(at < len(self.plan) and self.plan[at]["id"] == name,
                "actual check order differs from its already written plan")
        row = {"id": name, "actual": wire(value)}
        self.rows.append(row)
        with self.progress.open("ab") as stream:
            stream.write(canonical({"event": "recorded", "index": at, **row}) + b"\n")

    def scope(self, *, path=None, digest=None):
        p = product()
        return p.helpers.native_helpers_scope(
            str(self.args.bridge_bundle if path is None else path),
            self.args.expected_bridge_sha256 if digest is None else digest)

    def healthy(self, label, mode, operation, *, selected=None):
        p = product()
        name = self.fixture["names"][mode-1]
        old = p.references[name]
        old = old.__func__ if type(old) is staticmethod else old
        expected, expected_trace = operation(old)
        entries, forbidden = [], []
        with self.scope():
            function = getattr(p.Store, name) if selected is None else selected(p)
            before = count()
            with p.routes.watch(self.args.controller, entries), p.routes.deny_legacy_finish(forbidden):
                actual, trace = operation(function)
            after = count()
        require(same(expected, actual) and same(expected_trace, trace) and entries
                and forbidden == [], "actual original-first diagnostic differs")
        counter_check(before, after, mode)
        self.record(label, {"original": expected, "candidate": actual,
            "original_trace": expected_trace, "candidate_trace": trace,
            "before": before, "after": after, "entries": entries, "forbidden": forbidden})

    def refusal(self, label, operation, *, error_type=ValueError, contains="",
                entries=None, trace=None):
        before = count()
        actual_error = None
        try:
            operation()
        except BaseException as error:
            actual_error = error
        require(actual_error is not None and type(actual_error) is error_type
                and contains in str(actual_error), "actual refusal type/message differs")
        after = count()
        if before is None:
            require(after is None or sum(after["initialized"]) == 0,
                    "refusal initialized HIA")
        else:
            require(after["initialized"] == before["initialized"]
                    and after["raw_frame_calls"] == before["raw_frame_calls"]
                    and after["final_receipts"] == before["final_receipts"],
                    "refusal ran a native business effect")
        data = {"error": error_graph(actual_error), "before": before, "after": after,
                "entries": [] if entries is None else entries,
                "provider_trace": [] if trace is None else trace}
        require(data["entries"] == [] and data["provider_trace"] == [],
                "refusal called a provider or HIA")
        self.record(label, data)
        return actual_error

    def route_children(self):
        rows = []
        for name in self.case["routes"]:
            directory = self.args.output / ("route-" + name)
            observation = directory / "observation"
            command = [sys.executable, "-I", "-B",
                str(ROOT / "tests/hia_slot_mechanical_route_controls.py"),
                "--case", name, "--controller", str(self.args.controller),
                "--base-v1", str(self.args.base_v1), "--base-sha256", self.args.base_sha256,
                "--bridge-bundle", str(self.args.bridge_bundle),
                "--expected-bridge-sha256", self.args.expected_bridge_sha256,
                "--product-freeze", str(self.args.product_freeze),
                "--product-freeze-sha256", self.args.product_freeze_sha256,
                "--output", str(observation)]
            result = run_owned(command, cwd=ROOT, directory=directory / "owned",
                timeout_seconds=self.fixture["route_seconds"], environment=clean_environment())
            row = {"case": name, "directory": str(directory), "result": result,
                   "report": None}
            if (observation / "report.json").is_file():
                row["report"] = {"path": str(observation / "report.json"),
                                 **pin(observation / "report.json")}
            rows.append(row)
        self.record("original-actual-routes", rows)
        require(all(successful_exit(row["result"]) for row in rows),
                "an original delegated route did not naturally finish")

    def external(self):
        # This invokes only independent pure-data readers. Explicit prior
        # external root terminal pins were frozen before any control child.
        from tools.read_hia_slot_definition_lifetime import verify_external_native4
        from tools.read_hia_slot_mechanical_installed import Captures
        captured = Captures()
        binding = captured.json(self.args.external_binding,
            {"bytes": self.args.external_binding_bytes,
             "sha256": self.args.external_binding_sha256})
        value = verify_external_native4(captured, binding, ROOT,
            scopes=self.case["external_scopes"], output=self.args.output / "external-readback")
        captured.stable()
        target = self.args.output / "external-readback.json"
        write_json(target, {"schema": "hepta.slot.definition.external-consumption.v1",
            "status": "PASS", "detail": value, "actual_inputs": captured.pins()})
        self.record("full-original-native4", {"path": str(target), **pin(target)})


def validate_operation(function):
    p = product()
    trace = []
    return p.routes.invoke(function, trace), trace


def static_operation(function):
    fields = (b"Slease", b"Sslot", b"S17", b"null")
    return function(fields), [{"fields": fields}]


def init_operation(function):
    obj, store, image = types.SimpleNamespace(), object(), object()
    result = function(obj, store, image)
    return [result, obj.store is store, obj.image is image], []


def conditional_operation(function):
    trace = []
    def validate(value, label):
        trace.append({"validate": [value, label]})
        return 17
    def call(*args, **kwargs):
        trace.append({"call": [list(args), kwargs]})
        return types.SimpleNamespace(values=(17,))
    def snapshot_reader(slot):
        trace.append({"snapshot": slot})
        return {"current": {"generation": "17", "epoch": "2"}, "target_slot": slot}
    receiver = types.SimpleNamespace(validate_u64=validate, _call=call)
    args = {"expected_current": {"generation": "17", "epoch": "2"}, "target_slot": "slot"}
    return function(receiver, args, snapshot_reader), trace


def call_operation(function):
    p = product()
    trace = []
    receipt = p.ledger.SlotLedgerReceipt(0, 0, (17, 0), (), b"diagnostic-receipt")
    def transition(request, state):
        trace.append({"request": request, "state": state})
        return receipt
    receiver = types.SimpleNamespace(image=types.SimpleNamespace(transition=transition))
    result = function(receiver, 1, (b"17",), flags=1)
    return {"same_receipt": result is receipt, "status": result.status,
            "action": result.action, "values": result.values,
            "fields": result.fields, "raw": result.raw}, trace


def lease_operation(function):
    trace = []
    row = {"id": "lease", "slot": "slot", "generation": "17", "active": 1,
           "artifact": "null"}
    connection = object()
    def execute(db, statement, parameters=()):
        trace.append({"sql": statement, "parameters": parameters,
                      "same_connection": db is connection})
        return types.SimpleNamespace(fetchone=lambda: row)
    def call(opcode, fields=(), **kwargs):
        trace.append({"call": [opcode, fields, kwargs]})
        return types.SimpleNamespace(fields=(b"lease", b"slot", b"17", b"null"))
    def lease_value(fields):
        trace.append({"lease_value": fields})
        return {"id": "lease", "slot": "slot", "generation": "17", "artifact": None}
    receiver = types.SimpleNamespace(store=types.SimpleNamespace(db=connection),
        _execute=execute, _call=call, _lease_value=lease_value)
    value = {"id": "lease", "slot": "slot", "generation": "17", "artifact": None}
    return function(receiver, value), trace


@contextmanager
def global_binding(namespace, name, value):
    missing = object()
    saved = namespace.get(name, missing)
    namespace[name] = value
    try:
        yield
    finally:
        if saved is missing:
            del namespace[name]
        else:
            namespace[name] = saved


def raw_function(p, name):
    value = p.references[name]
    return value.__func__ if type(value) is staticmethod else value


def definition_facts(p, name, methods):
    from hepta.hia_slot_continuations import CONTINUATIONS
    descriptor = vars(p.Store)[name]
    value = descriptor._mechanical_definition
    template = CONTINUATIONS[descriptor.mode]
    return {"function": type(value) is types.FunctionType,
        "globals": value.__globals__ is vars(p.ledger), "closure": value.__closure__ is None,
        "code": value.__code__ is template.__code__,
        "defaults": value.__defaults__ is template.__defaults__,
        "kwdefaults": value.__kwdefaults__ is template.__kwdefaults__,
        "stable": all(item[0] is value for item in methods),
        "fresh_methods": len({id(item[1]) for item in methods}) == len(methods)}


def generic_global_value(value):
    # Controlled class operands have an explicit closed identity vocabulary.
    for name, known in (("dict", dict), ("int", int), ("str", str),
                        ("list", list), ("tuple", tuple), ("bytes", bytes)):
        if value is known:
            return {"builtin_type_identity": "builtins." + name}
    if type(value) in (list, tuple):
        items = [generic_global_value(x) for x in value]
        return tuple(items) if type(value) is tuple else items
    if type(value) is dict:
        return {generic_global_value(k): generic_global_value(v) for k, v in value.items()}
    wire(value)  # refuse unsupported values; never repr/string-coerce them
    return value


def install_private_copy(recorder):
    args = recorder.args
    source = json.loads(regular_bytes(args.bridge_bundle), object_pairs_hook=unique_pairs)
    original_bridge, = source["bridges"]
    package = args.output / "private-package/hepta"
    package.parent.mkdir()
    shutil.copytree(ROOT / "hepta", package, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for relative in ("examples/hia_bootstrap/slot_ledger.hepta",
                     "examples/hia_bootstrap/slot_operations.hepta"):
        raw = regular_bytes(ROOT / relative)
        destination = package / "_data" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            require(regular_bytes(destination) == raw, "copied source resource differs")
        else:
            destination.write_bytes(raw)
        require(regular_bytes(ROOT / relative) == raw
                and regular_bytes(destination) == raw, "source resource copy raced")
    from tools.build_hia_slot_mechanical_bundle import create
    bundle = args.output / "private-v5.json"
    receipt_pin = {k: original_bridge["build_receipt"][k] for k in ("bytes", "sha256")}
    require(pin(package / "_slot_mechanical_build.json") == receipt_pin, "copied receipt differs")
    created = create(package, args.base_v1, args.base_sha256, receipt_pin["sha256"], bundle)
    copied = read_json(bundle)["bridges"][0]
    for field in ("binary", "build_receipt"):
        require({k: copied[field][k] for k in ("bytes", "sha256")}
                == {k: original_bridge[field][k] for k in ("bytes", "sha256")},
                "private package changed its executable inputs")
    require(set(copied["sources"]) == set(original_bridge["sources"]),
            "private package widened source admission")
    for name in copied["sources"]:
        require({k: copied["sources"][name][k] for k in ("bytes", "sha256")}
                == {k: original_bridge["sources"][name][k] for k in ("bytes", "sha256")},
                "private package changed an admitted source")
    require(not any(name == "hepta" or name.startswith("hepta.") for name in sys.modules),
            "private copy was not selected before product import")
    sys.path.insert(0, str(package.parent))
    args.bridge_bundle, args.expected_bridge_sha256 = bundle, created["sha256"]
    return package, copied, created


def case_01(c):
    p = product()
    with c.scope():
        for name in c.fixture["names"]:
            descriptor = vars(p.Store)[name]
            captures = [(descriptor._mechanical_definition, getattr(p.Store, name)) for _ in range(3)]
            c.record("definition/" + name, definition_facts(p, name, captures))
    c.healthy("real-validate", 5, validate_operation)


def case_02(c):
    p = product()
    descriptor = vars(p.Store)["validate_u64"]
    function = descriptor._mechanical_definition
    c.record("definition-edges", {"descriptor_slots": list(type(descriptor).__slots__),
        "function_dict_empty": function.__dict__ == {}, "closure_none": function.__closure__ is None})
    trace = []
    receiver = object.__new__(p.Store)
    receiver._call = p.routes.receiver(trace)._call
    reference = weakref.ref(receiver)
    before_alive = reference() is receiver
    with c.scope():
        method = receiver.validate_u64
        require(method(17, "generation") == 17, "successful receiver call differs")
    del method, receiver
    c.record("success-receiver-release", {"before_alive": before_alive,
        "after_alive": reference() is not None,
        "definition_stable": descriptor._mechanical_definition is function})
    fault = RuntimeError("DEF-02 actual provider failure")
    receiver = object.__new__(p.Store)
    receiver._call = p.routes.receiver([], fault)._call
    failing_reference = weakref.ref(receiver)
    retained = None
    with c.scope():
        method = receiver.validate_u64
        try:
            method(17, "generation")
        except BaseException as error:
            retained = error
    del method, receiver
    c.record("actual-failure-retains-through-caller-traceback", {
        "same_error": retained is fault, "receiver_alive": failing_reference() is not None,
        "definition_stable": descriptor._mechanical_definition is function,
        "function_dict_empty": function.__dict__ == {}})
    # The caller's retained error/TB remains intact. No immediate cyclic
    # collection prediction is substituted for the original full lifecycle gate.
    c.healthy("real-validate", 5, validate_operation)


def case_03(c):
    p = product()
    receiver = object.__new__(p.Store)
    with c.scope():
        for name in c.fixture["names"]:
            original = raw_function(p, name)
            class_method, instance_method = getattr(p.Store, name), getattr(receiver, name)
            old_bound = p.references[name].__get__(receiver, p.Store)
            c.record("signature/" + name, [
                [str(inspect.signature(original)), str(inspect.signature(old_bound))],
                [str(inspect.signature(class_method)), str(inspect.signature(instance_method))]])
        for name in c.fixture["names"]:
            descriptor = vars(p.Store)[name]
            class_method, instance_method = getattr(p.Store, name), getattr(receiver, name)
            c.record("binding/" + name, {
                "class_has_self": getattr(class_method, "__self__", None) is receiver,
                "instance_has_self": getattr(instance_method, "__self__", None) is receiver,
                "internal_same": descriptor._mechanical_definition.__globals__ is vars(p.ledger)})
    c.healthy("real-init", 1, init_operation)
    c.healthy("real-validate", 5, validate_operation)
    c.healthy("real-static", 12, static_operation)


def case_04(c):
    p = product()
    with c.scope():
        functions = {name: getattr(p.Store, name) for name in c.fixture["names"]}
    # The exact captured owner is closed. A valid call would now fail admission.
    # Real Python signature binding must reject these calls first.
    receiver = types.SimpleNamespace()
    for name in c.fixture["names"]:
        function = functions[name]
        c.refusal(name + "/missing", lambda: function(), error_type=TypeError)
        key = "fields" if name == "_lease_value" else "self"
        c.refusal(name + "/duplicate", lambda: function(receiver, **{key: receiver}),
                  error_type=TypeError)
        c.refusal(name + "/excess", lambda: function(*([receiver] * 32)), error_type=TypeError)


def case_05(c):
    p = product()
    namespace = vars(p.ledger)
    import builtins
    for name in c.case["globals"]:
        original = namespace.get(name, getattr(builtins, name, None))
        require(callable(original), "declared actual global is not callable")
        log = []
        def wrapper(*args, **kwargs):
            if name == "_raise":
                receipt = args[0]
                observed = {"status": receipt.status, "action": receipt.action,
                    "values": receipt.values, "fields": receipt.fields, "raw": receipt.raw,
                    "labels": args[1] if len(args) > 1 else ()}
                log.append({"receipt": observed, "kwargs": generic_global_value(kwargs)})
            else:
                log.append({"args": generic_global_value(args),
                            "kwargs": generic_global_value(kwargs)})
            return original(*args, **kwargs)
        mode = 5 if name == "_decimal" else (
            6 if name in ("isinstance", "set", "int", "_text") else
            14 if name in ("type", "str") else 12 if name == "_untext" else 3)
        operation = {5: validate_operation, 6: conditional_operation, 14: lease_operation,
                     12: static_operation, 3: call_operation}[mode]
        def observed(function):
            log.clear()
            result, trace = operation(function)
            require(log, "actual rebound provider was not used")
            return result, {"provider_trace": trace, "rebound_global_calls": list(log)}
        with global_binding(namespace, name, wrapper):
            c.healthy("global/" + name, mode, observed)
    c.record("all-definitions-use-actual-dictionary", [
        vars(p.Store)[name]._mechanical_definition.__globals__ is namespace
        for name in c.fixture["names"]])


def case_06(c):
    p = product()
    namespace = vars(p.ledger)
    original = raw_function(p, "conditional")
    function = vars(p.Store)["conditional"]._mechanical_definition
    traps = []
    def trap(*args, **kwargs):
        traps.append([generic_global_value(args), generic_global_value(kwargs)])
        raise AssertionError("replacement builtins mapping was consulted")
    replacement = dict(original.__builtins__)
    for name in ("isinstance", "set", "int", "dict"):
        replacement[name] = trap
    with global_binding(namespace, "__builtins__", replacement):
        c.record("definition-builtins", {"same_as_original": function.__builtins__ is original.__builtins__,
            "replacement_not_captured": function.__builtins__ is not replacement})
        c.healthy("real-conditional", 6, conditional_operation)
        c.record("replacement-trap-calls", traps)


def case_07(c):
    p = product()
    from hepta.hia_slot_continuations import CONTINUATIONS
    for name in c.fixture["names"]:
        descriptor = vars(p.Store)[name]
        function, template = descriptor._mechanical_definition, CONTINUATIONS[descriptor.mode]
        c.record("defaults/" + name, {"positional": function.__defaults__ is template.__defaults__,
            "keyword": function.__kwdefaults__ is template.__kwdefaults__})
    descriptor = vars(p.Store)["_call"]
    function, original = descriptor._mechanical_definition, raw_function(p, "_call")
    old_candidate, old_original = function.__kwdefaults__["labels"], original.__kwdefaults__["labels"]
    seen = []
    old_raise = p.ledger._raise
    def observed_raise(receipt, labels=()):
        seen.append(labels)
        return old_raise(receipt, labels)
    try:
        with c.scope():
            selected = p.Store._call
            selected.__kwdefaults__["labels"] = ("definition-default",)
            original.__kwdefaults__["labels"] = ("definition-default",)
            c.record("mutable-keyword-default-visible", [
                p.Store._call.__kwdefaults__["labels"], original.__kwdefaults__["labels"]])
        def observed(function):
            seen.clear()
            result, trace = call_operation(function)
            return result, {"trace": trace, "actual_labels": list(seen)}
        with global_binding(vars(p.ledger), "_raise", observed_raise):
            c.healthy("real-default-call", 3, observed)
        original.__defaults__ = original.__defaults__
        original.__kwdefaults__ = original.__kwdefaults__
        errors = {}
        with c.scope():
            selected = p.Store._call
            for attribute in ("__defaults__", "__kwdefaults__"):
                try:
                    setattr(selected, attribute, getattr(selected, attribute))
                except BaseException as error:
                    errors[attribute] = type(error).__module__ + "." + type(error).__qualname__
                else:
                    errors[attribute] = None
        c.record("public-setter-boundary", {"original_defaults_settable": True,
            "original_kwdefaults_settable": True, "selected_defaults_error": errors["__defaults__"],
            "selected_kwdefaults_error": errors["__kwdefaults__"], "public_reflection_closed": False})
    finally:
        function.__kwdefaults__["labels"] = old_candidate
        original.__kwdefaults__["labels"] = old_original


def case_09(c):
    p = product()
    from hepta.hia_native_delivery import current_record
    with c.scope():
        def nested_scope():
            with c.scope():
                raise AssertionError("nested worker authority was accepted")
        c.refusal("actual-nested-worker-scope", nested_scope, error_type=ValueError)
        function = p.Store.validate_u64
        original = raw_function(p, "validate_u64")
        def invoke_pair(selected, record_ids):
            trace = []
            def inner(*args, **kwargs):
                if record_ids is not None:
                    record = current_record()
                    record_ids["inner_records"].append(id(record))
                    record_ids["inner_sessions"].append(id(record.owner._mechanical_session))
                trace.append({"inner": [list(args), kwargs]})
                return types.SimpleNamespace(values=(17,))
            def outer(*args, **kwargs):
                if record_ids is not None:
                    record = current_record()
                    record_ids["outer_records"].append(id(record))
                    record_ids["outer_sessions"].append(id(record.owner._mechanical_session))
                trace.append({"outer": [list(args), kwargs]})
                require(selected(types.SimpleNamespace(_call=inner), 19, "epoch") == 17,
                        "reentrant result differs")
                if record_ids is not None:
                    record = current_record()
                    record_ids["outer_records"].append(id(record))
                    record_ids["outer_sessions"].append(id(record.owner._mechanical_session))
                return types.SimpleNamespace(values=(17,))
            return selected(types.SimpleNamespace(_call=outer), 17, "generation"), trace
        expected, expected_trace = invoke_pair(original, None)
        ids = {"outer_records": [], "inner_records": [], "outer_sessions": [], "inner_sessions": []}
        before, entries, forbidden = count(), [], []
        with p.routes.watch(c.args.controller, entries), p.routes.deny_legacy_finish(forbidden):
            actual, trace = invoke_pair(function, ids)
        after = count()
        counter_check(before, after, 5, 2)
        require(same(actual, expected) and same(trace, expected_trace),
                "actual reentrant provider result differs")
        c.record("actual-reentrant-calls", {"original": expected, "candidate": actual,
            "original_trace": expected_trace, "candidate_trace": trace, "before": before,
            "after": after, "entries": entries, "forbidden": forbidden})
        c.record("actual-record-restoration", ids)


def case_12(c):
    p = product()
    receiver = object.__new__(p.Store)
    with c.scope():
        before = count()
        receiver.validate_u64 = lambda value, label: 91
        value = receiver.validate_u64(17, "generation")
        after = count()
        c.record("instance-override", {"value": value,
            "native_initialization": sum(after["initialized"]) - sum(before["initialized"])})
        del receiver.validate_u64
        class Override(p.Store):
            def validate_u64(self, value, label):
                return 92
        obj = object.__new__(Override)
        before = count()
        value = obj.validate_u64(17, "generation")
        after = count()
        c.record("subclass-override", {"value": value,
            "native_initialization": sum(after["initialized"]) - sum(before["initialized"])})
        class Inherited(p.Store):
            pass
        inherited = object.__new__(Inherited)
        first, second = inherited.validate_u64, inherited.validate_u64
        c.record("inherited-definition", {
            "same_descriptor": inspect.getattr_static(Inherited, "validate_u64")
                is vars(p.Store)["validate_u64"],
            "same_definition": inspect.getattr_static(Inherited, "validate_u64")._mechanical_definition
                is vars(p.Store)["validate_u64"]._mechanical_definition,
            "bound_receiver": first.__self__ is inherited,
            "fresh_method": first.__func__ is not second.__func__})
    c.healthy("actual-call-override", 5, validate_operation)
    c.healthy("static-class", 12, static_operation)
    c.healthy("static-instance", 12, static_operation,
              selected=lambda p: object.__new__(p.Store)._lease_value)


def case_13(c):
    p = product()
    original = raw_function(p, "validate_u64")
    one = {"__name__": "definition_one", "__builtins__": original.__builtins__}
    two = {"__name__": "definition_two", "__builtins__": original.__builtins__}
    r1 = types.FunctionType(original.__code__, one, original.__name__, original.__defaults__)
    r2 = types.FunctionType(original.__code__, two, original.__name__, original.__defaults__)
    d1 = p.selection._SlotControlMethod(5, "validate_u64", {"validate_u64": r1})
    d2 = p.selection._SlotControlMethod(5, "validate_u64", {"validate_u64": r2})
    f1, f2 = d1._mechanical_definition, d2._mechanical_definition
    c.record("distinct-namespaces", {"same_code": f1.__code__ is f2.__code__,
        "different_namespace": f1.__globals__ is not f2.__globals__,
        "different_definition": f1 is not f2,
        "correct_namespaces": f1.__globals__ is one and f2.__globals__ is two})
    class Holder:
        pass
    Holder.validate_u64 = d2
    with c.scope():
        c.refusal("foreign-definition-refusal", lambda: Holder.validate_u64,
                  contains="Slot mechanical definition identity changed")
    Holder.validate_u64 = d1
    reference = weakref.ref(f1)
    before_alive = reference() is f1
    Holder.validate_u64 = d2
    del d1, f1
    c.record("ordinary-definition-replacement", {"old_function_alive_before": before_alive,
        "old_function_alive_after": reference() is not None,
        "new_definition_owned": vars(Holder)["validate_u64"]._mechanical_definition is f2})


def case_14(c):
    p = product()
    receiver = object.__new__(p.Store)
    reference = p.references["validate_u64"]
    a, b = reference.__get__(receiver, p.Store), reference.__get__(receiver, p.Store)
    with c.scope():
        first, second = receiver.validate_u64, receiver.validate_u64
        class_first, class_second = p.Store.validate_u64, p.Store.validate_u64
        function = vars(p.Store)["validate_u64"]._mechanical_definition
        c.record("public-counterexample", {
            "original_func_stable": a.__func__ is b.__func__,
            "original_function_type": type(a.__func__) is types.FunctionType,
            "selected_func_stable": first.__func__ is second.__func__,
            "selected_function_type": type(first.__func__) is types.FunctionType,
            "internal_definition_stable": function is vars(p.Store)["validate_u64"]._mechanical_definition,
            "original_globals": hasattr(a.__func__, "__globals__"),
            "original_closure": hasattr(a.__func__, "__closure__"),
            "original_annotations": hasattr(a.__func__, "__annotations__"),
            "selected_globals": hasattr(first.__func__, "__globals__"),
            "selected_closure": hasattr(first.__func__, "__closure__"),
            "selected_annotations": hasattr(first.__func__, "__annotations__"),
            "class_lookup_stable": class_first is class_second,
            "public_reflection_closed": False})


def custody_lane(c):
    p = product()
    from hepta import hia_native_delivery as delivery
    import ctypes
    entries, trace, records = [], [], []
    before = after = None
    fault = (ValueError("DEF-16 actual returned receipt lost") if c.args.lane == "receipt-loss"
             else RuntimeError("DEF-16 actual retirement failed"))
    actual_error = None
    with c.scope():
        function = p.Store.validate_u64
        before = count()
        if c.args.lane == "receipt-loss":
            image = p.routes.native.installed_slot_operations(c.args.controller)
            saved = image._entry
            def actual(*args):
                result = saved(*args)
                entries.append({"return": result,
                    "request_size": args[1], "output_capacity": args[3], "state_size": args[5],
                    "source": bytes(args[0].raw), "output": bytes(args[2].raw),
                    "workspace": bytes(args[4].raw),
                    "source_id": id(args[0]), "output_id": id(args[2]), "workspace_id": id(args[4])})
                records.append(delivery.current_record())
                raise fault
            image._entry = actual
            try:
                p.routes.invoke(function, trace)
            except BaseException as error:
                actual_error = error
            finally:
                image._entry = saved
        else:
            saved = delivery.DeliveryRecord.retire
            def retire(record):
                if records and record is records[0]:
                    raise fault
                return saved(record)
            def provider(*args, **kwargs):
                records.append(delivery.current_record())
                trace.append({"args": list(args), "kwargs": kwargs})
                return types.SimpleNamespace(values=(17,))
            delivery.DeliveryRecord.retire = retire
            try:
                with p.routes.watch(c.args.controller, entries):
                    function(types.SimpleNamespace(_call=provider), 17, "generation")
            except BaseException as error:
                actual_error = error
            finally:
                delivery.DeliveryRecord.retire = saved
        after = count()
    require(actual_error is not None and len(records) == 1 and records[0] is not None,
            "actual custody failure was not observed")
    record = records[0]
    frame = record.owner
    receipt = frame.receipt
    c.record("actual-custody", {
        "lane": c.args.lane, "error": error_graph(actual_error),
        "same_top_error": actual_error is fault,
        "actual_loss_is_fault": record.loss is not None and record.loss.error is fault,
        "custody_registered": delivery._CUSTODY.get(id(record)) is record,
        "record_owner_type": type(frame).__module__ + "." + type(frame).__qualname__,
        "same_record": frame._delivery is record,
        "session_retained": frame._mechanical_session is not None,
        "retired": record.retired, "terminal": record.terminal,
        "native_pending": record.native_pending, "observation_pending": record.observation_pending,
        "loss_present": record.loss is not None, "frame_mode": frame.mode,
        "frame_fenced": frame.fenced, "frame_native_failed": frame.native_failed,
        "workspace_id": id(frame.buffer), "buffer_bytes": ctypes.sizeof(frame.buffer),
        "buffer": bytes(frame.buffer.raw), "entries": entries, "provider_trace": trace,
        "receipt": None if receipt is None else
            {"port": receipt.port, "sequence": receipt.sequence,
             "phase": receipt.phase, "failed": receipt.failed},
        "before": before, "after": after})


def common_arguments(args, output, *, lane=None):
    values = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_slot_definition_lifetime_controls.py"),
        "--case", args.case, "--controller", str(args.controller),
        "--base-v1", str(args.base_v1), "--base-sha256", args.base_sha256,
        "--bridge-bundle", str(args.bridge_bundle),
        "--expected-bridge-sha256", args.expected_bridge_sha256,
        "--product-freeze", str(args.product_freeze),
        "--product-freeze-sha256", args.product_freeze_sha256,
        "--control-freeze", str(args.control_freeze),
        "--control-freeze-sha256", args.control_freeze_sha256,
        "--external-binding", str(args.external_binding),
        "--external-binding-bytes", str(args.external_binding_bytes),
        "--external-binding-sha256", args.external_binding_sha256,
        "--output", str(output)]
    if lane is not None:
        values.extend(("--lane", lane))
    return values


def case_16(c):
    if c.args.lane:
        custody_lane(c)
        return
    rows = []
    for lane in c.case["lanes"]:
        directory = c.args.output / ("lane-" + lane["id"])
        observation = directory / "observation"
        result = run_owned(common_arguments(c.args, observation, lane=lane["id"]),
            cwd=ROOT, directory=directory / "owned", timeout_seconds=lane["seconds"],
            environment=clean_environment())
        row = {"lane": lane["id"], "directory": str(directory), "result": result, "report": None}
        if (observation / "report.json").is_file():
            row["report"] = {"path": str(observation / "report.json"),
                             **pin(observation / "report.json")}
        rows.append(row)
    c.record("actual-custody-lanes", rows)
    # All new actual child outcomes are retained even if original full proof is HOLD.
    c.external()
    require(all(successful_exit(row["result"]) for row in rows),
            "an actual custody child did not naturally finish")


def case_17(c):
    p = product()
    from hepta import hia_slot_mechanical as mechanical
    with c.scope():
        function = p.Store.validate_u64
        module = mechanical._EXTENSION
        saved = module.ack
        try:
            module.ack = module.begin
            c.refusal("warm-export-drift", lambda: p.Store.validate_u64)
        finally:
            module.ack = saved
    copied = c.args.output / "copied-identical-v5.json"
    raw = regular_bytes(c.args.bridge_bundle)
    with copied.open("xb") as stream:
        stream.write(raw)
    with c.scope(path=copied):
        function = p.Store.validate_u64
        trace = []
        try:
            copied.write_bytes(raw + b"\n")
            c.refusal("warm-private-capsule-drift",
                lambda: p.routes.invoke(function, trace), trace=trace)
        finally:
            copied.write_bytes(raw)
    require(regular_bytes(copied) == raw, "private bundle restoration differs")
    c.healthy("healthy-after-restoration", 5, validate_operation)


def case_18(c):
    p = product()
    originals = tuple(vars(p.Store)[name]._mechanical_definition for name in c.fixture["names"])
    saved_types = p.selection.types
    def cannot_allocate(*args, **kwargs):
        raise MemoryError("DEF-18 definition allocation")
    p.selection.types = types.SimpleNamespace(FunctionType=cannot_allocate)
    try:
        c.refusal("actual-definition-allocation-fault",
            lambda: p.selection._SlotControlMethod(5, "validate_u64", p.references),
            error_type=MemoryError, contains="DEF-18 definition allocation")
    finally:
        p.selection.types = saved_types
    c.record("original-definitions-unchanged", [
        vars(p.Store)[name]._mechanical_definition is value
        for name, value in zip(c.fixture["names"], originals)])
    from hepta import hia_slot_mechanical as mechanical
    saved_private = mechanical._private_globals
    yielded = []
    class Incomplete:
        def items(self):
            actual = saved_private()
            key = next(iter(actual))
            yielded.append(key)
            yield key, actual[key]
            raise MemoryError("DEF-18 primitive installation")
    with c.scope():
        mechanical._private_globals = lambda: Incomplete()
        try:
            c.refusal("actual-partial-private-installation", lambda: p.Store.validate_u64,
                error_type=MemoryError, contains="DEF-18 primitive installation")
        finally:
            mechanical._private_globals = saved_private
        c.record("actual-prefix-publication", {"yielded": yielded,
            "definition_same": vars(p.Store)["validate_u64"]._mechanical_definition is originals[4],
            "method_returned": False})
    c.healthy("healthy-after-restoration", 5, validate_operation)


def case_19(c):
    p = product()
    namespace = vars(p.ledger)
    function = vars(p.Store)["validate_u64"]._mechanical_definition
    with c.scope():
        warm = p.Store.validate_u64
        require(p.routes.invoke(warm, []) == 17, "actual warm call failed")
        for key in c.fixture["private_names"]:
            saved = namespace[key]
            try:
                namespace[key] = object()
                c.refusal("primitive/" + key, lambda: p.Store.validate_u64,
                    contains="Slot mechanical primitive binding changed")
                require(namespace[key] is not saved, "primitive drift was silently repaired")
            finally:
                namespace[key] = saved
    c.record("definition-survived-all-drift",
             vars(p.Store)["validate_u64"]._mechanical_definition is function)
    c.healthy("healthy-after-restoration", 5, validate_operation)


def case_20(c):
    package, bridge, created = install_private_copy(c)
    p = product()
    from hepta import hia_slot_mechanical as mechanical
    require(Path(mechanical.__file__).resolve().parent == package, "warm lane did not import private copy")
    c.healthy("private-copy-warm", 5, validate_operation)
    targets = {
        "source": package / "native/slot_mechanical.c",
        "binary": Path(bridge["binary"]["path"]),
        "receipt": Path(bridge["build_receipt"]["path"])}
    with c.scope():
        function = p.Store.validate_u64
        definition = vars(p.Store)["validate_u64"]._mechanical_definition
        for label, target in targets.items():
            original = regular_bytes(target)
            trace = []
            try:
                target.write_bytes(original + (b"\x00" if label == "binary" else b"\n"))
                c.refusal("warm/" + label,
                    lambda: p.routes.invoke(function, trace), trace=trace)
            finally:
                target.write_bytes(original)
            require(regular_bytes(target) == original, "private authority was not restored")
        loaded = mechanical._EXTENSION
        saved = loaded.ack
        trace = []
        try:
            loaded.ack = loaded.begin
            c.refusal("warm/export", lambda: p.routes.invoke(function, trace), trace=trace)
        finally:
            loaded.ack = saved
        import fcntl
        descriptor = os.memfd_create("definition-negative-unsealed", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        sealed = mechanical._SEALED
        try:
            require(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == 0,
                    "negative fixture unexpectedly sealed")
            mechanical._SEALED = (descriptor, sealed[1])
            trace = []
            c.refusal("warm/sealed-fd", lambda: p.routes.invoke(function, trace), trace=trace)
        finally:
            mechanical._SEALED = sealed
            os.close(descriptor)  # exactly this owned test descriptor, once
        require(vars(p.Store)["validate_u64"]._mechanical_definition is definition,
                "warm refusal replaced the definition")
    c.healthy("private-copy-restored", 5, validate_operation)
    # Preserve original args in the outer source bindings; this records the
    # additional explicitly supplied identical-byte private authority separately.
    write_json(c.args.output / "private-package-custody.json", {
        "schema": "hepta.slot.definition.private-package.v1",
        "package": str(package), "capsule": created, "bridge": bridge,
        "source_root": str(ROOT), "whole_native_stack_qualified": False})
    c.external()


def case_21(c):
    from tests.hia_slot_definition_epoch_control import run_epoch_control
    directory = c.args.output / "actual-epoch"
    result = run_epoch_control(c.args.bridge_bundle, c.args.expected_bridge_sha256,
        directory, child_seconds=c.case["epoch_child_seconds"],
        max_report_bytes=c.case["epoch_max_report_bytes"])
    c.record("actual-first-load-fork", {
        "directory": str(directory), "parent": pin(directory / "epoch-parent.json"),
        "child": pin(directory / "epoch-child.raw.json")})
    require(result["status"] == "PASS", "actual epoch diagnostic is HOLD")


def case_22(c):
    before_loader = "hepta.hia_slot_mechanical" in sys.modules
    before_extension = "hepta._hia_slot_mechanical" in sys.modules
    from hepta import hia_slot_ledger_native as ledger
    store = ledger.NativeSlotLedgerStore
    definitions = [vars(store)[name]._mechanical_definition for name in c.fixture["names"]]
    c.record("ordinary-import", {
        "before_native_module": before_loader, "before_extension": before_extension,
        "after_native_module": "hepta.hia_slot_mechanical" in sys.modules,
        "after_extension": "hepta._hia_slot_mechanical" in sys.modules,
        "definitions": len(definitions),
        "all_function": all(type(value) is types.FunctionType for value in definitions),
        "all_actual_globals": all(value.__globals__ is vars(ledger) for value in definitions)})
    for name in c.fixture["names"]:
        original = store._hia_slot_reference_methods[name]
        expected = original.__func__ if type(original) is staticmethod else original
        c.record("unselected/" + name, getattr(store, name) is expected)
    old = store._hia_slot_reference_methods["validate_u64"]
    c.record("ordinary-result-and-provider-trace", [
        list(validate_operation(old)), list(validate_operation(store.validate_u64))])


def case_23(c):
    p = product()
    namespace = vars(p.ledger)
    with c.scope():
        warm = p.Store.validate_u64
        require(p.routes.invoke(warm, []) == 17, "actual initial healthy call failed")
        for label in ("wrong-type", "foreign-globals", "wrong-code", "closure-substitute",
                      "defaults-identity", "kwdefaults-identity", "name", "qualname", "module", "doc"):
            name = "_execute" if label == "defaults-identity" else "_call" if label == "kwdefaults-identity" else "validate_u64"
            descriptor = vars(p.Store)[name]
            function = descriptor._mechanical_definition
            restored = []
            try:
                if label == "wrong-type":
                    descriptor._mechanical_definition = object()
                elif label == "foreign-globals":
                    substitute = types.FunctionType(function.__code__, dict(namespace),
                        function.__name__, function.__defaults__)
                    substitute.__kwdefaults__ = function.__kwdefaults__
                    substitute.__qualname__, substitute.__module__, substitute.__doc__ = (
                        function.__qualname__, function.__module__, function.__doc__)
                    descriptor._mechanical_definition = substitute
                elif label == "closure-substitute":
                    def outer():
                        closed = object()
                        return lambda: closed
                    # A real closure necessarily has a different co_freevars/
                    # code from the zero-freevar template. Do not claim this
                    # isolates a same-code closure that Python cannot construct.
                    descriptor._mechanical_definition = outer()
                else:
                    attribute = {"wrong-code": "__code__", "defaults-identity": "__defaults__",
                        "kwdefaults-identity": "__kwdefaults__", "name": "__name__",
                        "qualname": "__qualname__", "module": "__module__", "doc": "__doc__"}[label]
                    saved = getattr(function, attribute)
                    restored.append((attribute, saved))
                    value = ((lambda: None).__code__ if label == "wrong-code"
                        else tuple(list(saved)) if label == "defaults-identity"
                        else dict(saved) if label == "kwdefaults-identity" else "changed-definition")
                    require(value is not saved, "identity-negative fixture failed to change identity")
                    setattr(function, attribute, value)
                c.refusal("corruption/" + label, lambda: getattr(p.Store, name),
                    contains="Slot mechanical definition identity changed")
            finally:
                descriptor._mechanical_definition = function
                for attribute, value in restored:
                    setattr(function, attribute, value)
        descriptor = vars(p.Store)["validate_u64"]
        function = descriptor._mechanical_definition
        saved_name, saved_primitive = function.__name__, namespace["_HIA_SLOT_ACK"]
        try:
            function.__name__ = "bad-definition"
            namespace["_HIA_SLOT_ACK"] = object()
            c.refusal("primitive-check-precedes-definition-check", lambda: p.Store.validate_u64,
                contains="Slot mechanical primitive binding changed")
        finally:
            function.__name__ = saved_name
            namespace["_HIA_SLOT_ACK"] = saved_primitive
    c.healthy("healthy-after-restoration", 5, validate_operation)


def admit_controls(path, expected_sha256):
    raw = regular_bytes(path)
    require(sha256(raw).hexdigest() == expected_sha256, "control source freeze differs")
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    require(value["schema"] == "hepta.slot.definition.control-source-freeze.v1",
            "control source freeze schema differs")
    for name, expected in value["files"].items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts,
                "unsafe control input")
        require(pin(ROOT / name) == expected, "control input changed: " + name)
    require(regular_bytes(path) == raw, "control freeze raced")
    return value["files"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("controller", "base-v1", "bridge-bundle", "product-freeze",
                 "control-freeze", "external-binding", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("base-sha256", "expected-bridge-sha256", "product-freeze-sha256",
                 "control-freeze-sha256", "external-binding-sha256", "case"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--external-binding-bytes", type=int, required=True)
    parser.add_argument("--lane")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    fixture = read_json(ROOT / FIXTURE)
    matches = [row for row in fixture["cases"] if row["id"] == args.case]
    require(len(matches) == 1, "undeclared logical control")
    case = matches[0]
    require(args.lane is None or args.lane in [x["id"] for x in case["lanes"]],
            "undeclared additional custody lane")
    product_sources = admit_product(ROOT, args.product_freeze, args.product_freeze_sha256)
    control_sources = admit_controls(args.control_freeze, args.control_freeze_sha256)
    originals = {str(path): regular_bytes(path) for path in
                 (args.controller, args.base_v1, args.bridge_bundle, args.external_binding)}
    require(sha256(originals[str(args.base_v1)]).hexdigest() == args.base_sha256
            and sha256(originals[str(args.bridge_bundle)]).hexdigest() == args.expected_bridge_sha256
            and len(originals[str(args.external_binding)]) == args.external_binding_bytes
            and sha256(originals[str(args.external_binding)]).hexdigest() == args.external_binding_sha256,
            "explicit prior child input differs")
    original_arguments = dict(vars(args))
    c = Recorder(args, fixture, case)
    plan = {"schema": "hepta.slot.definition.child-plan.v1", "case": args.case, "lane": args.lane,
        "steps": c.plan, "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp(),
        "argv": list(sys.argv), "product_sources": product_sources,
        "control_sources": control_sources, "input_pins": {
            name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest()} for name, raw in originals.items()}}
    write_json(args.output / "planned.json", plan)
    report = {"schema": "hepta.slot.definition.child-report.v1", "case": args.case,
        "lane": args.lane, "status": "HOLD", "plan": pin(args.output / "planned.json"),
        "steps": c.rows, "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp(),
        "argv": list(sys.argv), "qualification_limits": fixture["qualification_limits"],
        "source_before": product_sources, "control_before": control_sources}
    failure = None
    try:
        number = case["number"]
        if case["routes"]:
            c.route_children()
        elif number == 15:
            c.external()
        else:
            globals()["case_" + str(number).zfill(2)](c)
        require([row["id"] for row in c.rows] == [row["id"] for row in c.plan],
                "actual diagnostic stopped before all planned checks")
        require(admit_product(ROOT, args.product_freeze, args.product_freeze_sha256) == product_sources
                and admit_controls(args.control_freeze, args.control_freeze_sha256) == control_sources,
                "actual source changed")
        require(all(regular_bytes(path) == raw for path, raw in originals.items()),
                "an original explicit input changed")
        report.update(status="RECORDED", source_after=product_sources, control_after=control_sources)
    except BaseException as error:
        failure = error
        report["error"] = error_graph(error)
        traceback.print_exception(type(error), error, error.__traceback__)
    finally:
        # DEF-20 changes only the local args to point to its explicitly copied
        # authority. Evidence always preserves the original command arguments.
        for name, value in original_arguments.items():
            setattr(args, name, value)
        write_json(args.output / "report.json", report)
    raw = regular_bytes(args.output / "report.json")
    print(json.dumps({"case": args.case, "lane": args.lane, "status": report["status"],
        "report": {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}}, sort_keys=True))
    require(regular_bytes(args.output / "report.json") == raw, "child report changed after terminal")
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
