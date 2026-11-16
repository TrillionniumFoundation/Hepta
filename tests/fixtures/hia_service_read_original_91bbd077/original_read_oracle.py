"""Independent finite oracle for the frozen original service read method.

No product package is imported. This file contains fake foreign providers, not
another implementation of the read algorithm. The original complete bodies
are compiled unchanged from their separately pinned text. There is no candidate
entry point. Observed SQL is an in-memory effect at the original execute call.
"""
from __future__ import annotations

import base64 as _base64
import builtins
import hashlib
import json
from pathlib import Path
import sys
import textwrap
import types


HERE = Path(__file__).resolve().parent
READ_SHA256 = "b8c81da6c1bd879756e29ba9cc2f943af00deef35d5729928253d2ec395dcd80"


class InjectedError(ValueError):
    pass


class FakeSQLiteError(Exception):
    pass


def _raw(value):
    if isinstance(value, MappingProbe):
        return {key: _raw(item) for key, item in object.__getattribute__(value, "_items").items()}
    if isinstance(value, Blob):
        return object.__getattribute__(value, "_data")
    if isinstance(value, Text):
        return str.__str__(value)
    if isinstance(value, Number):
        return object.__getattribute__(value, "_value")
    if isinstance(value, Comparison):
        return object.__getattribute__(value, "_value")
    if type(value) is dict:
        return {key: _raw(item) for key, item in value.items()}
    if type(value) is list:
        return [_raw(item) for item in value]
    if type(value) is tuple:
        return tuple(_raw(item) for item in value)
    return value


def snapshot(value):
    """No arbitrary repr/equality/getattr while observing user protocols."""
    kind = type(value)
    if value is None:
        return {"none": True}
    if kind is bool:
        return {"bool": value}
    if kind is int:
        return {"int": str(value)}
    if kind is float:
        return {"float_hex": value.hex()}
    if kind is str:
        return {"str": value}
    if kind in (bytes, bytearray):
        return {kind.__name__: bytes(value).hex()}
    if kind is slice:
        return {"slice": [snapshot(value.start), snapshot(value.stop), snapshot(value.step)]}
    if isinstance(value, Text):
        return {"text_probe": object.__getattribute__(value, "_label"),
                "value": str.__str__(value)}
    if isinstance(value, Blob):
        return {"blob_probe": object.__getattribute__(value, "_label"),
                "bytes": bytes(object.__getattribute__(value, "_data")).hex()}
    if isinstance(value, (Number, Comparison, Truth)):
        return {"opaque": kind.__name__, "label": object.__getattribute__(value, "_label"),
                "value": snapshot(object.__getattribute__(value, "_value"))}
    if isinstance(value, MappingProbe):
        return {"mapping_probe": object.__getattribute__(value, "_label"),
                "items": [[snapshot(k), snapshot(v)] for k, v in
                          object.__getattribute__(value, "_items").items()]}
    if kind in (tuple, list):
        return {kind.__name__: [snapshot(item) for item in value]}
    if kind is dict:
        return {"dict": [[snapshot(k), snapshot(v)] for k, v in value.items()]}
    if isinstance(value, Provider):
        return {"provider": value.name, "version": value.version}
    if isinstance(value, Metadata):
        return {"metadata": object.__getattribute__(value, "_label")}
    if isinstance(value, Cursor):
        return {"cursor_provider": object.__getattribute__(value, "_label")}
    if isinstance(value, Store):
        return {"store_provider": object.__getattribute__(value, "_label")}
    if isinstance(value, Database):
        return {"database_provider": object.__getattribute__(value, "_label")}
    return {"opaque_type": kind.__module__ + "." + kind.__qualname__}


def exception_snapshot(error, fixture, seen=None):
    if seen is None:
        seen = {}
    if id(error) in seen:
        return {"same_exception_in_this_graph": seen[id(error)]}
    graph_identity = len(seen)
    seen[id(error)] = graph_identity
    result = {
        "type": type(error).__module__ + "." + type(error).__qualname__,
        "identity_in_this_graph": graph_identity,
        "is_exact_injected_fault": error is fixture.injected_fault,
        "args": snapshot(error.args), "message": str(error),
        "cause": None, "context": None,
        "suppress_context": error.__suppress_context__,
    }
    if isinstance(error, AttributeError):
        result["name"] = snapshot(error.name)
        result["obj"] = snapshot(error.obj)
    if isinstance(error, UnicodeDecodeError):
        result["unicode"] = {"encoding": error.encoding, "object": snapshot(error.object),
                             "start": error.start, "end": error.end, "reason": error.reason}
    for field in ("code", "phase", "retry_action", "details_artifact"):
        if field in getattr(error, "__dict__", {}):
            result[field] = snapshot(error.__dict__[field])
    if error.__cause__ is not None:
        result["cause"] = exception_snapshot(error.__cause__, fixture, seen)
    if error.__context__ is not None:
        result["context"] = exception_snapshot(error.__context__, fixture, seen)
    # Preserve original stack information as diagnostic raw evidence, outside
    # the predefined semantic record. A future native adapter necessarily has
    # different transport frames; this is not an exception-field rewrite.
    frames = []
    traceback = error.__traceback__
    while traceback is not None:
        frames.append({"function": traceback.tb_frame.f_code.co_name,
                       "filename": Path(traceback.tb_frame.f_code.co_filename).name,
                       "line": traceback.tb_lineno})
        traceback = traceback.tb_next
    fixture.traceback_diagnostics.append({"phase": fixture.phase,
        "at_trace_length": len(fixture.trace), "exception_type": result["type"],
        "identity_in_this_graph": graph_identity, "frames": frames})
    return result


class Provider:
    def __init__(self, fixture, name, operation, version="v1"):
        self.fixture, self.name, self.operation, self.version = fixture, name, operation, version

    def __call__(self, *args, **kwargs):
        return self.fixture.external(self.name + ".call", args,
            lambda: self.operation(*args, **kwargs), {"version": self.version, "kwargs": snapshot(kwargs)})


class MappingProbe:
    def __init__(self, fixture, label, items):
        self._fixture, self._label, self._items = fixture, label, items

    def __getitem__(self, key):
        return self._fixture.external(self._label + ".getitem", (key,), lambda: self._items[key])

    def __contains__(self, key):
        return self._fixture.external(self._label + ".contains", (key,), lambda: key in self._items)

    def __getattribute__(self, name):
        if name == "get":
            f, label = object.__getattribute__(self, "_fixture"), object.__getattribute__(self, "_label")
            items = object.__getattribute__(self, "_items")
            return f.external(label + ".get.lookup", (),
                lambda: Provider(f, label + ".get", lambda key, default=None: items.get(key, default)))
        return object.__getattribute__(self, name)

    def __del__(self):
        self._fixture.released(self._label, "mapping")


class Text(str):
    def __new__(cls, fixture, label, value):
        instance = str.__new__(cls, value)
        instance._fixture, instance._label = fixture, label
        return instance

    def __del__(self):
        self._fixture.released(self._label, "text")


class Blob:
    def __init__(self, fixture, label, data, reported_length=None):
        self._fixture, self._label, self._data = fixture, label, data
        self._reported_length = reported_length

    def __len__(self):
        return self._fixture.external(self._label + ".len", (),
            lambda: len(self._data) if self._reported_length is None else self._reported_length)

    def __getitem__(self, key):
        def apply():
            data = self._data[key]
            if isinstance(data, (bytes, bytearray)):
                return Blob(self._fixture, self._fixture.label("chunk"), data)
            return data
        return self._fixture.external(self._label + ".slice", (key,), apply)

    def __getattribute__(self, name):
        if name == "decode":
            f, label, data = (object.__getattribute__(self, n) for n in ("_fixture", "_label", "_data"))
            return f.external(label + ".decode.lookup", (),
                lambda: Provider(f, label + ".decode",
                    lambda encoding="utf-8": Text(f, label + ".decoded", data.decode(encoding))))
        return object.__getattribute__(self, name)

    def __del__(self):
        self._fixture.released(self._label, "blob")


class Number:
    def __init__(self, fixture, label, value, int_return=None):
        self._fixture, self._label, self._value, self._int_return = fixture, label, value, int_return

    def __int__(self):
        return self._fixture.external(self._label + ".int", (),
            lambda: self._value if self._int_return is None else self._int_return)

    def __index__(self):
        return self._fixture.external(self._label + ".index", (), lambda: self._value)

    def __add__(self, other):
        return self._fixture.external(self._label + ".add", (other,),
            lambda: Number(self._fixture, self._fixture.label("number"), self._value + _raw(other)))

    def __radd__(self, other):
        return self._fixture.external(self._label + ".radd", (other,), lambda: _raw(other) + self._value)

    def __lt__(self, other):
        return self._fixture.external(self._label + ".lt", (other,),
            lambda: Truth(self._fixture, self._fixture.label("truth"), self._value < _raw(other)))

    def __del__(self):
        self._fixture.released(self._label, "number")


class Truth:
    def __init__(self, fixture, label, value):
        self._fixture, self._label, self._value = fixture, label, value

    def __bool__(self):
        return self._fixture.external(self._label + ".bool", (), lambda: self._value)

    def __del__(self):
        self._fixture.released(self._label, "truth")


class Comparison:
    def __init__(self, fixture, label, value):
        self._fixture, self._label, self._value = fixture, label, value

    def __ne__(self, other):
        return self._fixture.external(self._label + ".ne", (other,),
            lambda: Truth(self._fixture, self._label + ".truth", self._value != _raw(other)))

    def __del__(self):
        self._fixture.released(self._label, "comparison")


class Metadata:
    def __init__(self, fixture, label):
        self._fixture, self._label = fixture, label

    def __del__(self):
        self._fixture.released(self._label, "metadata")


class PairIterator:
    def __init__(self, fixture, values):
        self.fixture, self.values, self.index = fixture, values, 0

    def __iter__(self):
        return self.fixture.external("get-result.iter", (), lambda: self)

    def __next__(self):
        def step():
            if self.index == len(self.values):
                raise StopIteration
            value = self.values[self.index]
            self.index += 1
            return value
        return self.fixture.external("get-result.next", (), step)

    def __del__(self):
        self.fixture.released("get-result", "iterator")


class Cursor:
    def __init__(self, fixture, label, row):
        self._fixture, self._label, self._row = fixture, label, row

    def __getattribute__(self, name):
        if name == "fetchone":
            f, label, row = (object.__getattribute__(self, n) for n in ("_fixture", "_label", "_row"))
            return f.external(label + ".fetchone.lookup", (),
                lambda: Provider(f, label + ".fetchone", lambda: row))
        return object.__getattribute__(self, name)

    def __del__(self):
        self._fixture.released(self._label, "sql-cursor")


class Database:
    def __init__(self, fixture, label):
        self._fixture, self._label = fixture, label

    def __getattribute__(self, name):
        if name == "execute":
            f, label = object.__getattribute__(self, "_fixture"), object.__getattribute__(self, "_label")
            return f.external(label + ".execute.lookup", (),
                lambda: Provider(f, label + ".execute", self._execute))
        return object.__getattribute__(self, name)

    def _execute(self, sql, parameters):
        f = self._fixture
        if sql == "SELECT * FROM cursors WHERE id=?":
            return Cursor(f, "cursor.select", f.make_row())
        if sql == "SELECT * FROM artifacts WHERE uri=?":
            return Cursor(f, "artifact.select", None if f.case.get("uri_missing") else {"issued": True})
        # Record the completed fake provider effect before the external return
        # cutpoint. A later injected error does not erase this observation.
        f.effects.append({"database": self._label, "sql": sql, "parameters": snapshot(parameters)})
        f.trace.append({"phase": f.phase, "effect": "fake-sql-executed", "sql": sql,
                        "parameters": snapshot(parameters)})
        return Cursor(f, "cursor.insert" if sql.startswith("INSERT OR IGNORE INTO cursors") else "caller.sql", None)


class Store:
    def __init__(self, fixture, label):
        self._fixture, self._label = fixture, label
        self._db = Database(fixture, label + ".db")

    def __getattribute__(self, name):
        if name in {"get", "resolve_uri", "_ref", "db"}:
            f, label = object.__getattribute__(self, "_fixture"), object.__getattribute__(self, "_label")
            def value():
                if name == "db":
                    return object.__getattribute__(self, "_db")
                if name == "get":
                    operation = f.store_get
                elif name == "_ref":
                    operation = lambda row: f.ref
                else:
                    operation = lambda uri: f.original_resolve(self, uri)
                return Provider(f, label + "." + name, operation)
            return f.external(label + "." + name + ".lookup", (), value)
        return object.__getattribute__(self, name)


class Service:
    def __init__(self, fixture):
        self._fixture, self._store = fixture, Store(fixture, "store.v1")
        self.catalog_sha256 = "catalog-original-fixture"
        self.identities = {"fixture": "original-only"}
        self.tools = {"hia_read": {"inputSchema": {}, "outputSchema": {}}}

    def __getattribute__(self, name):
        if name == "store":
            f = object.__getattribute__(self, "_fixture")
            return f.external("service.store.lookup", (), lambda: object.__getattribute__(self, "_store"))
        if name == "_hia_read":
            f = object.__getattribute__(self, "_fixture")
            return f.external("service._hia_read.lookup", (),
                lambda: Provider(f, "service._hia_read", lambda args: f.original_read(self, args)))
        if name == "_error":
            f = object.__getattribute__(self, "_fixture")
            return Provider(f, "service._error", lambda request, error: {
                "contract_version": f.namespace["VERSION"], "request_id": request,
                "status": "rejected", "error": {"message": str(error),
                    "code": getattr(error, "code", type(error).__name__)}})
        return object.__getattribute__(self, name)


class AttributeProvider:
    def __init__(self, fixture, label, providers):
        self._fixture, self._label, self._providers = fixture, label, providers

    def __getattribute__(self, name):
        if not name.startswith("_"):
            f, label, values = (object.__getattribute__(self, n) for n in ("_fixture", "_label", "_providers"))
            if name in values:
                return f.external(label + "." + name + ".lookup", (), lambda: values[name])
        return object.__getattribute__(self, name)


class Fixture:
    def __init__(self, case, bodies):
        self.case = case
        self.trace, self.effects, self.destructor_errors = [], [], []
        self.traceback_diagnostics = []
        self.counts, self.labels = {}, {}
        self.phase, self.recording = "owner", True
        self.fault_triggered = False
        # One explicitly owned foreign input object. It is released at the
        # documented consumer boundary, so identity checks never retain an
        # otherwise short-lived natural codec exception or use recycled ids.
        self.injected_fault = self.make_fault(case["fault"]["kind"]) if case.get("fault") else None
        self.applied_actions = set()
        self.wire_calls = self.get_calls = 0
        self.namespace = {"__name__": "frozen_service_read_original", "__builtins__": builtins.__dict__}
        for name in ("AgentRejected", "reject", "keys", "_hia_read", "_reference_call", "_resolve_uri_reference"):
            exec(compile(textwrap.dedent(bodies[name]), name + ".original.py", "exec"), self.namespace)
        self.original_read = self.namespace["_hia_read"]
        self.original_resolve = self.namespace["_resolve_uri_reference"]
        self.original_caller = self.namespace["_reference_call"]
        self.raw_reject = self.namespace["reject"]
        raw = bytes.fromhex(case.get("data_hex", "616263646566"))
        data_kind = case.get("data_kind", "blob")
        if data_kind == "bytearray":
            raw = bytearray(raw)
        self.data = raw if data_kind in {"bytes", "bytearray"} else Blob(self, "data", raw)
        if data_kind == "none":
            self.data = None
        self.ref = MappingProbe(self, "ref", {"id": "artifact-1", "sha256": "ab" * 32})
        self.service = Service(self)
        self.namespace.update({"UnicodeDecodeError": UnicodeDecodeError,
            "int": self.provider("int"), "len": self.provider("len"), "max": self.provider("max"),
            "wire": self.provider("wire"), "digest": self.provider("digest"),
            "reject": Provider(self, "reject", self.raw_reject),
            "base64": AttributeProvider(self, "base64", {"b64encode": Provider(self, "base64.b64encode", self.base64_encode)}),
            "time": AttributeProvider(self, "time", {
                "monotonic_ns": Provider(self, "time.monotonic_ns", lambda: 1000),
                "time_ns": Provider(self, "time.time_ns", lambda: 2000)}),
            "uuid": AttributeProvider(self, "uuid", {"uuid4": Provider(self, "uuid.uuid4", lambda: types.SimpleNamespace(hex="012345"))}),
            "sqlite3": types.SimpleNamespace(Error=FakeSQLiteError),
            "decode_data": Provider(self, "decode_data", lambda value: json.loads(bytes(_raw(value)))),
            "validate": Provider(self, "validate", lambda *args: None),
            "installation_manifest": Provider(self, "installation_manifest", lambda: self.service.identities),
            "_delivery_check": Provider(self, "delivery_check", lambda: None),
            "_delivery_guard": Provider(self, "delivery_guard", lambda value: value),
            "_delivery_lost": Provider(self, "delivery_lost", lambda: False),
            "VERSION": "hepta.hia.agent-native.v1"})
        values = {"artifact": self.ref}
        if case.get("cursor", False):
            values["cursor"] = "cursor-1"
        if "limit" in case:
            values["max_bytes"] = self.value(case["limit"], "limit")
        if case.get("missing_artifact"):
            del values["artifact"]
        self.arguments = MappingProbe(self, "arguments", values)

    def label(self, prefix):
        number = self.labels.get(prefix, 0) + 1
        self.labels[prefix] = number
        return prefix + "." + str(number)

    def value(self, value, label):
        if type(value) is dict and "number" in value:
            return Number(self, label, value["number"], value.get("int_return"))
        return value

    def active_exception(self):
        error = sys.exception()
        return None if error is None else {"type": type(error).__module__ + "." + type(error).__qualname__,
                                          "is_exact_injected_fault": error is self.injected_fault}

    def make_fault(self, kind):
        message = "original-only injected " + kind
        table = {"ValueError": InjectedError, "TypeError": TypeError, "OSError": OSError,
                 "MemoryError": MemoryError, "KeyboardInterrupt": KeyboardInterrupt,
                 "SystemExit": SystemExit, "GeneratorExit": GeneratorExit,
                 "StopIteration": StopIteration, "OverflowError": OverflowError,
                 "AttributeError": AttributeError}
        if kind == "UnicodeDecodeError":
            return UnicodeDecodeError("utf-8", b"\xff", 0, 1, message)
        return table[kind](message)

    def actions(self, event, occurrence, phase):
        for index, action in enumerate(self.case.get("actions", [])):
            if index in self.applied_actions:
                continue
            if (action["event"], action.get("occurrence", 1), action.get("phase", "after")) != (event, occurrence, phase):
                continue
            self.applied_actions.add(index)
            kind = action["action"]
            if kind == "replace_global":
                name = action["name"]
                if name == "UnicodeDecodeError":
                    self.namespace[name] = {"ValueError": ValueError, "invalid": "not-an-exception-class",
                                            "UnicodeDecodeError": UnicodeDecodeError}[action["value"]]
                else:
                    self.namespace[name] = self.provider(name, action.get("version", "v2"))
            elif kind == "replace_store":
                self.service._store = Store(self, action.get("label", "store.v2"))
            elif kind == "replace_db":
                self.service._store._db = Database(self, action.get("label", "store.db.v2"))
            elif kind == "mutate_ref":
                self.ref._items[action["key"]] = action["value"]
            else:
                raise AssertionError(("unrecognized fixture action", action))
            self.trace.append({"phase": self.phase, "fixture_action": index, "action": dict(action)})

    def external(self, event, args, operation, details=None):
        occurrence = self.counts.get(event, 0) + 1
        self.counts[event] = occurrence
        for_phase = {"phase": self.phase, "boundary": True, "event": event,
                     "occurrence": occurrence, "arguments": snapshot(args),
                     "active_exception": self.active_exception()}
        if details:
            for_phase["details"] = details
        self.trace.append(dict(for_phase, boundary_phase="before"))
        self.actions(event, occurrence, "before")
        fault = self.case.get("fault")
        if fault and (fault["event"], fault["occurrence"], fault["phase"]) == (event, occurrence, "before"):
            self.fault_triggered = True
            raise self.injected_fault
        try:
            result = operation()
        except BaseException as error:
            self.trace.append({"phase": self.phase, "event": event, "occurrence": occurrence,
                               "raised": exception_snapshot(error, self)})
            raise
        self.trace.append(dict(for_phase, boundary_phase="after", returned=snapshot(result),
                               active_exception=self.active_exception()))
        self.actions(event, occurrence, "after")
        if fault and (fault["event"], fault["occurrence"], fault["phase"]) == (event, occurrence, "after"):
            self.fault_triggered = True
            raise self.injected_fault
        return result

    def released(self, label, kind):
        if not self.recording:
            return
        try:
            self.trace.append({"phase": self.phase, "release": label, "kind": kind,
                               "active_exception": self.active_exception()})
            self.actions("release:" + label, 1, "after")
        except BaseException as error:
            # Never rely on a failing assertion inside __del__: the outer
            # observer explicitly rejects any observer/destructor error.
            self.destructor_errors.append({"type": type(error).__name__, "message": str(error)})

    def provider(self, name, version="v1"):
        if name == "wire":
            operation = self.wire
        elif name == "digest":
            operation = lambda value: hashlib.sha256(self.json_wire(value)).hexdigest()
        else:
            operation = {"int": builtins.int, "len": builtins.len, "max": builtins.max}[name]
        return Provider(self, name, operation, version)

    def json_wire(self, value):
        return json.dumps(_raw(value), ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")

    def wire(self, value):
        self.wire_calls += 1
        sizes = self.case.get("wire_sizes", [])
        size = sizes[self.wire_calls - 1] if self.wire_calls <= len(sizes) else None
        return Blob(self, "wire." + str(self.wire_calls), self.json_wire(value), size)

    def base64_encode(self, chunk):
        return Blob(self, self.label("base64"), _base64.b64encode(_raw(chunk)))

    def store_get(self, ref):
        self.get_calls += 1
        values = [self.data, Metadata(self, "metadata." + str(self.get_calls))]
        form = self.case.get("get_result", "tuple")
        if form == "short":
            values = values[:1]
        elif form == "long":
            values.append(Metadata(self, "metadata.extra"))
        if form == "iterator":
            return PairIterator(self, values)
        return tuple(values)

    def make_row(self):
        mode = self.case.get("row", "valid")
        if mode == "missing":
            return None
        values = {"artifact_id": self.ref._items["id"], "sha256": self.ref._items["sha256"],
                  "offset": self.value(self.case.get("offset", 0), "offset")}
        if mode == "id_mismatch":
            values["artifact_id"] = "foreign-id"
        if mode == "sha_mismatch":
            values["sha256"] = "foreign-sha"
        if self.case.get("comparison_protocol"):
            for key in ("artifact_id", "sha256"):
                values[key] = Comparison(self, "row." + key, values[key])
        return MappingProbe(self, "row", values)

    def run_original(self):
        recorded_error = None
        result = None
        try:
            if self.case.get("entry", "read") == "alias":
                arguments = {"uri": self.case.get("uri", "hia://artifact-1")}
                if "limit" in self.case:
                    arguments["max_bytes"] = self.case["limit"]
                arguments.update(self.case.get("alias_extra", {}))
                result = self.original_caller(self.service, "hia_resource_read", arguments)
            else:
                result = self.original_read(self.service, self.arguments)
        except BaseException as error:
            recorded_error = error
            outcome = {"status": "raised", "error": exception_snapshot(error, self),
                       "raised_error_is_exact_injected_fault": error is self.injected_fault}
        else:
            outcome = {"status": "returned", "value": snapshot(result),
                       "artifact_is_original_ref": (type(result) is dict and result.get("artifact") is self.ref)}
        body_end = len(self.trace)
        # This is an explicit consumer history. No gc.collect, warm reset or
        # normalization is inserted into the original method itself.
        self.phase = "consumer-release"
        result = None
        if recorded_error is not None or self.injected_fault is not None:
            pending = [error for error in (recorded_error, self.injected_fault) if error is not None]
            seen = set()
            while pending:
                error = pending.pop()
                if id(error) in seen:
                    continue
                seen.add(id(error))
                if error.__cause__ is not None:
                    pending.append(error.__cause__)
                if error.__context__ is not None:
                    pending.append(error.__context__)
                error.__traceback__ = None
            recorded_error = None
            self.injected_fault = None
            # AttributeError.obj may own a temporary cursor. Do not leave the
            # observer's traversal variable retaining that original object
            # beyond the declared consumer-release boundary.
            error = None
        observation = {"case_id": self.case["id"], "outcome": outcome,
            "trace": list(self.trace), "body_trace_end": body_end,
            "fake_sql_effects": list(self.effects), "wire_calls": self.wire_calls,
            "store_get_calls": self.get_calls, "fault_triggered": self.fault_triggered,
            "actions_applied": sorted(self.applied_actions),
            "destructor_observer_errors": list(self.destructor_errors)}
        self.recording = False
        if self.destructor_errors:
            raise AssertionError(("destructor observer failed", self.destructor_errors))
        if self.case.get("fault") and not self.fault_triggered:
            raise AssertionError(("declared cutpoint was not reached", self.case["fault"]))
        if len(self.applied_actions) != len(self.case.get("actions", [])):
            raise AssertionError(("declared action was not reached", self.case["id"], self.applied_actions))
        return observation


def load_originals(frozen_directory):
    directory = Path(frozen_directory)
    names = {"_hia_read": "_hia_read.py.txt", "_reference_call": "_reference_call.py.txt",
             "_resolve_uri_reference": "store-_resolve_uri_reference.py.txt",
             "AgentRejected": "AgentRejected.py.txt", "reject": "reject.py.txt", "keys": "keys.py.txt"}
    bodies = {name: (directory / "originals" / filename).read_text() for name, filename in names.items()}
    if hashlib.sha256(bodies["_hia_read"].encode()).hexdigest() != READ_SHA256:
        raise ValueError("original read method bytes changed")
    return bodies


def observe_original(case, bodies):
    return Fixture(case, bodies).run_original()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
