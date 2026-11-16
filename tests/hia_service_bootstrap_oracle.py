"""Independent frozen bootstrap bodies and explicit finite providers.

This file never imports a product module. Candidate wiring belongs to the
separate observer and runs only after a complete immutable original authority.
No expected outcome is constructed here: the five original bodies execute.
"""
from __future__ import annotations
import builtins
import contextvars
from hashlib import sha256
import json
from pathlib import Path
import sys
import textwrap
import threading
import types
import weakref

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/hia_service_bootstrap_original_r12"
DOMAIN_PIN = "cb514a6ba953e6ffb3cbf293ded95fb1bd6631cb42a06212345bb94987221c57"
METHOD_PINS = {
    "__init__": "03570fc017e76dd35f4bbd12b45672a21b735a7cb52933c715ce33f9271f3f0f",
    "close": "60f1d4eaf32534640d3f4a17db901705b48ae6fc6982d3b4ea6cda19b4065ef6",
    "_profiles": "0faed3cf3fdb0642867c4b4430ffa965b9dba1f560b3ae65f1f1e89fa65c8b7d",
    "_profile": "0adeac9e1bf6164386db92d0a24fef3a8e083b39e027fe3063926ba1e14aeb3c",
    "_program": "7de11c0755047bab19cb7625741bfb2aa6c79dc64d7fd99b4b57fbd2c340402a",
}
METHODS = tuple(METHOD_PINS)
FAMILIES = {name: getattr(builtins, name) for name in (
    "RuntimeError", "OSError", "ValueError", "TypeError", "AttributeError",
    "KeyError", "KeyboardInterrupt", "SystemExit", "MemoryError",
    "StopIteration", "GeneratorExit")}
_ORIGINAL_BODIES = {}
for _name, _pin in METHOD_PINS.items():
    _raw = (FIXTURE / (_name + ".py.txt")).read_bytes()
    if sha256(_raw).hexdigest() != _pin:
        raise ValueError("frozen bootstrap body differs: " + _name)
    _ORIGINAL_BODIES[_name] = _raw
del _name, _pin, _raw
_ORIGINAL_NAMESPACE = {"__name__": "hepta.hia_agent_service", "__package__": "hepta"}
_ORIGINAL_BUILTINS = dict(vars(builtins))
_ORIGINAL_NAMESPACE["__builtins__"] = _ORIGINAL_BUILTINS
_ORIGINAL_CLASS_CODE = compile("class HIAAgentService:\n" +
    "\n".join(raw.decode() for raw in _ORIGINAL_BODIES.values()),
    str(FIXTURE / "complete-five-original-bodies"), "exec")
exec(_ORIGINAL_CLASS_CODE, _ORIGINAL_NAMESPACE)
_ORIGINAL_CLASS = _ORIGINAL_NAMESPACE["HIAAgentService"]
ORIGINALS = {name:vars(_ORIGINAL_CLASS)[name] for name in METHODS}
_ORIGINAL_CODE = {name:function.__code__ for name,function in ORIGINALS.items()}
_ORIGINAL_FIXED = dict(_ORIGINAL_NAMESPACE)
_THREAD_LABEL = contextvars.ContextVar("bootstrap-observer-context", default="main")
_ARGS = BaseException.__dict__["args"]
_CAUSE = BaseException.__dict__["__cause__"]
_CONTEXT = BaseException.__dict__["__context__"]
_TRACEBACK = BaseException.__dict__["__traceback__"]
_SUPPRESS = BaseException.__dict__["__suppress_context__"]

def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def captured(path, expected=None):
    raw = Path(path).read_bytes()
    pin = {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    if expected is not None and pin != expected:
        raise ValueError("captured bootstrap bytes differ: " + str(path))
    return raw, json.loads(raw), pin

def cases():
    raw = (FIXTURE / "observation-domain.json").read_bytes()
    if sha256(raw).hexdigest() != DOMAIN_PIN:
        raise ValueError("bootstrap input domain differs")
    value = json.loads(raw)
    rows = value["cases"]
    if len(rows) != 232 or len({row["id"] for row in rows}) != 232:
        raise ValueError("complete 232 input identities are required")
    return rows, raw

class AgentRejected(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code

class OuterError(RuntimeError):
    pass

class ProviderHandledError(RuntimeError):
    pass

class CaseFault(RuntimeError):
    def __init__(self, world, name):
        super().__init__(name)
        self.world = world
        self.fault_name = name
    def __getattribute__(self, name):
        if name == "add_note":
            world = object.__getattribute__(self, "world")
            world.point("error.add_note.lookup.before")
            value = NoteCall(world, self)
            world.point("error.add_note.lookup.after")
            return value
        return super().__getattribute__(name)

class World:
    def __init__(self, case):
        self.case = dict(case)
        self.method = case["method"]
        self.scenario = case["scenario"]
        self.events = EventLog()
        self.hits = []
        self.counts = {}
        self.labels = {}
        self.created = []
        self.error_names = []
        self.phase = "setup"
        self.active = False
        self.named_faults = {}
        self.fault_settings = []
        self.scenario_hits = []
        self.target_hits = []
        self.target = case.get("fault")
        self.target_error = None
        if self.target is not None:
            self.target_error = FAMILIES[self.target["family"]]("bootstrap target " + self.target["label"])
            self.error_names.append(("target", self.target_error))
        self.outer = OuterError("outer")
        self.second_outer = OuterError("second outer")
        self.generator_error = RuntimeError("generator throw instance")
        self.error_names.extend((("outer", self.outer), ("outer-second", self.second_outer),
                                 ("generator-throw", self.generator_error)))
        self.held_generators = []
        self.held_tracebacks = []
        self.external = {}
        self.raw_errors = []
        self.namespace = None
        self.modules = {}
        self.unraisable = EventLog()
        self.thread_errors = EventLog()
        self.reentry = None
        self.configure()

    def register(self, value, label):
        number = self.counts.get("object:" + label, 0) + 1
        self.counts["object:" + label] = number
        token = label + "#" + str(number)
        self.labels[id(value)] = (weakref.ref(value), token)
        self.created.append((token, weakref.ref(value)))
        return token

    def token(self, value):
        row = self.labels.get(id(value))
        if row is not None and row[0]() is value:
            return row[1]
        return None

    def value(self, value, seen=None):
        if value is None or type(value) in (bool, int, str):
            return value
        if type(value) is float:
            return {"float_hex": value.hex()}
        if type(value) is bytes:
            return {"bytes_hex": value.hex()}
        token = self.token(value)
        if token is not None:
            return {"object": token}
        if seen is None:
            seen = set()
        if id(value) in seen:
            return {"cycle": True}
        if type(value) in (dict, list, tuple):
            seen.add(id(value))
            try:
                if type(value) is dict:
                    return {"dict": [[self.value(k, seen), self.value(v, seen)] for k, v in value.items()]}
                return {type(value).__name__: [self.value(v, seen) for v in value]}
            finally:
                seen.remove(id(value))
        if isinstance(value, BaseException):
            return self.error(value)
        if isinstance(value, types.GeneratorType):
            return {"generator": True, "running": value.gi_running,
                    "closed": value.gi_frame is None}
        if isinstance(value, types.FunctionType):
            return {"function": value.__name__}
        if isinstance(value, type):
            return {"type": type.__getattribute__(value, "__module__") + "." + type.__getattribute__(value, "__qualname__")}
        return {"opaque_type": type(value).__module__ + "." + type(value).__qualname__}

    def error(self, error, seen=None):
        if error is None:
            return None
        if seen is None:
            seen = {}
        key = id(error)
        if key in seen:
            return {"same_exception": seen[key]}
        label = "exception-" + str(len(seen))
        seen[key] = label
        known = next((name for name, current in self.error_names if current is error), None)
        args = _ARGS.__get__(error)
        row = {"type": type(error).__module__ + "." + type(error).__qualname__,
               "args": self.value(args), "known_identity": known,
               "same_outer": error is self.outer,
               "same_target": self.target_error is not None and error is self.target_error,
               "suppress_context": _SUPPRESS.__get__(error)}
        if isinstance(error, AttributeError):
            row["name"] = self.value(AttributeError.__dict__["name"].__get__(error))
            row["obj"] = self.value(AttributeError.__dict__["obj"].__get__(error))
        if isinstance(error, OSError):
            for name in ("errno", "strerror", "filename", "filename2"):
                row[name] = self.value(getattr(error, name))
        data = BaseException.__dict__["__dict__"].__get__(error) if "__dict__" in BaseException.__dict__ else object.__getattribute__(error, "__dict__")
        row["notes"] = self.value(data.get("__notes__"))
        if isinstance(error, AgentRejected):
            row["code"] = self.value(data.get("code"))
        row["cause"] = self.error(_CAUSE.__get__(error), seen)
        row["context"] = self.error(_CONTEXT.__get__(error), seen)
        return row

    def emit(self, event, **values):
        self.events.append({"event": event, "phase": self.phase,
                            "active": self.error(sys.exception()),
                            "context": _THREAD_LABEL.get(),
                            "main_thread": threading.current_thread() is threading.main_thread(),
                            **{key: self.value(value) for key, value in values.items()}})

    def point(self, label):
        if not self.active:
            return
        occurrence = self.counts.get("point:" + label, 0) + 1
        self.counts["point:" + label] = occurrence
        hit = {"index": len(self.hits), "label": label, "occurrence": occurrence, "phase": self.phase}
        self.hits.append(hit)
        self.emit(label, occurrence=occurrence)
        if self.target is not None and hit["index"] == self.target["index"]:
            if any(hit[key] != self.target[key] for key in ("label", "occurrence", "phase")):
                raise AssertionError("bootstrap target changed its exact original cutpoint")
            self.target_hits.append(dict(hit))
            raise self.target_error
        for rule in self.fault_settings:
            if label == rule["label"] and occurrence == rule["occurrence"]:
                if self.target is not None and self.target.get("replace_scenario_at_or_after") is not None:
                    if hit["index"] >= self.target["replace_scenario_at_or_after"]:
                        continue
                self.scenario_hits.append({**hit, "fault": rule["fault"]})
                raise self.named_faults[rule["fault"]]

    def fault(self, label, family="RuntimeError", occurrence=1, name=None, note=False):
        name = name or label
        error = CaseFault(self, name) if note else FAMILIES[family](name)
        self.named_faults[name] = error
        self.error_names.append((name, error))
        self.fault_settings.append({"label": label, "occurrence": occurrence, "fault": name})

    def keep_traceback(self, name):
        try:
            raise ProviderHandledError(name)
        except ProviderHandledError as error:
            self.emit("provider.handled", label=name, is_current=sys.exception() is error)
            self.held_tracebacks.append(error.__traceback__)

    def trace(self, error, role):
        def walk(current, visited):
            if current is None:
                return None
            key = id(current)
            if key in visited:
                return {"same_exception": visited[key]}
            visited[key] = len(visited)
            frames = []
            tb = _TRACEBACK.__get__(current)
            while tb is not None:
                code = tb.tb_frame.f_code
                frames.append({"filename": code.co_filename, "function": code.co_name,
                               "lineno": tb.tb_lineno, "lasti": tb.tb_lasti})
                tb = tb.tb_next
            return {"type": type(current).__module__ + "." + type(current).__qualname__,
                    "frames": frames, "cause": walk(_CAUSE.__get__(current), visited),
                    "context": walk(_CONTEXT.__get__(current), visited)}
        self.raw_errors.append({"role": role, "traceback": walk(error, {})})

    def alive(self):
        return [label for label, ref in self.created if ref() is not None]


    def configure(self):
        self.candidate_selected = self.scenario not in ("no-selected-budget-or-ledger", "ledger-only", "empty-selector-refusal")
        self.slot_selected = self.scenario not in ("no-selected-budget-or-ledger", "candidate-only", "empty-selector-refusal")
        self.root_count = 0 if self.scenario in ("empty-roots", "no-selected-budget-or-ledger") else 2
        self.detach_store = self.scenario in (
            "temporary-store-detached-callable", "temporary-store-detached-get",
            "temporary-bound-and-detached-store", "temporary-store-detached-close")
        self.detach_budget = self.scenario in ("temporary-bound-and-detached-budget", "temporary-budget-detached-close")
        self.budget_present = self.scenario != "budget-none"
        method, scenario = self.method, self.scenario
        if method == "__init__":
            simple = {
                "iterator-acquisition-fails": ("roots.iter.before", "TypeError"),
                "catalog-unpack-first-store-fails": ("service.set.catalog.before", "AttributeError"),
                "tools-key-lookup-error": ("tool.get.name.before", "KeyError"),
                "installation-manifest-error": ("installation_manifest.call.before", "RuntimeError"),
                "store-construction-error-before-try": ("AgentStore.call.before", "OSError"),
                "first-None-attribute-set-error-before-try": ("service.set._candidate_budget.before", "AttributeError"),
                "candidate-construction-error": ("NativeCandidateBudgetStore.call.before", "RuntimeError"),
                "ledger-construction-error": ("NativeSlotLedgerStore.call.before", "RuntimeError"),
                "root-path-call-error": ("Path.call.before", "RuntimeError"),
                "absolute-error": ("path.absolute.call.before", "OSError"),
                "resolve-error": ("path.resolve.call.before", "OSError"),
                "is-dir-error": ("path.is_dir.call.before", "OSError"),
                "dynamic-profiles-error": ("service._profiles.call.before", "RuntimeError"),
                "empty-selector-refusal": ("selected_candidate_budget.call.before", "ValueError"),
            }
            if scenario in simple:
                self.fault(*simple[scenario])
            cleanup = {
                "cleanup-budget-property-error": ("service.get._candidate_budget.before", "AttributeError"),
                "cleanup-bound-close-error": ("budget.close.lookup.before", "AttributeError"),
                "cleanup-store-property-error": ("service.get.store.before", "AttributeError"),
                "cleanup-first-call-error": ("budget.close.call.before", "RuntimeError"),
                "cleanup-second-call-error": ("store.close.call.before", "RuntimeError"),
                "cleanup-note-lookup-error": ("error.add_note.lookup.before", "AttributeError"),
                "cleanup-note-call-error": ("error.add_note.call.before", "RuntimeError"),
            }
            if scenario in cleanup or scenario in (
                    "temporary-bound-and-detached-budget", "dynamic-BaseException-nonmatching",
                    "dynamic-BaseException-invalid-tuple"):
                self.fault("service._profiles.call.before", name="construction-body", note=scenario.startswith("cleanup-note"))
            if scenario in cleanup:
                label, family = cleanup[scenario]
                occurrence = 3 if scenario == "cleanup-store-property-error" else 1
                self.fault(label, family, occurrence=occurrence, name="construction-cleanup")
                if scenario.startswith("cleanup-note"):
                    self.fault("budget.close.call.before", name="cleanup-callee")
        elif method == "close":
            simple = {
                "budget-presence-getter-error": ("service.get._candidate_budget.before", "AttributeError", 1),
                "second-budget-getter-error": ("service.get._candidate_budget.before", "AttributeError", 2),
                "budget-close-lookup-error": ("budget.close.lookup.before", "AttributeError", 1),
                "budget-close-call-error": ("budget.close.call.before", "RuntimeError", 1),
                "store-getter-error": ("service.get.store.before", "AttributeError", 1),
                "store-close-lookup-error": ("store.close.lookup.before", "AttributeError", 1),
                "store-close-call-error": ("store.close.call.before", "RuntimeError", 1),
            }
            if scenario in simple:
                label, family, occurrence = simple[scenario]
                self.fault(label, family, occurrence)
            if scenario == "body-and-finally-error-context":
                self.fault("budget.close.call.before", "ValueError", name="close-body")
                self.fault("store.close.call.before", "RuntimeError", name="close-finally")
        elif method == "_profiles":
            simple = {
                "catalog-sha-getter-error": ("service.get.catalog_sha256.before", "AttributeError"),
                "sorted-core-error": ("sorted.core.call.before", "RuntimeError"),
                "sorted-opcodes-error": ("sorted.opcodes.call.before", "RuntimeError"),
                "sorted-imports-error": ("sorted.imports.call.before", "RuntimeError"),
                "artifact-roots-len-error": ("roots.len.before", "TypeError"),
                "roots-iterator-error": ("roots.iter.before", "TypeError"),
                "root-string-error": ("root.str.before", "RuntimeError"),
                "digest-raises-after-full-list": ("digest.call.before", "RuntimeError"),
                "first-profile-subscript-store-error": ("profiles.set.before", "TypeError"),
                "second-profile-subscript-store-error": ("profile_artifacts.set.before", "TypeError"),
                "schema-registry-error": ("schema_registry.call.before", "RuntimeError"),
                "macro-provider-error": ("macro_policy_guidance.call.before", "RuntimeError"),
                "examples-provider-error": ("service._examples.call.before", "RuntimeError"),
                "diagnostics-call-error": ("store.json.diagnostics.call.before", "RuntimeError"),
                "manifest-call-error": ("store.json.manifest.call.before", "RuntimeError"),
            }
            if scenario in simple:
                self.fault(*simple[scenario])
        elif method == "_profile":
            simple = {
                "store-getter-error": ("service.get.store.before", "AttributeError"),
                "check-profile-lookup-error": ("store.check_profile.lookup.before", "AttributeError"),
                "profiles-getter-error": ("service.get.profiles.before", "AttributeError"),
                "profile-name-subscript-error": ("profiles.get.name.before", "KeyError"),
                "check-profile-call-error": ("store.check_profile.call.before", "RuntimeError"),
            }
            if scenario in simple:
                self.fault(*simple[scenario])
        elif method == "_program":
            simple = {
                "store-getter-error": ("service.get.store.before", "AttributeError"),
                "get-lookup-error": ("store.get.lookup.before", "AttributeError"),
                "get-call-error": ("store.get.call.before", "RuntimeError"),
                "unpack-iterator-raises": ("get-result.next.before", "RuntimeError"),
                "decode-error": ("decode_json.call.before", "ValueError"),
                "verify-error": ("verify_program.call.before", "RuntimeError"),
            }
            if scenario in simple:
                self.fault(*simple[scenario])

class Watch:
    __slots__ = ("_world", "_token", "_label", "__weakref__")
    def __init__(self, world, label):
        object.__setattr__(self, "_world", world)
        object.__setattr__(self, "_label", label)
        object.__setattr__(self, "_token", world.register(self, label))
    def __repr__(self):
        return "<bootstrap " + object.__getattribute__(self, "_token") + ">"
    def __del__(self):
        world = object.__getattribute__(self, "_world")
        try:
            world.emit("delete", object=object.__getattribute__(self, "_token"))
        except BaseException as error:
            world.unraisable.append({"source": "Watch.__del__", "type": type(error).__name__})

class Atom(Watch):
    pass

class Mapping(Watch):
    __slots__ = ("_values",)
    def __init__(self, world, label, values):
        super().__init__(world, label)
        self._values = values
    def __getitem__(self, key):
        world, label = self._world, self._label
        suffix = "name" if label in ("profiles", "tool") else str(key)
        world.point(label + ".get." + suffix + ".before")
        value = self._values[key]
        world.point(label + ".get." + suffix + ".after")
        return value
    def __setitem__(self, key, value):
        self._world.point(self._label + ".set.before")
        self._values[key] = value
        self._world.point(self._label + ".set.after")
    def keys(self):
        self._world.point(self._label + ".keys.before")
        result = self._values.keys()
        self._world.point(self._label + ".keys.after")
        return result
    def __iter__(self):
        self._world.point(self._label + ".iter.before")
        result = iter(self._values)
        self._world.point(self._label + ".iter.after")
        return result

class Sequence(Watch):
    __slots__ = ("_kind", "_size")
    def __init__(self, world, label, kind, size):
        super().__init__(world, label)
        self._kind, self._size = kind, size
    def __iter__(self):
        self._world.point(self._label + ".iter.before")
        value = Iterator(self._world, self._label, self._kind, self._size)
        self._world.point(self._label + ".iter.after")
        return value
    def __len__(self):
        self._world.point(self._label + ".len.before")
        value = self._size
        self._world.point(self._label + ".len.after")
        return value

class Iterator(Watch):
    __slots__ = ("_kind", "_size", "_index")
    def __init__(self, world, label, kind, size):
        super().__init__(world, label + "-iterator")
        self._label, self._kind, self._size, self._index = label, kind, size, 0
    def __iter__(self):
        return self
    def __next__(self):
        world, label = self._world, self._label
        world.point(label + ".next.before")
        if self._index == self._size:
            world.emit(label + ".stop")
            raise StopIteration
        index = self._index
        self._index += 1
        if self._kind == "root-input":
            value = Atom(world, "root-input-" + str(index))
        elif self._kind == "resolved-root":
            value = PathValue(world, "resolved-root-" + str(index), index)
        elif self._kind == "tool":
            value = Mapping(world, "tool", {"name": "tool-" + str(index)})
        elif self._kind == "get-result":
            value = Atom(world, ("data", "metadata", "extra")[index])
        else:
            raise AssertionError("unknown scripted iterator kind")
        world.point(label + ".next.after")
        return value

class Call(Watch):
    __slots__ = ("_action", "_receiver")
    def __init__(self, world, label, action, receiver=None):
        super().__init__(world, label + "-callable")
        self._label, self._action, self._receiver = label, action, receiver
    def __call__(self, *args, **kwargs):
        world = self._world
        world.point(self._label + ".call.before")
        world.emit("call.arguments", callee=self._label, args=args, kwargs=kwargs)
        value = self._action(world, self._label, self._receiver, args, kwargs)
        world.point(self._label + ".call.after")
        return value

class NoteCall(Call):
    def __init__(self, world, error):
        super().__init__(world, "error.add_note", _note_action, error)

def _note_action(world, label, error, args, kwargs):
    return BaseException.add_note(error, *args, **kwargs)

class PathValue(Watch):
    __slots__ = ("_index",)
    def __init__(self, world, label, index=0):
        super().__init__(world, label)
        self._index = index
    def __getattribute__(self, name):
        if name in ("absolute", "resolve", "is_dir", "read_bytes"):
            world = object.__getattribute__(self, "_world")
            world.point("path." + name + ".lookup.before")
            result = Call(world, "path." + name, _path_action, self)
            world.point("path." + name + ".lookup.after")
            return result
        return object.__getattribute__(self, name)
    def __str__(self):
        self._world.point("root.str.before")
        result = "/root/" + str(self._index)
        self._world.point("root.str.after")
        return result

def _path_action(world, label, receiver, args, kwargs):
    if label == "path.absolute":
        return PathValue(world, "absolute", receiver._index)
    if label == "path.resolve":
        if args or kwargs != {"strict": True}:
            raise AssertionError("original resolve call arguments changed")
        return PathValue(world, "resolved", receiver._index)
    if label == "path.is_dir":
        if world.reentry is not None:
            callback, world.reentry = world.reentry, None
            callback()
        if world.method == "generator_protocol" and world.generator_kind == "directories" and world.scenario in ("body-StopIteration-PEP479", "retained-body-traceback"):
            raise StopIteration("generator-body") if world.scenario == "body-StopIteration-PEP479" else RuntimeError("generator-body")
        return world.scenario != "root-not-directory"
    if label == "path.read_bytes":
        return b"document-bytes"
    raise AssertionError("unknown path operation")


class Store(Watch):
    __slots__ = ("_closed",)
    def __init__(self, world, label="store"):
        super().__init__(world, label)
        self._closed = world.scenario == "idempotent-existing-closed-provider"
    def __getattribute__(self, name):
        if name in ("close", "profile", "json", "put", "get", "check_profile"):
            world = object.__getattribute__(self, "_world")
            world.point("store." + name + ".lookup.before")
            receiver = None if world.detach_store else self
            result = Call(world, "store." + name, _store_action, receiver)
            world.point("store." + name + ".lookup.after")
            return result
        return object.__getattribute__(self, name)

class Budget(Watch):
    __slots__ = ("_closed",)
    def __init__(self, world, label="budget"):
        super().__init__(world, label)
        self._closed = world.scenario == "idempotent-existing-closed-provider"
    def __getattribute__(self, name):
        if name == "close":
            world = object.__getattribute__(self, "_world")
            world.point("budget.close.lookup.before")
            result = Call(world, "budget.close", _budget_action, None if world.detach_budget else self)
            world.point("budget.close.lookup.after")
            return result
        return object.__getattribute__(self, name)

def _budget_action(world, label, receiver, args, kwargs):
    world.emit("budget.close.effect", already_closed=None if receiver is None else receiver._closed)
    if receiver is not None:
        receiver._closed = True
    return None

def _store_action(world, label, receiver, args, kwargs):
    if label == "store.close":
        world.emit("store.close.effect", already_closed=None if receiver is None else receiver._closed)
        if receiver is not None:
            receiver._closed = True
        return None
    if label == "store.get":
        sizes = {"unpack-zero": 0, "unpack-one": 1, "unpack-three": 3}
        if world.scenario in sizes or world.scenario == "unpack-iterator-raises":
            return Sequence(world, "get-result", "get-result", sizes.get(world.scenario, 2))
        return Atom(world, "data"), Atom(world, "metadata")
    if label == "store.check_profile":
        if world.scenario == "provider-retains-actual-method-traceback":
            world.keep_traceback("check_profile")
        return Atom(world, "checked-profile")
    if label == "store.profile":
        if world.scenario == "profile-result-unpack-error":
            return Sequence(world, "profile-result", "get-result", 1)
        if world.scenario == "handled-provider-traceback-retained":
            world.keep_traceback("profile")
        return Atom(world, "profile-ref"), Atom(world, "profile-artifact")
    if label == "store.json":
        body = args[0]
        schema = body.get("schema", "") if type(body) is dict else ""
        suffix = "diagnostics" if schema == "hepta.hia.agent.diagnostics.v1" else "manifest" if schema == "hepta.hia.agent.manifest.v1" else "resource"
        world.point("store.json." + suffix + ".call.before")
        world.emit("store.json.effect", value=body, profile=args[1])
        value = Atom(world, "json-" + suffix)
        world.point("store.json." + suffix + ".call.after")
        return value
    if label == "store.put":
        world.emit("store.put.effect", data=args[0], profile=args[1])
        return Atom(world, "document-reference")
    raise AssertionError("unknown scripted Store operation")

class Service(Watch):
    __slots__ = ("_values",)
    def __init__(self, world):
        super().__init__(world, "service")
        object.__setattr__(self, "_values", {})
    def __getattribute__(self, name):
        if name in ("_world", "_token", "_label", "_values", "__class__", "__weakref__", "__repr__", "__del__"):
            return object.__getattribute__(self, name)
        world = object.__getattribute__(self, "_world")
        world.point("service.get." + name + ".before")
        values = object.__getattribute__(self, "_values")
        if name == "store" and world.detach_store:
            value = Store(world, "temporary-store")
        elif name == "_candidate_budget" and world.detach_budget:
            value = Budget(world, "temporary-budget")
        elif name in ("_profiles", "_examples"):
            value = Call(world, "service." + name, _service_action)
        else:
            value = values[name]
        if (name == "artifact_roots" and world.scenario == "digest-callee-before-roots-getter"
                and world.counts.get("point:service.get.artifact_roots.before") == 2):
            world.namespace["digest"] = Call(world, "digest-replacement", _global_action)
            world.emit("namespace.rebind", name="digest")
        world.point("service.get." + name + ".after")
        return value
    def __setattr__(self, name, value):
        if name.startswith("_") and name in ("_world", "_token", "_label", "_values"):
            object.__setattr__(self, name, value)
            return
        world = object.__getattribute__(self, "_world")
        world.point("service.set." + name + ".before")
        if (name in ("profiles", "profile_artifacts") and world.scenario in
                ("first-profile-subscript-store-error", "second-profile-subscript-store-error")):
            value = Mapping(world, name, value)
        object.__getattribute__(self, "_values")[name] = value
        world.point("service.set." + name + ".after")

def _service_action(world, label, receiver, args, kwargs):
    if label == "service._profiles":
        world.emit("service._profiles.effect")
        return None
    if label == "service._examples":
        return [{"example": "frozen-fake"}]
    raise AssertionError("unknown scripted Service operation")

class ImportView(Watch):
    __slots__ = ("_values", "_module")
    def __init__(self, world, module, values):
        super().__init__(world, "import-" + module)
        self._values, self._module = values, module
    def __getattribute__(self, name):
        if name in ("_world", "_token", "_label", "_values", "_module", "__class__", "__weakref__", "__repr__", "__del__"):
            return object.__getattribute__(self, name)
        world = object.__getattribute__(self, "_world")
        world.point("import." + self._module + "." + name + ".before")
        values = object.__getattribute__(self, "_values")
        if name not in values:
            raise AttributeError(name)
        result = values[name]
        world.point("import." + self._module + "." + name + ".after")
        return result

def _global_action(world, label, receiver, args, kwargs):
    if label == "catalog":
        return Mapping(world, "catalog", {"tools": Sequence(world, "tools", "tool", 2)}), Atom(world, "catalog-sha")
    if label == "installation_manifest":
        return Mapping(world, "identities", {"worker_sha256": "worker", "backend_sha256": "backend"})
    if label == "AgentStore":
        return Store(world)
    if label == "selected_candidate_budget":
        return Atom(world, "candidate-image") if world.candidate_selected else None
    if label == "selected_slot_ledger":
        return Atom(world, "slot-image") if world.slot_selected else None
    if label == "NativeCandidateBudgetStore":
        return Budget(world)
    if label == "NativeSlotLedgerStore":
        return Atom(world, "ledger")
    if label == "Path":
        if world.reentry is not None:
            callback, world.reentry = world.reentry, None
            callback()
        if world.method == "generator_protocol" and world.generator_kind == "roots" and world.scenario in ("body-StopIteration-PEP479", "retained-body-traceback"):
            raise StopIteration("generator-body") if world.scenario == "body-StopIteration-PEP479" else RuntimeError("generator-body")
        return PathValue(world, "path")
    if label == "_agent_resource_path":
        return PathValue(world, "document-path")
    if label.startswith("digest"):
        return "digest-value" if label == "digest" else "replacement-digest"
    if label == "schema_registry":
        return {"schema": "scripted-schema-registry"}
    if label == "proof_contract_description":
        return {"schema": "scripted-proof-contract"}
    if label == "macro_policy_guidance":
        return {"schema": "scripted-macro-policy"}
    if label == "decode_json":
        if world.scenario == "verify-callee-before-decode-callee":
            world.namespace["verify_program"] = Call(world, "verify_program-replacement", _global_action)
            world.emit("namespace.rebind", name="verify_program")
        return Atom(world, "decoded")
    if label.startswith("verify_program"):
        return Atom(world, "verified" if label == "verify_program" else "verified-replacement")
    if label == "reject":
        raise AgentRejected(*args)
    raise AssertionError("unknown scripted global " + label)

class ImportCall:
    def __init__(self, world, namespace):
        self.world, self.namespace = world, namespace
    def __call__(self, name, globals=None, locals=None, fromlist=(), level=0):
        if globals is self.namespace and level == 1 and name in self.world.modules:
            world = self.world
            world.point("import." + name + ".before")
            world.emit("import.arguments", name=name, fromlist=tuple(fromlist), level=level,
                       globals_same=globals is self.namespace, locals_names=tuple(locals) if locals is not None else None)
            result = ImportView(world, name, world.modules[name])
            world.point("import." + name + ".after")
            return result
        return builtins.__import__(name, globals, locals, fromlist, level)

class TupleCall:
    def __init__(self, world):
        self.world = world
    def __call__(self, values=()):
        world = self.world
        world.point("tuple.call.before")
        if world.scenario in ("tuple-retains-never-started-generator", "tuple-partial-consumption-retains-generator") or world.method == "generator_protocol" and world.generator_kind == "roots":
            world.held_generators.append(values)
            world.emit("generator.captured", kind="roots", real_generator=type(values) is types.GeneratorType)
            result = (next(values),) if world.scenario == "tuple-partial-consumption-retains-generator" else ()
        else:
            result = tuple(values)
        world.point("tuple.call.after")
        return result

class AnyCall:
    def __init__(self, world):
        self.world = world
    def __call__(self, values):
        world = self.world
        world.point("any.call.before")
        if world.scenario == "any-retains-generator" or world.method == "generator_protocol" and world.generator_kind == "directories":
            world.held_generators.append(values)
            world.emit("generator.captured", kind="directories", real_generator=type(values) is types.GeneratorType)
            result = False
        else:
            result = any(values)
        world.point("any.call.after")
        return result

class SortedCall:
    def __init__(self, world, sequences):
        self.world, self.sequences = world, sequences
    def __call__(self, values):
        key = next((name for name, value in self.sequences.items() if values is value), "other")
        self.world.point("sorted." + key + ".call.before")
        result = sorted(values)
        self.world.point("sorted." + key + ".call.after")
        return result

def prepare(world, namespace=None, captured_builtins=None):
    namespace = _ORIGINAL_NAMESPACE if namespace is None else namespace
    captured_builtins = _ORIGINAL_BUILTINS if captured_builtins is None else captured_builtins
    world.namespace = namespace
    captured_builtins.clear()
    captured_builtins.update(vars(builtins))
    captured_builtins["__import__"] = ImportCall(world, namespace)
    constants = {"TARGET": "target", "PROFILE": "profile", "SUPPORTED_OPCODES": ("b", "a"),
                 "CORE_SCHEMAS": ("schema-b", "schema-a"), "IMPORTS": ("import-b", "import-a"),
                 "ARTIFACT_PROFILE": "artifact-profile", "LIMITS": {"limit": 3}}
    globals_to_add = {
        name: Call(world, name, _global_action) for name in (
            "catalog", "installation_manifest", "AgentStore", "Path", "digest",
            "_agent_resource_path", "proof_contract_description", "decode_json",
            "verify_program", "reject")}
    globals_to_add.update({
        "tuple": TupleCall(world), "any": AnyCall(world),
        "sorted": SortedCall(world, {"core": constants["CORE_SCHEMAS"], "opcodes": constants["SUPPORTED_OPCODES"], "imports": constants["IMPORTS"]}),
        "SAFE_CORE_METHOD": "safe-method", "SAFE_CORE_SERVICE_PROFILE": "safe-service",
        "SAFE_CORE_DOMAIN": "safe-domain", "PROOF_SCHEMA": {"schema": "proof"},
        "PROVED_MEANING": "proved", "PLAN_SCHEMA": {"schema": "plan"},
        "WORKLOAD_SCHEMA": {"schema": "workload"}, "OBJECTIVE_SCHEMA": {"schema": "objective"},
        "COST_POLICY_SCHEMA": {"schema": "cost-policy"},
        "BaseException": OSError if world.scenario == "dynamic-BaseException-nonmatching"
            else (BaseException, 17) if world.scenario == "dynamic-BaseException-invalid-tuple" else BaseException,
    })
    namespace.update(globals_to_add)
    world.modules = {
        "hia_candidate_budget_native": {name: Call(world, name, _global_action) for name in ("selected_candidate_budget", "NativeCandidateBudgetStore")},
        "hia_slot_ledger_native": {name: Call(world, name, _global_action) for name in ("selected_slot_ledger", "NativeSlotLedgerStore")},
        "hia_program_native": {name: constants[name] for name in ("TARGET", "PROFILE", "SUPPORTED_OPCODES", "CORE_SCHEMAS", "IMPORTS")},
        "hia_schema": {"schema_registry": Call(world, "schema_registry", _global_action)},
        "hia_safe_core": {name: constants[name] for name in ("ARTIFACT_PROFILE", "LIMITS")},
        "hia_agent_macro_discovery": {"macro_policy_guidance": Call(world, "macro_policy_guidance", _global_action)},
    }
    service = Service(world)
    values = object.__getattribute__(service, "_values")
    if world.method not in ("__init__", "generator_protocol"):
        values.update({"store": Store(world), "_candidate_budget": Budget(world) if world.budget_present else None,
                       "_slot_ledger": None, "identities": Mapping(world, "identities", {"worker": "worker"}),
                       "catalog_sha256": Atom(world, "catalog-sha"),
                       "artifact_roots": Sequence(world, "roots", "resolved-root", world.root_count),
                       "profiles": Mapping(world, "profiles", {"name": Atom(world, "profile")})})
    world.external["service"] = service
    args = {"self": service}
    if world.method in ("__init__", "generator_protocol"):
        args.update({"state_root": Atom(world, "state-root"),
                     "artifact_roots": Sequence(world, "roots", "root-input", world.root_count)})
    if world.method in ("_profile", "_program"):
        args["ref"] = Atom(world, "input-ref")
    if world.method == "_profile":
        args["name"] = "name"
    return args, tuple(globals_to_add)

def release_namespace(world, names, captured_builtins=None):
    captured_builtins = _ORIGINAL_BUILTINS if captured_builtins is None else captured_builtins
    for name in names:
        world.namespace.pop(name, None)
    captured_builtins["__import__"] = builtins.__import__
    world.modules.clear()
    world.namespace = None


def invoke(functions, method, arguments):
    arguments["callee"] = functions[method]
    if method == "__init__":
        return arguments.pop("callee")(arguments.pop("self"), arguments.pop("state_root"),
                                        artifact_roots=arguments.pop("artifact_roots"))
    if method in ("close", "_profiles"):
        return arguments.pop("callee")(arguments.pop("self"))
    if method == "_profile":
        return arguments.pop("callee")(arguments.pop("self"), arguments.pop("ref"), arguments.pop("name"))
    if method == "_program":
        return arguments.pop("callee")(arguments.pop("self"), arguments.pop("ref"))
    raise AssertionError("unknown frozen method")

def _snapshot_service(world):
    service = world.external.get("service")
    if service is None:
        return None
    return world.value(object.__getattribute__(service, "_values"))

def _step(world, generator, label, operation):
    world.emit("generator.before", operation=label, running=generator.gi_running,
               closed=generator.gi_frame is None)
    try:
        result = operation()
    except BaseException as error:
        world.trace(error, "generator." + label)
        outcome = {"kind": "error", "error": world.error(error)}
        if isinstance(error, StopIteration):
            outcome["stop_value"] = world.value(error.value)
        if world.scenario == "retained-body-traceback":
            world.held_tracebacks.append(error.__traceback__)
    else:
        outcome = {"kind": "return", "value": world.value(result)}
        del result
    world.emit("generator.after", operation=label, outcome=outcome,
               running=generator.gi_running, closed=generator.gi_frame is None)
    return outcome

def _exercise_generator(world):
    if len(world.held_generators) != 1:
        raise AssertionError("a complete original generator expression was not captured")
    generator = world.held_generators[0]
    if type(generator) is not types.GeneratorType:
        raise AssertionError("the provider did not receive a real Python generator")
    scenario = world.scenario
    world.phase = "generator." + world.generator_kind
    outcomes = []
    if scenario == "send-before-start":
        outcomes.append(_step(world, generator, "send-before-start", lambda: generator.send("non-None")))
    if scenario == "close-before-start":
        outcomes.append(_step(world, generator, "close-before-start", generator.close))
    elif scenario in ("Context-switch", "legal-thread-switch"):
        if scenario == "Context-switch":
            context = contextvars.copy_context()
            context.run(_THREAD_LABEL.set, "alternate")
            outcomes.append(context.run(_step, world, generator, "context-next", lambda: next(generator)))
        else:
            rows = []
            def worker():
                token = _THREAD_LABEL.set("worker")
                try:
                    rows.append(_step(world, generator, "thread-next", lambda: next(generator)))
                except BaseException as error:
                    world.thread_errors.append(world.error(error))
                    world.trace(error, "thread-supervisor")
                finally:
                    _THREAD_LABEL.reset(token)
            thread = threading.Thread(target=worker, name="bootstrap-generator-resume", daemon=True)
            thread.start()
            thread.join(10)
            if thread.is_alive():
                raise AssertionError("declared generator thread did not finish within 10 seconds")
            if world.thread_errors or len(rows) != 1:
                raise AssertionError("generator thread did not preserve its complete outcome")
            outcomes.extend(rows)
    else:
        if scenario == "gi-running-reentry":
            generator_ref = weakref.ref(generator)
            def reenter():
                current = generator_ref()
                if current is None:
                    raise AssertionError("running generator disappeared")
                _step(world, current, "reentrant-next", lambda: next(current))
            world.reentry = reenter
        outcomes.append(_step(world, generator, "first-next", lambda: next(generator)))
        if scenario == "send-none":
            outcomes.append(_step(world, generator, "send-none", lambda: generator.send(None)))
        elif scenario == "send-non-None-after-yield":
            outcomes.append(_step(world, generator, "send-value", lambda: generator.send("ignored")))
        elif scenario == "throw-instance":
            outcomes.append(_step(world, generator, "throw-instance", lambda: generator.throw(world.generator_error)))
        elif scenario == "throw-class":
            outcomes.append(_step(world, generator, "throw-class", lambda: generator.throw(RuntimeError)))
        elif scenario == "close-after-first-yield":
            outcomes.append(_step(world, generator, "close-after-yield", generator.close))
        elif scenario == "outer-exception-resume-change":
            try:
                raise world.second_outer
            except OuterError:
                outcomes.append(_step(world, generator, "different-outer-next", lambda: next(generator)))
    for ordinal in range(4):
        if generator.gi_frame is None:
            break
        row = _step(world, generator, "drain-" + str(ordinal), lambda: next(generator))
        outcomes.append(row)
        if row["kind"] == "error":
            break
    if generator.gi_frame is not None:
        raise AssertionError("finite two-root generator did not reach its declared terminal")
    return outcomes


def _run_body(world, functions, arguments):
    method = "__init__" if world.method == "generator_protocol" else world.method
    world.phase = "invoke"
    world.active = True
    try:
        result = invoke(functions, method, arguments)
    except BaseException as error:
        world.trace(error, "method")
        outcome = {"kind": "error", "error": world.error(error)}
    else:
        outcome = {"kind": "return", "value": world.value(result)}
        world.external["result"] = result
        del result
    if arguments:
        raise AssertionError("observer forwarding retained an unconsumed argument")
    world.emit("observer.handback", outcome=outcome)
    if world.method == "generator_protocol" and outcome["kind"] == "return":
        outcome["generator_outcomes"] = _exercise_generator(world)
    state = _snapshot_service(world)
    before_consumer = world.alive()
    world.phase = "consumer.generators"
    world.held_generators.clear()
    world.reentry = None
    world.phase = "consumer.external"
    world.external.clear()
    world.phase = "consumer.errors"
    world.named_faults.clear()
    world.error_names[:] = [(name, error) for name, error in world.error_names
                            if error is world.outer or error is world.second_outer or error is world.generator_error]
    world.target_error = None
    world.phase = "consumer.tracebacks"
    world.held_tracebacks.clear()
    return outcome, state, before_consumer

def observe(case, *, functions=None, namespace=None, captured_builtins=None):
    """Seal returned canonical bytes immediately; separately retain all late events."""
    functions = ORIGINALS if functions is None else functions
    kinds = ("roots", "directories") if case["method"] == "generator_protocol" else ("method",)
    parts, hits, raw = [], [], []
    for part_number, kind in enumerate(kinds):
        local_case = dict(case)
        target = local_case.get("fault")
        if target is not None:
            if target["part"] != part_number:
                local_case.pop("fault")
            else:
                local_case["fault"] = {**target, "index": target["local_index"]}
        world = World(local_case)
        world.generator_kind = kind
        arguments, added_names = prepare(world, namespace, captured_builtins)
        if case["outer_exception"]:
            try:
                raise world.outer
            except OuterError:
                outcome, state, alive_before = _run_body(world, functions, arguments)
                world.phase = "consumer.namespace"
                release_namespace(world, added_names, captured_builtins)
                world.emit("observer.seal")
        else:
            outcome, state, alive_before = _run_body(world, functions, arguments)
            world.phase = "consumer.namespace"
            release_namespace(world, added_names, captured_builtins)
            world.emit("observer.seal")
        part = {
            "kind": kind, "outcome": outcome, "service_state": state,
            "events": world.events, "alive_before_consumer": alive_before,
            "alive_at_seal": world.alive(), "scenario_faults": list(world.scenario_hits),
            "target_hits": list(world.target_hits), "unraisable": world.unraisable,
            "thread_errors": world.thread_errors,
        }
        if target is not None and target["part"] == part_number and len(world.target_hits) != 1:
            raise AssertionError("frozen bootstrap fault target was not hit exactly once")
        if target is None:
            for rule in world.fault_settings:
                if not any(row["fault"] == rule["fault"] for row in world.scenario_hits):
                    raise AssertionError("declared original scenario fault did not occur: " + rule["fault"])
        for hit in world.hits:
            hits.append({**hit, "index": len(hits), "part": part_number, "local_index": hit["index"]})
        raw.append({"part": part_number, "kind": kind, "errors": world.raw_errors})
        parts.append(part)
        del world
    return ({"id": case["id"], "method": case["method"], "scenario": case["scenario"],
             "outer_exception": case["outer_exception"], "parts": parts, "hits": hits},
            {"id": case["id"], "parts": raw})

BASIS_IDS = (
    "__init__.both-selected.outer0",
    "__init__.root-not-directory.outer0",
    "__init__.cleanup-first-call-error.outer0",
    "__init__.cleanup-second-call-error.outer0",
    "__init__.dynamic-profiles-error.outer1",
    "close.budget-present.outer0",
    "close.body-and-finally-error-context.outer1",
    "_profiles.complete-all27-outer-writes.outer0",
    "_profile.provider-returns-opaque-object.outer0",
    "_program.normal.outer0",
    "generator_protocol.send-none.outer0",
    "generator_protocol.body-StopIteration-PEP479.outer0",
)

def derive(base_cases, records):
    by_id = {case["id"]: case for case in base_cases}
    observed = {row["id"]: row for row in records if row["id"] in BASIS_IDS}
    if set(observed) != set(BASIS_IDS):
        raise ValueError("all declared original-only bootstrap bases are required")
    result = list(base_cases)
    for identity in BASIS_IDS:
        row = observed[identity]
        for hit in row["hits"]:
            part = row["parts"][hit["part"]]
            first_fault = min((fault["index"] for fault in part["scenario_faults"]), default=None)
            for family in FAMILIES:
                case = dict(by_id[identity])
                target = {**hit, "family": family}
                if first_fault is not None and hit["local_index"] <= first_fault:
                    target["replace_scenario_at_or_after"] = hit["local_index"]
                case["id"] = identity + ".fault." + str(hit["index"]) + "." + family
                case["fault"] = target
                result.append(case)
    if result[:232] != base_cases or len({case["id"] for case in result}) != len(result):
        raise ValueError("derived scope changed the original 232 prefix or duplicated an identity")
    return result


class EventLog(list):
    """Append-only observations; sealing binds late writes without owning providers."""
    __slots__ = ("_sink", "_identity", "_part", "_field", "_sealed_length")
    def __init__(self):
        super().__init__()
        self._sink = None
        self._identity = self._part = self._field = None
        self._sealed_length = None
    def append(self, value):
        index = len(self)
        list.append(self, value)
        if self._sink is not None:
            self._sink({"id": self._identity, "part": self._part, "field": self._field,
                        "index": index, "value": value})
    def seal(self, identity, part, field, frozen, sink):
        if self._sink is not None or canonical(self[:len(frozen)]) != canonical(frozen):
            raise AssertionError("event prefix changed before its immutable seal")
        self._identity, self._part, self._field = identity, part, field
        self._sealed_length = len(frozen)
        self._sink = sink
        for index in range(len(frozen), len(self)):
            sink({"id": identity, "part": part, "field": field,
                  "index": index, "value": self[index]})
    def __setitem__(self, key, value):
        raise AssertionError("observation logs only permit append")
    def __delitem__(self, key):
        raise AssertionError("observation logs only permit append")
    def clear(self):
        raise AssertionError("observation logs cannot be cleared")
    def pop(self, *args):
        raise AssertionError("observation logs cannot be popped")
    def extend(self, *args):
        raise AssertionError("observation logs require individual append custody")
    def insert(self, *args):
        raise AssertionError("observation logs cannot be inserted")
    def reverse(self):
        raise AssertionError("observation logs cannot be reordered")
    def sort(self, *args, **kwargs):
        raise AssertionError("observation logs cannot be reordered")
