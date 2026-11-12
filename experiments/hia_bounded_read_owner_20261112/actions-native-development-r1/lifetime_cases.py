"""Real-image lifetime/global-binding controls for bounded-read revision4.

STATIC AUTHORING INPUT: unparsed and unexecuted. Every fixture is evaluated
against the complete original acffa AST and the newly built native image.
This finite differential set does not establish every CPython finalizer,
traceback/reflection or asynchronous-signal behavior.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import gc
from hashlib import sha256
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ORACLE_SHA256 = "953bcc57375f34210c319852091ce5a3a5a1479a723e388a4c989898911bf99c"
EXPECTED_IDS = (
    "temporary_manager_static_exit",
    "input_path_replacement_finalizer",
    "flags_expression_operands",
    "open_callable_and_descriptor",
    "stat_nested_call_temporaries",
    "isreg_bool_result_release",
    "isreg_len_result_release",
    "stat_comparison_result_release",
    "read_count_and_callable_release",
    "local_cleanup_return_order",
    "dynamic_len_rebound_at_exit",
    "captured_builtins_after_global_rebind",
    "global_getattr_replacement",
    "key_equality_KeyError_not_missing",
    "custom_limit_all_operations",
    "prebound_fdopen_unwind_before_match",
    "nonregular_returning_reject",
    "body_exception_close_order",
    "close_exception_replacement_context",
    "suppress_before_payload_then_unbound",
    "dynamic_exception_tuple_match",
    "malformed_exception_match_type",
    "path_error_outside_try",
    "old_ambient_context_chain_restore",
)


class ForeignStop(BaseException):
    pass


def require(value, message):
    if not value:
        raise RuntimeError(message)


def new_json(path, value):
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def oracle_nodes(raw):
    module = ast.parse(raw)
    named = {n.name: n for n in module.body
             if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    names = ("HIAEditRejected", "_reject", "read_bounded")
    require(all(name in named for name in names), "full original definitions missing")
    return ast.Module(body=[named[name] for name in names], type_ignores=[])


def error_graph(exception, fixture):
    seen = {}
    def node(value):
        if value is None:
            return None
        identity = id(value)
        if identity in seen:
            return {"cycle": seen[identity]}
        number = len(seen)
        seen[identity] = number
        return {
            "number": number, "type": type(value).__name__,
            "label": fixture.exception_label(value),
            "args": [arg if type(arg) in (str, int, float, bool, type(None))
                     else {"type": type(arg).__name__} for arg in value.args],
            "suppress_context": value.__suppress_context__,
            "cause": node(value.__cause__), "context": node(value.__context__),
        }
    return node(exception)


def raw_traceback(exception):
    out, current = [], exception.__traceback__
    while current is not None:
        code = current.tb_frame.f_code
        out.append({"name": code.co_name, "filename": code.co_filename, "line": current.tb_lineno})
        current = current.tb_next
    return out


class Fixture:
    def __init__(self, case_id, nodes, filename):
        self.case_id, self.trace = case_id, []
        self.read_error = OSError("fixed read failure")
        self.open_error = OSError("fixed open failure")
        self.close_error = ForeignStop("fixed close failure")
        self.path_error = OSError("fixed path failure")
        self.key_error = KeyError("foreign key comparison")
        self.ambient = OSError("outer handled failure")
        self.middle = RuntimeError("ambient middle")
        self.namespace = {"MAX_INPUT_BYTES": 8 * 1024 * 1024}
        exec(compile(nodes, filename, "exec"), self.namespace)
        self.oracle = self.namespace["read_bounded"]
        parent = self

        class Life:
            def __init__(self, tag):
                self.tag = tag
            def __del__(self):
                parent.note("del", self.tag)

        class Truth(Life):
            def __init__(self, tag, value):
                super().__init__(tag)
                self.value = value
            def __bool__(self):
                parent.note("bool", self.tag)
                return self.value

        class LengthTruth(Life):
            def __len__(self):
                parent.note("len", self.tag)
                return 1

        class Flags(Life):
            def __or__(self, other):
                parent.note("or", self.tag, other.tag if type(other) is Flags else other)
                return Flags("combined:" + self.tag)

        class Compared(Life):
            def __gt__(self, other):
                parent.note("greater", self.tag)
                return Truth("comparison-result", False)

        class Limit(Life):
            def __add__(self, amount):
                parent.note("limit-add", amount)
                return Life("read-count")
            def __lt__(self, amount):
                parent.note("limit-reflected-less", amount)
                return Truth("limit-comparison-result", False)

        class Callable(Life):
            def __init__(self, tag, function):
                super().__init__(tag)
                self.function = function
            def __call__(self, *args):
                parent.note("call", self.tag)
                return self.function(*args)

        class Payload(Life):
            def __len__(self):
                parent.note("payload-len")
                return 2

        class Info(Life):
            @property
            def st_mode(self):
                parent.note("get-st-mode")
                if parent.case_id in ("isreg_bool_result_release", "isreg_len_result_release",
                                      "stat_nested_call_temporaries"):
                    return Life("mode")
                return 0o100600
            @property
            def st_size(self):
                parent.note("get-st-size")
                if parent.case_id == "stat_comparison_result_release":
                    return Compared("stat-size")
                return 0

        def actual_read(amount):
            parent.note("read", amount.tag if isinstance(amount, Life) else amount)
            if parent.case_id in ("body_exception_close_order", "close_exception_replacement_context",
                                  "dynamic_exception_tuple_match", "malformed_exception_match_type",
                                  "old_ambient_context_chain_restore"):
                raise parent.read_error
            return Payload("returned-payload")

        class Stream(Life):
            @property
            def fileno(self):
                parent.note("bind-fileno")
                if parent.case_id == "suppress_before_payload_then_unbound":
                    def failed_fileno():
                        raise parent.read_error
                    return Callable("fileno-callable", failed_fileno)
                return Callable("fileno-callable", lambda: Life("fileno-descriptor"))
            @property
            def read(self):
                parent.note("bind-read")
                return Callable("read-callable", actual_read)

        class Manager(Life):
            def __enter__(self):
                parent.note("enter-manager")
                return Stream("stream")
            @staticmethod
            def __exit__(typ, value, traceback):
                parent.note("exit-manager", None if typ is None else typ.__name__,
                            parent.exception_label(value))
                if parent.case_id == "close_exception_replacement_context":
                    raise parent.close_error
                if parent.case_id == "suppress_before_payload_then_unbound":
                    return Truth("suppression-result", True)
                if parent.case_id == "dynamic_len_rebound_at_exit":
                    def dynamic_len(payload):
                        parent.note("dynamic-len", payload.tag)
                        return Compared("dynamic-length")
                    parent.namespace["len"] = dynamic_len
                if parent.case_id == "captured_builtins_after_global_rebind":
                    def forbidden_len(payload):
                        parent.note("wrong-rebound-builtins-len")
                        raise AssertionError("global __builtins__ replaced the frame's captured builtins")
                    parent.namespace["__builtins__"] = {"len": forbidden_len}
                if parent.case_id == "temporary_manager_static_exit":
                    return Truth("unused-normal-exit-result", False)
                return False

        def path(value):
            parent.note("Path", value.tag)
            if parent.case_id == "path_error_outside_try":
                raise parent.path_error
            return Life("converted-path")

        def actual_open(path, flags):
            parent.note("open", path.tag,
                        flags.tag if isinstance(flags, Life) else flags)
            if parent.case_id == "prebound_fdopen_unwind_before_match":
                raise parent.open_error
            return Life("open-descriptor")

        def actual_fdopen(descriptor, mode):
            parent.note("fdopen", descriptor.tag, mode)
            return Manager("manager")

        def actual_fstat(descriptor):
            parent.note("fstat", descriptor.tag)
            return Info("stat-info")

        class OS:
            @property
            def O_RDONLY(self):
                parent.note("O_RDONLY")
                if parent.case_id in ("flags_expression_operands", "local_cleanup_return_order"):
                    return Flags("rdonly")
                return 0
            @property
            def O_NOFOLLOW(self):
                parent.note("O_NOFOLLOW")
                if parent.case_id in ("flags_expression_operands", "local_cleanup_return_order"):
                    return Flags("nofollow")
                return 0x20000
            @property
            def O_NONBLOCK(self):
                parent.note("O_NONBLOCK")
                if parent.case_id in ("flags_expression_operands", "local_cleanup_return_order"):
                    return Flags("nonblock")
                return 0x800
            @property
            def fdopen(self):
                parent.note("bind-fdopen")
                return Callable("fdopen-callable", actual_fdopen)
            @property
            def open(self):
                parent.note("bind-open")
                return Callable("open-callable", actual_open)
            @property
            def fstat(self):
                parent.note("bind-fstat")
                return Callable("fstat-callable", actual_fstat)

        def actual_isreg(mode):
            parent.note("S_ISREG", mode.tag if isinstance(mode, Life) else mode)
            if parent.case_id == "nonregular_returning_reject":
                return Truth("isreg-result", False)
            if parent.case_id == "isreg_len_result_release":
                return LengthTruth("isreg-length-result")
            return Truth("isreg-result", True)

        class Stat:
            @property
            def S_ISREG(self):
                parent.note("bind-S_ISREG")
                return Callable("isreg-callable", actual_isreg)

        def returning_reject(reason):
            parent.note("returning-reject", reason)
            return Life("discarded-reject-result")

        def observed_getattr(value, name, default):
            parent.note("dynamic-getattr", name)
            return getattr(value, name, default)

        self.namespace.update(Path=path, os=OS(), stat=Stat())
        if case_id == "nonregular_returning_reject":
            self.namespace["_reject"] = returning_reject
        if case_id == "global_getattr_replacement":
            self.namespace["getattr"] = observed_getattr
        if case_id == "dynamic_exception_tuple_match":
            self.namespace["OSError"] = (ValueError, OSError)
        if case_id == "malformed_exception_match_type":
            self.namespace["OSError"] = (OSError, 3)
        if case_id == "old_ambient_context_chain_restore":
            self.ambient.__context__ = self.middle
            self.middle.__context__ = self.read_error

        class LookupKey:
            def __init__(self, name, fail):
                self.name, self.fail = name, fail
            def __hash__(self):
                return hash(self.name)
            def __eq__(self, other):
                parent.note("global-key-compare", self.name,
                            other if type(other) is str else type(other).__name__)
                if self.fail:
                    raise parent.key_error
                return type(other) is str and other == self.name

        if case_id == "key_equality_KeyError_not_missing":
            self.namespace.pop("Path")
            self.namespace[LookupKey("Path", True)] = path
        if case_id == "prebound_fdopen_unwind_before_match":
            self.namespace[LookupKey("OSError", False)] = OSError
        # SimpleNamespace cannot accept a non-string mapping key; only the
        # original function and its actual globals are observed by the owner.
        self.bindings = SimpleNamespace(read_bounded=self.oracle)
        self.input = lambda: Life("input-path")
        self.limit = (lambda: Limit("limit")) if case_id in (
            "custom_limit_all_operations", "read_count_and_callable_release",
            "local_cleanup_return_order") else (lambda: 4)

    def exception_label(self, value):
        if value is None:
            return None
        for name in ("read_error", "open_error", "close_error", "path_error",
                     "key_error", "ambient", "middle"):
            if value is getattr(self, name):
                return name
        if type(value) is self.namespace["HIAEditRejected"]:
            return "converted-diagnostic"
        return "other:" + type(value).__name__

    def note(self, *parts):
        self.trace.append([*parts, {"active": self.exception_label(sys.exception())}])


def one_observation(fixture, invoke):
    def body():
        try:
            value = invoke()
        except BaseException as exception:
            result = {"kind": "exception", "exception": error_graph(exception, fixture),
                      "traceback": raw_traceback(exception)}
        else:
            result = {"kind": "return", "type": type(value).__name__,
                      "label": object.__getattribute__(value, "tag")}
            value = None
        return result
    if fixture.case_id == "old_ambient_context_chain_restore":
        try:
            raise fixture.ambient
        except OSError:
            result = body()
            result["active_after_identity"] = sys.exception() is fixture.ambient
    else:
        result = body()
    trace = json.loads(json.dumps(fixture.trace, ensure_ascii=True))
    return {"result": result, "trace": trace,
            "ambient_after": error_graph(fixture.ambient, fixture)}


def semantic_observation(value):
    result = dict(value["result"])
    result.pop("traceback", None)
    return {"result": result, "trace": value["trace"], "ambient_after": value["ambient_after"]}


def ledger(owner):
    return {"calls": owner.calls, "transitions": owner.transitions,
            "attempts": dict(owner.effect_attempts), "returns": dict(owner.effect_returns),
            "errors": dict(owner.effect_errors)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    output = args.output.parent.resolve(strict=True) / args.output.name
    require(output != source and source not in output.parents, "evidence entered source")
    output.mkdir(mode=0o700, exist_ok=False)
    report = {
        "schema": "hepta.hia.bounded-read-lifetime-controls.v1", "status": "HOLD",
        "expected_ids": list(EXPECTED_IDS), "loaded_ids": list(EXPECTED_IDS),
        "executed_ids": [], "cases": [], "errors": [],
        "anomalies": {"skips": [], "expected_failures": [], "unexpected_successes": [],
                     "failures": [], "errors": []},
        "foreign_cyclic_GC_schedule_proved": False,
        "raw_traceback_preserved_but_frame_locations_not_equated": True,
        "cold_qualification": False, "whole_native_delivery_qualified": False,
    }
    fixed = ("hepta/hia_program_tools.py", "hepta/hia_bounded_read_native.py",
             "tools/generate_hia_bounded_read.py", "examples/hia_bootstrap/bounded_read.hiaasm")
    was_enabled = gc.isenabled()
    owner = None
    try:
        original = args.oracle.read_bytes()
        require(sha256(original).hexdigest() == ORACLE_SHA256, "exact acffa oracle bytes differ")
        nodes = oracle_nodes(original)
        candidate = oracle_nodes((source / "hepta/hia_program_tools.py").read_bytes())
        require(ast.dump(nodes, include_attributes=False) == ast.dump(candidate, include_attributes=False),
                "complete retained original AST changed")
        report["source_before"] = {name: sha256((source / name).read_bytes()).hexdigest() for name in fixed}
        report["oracle_sha256"] = ORACLE_SHA256
        report["oracle_AST_sha256"] = sha256(ast.dump(nodes, include_attributes=False).encode()).hexdigest()
        report["manifest_before"] = sha256(args.manifest.read_bytes()).hexdigest()
        sys.path.insert(0, str(source))
        from hepta.hia_bounded_read_native import installed_bounded_read
        owner = installed_bounded_read(args.manifest)
        report["native_before"] = owner.identity()
        report["ledger_before"] = ledger(owner)
        # Deterministic refcount releases remain enabled; unrelated cyclic-GC
        # collection scheduling is explicitly outside this finite comparison.
        gc.disable()
        for case_id in EXPECTED_IDS:
            reference = Fixture(case_id, nodes, str(args.oracle))
            reference_value = one_observation(reference,
                lambda: reference.oracle(reference.input(), reference.limit()))
            native = Fixture(case_id, nodes, str(args.oracle))
            before = ledger(owner)
            retained_calls = []
            def native_call():
                previous_profile = sys.getprofile()
                require(previous_profile is None, "unexpected differential profiler")
                def forbid_reference(frame, event, unused):
                    if event == "call" and frame.f_code is native.oracle.__code__:
                        retained_calls.append(frame.f_code.co_name)
                        raise AssertionError("original Python policy entered during native control")
                sys.setprofile(forbid_reference)
                try:
                    return owner.read(native.input(), native.limit(), bindings=native.bindings)
                finally:
                    sys.setprofile(previous_profile)
            native_value = one_observation(native, native_call)
            after = ledger(owner)
            passed = (semantic_observation(reference_value) == semantic_observation(native_value)
                      and after["calls"] == before["calls"] + 1
                      and after["transitions"] > before["transitions"] and not retained_calls)
            detail = {"id": case_id, "status": "PASS" if passed else "FAIL",
                      "reference": reference_value, "native": native_value,
                      "ledger_before": before, "ledger_after": after,
                      "real_native_entry_required": True, "retained_policy_calls": retained_calls}
            record = new_json(output / (case_id + ".json"), detail)
            report["cases"].append({"id": case_id, "status": detail["status"], "record": record})
            report["executed_ids"].append(case_id)
            if not passed:
                report["anomalies"]["failures"].append(case_id)
        report["ledger_after"] = ledger(owner)
        report["native_after"] = owner.identity()
        report["manifest_after"] = sha256(args.manifest.read_bytes()).hexdigest()
        if (report["executed_ids"] == list(EXPECTED_IDS)
                and all(not v for v in report["anomalies"].values())
                and report["native_before"] == report["native_after"]
                and report["manifest_before"] == report["manifest_after"]):
            report["status"] = "FINITE_LIFETIME_CONTROLS_PASS_NOT_QUALIFICATION"
    except BaseException as error:
        report["status"] = "HOLD"
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
    finally:
        if was_enabled:
            gc.enable()
        try:
            report["source_after"] = {name: sha256((source / name).read_bytes()).hexdigest() for name in fixed}
            report["source_preserved"] = report.get("source_before") == report["source_after"]
            if not report["source_preserved"]:
                report["status"] = "HOLD"
        except BaseException as error:
            report["source_preserved"] = False
            report["status"] = "HOLD"
            report["errors"].append({"phase": "final_source", "type": type(error).__name__,
                                     "message": str(error)})
        new_json(output / "report.json", report)
    print(json.dumps({"status": report["status"], "executed": len(report["executed_ids"]),
                      "expected": len(EXPECTED_IDS)}))
    return 0 if report["status"] == "FINITE_LIFETIME_CONTROLS_PASS_NOT_QUALIFICATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
