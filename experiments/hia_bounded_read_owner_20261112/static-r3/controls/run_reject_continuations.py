"""Finite real-image controls for the reconstructed bounded-read r3 candidate.

UNPARSED / UNEXECUTED authoring input. This is not a filesystem qualification,
the original eight-test gate, a cold build, or a replacement for either.
The reference function is compiled from the complete exact acffa source AST.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ORACLE_SHA256 = "953bcc57375f34210c319852091ce5a3a5a1479a723e388a4c989898911bf99c"
GENERATOR_SHA256 = "56d7ccdd9e7a26aae67ad18db7fa0f67ecb7efd7749088907cb0af00f87cf13c"
BRIDGE_SHA256 = "37a76e8b7fee6d75ea5900bde9a72878f5dabd01c8c46dcf1840ceabe5a006bd"
CASES = (
    ("ordinary_without_reject", True, 0, b"ok", "return"),
    ("nonregular_helper_returns", False, 0, b"ok", "return"),
    ("pre_size_helper_returns", True, 5, b"ok", "return"),
    ("post_size_helper_returns", True, 0, b"12345", "return"),
    ("pre_helper_replaces_read", False, 0, b"ok", "replace_read"),
    ("pre_return_finalizer", False, 0, b"ok", "return_finalizer"),
    ("post_return_finalizer", True, 0, b"12345", "return_finalizer"),
    ("pre_helper_raises_oserror", False, 0, b"ok", "raise_os"),
    ("post_helper_raises_oserror", True, 0, b"12345", "raise_os"),
    ("pre_helper_raises_baseexception", False, 0, b"ok", "raise_stop"),
    ("reg_test_rebinds_helper", False, 0, b"ok", "rebind"),
    ("default_helper_keeps_original_diagnostic", False, 0, b"ok", "default"),
)
EXPECTED_IDS = tuple(row[0] for row in CASES)


class ForeignStop(BaseException):
    pass


def write_new(path, value):
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as out:
        out.write(raw)
        out.flush()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def original_nodes(source):
    module = ast.parse(source)
    wanted = ("HIAEditRejected", "_reject", "read_bounded")
    by_name = {node.name: node for node in module.body
               if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
    if any(name not in by_name for name in wanted):
        raise RuntimeError("complete original AST does not contain the required definitions")
    return ast.Module(body=[by_name[name] for name in wanted], type_ignores=[])


def exception_record(exception, fixture):
    if exception is None:
        return None
    seen = {}
    def one(value):
        if value is None:
            return None
        ident = id(value)
        if ident in seen:
            return {"cycle_to": seen[ident]}
        ordinal = len(seen)
        seen[ident] = ordinal
        label = fixture.exception_label(value)
        return {
            "ordinal": ordinal, "identity_label": label,
            "type": type(value).__name__, "args": list(value.args),
            "suppress_context": bool(value.__suppress_context__),
            "cause": one(value.__cause__), "context": one(value.__context__),
        }
    return one(exception)


def traceback_record(exception):
    rows = []
    current = exception.__traceback__
    while current is not None:
        code = current.tb_frame.f_code
        rows.append({"function": code.co_name, "file": code.co_filename,
                     "line": current.tb_lineno})
        current = current.tb_next
    return rows


class Fixture:
    def __init__(self, definition, module_ast, source_name):
        self.case_id, self.regular, self.stat_size, self.payload, self.mode = definition
        self.trace = []
        self.fixed_os = OSError("foreign reject failed")
        self.fixed_stop = ForeignStop("foreign reject stopped")
        self.limit = 4
        self.original_path = object()
        self.converted_path = object()
        self.fd = object()
        self.bindings = None
        self.namespace = {"MAX_INPUT_BYTES": 8 * 1024 * 1024}
        exec(compile(module_ast, source_name, "exec"), self.namespace)
        self.oracle = self.namespace["read_bounded"]
        self.original_reject = self.namespace["_reject"]
        parent = self

        class DiscardedResult:
            def __del__(self):
                parent.trace.append(["reject_return_finalized"])

        class Info:
            @property
            def st_mode(self):
                parent.trace.append(["get_st_mode"])
                return 0o100600

            @property
            def st_size(self):
                parent.trace.append(["get_st_size"])
                return parent.stat_size

        class Stream:
            def __getattribute__(self, name):
                if name in ("fileno", "read"):
                    parent.trace.append(["bind_" + name])
                return object.__getattribute__(self, name)

            def __enter__(self):
                parent.trace.append(["enter"])
                return self

            def __exit__(self, typ, value, traceback):
                active = sys.exception()
                parent.trace.append(["exit", None if typ is None else typ.__name__,
                                     parent.exception_label(value),
                                     parent.exception_label(active)])
                return False

            def fileno(self):
                parent.trace.append(["fileno"])
                return parent.fd

            def read(self, amount):
                parent.trace.append(["read", amount])
                return parent.payload

        class OS:
            O_RDONLY = 0
            O_NOFOLLOW = 0x20000
            O_NONBLOCK = 0x800

            def __getattribute__(self, name):
                if name in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK",
                            "fdopen", "open", "fstat"):
                    parent.trace.append(["os_get", name])
                return object.__getattribute__(self, name)

            def open(self, path, flags):
                parent.trace.append(["open", path is parent.converted_path, flags])
                return parent.fd

            def fdopen(self, descriptor, mode):
                parent.trace.append(["fdopen", descriptor is parent.fd, mode])
                return parent.stream

            def fstat(self, descriptor):
                parent.trace.append(["fstat", descriptor is parent.fd])
                return parent.info

        class Stat:
            def __getattribute__(self, name):
                if name == "S_ISREG":
                    parent.trace.append(["bind_isreg"])
                return object.__getattribute__(self, name)

            def S_ISREG(self, mode):
                parent.trace.append(["isreg", mode])
                if parent.mode == "rebind":
                    parent.set_reject(parent.replacement)
                return parent.regular

        def path(value):
            self.trace.append(["path", value is self.original_path])
            return self.converted_path

        def replacement(reason):
            self.trace.append(["replacement_reject", reason])
            return None

        def reject(reason):
            self.trace.append(["reject", reason])
            if self.mode == "raise_os":
                raise self.fixed_os
            if self.mode == "raise_stop":
                raise self.fixed_stop
            if self.mode == "replace_read":
                def changed_read(amount):
                    self.trace.append(["changed_read", amount])
                    return self.payload
                self.stream.read = changed_read
            if self.mode == "return_finalizer":
                return DiscardedResult()
            return None

        def stale_reject(reason):
            self.trace.append(["stale_reject_must_not_run", reason])
            raise AssertionError("helper was eagerly bound before the regular-file test")

        self.stream, self.info = Stream(), Info()
        self.replacement = replacement
        self.namespace.update({"Path": path, "os": OS(), "stat": Stat()})
        selected = (self.original_reject if self.mode == "default" else
                    stale_reject if self.mode == "rebind" else reject)
        self.set_reject(selected)
        self.bindings = SimpleNamespace(**self.namespace)

    def set_reject(self, function):
        self.namespace["_reject"] = function
        if self.bindings is not None:
            self.bindings._reject = function

    def exception_label(self, value):
        if value is None:
            return None
        if value is self.fixed_os:
            return "fixed_foreign_oserror"
        if value is self.fixed_stop:
            return "fixed_foreign_baseexception"
        if type(value) is self.namespace["HIAEditRejected"]:
            return "diagnostic"
        return "other:" + type(value).__name__


def observe(call, fixture):
    try:
        value = call()
    except BaseException as exception:
        return {
            "outcome": {"kind": "exception",
                        "exception": exception_record(exception, fixture)},
            "trace": fixture.trace,
            "raw_traceback": traceback_record(exception),
        }
    return {
        "outcome": {"kind": "return", "type": type(value).__name__,
                    "payload_identity": value is fixture.payload,
                    "bytes_hex": value.hex() if type(value) is bytes else None},
        "trace": fixture.trace, "raw_traceback": [],
    }


def counter_snapshot(owner):
    return {
        "calls": owner.calls, "transitions": owner.transitions,
        "attempts": dict(owner.effect_attempts),
        "returns": dict(owner.effect_returns),
        "errors": dict(owner.effect_errors),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    output = args.output.parent.resolve(strict=True) / args.output.name
    if output == source or source in output.parents:
        raise RuntimeError("evidence must be outside the source tree")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {
        "schema": "hepta.hia.bounded-read-reject-continuation-controls.v1",
        "status": "HOLD", "expected_ids": list(EXPECTED_IDS),
        "executed_ids": [], "cases": [], "errors": [],
        "source_before": {}, "source_after": {},
        "default_reject_helper_migrated": False,
        "filesystem_qualification": False, "original_eight_tests_run": False,
        "cold_qualification": False, "whole_native_delivery_qualified": False,
    }
    sources = {
        "hepta/hia_program_tools.py": ORACLE_SHA256,
        "tools/generate_hia_bounded_read.py": GENERATOR_SHA256,
        "hepta/hia_bounded_read_native.py": BRIDGE_SHA256,
    }
    owner = None
    try:
        for name, expected in sources.items():
            data = (source / name).read_bytes()
            actual = sha256(data).hexdigest()
            report["source_before"][name] = {"bytes": len(data), "sha256": actual}
            if actual != expected:
                raise RuntimeError("source differs: " + name)
        original = (source / "hepta/hia_program_tools.py").read_text("utf-8")
        oracle_ast = original_nodes(original)
        report["oracle_AST_sha256"] = sha256(ast.dump(
            oracle_ast, include_attributes=False).encode()).hexdigest()
        report["manifest_before"] = {
            "path": str(args.manifest.resolve(strict=True)),
            "sha256": sha256(args.manifest.read_bytes()).hexdigest(),
        }
        sys.path.insert(0, str(source))
        from hepta.hia_bounded_read_native import installed_bounded_read
        owner = installed_bounded_read(args.manifest)
        report["image_identity_before"] = owner.identity()
        report["ledger_before"] = counter_snapshot(owner)
        for definition in CASES:
            case_id = definition[0]
            reference_fixture = Fixture(definition, oracle_ast, str(source / "hepta/hia_program_tools.py"))
            reference = observe(lambda: reference_fixture.oracle(
                reference_fixture.original_path, reference_fixture.limit),
                reference_fixture)
            native_fixture = Fixture(definition, oracle_ast, str(source / "hepta/hia_program_tools.py"))
            before = counter_snapshot(owner)
            native = observe(lambda: owner.read(native_fixture.original_path,
                native_fixture.limit, bindings=native_fixture.bindings), native_fixture)
            after = counter_snapshot(owner)
            needs_reject = case_id != "ordinary_without_reject"
            reject_count = after["attempts"].get(24, 0) - before["attempts"].get(24, 0)
            passed = (reference["outcome"] == native["outcome"] and
                      reference["trace"] == native["trace"] and
                      after["calls"] == before["calls"] + 1 and
                      after["transitions"] > before["transitions"] and
                      reject_count == (1 if needs_reject else 0))
            detail = {
                "id": case_id, "status": "PASS" if passed else "FAIL",
                "reference": reference, "native": native,
                "ledger_before": before, "ledger_after": after,
                "reject_call_attempts": reject_count,
                "real_native_entry_required": True,
            }
            pin = write_new(output / (case_id + ".json"), detail)
            report["cases"].append({"id": case_id, "status": detail["status"], "original": pin})
            report["executed_ids"].append(case_id)
        report["ledger_after"] = counter_snapshot(owner)
        report["image_identity_after"] = owner.identity()
        report["manifest_after"] = {
            "path": str(args.manifest.resolve(strict=True)),
            "sha256": sha256(args.manifest.read_bytes()).hexdigest(),
        }
        if (report["executed_ids"] == list(EXPECTED_IDS) and
                all(case["status"] == "PASS" for case in report["cases"]) and
                report["image_identity_before"] == report["image_identity_after"] and
                report["manifest_before"] == report["manifest_after"]):
            report["status"] = "FINITE_REJECT_CONTINUATIONS_PASS_NOT_FULL_QUALIFICATION"
    except BaseException as exception:
        report["status"] = "HOLD"
        report["errors"].append({"type": type(exception).__name__, "message": str(exception)})
    finally:
        try:
            for name, expected in sources.items():
                data = (source / name).read_bytes()
                report["source_after"][name] = {"bytes": len(data), "sha256": sha256(data).hexdigest()}
            report["source_preserved"] = report["source_before"] == report["source_after"]
            if not report["source_preserved"]:
                report["status"] = "HOLD"
        except BaseException as exception:
            report["source_preserved"] = False
            report["status"] = "HOLD"
            report["errors"].append({"phase": "source_after",
                                     "type": type(exception).__name__, "message": str(exception)})
        write_new(output / "report.json", report)
    print(json.dumps({"status": report["status"], "executed": len(report["executed_ids"]),
                      "expected": len(EXPECTED_IDS)}))
    return 0 if report["status"] == "FINITE_REJECT_CONTINUATIONS_PASS_NOT_FULL_QUALIFICATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
