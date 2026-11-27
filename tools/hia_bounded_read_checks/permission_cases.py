"""Ten private continuation permission controls, each using the actual native entry.

The injected faults occur around an actual image invocation or a real foreign
effect. No dummy entry result is used in place of HIA execution. This lower-level
protocol suite is separate from the original eight public caller methods.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import traceback

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import create, read, require, wire
from lifetime_cases import Fixture, ORACLE_SHA256, oracle_nodes

EXPECTED_IDS = (
    "repeat_observe_does_not_repeat_Path",
    "malformed_ACK_seals_effect_permission",
    "successful_finish_is_single_use",
    "closed_session_cannot_finish",
    "diagnostic_constructor_is_single_use",
    "foreign_exception_finish_is_single_use",
    "after_entry_transition_counter_fault",
    "after_actual_entry_exception_fault",
    "after_foreign_effect_return_counter_fault",
    "before_foreign_effect_attempt_counter_fault",
)


class Fault(BaseException):
    pass


class BadIncrement:
    def __init__(self, error):
        self.error = error
    def __add__(self, other):
        raise self.error


class BadCounter:
    def __init__(self, error):
        self.error = error
    def __getitem__(self, key):
        raise self.error


class ActualOwner:
    def __init__(self, actual):
        self.actual = actual
        self.actual_entry_returns = 0
        self.transitions = 0
        self.calls = 0
        self.effect_attempts = Counter()
        self.effect_returns = Counter()
        self.effect_errors = Counter()
        self.after_entry_error = None
    def _entry(self, *args):
        status = self.actual._entry(*args)
        self.actual_entry_returns += 1
        if self.after_entry_error is not None:
            raise self.after_entry_error
        return status


def failure(call):
    try:
        value = call()
    except BaseException as error:
        frames = []
        current = error.__traceback__
        while current is not None:
            frames.append(current.tb_frame.f_code.co_name)
            current = current.tb_next
        return error, {"type": type(error).__name__, "text": str(error),
                       "frames": frames, "context_type": None if error.__context__ is None
                       else type(error.__context__).__name__}
    raise AssertionError("expected refusal/exception returned: " + type(value).__name__)


def drive(session):
    status = session.step()
    while status == 1:
        session.observe()
        status = session.step()
    require(status == 0 and session.finished and session.finish_pending,
            "actual native terminal envelope missing")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    output = args.output.parent.resolve(strict=True) / args.output.name
    require(source != output and source not in output.parents, "permission evidence entered source")
    output.mkdir(mode=0o700, exist_ok=False)
    report = {"schema": "hepta.hia.bounded-read-permission-controls.v1", "status": "HOLD",
        "expected_ids": list(EXPECTED_IDS), "loaded_ids": list(EXPECTED_IDS),
        "executed_ids": [], "cases": [], "errors": [],
        "anomalies": {"skips": [], "expected_failures": [], "unexpected_successes": [],
                     "failures": [], "errors": []},
        "old_revision_execution_inherited": False,
        "lower_level_private_protocol_scope": True, "whole_native_delivery_qualified": False}
    try:
        raw, oracle_pin = read(args.oracle, 1 << 20)
        require(oracle_pin["sha256"] == ORACLE_SHA256, "exact original oracle differs")
        nodes = oracle_nodes(raw)
        sys.path.insert(0, str(source))
        from hepta.hia_bounded_read_native import BoundedReadSession, installed_bounded_read
        real = installed_bounded_read(args.manifest)
        report["native_before"] = real.identity()
        report["manifest_before"] = read(args.manifest, 16384)[1]
        for case_id in EXPECTED_IDS:
            fixture_id = ("body_exception_close_order" if case_id == "diagnostic_constructor_is_single_use"
                          else "temporary_manager_static_exit")
            fixture = Fixture(fixture_id, nodes, str(args.oracle))
            original_diagnostic = fixture.namespace["HIAEditRejected"]
            constructors = []
            def diagnostic(text):
                constructors.append(text)
                return original_diagnostic(text)
            if case_id == "diagnostic_constructor_is_single_use":
                fixture.namespace["HIAEditRejected"] = diagnostic
            error = Fault(case_id)
            if case_id == "foreign_exception_finish_is_single_use":
                fixture.namespace["Path"] = lambda unused: (_ for _ in ()).throw(error)
            owner = ActualOwner(real)
            session = BoundedReadSession(owner, fixture.bindings, fixture.input(), fixture.limit())
            observations = []
            expected_identity = None
            if case_id == "repeat_observe_does_not_repeat_Path":
                require(session.step() == 1, "initial actual effect missing")
                session.observe()
                caught, detail = failure(session.observe)
                observations.append(detail)
                require(type(caught) is RuntimeError, "repeat observe was not refused")
            elif case_id == "malformed_ACK_seals_effect_permission":
                require(session.step() == 1, "initial actual effect missing")
                packet = session.observe()
                malformed = b"\0" * 8 + packet[8:]
                status = session.step(malformed)
                observations.append({"actual_bad_ACK_status": status})
                require(status != 0 and status != 1, "malformed ACK was accepted")
                caught, detail = failure(session.observe)
                observations.append(detail)
                require(type(caught) is RuntimeError, "stale malformed-ACK effect survived")
            elif case_id in ("successful_finish_is_single_use", "closed_session_cannot_finish",
                             "diagnostic_constructor_is_single_use",
                             "foreign_exception_finish_is_single_use"):
                drive(session)
                if case_id == "closed_session_cannot_finish":
                    session.close()
                elif case_id == "diagnostic_constructor_is_single_use":
                    caught, detail = failure(session.finish)
                    observations.append(detail)
                    require(type(caught) is original_diagnostic and len(constructors) == 1,
                            "actual diagnostic construction differs")
                elif case_id == "foreign_exception_finish_is_single_use":
                    caught, detail = failure(session.finish)
                    observations.append(detail)
                    expected_identity = caught is error
                    require(expected_identity, "foreign exception object changed")
                else:
                    returned = session.finish()
                    observations.append({"returned_type": type(returned).__name__})
                    returned = None
                before = len(constructors)
                caught, detail = failure(session.finish)
                observations.append(detail)
                require(type(caught) is RuntimeError and len(constructors) == before,
                        "finish repeated a terminal foreign effect")
            elif case_id == "after_entry_transition_counter_fault":
                owner.transitions = BadIncrement(error)
                caught, detail = failure(session.step)
                observations.append(detail)
                expected_identity = caught is error
                require(expected_identity and owner.actual_entry_returns == 1,
                        "fault did not follow a real native return")
            elif case_id == "after_actual_entry_exception_fault":
                owner.after_entry_error = error
                caught, detail = failure(session.step)
                observations.append(detail)
                expected_identity = caught is error
                require(expected_identity and owner.actual_entry_returns == 1,
                        "post-entry fault did not use actual HIA")
            elif case_id == "after_foreign_effect_return_counter_fault":
                require(session.step() == 1, "initial actual effect missing")
                owner.effect_returns = BadCounter(error)
                caught, detail = failure(session.observe)
                observations.append(detail)
                expected_identity = caught is error
                require(expected_identity, "post-effect error object changed")
            elif case_id == "before_foreign_effect_attempt_counter_fault":
                require(session.step() == 1, "initial actual effect missing")
                owner.effect_attempts = BadCounter(error)
                caught, detail = failure(session.observe)
                observations.append(detail)
                expected_identity = caught is error
                require(expected_identity, "pre-effect error object changed")
            else:
                raise RuntimeError("unhandled fixed permission control")
            trace_before = json.loads(json.dumps(fixture.trace))
            entries_before = owner.actual_entry_returns
            for call in (session.observe, session.step):
                caught, detail = failure(call)
                observations.append(detail)
                require(type(caught) is RuntimeError, "sealed continuation reopened")
            require(fixture.trace == trace_before and owner.actual_entry_returns == entries_before
                    and session.finished and not session.pending
                    and not session.prepared and not session.finish_pending
                    and owner.actual_entry_returns >= 1,
                    "closed protocol performed another effect or native entry")
            path_count = sum(row[0] == "Path" for row in fixture.trace)
            expected_paths = 0 if case_id in ("after_entry_transition_counter_fault",
                "after_actual_entry_exception_fault", "before_foreign_effect_attempt_counter_fault",
                "foreign_exception_finish_is_single_use") else 1
            require(path_count == expected_paths, "actual Path callback attempt count differs")
            session.close()
            detail = {"id": case_id, "status": "PASS",
                "actual_native_entry_returns": owner.actual_entry_returns,
                "Path_callback_count": path_count, "constructor_calls": constructors,
                "foreign_exception_identity_preserved": expected_identity,
                "trace": trace_before, "observations": observations,
                "terminal_permission_sealed": True}
            raw = wire(detail)
            record = create(output / (case_id + ".json"), raw)
            report["cases"].append({"id": case_id, "status": "PASS", "record": record})
            report["executed_ids"].append(case_id)
        report["native_after"] = real.identity()
        report["manifest_after"] = read(args.manifest, 16384)[1]
        require(report["executed_ids"] == list(EXPECTED_IDS)
                and report["native_before"] == report["native_after"]
                and report["manifest_before"] == report["manifest_after"],
                "complete permission count or bundle identity differs")
        report["status"] = "TEN_REAL_ENTRY_PERMISSION_CONTROLS_PASS"
    except BaseException as error:
        report["status"] = "HOLD"
        report["errors"].append({"type": type(error).__name__, "text": str(error),
                                 "traceback": traceback.format_exc()})
        if "case_id" in locals():
            failure_original = {"id": case_id, "status": "FAIL",
                "trace": fixture.trace if "fixture" in locals() else [],
                "observations": observations if "observations" in locals() else [],
                "constructor_calls": constructors if "constructors" in locals() else [],
                "actual_native_entry_returns": owner.actual_entry_returns if "owner" in locals() else None,
                "terminal_flags": {name: getattr(session, name) for name in
                    ("finished", "pending", "prepared", "finish_pending")} if "session" in locals() else None,
                "failure": report["errors"][-1]}
            report["failed_case_original"] = create(output / (case_id + ".failed.json"),
                                                     wire(failure_original))
    finally:
        create(output / "report.json", wire(report))
    print(json.dumps({"status": report["status"], "executed": len(report["executed_ids"]),
                      "expected": len(EXPECTED_IDS)}))
    return 0 if report["status"] == "TEN_REAL_ENTRY_PERMISSION_CONTROLS_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
