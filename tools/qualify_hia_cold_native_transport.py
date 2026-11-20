"""Run full retained observer gates or the explicit fresh-source cold route.

All old test methods/inputs remain intact. The new outer supervisor records
custody; it does not increase the original cold owner's 180+3 deadline. No
finite-control count is promoted to whole-native qualification.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_cold_native_transport_evidence import (Captures, canonical, data_pin,
    parse, regular_bytes, run_owned, successful_exit, write_json)
from tools.hia_cold_native_transport_bridge import SOURCE_INPUTS, SELECTOR, DEVELOPMENT

GATES = ROOT / "tests/fixtures/cold_native_transport_original_gates_v3.json"


def _scope_inputs(capture):
    return {name: data_pin(capture.raw(ROOT / name)) for name in sorted(SOURCE_INPUTS)}


def _child_gates(output, selected, extra):
    from tools.run_hia_unittest_gate import load_declared_suite
    output = Path(output)
    output.mkdir(mode=0o700)
    capture = Captures()
    plan = capture.json(GATES)
    before = _scope_inputs(capture)
    expected = (["tests.test_hia_cold_native_transport.ColdNativeTransportHandoffTests.test_all_eight_actual_atomic_handoff_controls"]
                if extra else plan["original_method_ids"])
    selectors = (["tests.test_hia_cold_native_transport.ColdNativeTransportHandoffTests"]
                 if extra else plan["original_modules"])
    started, stopped, problems, statuses = [], [], [], {}
    report = {"schema": "hepta.cold-native-transport.original-gate-child.r3",
              "status": "HOLD", "planned": expected, "selected": selected,
              "extra_handoff_controls": extra, "source_before": before,
              "started": started, "stopped": stopped, "problems": problems}
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            identity = test.id()
            started.append(identity)
            statuses[identity] = "started"
            super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)
        def addSuccess(self, test):
            statuses[test.id()] = "ok"
            super().addSuccess(test)
        def addError(self, test, error):
            statuses[test.id()] = "error"
            super().addError(test, error)
        def addFailure(self, test, error):
            statuses[test.id()] = "failure"
            super().addFailure(test, error)
        def addSkip(self, test, reason):
            statuses[test.id()] = "skip"
            super().addSkip(test, reason)
        def addExpectedFailure(self, test, error):
            statuses[test.id()] = "expected-failure"
            super().addExpectedFailure(test, error)
        def addUnexpectedSuccess(self, test):
            statuses[test.id()] = "unexpected-success"
            super().addUnexpectedSuccess(test)
        def addSubTest(self, test, subtest, error):
            if error is not None:
                statuses[test.id()] = "subtest-error"
            super().addSubTest(test, subtest, error)
    success = False
    try:
        if (SELECTOR in os.environ) is not selected:
            raise ValueError("gate child selection differs from its declared lane")
        suite, identities = load_declared_suite(selectors)
        if list(identities) != expected:
            raise ValueError("complete original method identities/order differ")
        from tools import hia_selfhost_native_observer as flat
        from tools import hia_selfhost_linked_observer as linked
        profiles = []
        for module in (flat, linked):
            profile = getattr(module.execute, "hia_cold_native_profile", None)
            if (profile is not None) is not selected:
                raise ValueError("actual public execute selection differs")
            if profile is not None and all(profile is not value for value in profiles):
                profiles.append(profile)
        result = unittest.TextTestRunner(verbosity=2, stream=sys.stderr,
                                         resultclass=Result).run(suite)
        report["tests_run"] = result.testsRun
        report["errors"] = [[test.id(), text] for test, text in result.errors]
        report["failures"] = [[test.id(), text] for test, text in result.failures]
        report["skips"] = [[test.id(), reason] for test, reason in result.skipped]
        report["expected_failures"] = [[test.id(), text] for test, text in result.expectedFailures]
        report["unexpected_successes"] = [test.id() for test in result.unexpectedSuccesses]
        report["statuses"] = statuses
        report["native_profiles"] = [profile.statistics() for profile in profiles]
        success = (started == expected and stopped == expected and result.testsRun == len(expected)
                   and all(statuses.get(identity) == "ok" for identity in expected)
                   and not (result.errors or result.failures or result.skipped
                            or result.expectedFailures or result.unexpectedSuccesses))
        if selected and not extra:
            success = success and sum(row["calls"] for row in report["native_profiles"]) > 0
        capture.unchanged()
        report["source_after"] = _scope_inputs(capture)
        success = success and report["source_before"] == report["source_after"]
        report["source_stable"] = success or report["source_before"] == report["source_after"]
    except BaseException as error:
        problems.append({"type": type(error).__module__ + "." + type(error).__qualname__,
                         "message": str(error), "traceback": traceback.format_exc()})
        raise
    finally:
        report["status"] = "COMPLETE_ORIGINAL_METHODS_PASS" if success else "HOLD"
        report["consumed"] = capture.pins()
        report["whole_native"] = False
        report["qualification_complete"] = False
        write_json(output / "report.json", report)
    return success


def qualify(output, *, scope, manifest=None, linked_cold_report=None, linked_development_compiler=None):
    output = Path(output).resolve()
    output.mkdir(mode=0o700)
    capture = Captures()
    source_before = _scope_inputs(capture)
    runtime = Path(sys.executable).resolve(strict=True)
    capture.raw(runtime)
    commands, lanes = [], []
    report = {"schema": "hepta.cold-native-transport.gates.r3", "status": "HOLD",
              "scope": scope, "source_before": source_before, "commands": commands,
              "lanes": lanes, "whole_native": False, "qualification_complete": False}
    environment = dict(os.environ)
    environment.pop(SELECTOR, None)
    environment.pop(DEVELOPMENT, None)
    python = [str(runtime), "-I", "-S", "-B"]
    try:
        if scope == "regression":
            if manifest is None or (linked_cold_report is None) == (linked_development_compiler is None):
                raise ValueError("regression requires one actual R3 manifest and one original linked build authority")
            manifest = Path(manifest).resolve(strict=True)
            capture.raw(manifest)
            plan = capture.json(GATES)
            if linked_cold_report is not None:
                path = Path(linked_cold_report).resolve(strict=True);capture.raw(path)
                environment["HEPTA_HIA_LINKED_OBSERVER_COLD_REPORT"] = str(path)
                environment.pop("HEPTA_HIA_LINKED_OBSERVER_DEVELOPMENT_COMPILER", None)
            else:
                path = Path(linked_development_compiler).resolve(strict=True);capture.raw(path)
                environment["HEPTA_HIA_LINKED_OBSERVER_DEVELOPMENT_COMPILER"] = str(path)
                environment.pop("HEPTA_HIA_LINKED_OBSERVER_COLD_REPORT", None)
            for lane, selected, extra in (("original-1", False, False), ("original-2", False, False),
                                          ("selected", True, False), ("atomic-handoff-8", True, True)):
                child_env = dict(environment)
                child_env["HEPTA_HIA_LINKED_OBSERVER_EVIDENCE"] = str(output / (lane + "-linked-evidence"))
                if selected:
                    child_env[SELECTOR] = str(manifest);child_env[DEVELOPMENT] = "1"
                if extra:
                    child_env["HEPTA_HIA_COLD_NATIVE_TRANSPORT_HANDOFF_EVIDENCE"] = str(output / "actual-handoff-8")
                child_output = output / lane
                command = [*python, str(ROOT / "tools/qualify_hia_cold_native_transport.py"),
                           "--child", str(child_output)]
                if selected: command.append("--selected")
                if extra: command.append("--handoff")
                result = run_owned(command, cwd=ROOT, directory=output / (lane + "-owned"),
                                   timeout_seconds=1800, environment=child_env)
                commands.append(result)
                raw = capture.raw(child_output / "report.json") if (child_output / "report.json").exists() else None
                row = None if raw is None else parse(raw)
                lanes.append({"lane": lane, "directory": str(child_output),
                              "report": None if raw is None else data_pin(raw)})
                if not successful_exit(result) or row is None or row["status"] != "COMPLETE_ORIGINAL_METHODS_PASS":
                    raise ValueError("complete original/selected gate is not qualified: " + lane)
                if not extra and (row["planned"] != plan["original_method_ids"]
                                  or row["started"] != plan["original_method_ids"]
                                  or row["stopped"] != plan["original_method_ids"]):
                    raise ValueError("whole original 44 identities/order differ")
                if lane == "original-2":
                    first = capture.json(output / "original-1/report.json")
                    if first["statuses"] != row["statuses"] or first["planned"] != row["planned"]:
                        raise ValueError("fresh complete original method outcomes differ")
                    # Freeze the actual original reports before selecting any
                    # candidate; there are no candidate-derived expectations.
                    write_json(output / "original-authority.json", {
                        "schema": "hepta.cold-native-transport.original-method-authority.r3",
                        "planned": plan["original_method_ids"],
                        "reports": [data_pin(capture.raw(output / name / "report.json"))
                                    for name in ("original-1", "original-2")],
                        "source": source_before, "method_outcomes_only": True,
                        "all_gate_process_logs_retained_without_normalization": True,
                    })
            report["status"] = "ORIGINAL44_SELECTED44_HANDOFF8_PASS_NOT_WHOLE_COLD"
        elif scope == "cold":
            if manifest is not None or linked_cold_report is not None or linked_development_compiler is not None:
                raise ValueError("fresh source cold cannot inherit any native transport/compiler image")
            # Preserve the original 240-second outer owner, including source
            # export; the inner qualification still enforces 180+3.
            cold_path = output / "cold.json"
            command = [*python, str(ROOT / "tools/replay_hia_selfhost_cold.py"),
                       "--output", str(cold_path), "--native-transport"]
            result = run_owned(command, cwd=ROOT, directory=output / "cold-owned",
                               timeout_seconds=240, environment=environment)
            commands.append(result)
            raw = capture.raw(cold_path) if cold_path.exists() else None
            cold = None if raw is None else parse(raw)
            lanes.append({"lane": "fresh-cold", "report": None if raw is None else data_pin(raw)})
            if (not successful_exit(result) or cold is None
                    or cold.get("status") != "COLD_SELFHOST_REPLAY_PASS"
                    or cold.get("qualification_wall_limit_seconds") != 180
                    or cold.get("cleanup_wall_limit_seconds") != 3
                    or cold.get("native_transport_selection") != {
                        "mode": "fresh-source-export-build-after-B3",
                        "inherited_native_images": False, "whole_native": False}):
                raise ValueError("full original cold source replay did not qualify")
            report["status"] = "COLD_PRODUCER_PASS_INDEPENDENT_FULL_RAW_READER_REQUIRED"
            report["independent_cold_readback_required"] = True
        else:
            raise ValueError("unknown complete gate scope")
        capture.unchanged()
        report["source_after"] = _scope_inputs(capture)
        if report["source_after"] != source_before:
            raise ValueError("native cold gate source changed")
        report["source_stable"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__module__ + "." + type(error).__qualname__,
                           "message": str(error), "traceback": traceback.format_exc()}
        report["status"] = "HOLD"
        raise
    finally:
        report["consumed"] = capture.pins()
        write_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--selected", action="store_true")
    parser.add_argument("--handoff", action="store_true")
    parser.add_argument("--scope", choices=("regression", "cold"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--linked-cold-report", type=Path)
    parser.add_argument("--linked-development-compiler", type=Path)
    args = parser.parse_args()
    if args.child is not None:
        raise SystemExit(0 if _child_gates(args.child, args.selected, args.handoff) else 1)
    if args.scope is None or args.output is None or args.selected or args.handoff:
        parser.error("one complete scope/output is required")
    report = qualify(args.output, scope=args.scope, manifest=args.manifest,
                     linked_cold_report=args.linked_cold_report,
                     linked_development_compiler=args.linked_development_compiler)
    print(json.dumps({"status": report["status"], "whole_native": False,
                      "qualification_complete": False}, sort_keys=True))


if __name__ == "__main__":
    main()
