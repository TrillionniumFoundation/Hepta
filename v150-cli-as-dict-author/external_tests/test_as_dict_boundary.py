"""External op8 controls. Author only until a separately reviewed launcher runs them.

This file is deliberately outside the product tree. The original 43 CLI tests,
two report tests (140 observations), and 12 report Source tests stay unchanged.
The caller must select a real matching cold fixture or explicit development
bundle through the existing report fixture variables. There is no image stub.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import ctypes
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import weakref
import zlib
import base64

SOURCE_ROOT = None
EVIDENCE = None


def packed(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest(),
            "zlib_base64": base64.b64encode(zlib.compress(raw, 1)).decode("ascii")}


class CliAsDictBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE_ROOT is None or EVIDENCE is None:
            raise RuntimeError("the explicit external-control launcher is required")
        from tests.test_hia_cli_verified_report_native import fixture_selection
        from hepta.hia_cli_native import installed_cli_strict
        from hepta.hia_cli_verified_report_native import NativeReportCli
        from hepta.hia_verified_report_native import NativeVerifiedReport
        from hepta import hia_program
        from tests.test_hia_program import m, f, b, c, ret
        cls.manifest, cls.fixture, cls.scope = fixture_selection()
        cls.cli_owner = installed_cli_strict(str(cls.manifest))
        if type(cls.cli_owner) is not NativeReportCli:
            raise AssertionError("an actual six-image report CLI bundle is required")
        cls.owner = cls.cli_owner.verified_report
        if type(cls.owner) is not NativeVerifiedReport:
            raise AssertionError("the real report image is required")
        cls.program = hia_program
        cls.anchor = hia_program._NATIVE_VERIFIED_REPORT_ANCHORS["as_dict"]
        document = m(f("calculate", [], ["u32"], [],
                       [b("entry", [], [c("answer", "u32", 7)], ret("answer"))]))
        cls.value = hia_program.verify_program(document)
        cls.rows = []
        cls.frame_count = 0
        cls.native_entry = cls.owner._entry
        cls.frame_log = (EVIDENCE / "REPORT-FULL-SIX-BUFFERS.jsonl").open("x")

        def entry(source, source_size, output, output_size, workspace, workspace_size):
            before = (ctypes.string_at(source, source_size),
                      ctypes.string_at(output, output_size),
                      ctypes.string_at(workspace, workspace_size))
            result = None
            exception = None
            try:
                result = cls.native_entry(source, source_size, output, output_size,
                                          workspace, workspace_size)
                return result
            except BaseException as error:
                exception = {"type": type(error).__module__ + "." + type(error).__qualname__,
                             "text": str(error)}
                raise
            finally:
                after = (ctypes.string_at(source, source_size),
                         ctypes.string_at(output, output_size),
                         ctypes.string_at(workspace, workspace_size))
                row = {"index": cls.frame_count, "return": result,
                       "exception": exception,
                       "before": [packed(raw) for raw in before],
                       "after": [packed(raw) for raw in after]}
                cls.frame_log.write(json.dumps(row, separators=(",", ":")) + "\n")
                cls.frame_log.flush()
                cls.frame_count += 1

        cls.owner._entry = entry
        cls.addClassCleanup(cls.restore)

    @classmethod
    def restore(cls):
        cls.owner._entry = cls.native_entry
        cls.frame_log.close()
        raw = (EVIDENCE / "REPORT-FULL-SIX-BUFFERS.jsonl").read_bytes()
        (EVIDENCE / "OBSERVATIONS.json").write_text(json.dumps({
            "scope": cls.scope, "manifest": str(cls.manifest), "cases": cls.rows,
            "actual_native_calls": cls.frame_count,
            "full_six_buffer_journal": {"bytes": len(raw), "sha256": sha256(raw).hexdigest()},
            "qualification": "OBSERVATIONS_ONLY_NOT_DEFAULT_OR_COLD_AUTHORITY",
        }, sort_keys=True, indent=2) + "\n")

    def outcome(self, operation):
        calls = []
        old_profile = sys.getprofile()
        def profile(frame, event, arg):
            if event == "call" and frame.f_code is self.anchor[2]:
                calls.append("original-as-dict-body")
        try:
            sys.setprofile(profile)
            try:
                value = operation()
                result = {"status": "returned", "value": value}
            except BaseException as error:
                result = {"status": "raised", "type": type(error).__module__ + "." + type(error).__qualname__,
                          "text": str(error), "code": getattr(error, "code", None),
                          "context_type": None if error.__context__ is None else type(error.__context__).__qualname__,
                          "suppress_context": error.__suppress_context__}
        finally:
            sys.setprofile(old_profile)
        return result, calls

    def compare_bound(self, label, factory, *, native):
        rows = []
        for selected in (False, True):
            events = []
            with ExitStack() as stack:
                captured = factory(stack, events)
                before = self.owner.entries
                observed, old_calls = self.outcome(
                    lambda: self.owner.invoke_bound_as_dict(captured) if selected else captured())
                count = self.owner.entries - before
            rows.append({"outcome": observed, "events": events,
                         "original_policy_calls": old_calls, "report_entries": count})
        self.rows.append({"test": self.id(), "case": label, "reference": rows[0], "selected": rows[1]})
        self.assertEqual(rows[1]["outcome"], rows[0]["outcome"])
        self.assertEqual(rows[1]["events"], rows[0]["events"])
        if native:
            self.assertGreater(rows[1]["report_entries"], 0)
            self.assertEqual(rows[1]["original_policy_calls"], [])
        else:
            self.assertEqual(rows[1]["report_entries"], 0)

    def test_actual_mode6_uses_native_policy_and_original_decoder_arguments(self):
        original = self.program.decode_internal_canonical
        def factory(stack, events):
            def decode(raw, **kwargs):
                events.append(["decode", raw is self.value.canonical_bytes, list(kwargs.items())])
                return original(raw, **kwargs)
            stack.enter_context(patch.object(self.program, "decode_internal_canonical", decode))
            return self.value.as_dict
        self.assertEqual(self.owner.modes["as_dict"], (6, 1))
        self.compare_bound("exact-original", factory, native=True)

    def test_public_constructor_bad_bytes_keep_original_decoder_exceptions(self):
        for raw in (b"{", b"\xff", b"[]"):
            with self.subTest(raw=raw):
                value = self.program.VerifiedProgram(raw)
                self.compare_bound(raw.hex(), lambda stack, events: value.as_dict, native=True)

    def test_captured_foreign_callable_is_called_once_without_metadata_probes(self):
        def factory(stack, events):
            class Callable:
                def __getattribute__(self, name):
                    if name in ("__func__", "__self__", "__code__", "__class__"):
                        raise AssertionError("foreign callable metadata was probed")
                    return object.__getattribute__(self, name)
                def __call__(self):
                    events.append("called-once")
                    return {"actual": "foreign"}
            class Descriptor:
                def __get__(descriptor, value, kind):
                    events.append("original-descriptor-lookup")
                    return Callable()
            stack.enter_context(patch.object(self.program.VerifiedProgram, "as_dict", Descriptor()))
            return self.value.as_dict
        self.compare_bound("foreign-descriptor", factory, native=False)
        self.assertEqual(self.rows[-1]["selected"]["events"],
                         ["original-descriptor-lookup", "called-once"])

    def test_late_descriptor_and_definition_changes_use_the_captured_operand(self):
        def changed_descriptor(stack, events):
            captured = self.value.as_dict
            def forbidden(value):
                events.append("late-descriptor-entered")
                raise AssertionError("a second as_dict lookup occurred")
            stack.enter_context(patch.object(self.program.VerifiedProgram, "as_dict", property(forbidden)))
            return captured
        self.compare_bound("descriptor-after-capture", changed_descriptor, native=False)

        def changed_code(stack, events):
            captured = self.value.as_dict
            function = self.anchor[1]
            original_code = function.__code__
            def replacement(value):
                return {"actual": "late-code"}
            function.__code__ = replacement.__code__
            stack.callback(setattr, function, "__code__", original_code)
            return captured
        self.compare_bound("function-code-after-capture", changed_code, native=False)

    def test_subclass_shadow_and_custom_attribute_hooks_keep_foreign_behavior(self):
        def subclass_shadow(stack, events):
            class Child(self.program.VerifiedProgram):
                pass
            child = Child(self.value.canonical_bytes)
            def foreign():
                events.append("shadow")
                return {"actual": "instance-shadow"}
            object.__setattr__(child, "as_dict", foreign)
            return child.as_dict
        self.compare_bound("subclass-instance-shadow", subclass_shadow, native=False)

        def custom_lookup(stack, events):
            def lookup(value, name):
                events.append(name)
                return object.__getattribute__(value, name)
            stack.enter_context(patch.object(self.program.VerifiedProgram, "__getattribute__", lookup))
            return self.value.as_dict
        self.compare_bound("custom-getattribute", custom_lookup, native=False)

    def compare_cli(self, label, argv, install, *, native):
        from hepta import cli, hia_program_tools
        rows = []
        for selected in (False, True):
            events = []
            stdout, stderr = io.StringIO(), io.StringIO()
            with ExitStack() as stack:
                stack.enter_context(patch.object(hia_program_tools, "read_bounded", lambda *args, **kwargs: b"input"))
                stack.enter_context(patch.object(self.program, "verify_program", lambda raw: self.value))
                install(stack, events)
                stack.enter_context(redirect_stdout(stdout))
                stack.enter_context(redirect_stderr(stderr))
                before = self.owner.entries
                observed, old_calls = self.outcome(
                    lambda: self.cli_owner.run(argv, cli) if selected else cli._reference_hia_main(argv))
                count = self.owner.entries - before
            rows.append({"outcome": observed, "events": events, "stdout": stdout.getvalue(),
                         "stderr": stderr.getvalue(), "original_policy_calls": old_calls,
                         "report_entries": count})
        self.rows.append({"test": self.id(), "case": label, "reference": rows[0], "selected": rows[1]})
        for name in ("outcome", "events", "stdout", "stderr"):
            self.assertEqual(rows[1][name], rows[0][name], name)
        if native:
            self.assertGreater(rows[1]["report_entries"], 0)
            self.assertEqual(rows[1]["original_policy_calls"], [])
        else:
            self.assertEqual(rows[1]["report_entries"], 0)

    def test_cli_op8_routes_mode6_but_publication_keeps_its_original_provider(self):
        from hepta import cli, hia_program_tools
        def install(stack, events):
            def publish(program, destination):
                events.append(["publish", program is self.value, destination])
                return {"publication": "original-provider"}
            stack.enter_context(patch.object(hia_program_tools, "publish_program", publish))
            stack.enter_context(patch.object(cli, "output_json", lambda value: events.append(["output", value])))
        self.compare_cli("normalize-stdout", ["normalize", "unused"], install, native=True)
        self.compare_cli("normalize-output", ["normalize", "unused", "--output", "new-target"], install, native=False)

    def test_cli_exception_context_and_temporary_retirement_match_reference(self):
        from hepta import cli
        def install(stack, events):
            class Result(dict):
                def __del__(self):
                    events.append("mapping-drop")
            def decode(raw, **kwargs):
                events.append("decode")
                return Result(ok=True)
            stack.enter_context(patch.object(self.program, "decode_internal_canonical", decode))
            stack.enter_context(patch.object(cli, "output_json", lambda value: events.append("output")))
        self.compare_cli("native-result-retirement", ["normalize", "unused"], install, native=True)
        self.assertEqual(self.rows[-1]["selected"]["events"], ["decode", "output", "mapping-drop"])

        class Outer(Exception):
            pass
        class Provider(ValueError):
            pass
        def failure(stack, events):
            def decode(raw, **kwargs):
                events.append(["decode-context", type(sys.exception()).__name__])
                raise Provider("actual decoder error")
            stack.enter_context(patch.object(self.program, "decode_internal_canonical", decode))
        try:
            raise Outer("active outer")
        except Outer:
            self.compare_cli("native-decoder-error", ["normalize", "unused"], failure, native=True)

    def test_completed_op8_session_retires_without_gc_or_an_extra_owner_cycle(self):
        from hepta import cli, hia_program_tools
        with (patch.object(hia_program_tools, "read_bounded", lambda *args, **kwargs: b"input"),
              patch.object(self.program, "verify_program", lambda raw: self.value),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO())):
            session = self.cli_owner.prepare(["normalize", "unused"], cli)
            held = weakref.ref(session)
            before = self.owner.entries
            self.assertEqual(session.run(), 0)
            self.assertGreater(self.owner.entries, before)
            del session
            self.assertIsNone(held())


def main(argv=None):
    global SOURCE_ROOT, EVIDENCE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--evidence", required=True)
    arguments = parser.parse_args(argv)
    SOURCE_ROOT = Path(arguments.source_root).resolve(strict=True)
    if not (SOURCE_ROOT / "hepta/hia_cli_verified_report_native.py").is_file():
        raise ValueError("explicit complete product source is required")
    EVIDENCE = Path(arguments.evidence).absolute()
    EVIDENCE.mkdir(mode=0o700, exist_ok=False)
    sys.path.insert(0, str(SOURCE_ROOT))
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CliAsDictBoundaryTests)
    loaded = [test.id() for test in suite]
    events = []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            events.append(["start", test.id()]); super().startTest(test)
        def stopTest(self, test):
            events.append(["stop", test.id()]); super().stopTest(test)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
    report = {"loaded_ids": loaded, "events": events, "tests_run": result.testsRun,
              "failures": [(test.id(), text) for test, text in result.failures],
              "errors": [(test.id(), text) for test, text in result.errors],
              "skipped": [(test.id(), text) for test, text in result.skipped],
              "expected_failures": [(test.id(), text) for test, text in result.expectedFailures],
              "unexpected_successes": [test.id() for test in result.unexpectedSuccesses]}
    report["passed"] = (result.wasSuccessful() and not result.skipped
                        and not result.expectedFailures and not result.unexpectedSuccesses
                        and result.testsRun == len(loaded)
                        and events == [item for name in loaded for item in (["start", name], ["stop", name])])
    (EVIDENCE / "RESULT.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
