"""The native report gate binds the prepared request without rewriting result bytes."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from tests.test_hia_elf_linker import reference
from tools.generate_hia_mcp_terminal import IDENTITIES, SOURCE, render
from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]
RESULT_SCRATCH = 1 << 15


def frame(*, outcome=b'{"status":"completed","result":{}}', helpers="bound", exit_code=0,
          tool="hia_artifact", arguments=None):
    expected = {name: str(index) * 64 for index, name in enumerate(IDENTITIES)}
    expected["tool"] = tool
    expected["native_helpers_sha256"] = helpers
    report = dict(expected, schema="hia-agent-worker-report-v1", complete=True)
    expected["arguments"] = {} if arguments is None else arguments
    raw = json.dumps(report).encode()[:-1] + b',"response":' + outcome + b'}'
    return expected, raw, exit_code


def envelope(expected, report, exit_code):
    return (b'{"expected":' + json.dumps(expected).encode()
            + b',"exit_code":' + str(exit_code).encode() + b',"report":' + report + b'}')


class TerminalCases:
    def check_refused(self, expected, report, exit_code):
        status, _ = self.run_terminal(envelope(expected, report, exit_code))
        self.assertGreaterEqual(status, 0xfffffff0)

    def test_completed_and_rejected_keep_exact_wire_span(self):
        outcomes = (
            rb'{ "n":9007199254740993, "result":{}, "status":"compl\u0065ted", "text":"\ud83d\ude00"}',
            b'{\n "status":"rejected", "tiny":-5E-99, "nested": [null, true] }',
        )
        for outcome in outcomes:
            expected, report, code = frame(outcome=outcome)
            report = report.replace(b'"tool":', rb'"t\u006fol":')
            count, output = self.run_terminal(envelope(expected, report, code))
            self.assertEqual((count, output[:count]), (len(outcome), outcome))

    def test_each_identity_custody_and_optional_helpers(self):
        expected, raw, code = frame()
        report = json.loads(raw)
        for field in IDENTITIES:
            with self.subTest(field=field):
                self.check_refused(expected, json.dumps(dict(report, **{field: "wrong"})).encode(), code)
        del report["native_helpers_sha256"]
        self.check_refused(expected, json.dumps(report).encode(), code)
        expected["native_helpers_sha256"] = None
        for packet in (report, dict(report, native_helpers_sha256=None)):
            count, output = self.run_terminal(envelope(expected, json.dumps(packet).encode(), code))
            self.assertEqual(json.loads(output[:count]), report["response"])

    def test_incomplete_nonterminal_duplicate_and_unknown_reports_fail(self):
        expected, raw, code = frame()
        broken = (
            raw[:-1],
            raw[:-1] + b',"tool":"hia_artifact"}',
            raw[:-1] + b',"unknown":1}',
            raw.replace(b',"response":', b',"unexpected":'),
            raw.replace(b'"complete": true', b'"complete": 1'),
            raw.replace(b'"complete": true', b'"complete": false'),
            raw.replace(b'"completed"', b'"accepted"'),
            raw.replace(b'"status":"completed"', b'"status":"completed","st\\u0061tus":"rejected"'),
            raw.replace(b'"hia-agent-worker-report-v1"', b'"other"'),
        )
        for report in broken:
            with self.subTest(report=report):
                self.check_refused(expected, report, code)
        self.check_refused(expected, raw, 1)

    def test_artifact_profile_and_slot_fields_are_request_bound(self):
        asset = {"id": "a", "sha256": "b" * 64, "uri": "hia://artifacts/c"}
        slot = {"epoch": "2", "generation": "5"}
        cases = (
            ("hia_resource_read", {"uri": asset["uri"]}, {"artifact": asset}, "artifact"),
            ("hia_read", {"artifact": asset}, {"artifact": asset}, "artifact"),
            ("hia_candidate", {"change": {"kind": "patch", "base_program": asset}},
             {"base_program": asset}, "base_program"),
            ("hia_adopt", {"target_slot": "slot", "expected_current": slot, "candidate_artifact": asset},
             {"target_slot": "slot", "previous": slot, "active_artifact": asset}, "active_artifact"),
            ("hia_rollback", {"target_slot": "slot", "expected_current": slot},
             {"target_slot": "slot", "previous": slot}, "previous"),
        )
        for tool, args, result, changed in cases:
            with self.subTest(tool=tool):
                outcome = json.dumps({"status": "completed", "result": result}, sort_keys=True).encode()
                expected, raw, code = frame(tool=tool, arguments=args, outcome=outcome)
                count, output = self.run_terminal(envelope(expected, raw, code))
                self.assertEqual(count, len(outcome))
                self.assertEqual(output[:count], outcome)
                report = json.loads(raw)
                report["response"]["result"][changed] = {"id": "wrong"}
                self.check_refused(expected, json.dumps(report).encode(), code)

    def test_proof_checks_bind_claim_set_subject_profiles_and_installation(self):
        validation = {"id": "profile", "sha256": "d" * 64}
        candidate = {"id": "c", "sha256": "b" * 64, "uri": "hia://artifacts/c"}
        subject = {"kind": "canonical_lowering", "backend_profile": validation,
                   "lowering_profile": validation}
        args = {"subject": subject, "candidate": candidate, "base_program": None,
                "context": validation, "validation_profile": validation,
                "claims": ["core_admission", "lowering_refinement"]}
        expected, _, code = frame(tool="hia_verify", arguments=args)
        installation = {name: expected[name] for name in
                        ("worker_sha256", "backend_sha256", "catalog_sha256", "native_helpers_sha256")}
        scope = dict(subject, candidate=candidate, context=validation, base_core_sha256=None)
        checks = [{"claim": claim, "subject": scope, "property": {"id": claim},
                   "profile": validation, "validator": validation,
                   "checker": {"installation": installation}} for claim in reversed(args["claims"])]
        outcome = {"status": "completed", "result": {"candidate": candidate, "subject": subject,
                                                       "checks": checks}}
        wire = json.dumps(outcome, sort_keys=True).encode()
        _, raw, _ = frame(tool="hia_verify", arguments=args, outcome=wire)
        count, output = self.run_terminal(envelope(expected, raw, code))
        self.assertEqual(count, len(wire))
        self.assertEqual(output[:count], wire)
        for field, value in (
            ("claim", "core_admission"), ("claim", "encoding_check"), ("subject", subject),
            ("subject", dict(scope, base_core_sha256="e" * 64)), ("profile", {"id": "wrong"}),
            ("validator", {"id": "wrong"}), ("property", {"id": "encoding_check"}),
            ("checker", {"installation": dict(installation, native_helpers_sha256=None)}),
        ):
            with self.subTest(field=field, value=value):
                report = json.loads(raw)
                report["response"]["result"]["checks"][0][field] = value
                self.check_refused(expected, json.dumps(report).encode(), code)


class McpTerminalSourceTests(TerminalCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / SOURCE).read_text()
        if render() != source:
            raise AssertionError("generated MCP terminal policy drifted")
        cls.checked = assemble_program(source)

    def run_terminal(self, payload):
        return reference(self.checked, payload, capacity=RESULT_SCRATCH, workspace=1 << 15)


class McpTerminalNativeTests(TerminalCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix="hia-mcp-terminal-")
        cls.addClassCleanup(temp.cleanup)
        cls.folder = Path(temp.name)
        seed, _ = build_seed(cls.folder)
        compiler, _ = compile_stage(cls.folder, "B1", seed,
                                     (ROOT / "examples/hia_bootstrap/selfhost.hepta").read_bytes(),
                                     image_format="seed-shared")
        cls.image, _ = compile_stage(cls.folder, "terminal", compiler, (ROOT / SOURCE).read_bytes())
        cls.sequence = 0

    def run_terminal(self, payload):
        self.__class__.sequence += 1
        status, output = invoke(self.folder, f"wire-{self.sequence}", self.image, payload,
                                capacity=RESULT_SCRATCH, workspace_size=1 << 15)
        self.assertEqual(status["status"], "returned", status)
        self.assertEqual(status["abi_status"], 0, status)
        return status["core_u32"], output
