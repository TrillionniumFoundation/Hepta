"""Zero-task startup probes cannot authorize old frozen Agent results."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_agent_preflight as probe
from tools.hia_agent_codex_transport import identity


GOOD = b'{"id":1,"result":{"userAgent":"local-startup-probe"}}\n'


def ok_process():
    return {"status": "exited", "returncode": 0, "cleanup_confirmed": True,
            "leader_reaped": True, "streams_complete": True}


class AgentPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-agent-preflight-tests-")
        self.root = Path(self.temp.name)
        self.tools = {}
        for name in ("codex", "clang", "rustc"):
            tool = self.root / name
            tool.write_text("#!/bin/sh\nexit 0\n")
            tool.chmod(0o700)
            self.tools[name] = str(tool)

    def tearDown(self):
        self.temp.cleanup()

    def fake_process(self, argv, cwd, output, **kwargs):
        output.mkdir()
        (output / "stdout.raw").write_bytes(GOOD if "app-server" in argv else b"fixture-version\n")
        (output / "stderr.raw").write_bytes(b"")
        return ok_process()

    def fake_preflight(self, **kwargs):
        with patch.object(probe, "run_owned", side_effect=self.fake_process), \
                patch.object(probe, "_native_probe", return_value={"passed": True, "scope": "test-fixture"}):
            return probe.preflight(self.root / "result", **self.tools, **kwargs)

    def test_only_initialize_notifications_are_sent_and_no_turn_or_task_exists(self):
        rows = [json.loads(line) for line in probe.initialization_wire().splitlines()]
        self.assertEqual([row["method"] for row in rows], ["initialize", "initialized"])
        self.assertEqual([row["id"] for row in rows if "id" in row], [1])
        self.assertNotIn("model", probe.initialization_wire().decode())
        self.assertEqual(probe.startup_response(GOOD)["initialization_acknowledged"], True)

    def test_response_rejects_generation_unknown_events_and_ambiguous_identity(self):
        bad = [b"", GOOD + GOOD, GOOD + b'{"method":"turn/started"}\n',
               b'{"id":true,"result":{"userAgent":"x"}}',
               b'{"id":2,"result":{"userAgent":"x"}}',
               b'{"id":1,"id":1,"result":{"userAgent":"x"}}',
               b'{"id":1,"error":{"message":"startup failed"}}',
               b'{"id":1,"result":{}}']
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                probe.startup_response(raw)

    def test_successful_probe_preserves_freeze_and_cannot_authorize_study(self):
        freeze = self.root / "FREEZE.json"
        freeze.write_text('{"historical":"unchanged"}\n')
        before = identity(freeze)
        result = self.fake_preflight(freeze_path=freeze, registered_paths={"codex": "/old/tool"})
        self.assertTrue(result["passed"])
        self.assertTrue(result["existing_freeze_unchanged"])
        self.assertEqual(identity(freeze), before)
        self.assertFalse(result["requested_paths_match_registered_protocol"])
        for key in ("registered_campaign_run_authorized", "model_access_verified", "prior_results_replaced"):
            self.assertIs(result[key], False)
        self.assertTrue(result["new_registration_required"])
        self.assertIsNone(result["model_usage"])
        self.assertEqual(result["task_requests"], 0)
        self.assertEqual(result["model_requests_sent_by_probe"], 0)

    def test_missing_tool_refuses_before_startup_or_native_probe(self):
        (self.root / "rustc").unlink()
        with patch.object(probe, "run_owned", side_effect=AssertionError("must not start")):
            result = probe.preflight(self.root / "result", **self.tools)
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "blocked")
        self.assertIn("rustc", result["error"]["message"])
        self.assertEqual(result["probes"], {})

    def test_unwritable_output_and_in_checkout_output_refuse_before_launch(self):
        # A regular-file parent refuses deterministically even under a root
        # test user; it does not depend on that user's chmod bypass privileges.
        blocker = self.root / "not-a-directory"
        blocker.write_text("retained")
        with patch.object(probe, "run_owned", side_effect=AssertionError("must not start")):
            with self.assertRaises(OSError):
                probe.preflight(blocker / "output", **self.tools)
            with self.assertRaisesRegex(ValueError, "outside"):
                probe.preflight(probe.ROOT / "preflight-output-forbidden", **self.tools)
        self.assertEqual(blocker.read_text(), "retained")
        if os.geteuid() != 0:
            readonly = self.root / "read-only-parent"
            readonly.mkdir(mode=0o500)
            try:
                with patch.object(probe, "run_owned", side_effect=AssertionError("must not start")):
                    with self.assertRaises(PermissionError):
                        probe.preflight(readonly / "output", **self.tools)
            finally:
                readonly.chmod(0o700)

    def test_recorded_executable_binding_change_withdraws_readiness(self):
        actual = self.fake_process

        def mutate(argv, cwd, output, **kwargs):
            row = actual(argv, cwd, output, **kwargs)
            if "app-server" in argv:
                Path(self.tools["codex"]).write_text("#!/bin/sh\nexit 1\n")
            return row

        with patch.object(probe, "run_owned", side_effect=mutate), \
                patch.object(probe, "_native_probe", return_value={"passed": True}):
            result = probe.preflight(self.root / "result", **self.tools)
        self.assertFalse(result["passed"])
        self.assertFalse(result["tools_unchanged"])

    def test_requested_tool_symlink_rebinding_cannot_preserve_readiness(self):
        selected = self.root / "selected-codex"
        selected.symlink_to(self.tools["codex"])
        replacement = self.root / "other-codex"
        replacement.write_bytes(Path(self.tools["codex"]).read_bytes())
        replacement.chmod(0o700)
        self.tools["codex"] = str(selected)
        actual = self.fake_process

        def mutate(argv, cwd, output, **kwargs):
            row = actual(argv, cwd, output, **kwargs)
            if "app-server" in argv:
                selected.unlink()
                selected.symlink_to(replacement)
            return row

        with patch.object(probe, "run_owned", side_effect=mutate), \
                patch.object(probe, "_native_probe", return_value={"passed": True}):
            result = probe.preflight(self.root / "result", **self.tools)
        self.assertFalse(result["passed"])
        self.assertFalse(result["tools_unchanged"])

    def test_nonzero_exit_or_uncertain_cleanup_never_counts_as_ready_startup(self):
        for field, value in (("returncode", True), ("returncode", 1),
                             ("cleanup_confirmed", 1), ("streams_complete", False),
                             ("leader_reaped", False), ("status", "process_failure")):
            row = ok_process()
            row[field] = value
            self.assertFalse(probe.process_ok(row), (field, value))

    def test_old_output_cannot_be_overwritten_and_boolean_wall_limit_refuses(self):
        output = self.root / "retained-output"
        output.mkdir()
        (output / "RESULT.json").write_text("old-result")
        with self.assertRaises(FileExistsError):
            probe.preflight(output, **self.tools)
        with self.assertRaises(ValueError):
            probe.preflight(self.root / "new-output", **self.tools, wall_seconds=True)
        self.assertEqual((output / "RESULT.json").read_text(), "old-result")


CLANG = os.environ.get("CLANG") or shutil.which("clang")
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


@unittest.skipUnless(CLANG and RUSTC, "actual Clang and Rust required for native startup control")
class AgentPreflightNativeTests(unittest.TestCase):
    def test_actual_hia_and_rust_native_probes_with_non_model_startup_fixture(self):
        with tempfile.TemporaryDirectory(prefix="hia-agent-preflight-native-") as temporary:
            root = Path(temporary)
            codex = root / "startup-fixture"
            codex.write_text('#!/usr/bin/env python3\nimport sys,json\n'
                'if sys.argv[1:]==["--version"]:print("startup-fixture");sys.exit(0)\n'
                'assert sys.argv[1:]==["app-server","--stdio"]\n'
                'rows=[json.loads(line) for line in sys.stdin]\n'
                'assert [r["method"] for r in rows]==["initialize","initialized"]\n'
                'print(json.dumps({"id":1,"result":{"userAgent":"non-model-fixture"}}))\n')
            codex.chmod(0o700)
            result = probe.preflight(root / "result", codex=str(codex), clang=CLANG, rustc=RUSTC)
            self.assertTrue(result["passed"], result)
            self.assertTrue(result["probes"]["hia_native"]["passed"])
            self.assertTrue(result["probes"]["rust_native"]["passed"])
            self.assertFalse(result["model_access_verified"])
            self.assertEqual(result["model_requests_sent_by_probe"], 0)


if __name__ == "__main__":
    unittest.main()
