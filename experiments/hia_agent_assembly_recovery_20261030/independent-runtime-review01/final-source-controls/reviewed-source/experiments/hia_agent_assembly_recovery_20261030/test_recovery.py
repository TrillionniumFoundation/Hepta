"""Bounded controls for the new wrapper, never model or native experiments."""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from experiments.hia_agent_assembly_recovery_20261030 import resource_gate as resources
from experiments.hia_agent_assembly_recovery_20261030 import run_recovery as recovery


class ResourceControls(unittest.TestCase):
    def observe(self, changes=None, *, membership="0::/job\n", available=8 * 1024**2):
        files = {
            "/cg/cgroup.controllers": "cpu memory", "/cg/cgroup.subtree_control": "cpu memory",
            "/cg/cpu.max": "max 100000", "/cg/memory.max": "max",
            "/cg/job/cgroup.controllers": "cpu memory", "/cg/job/cpu.max": "400000 100000",
            "/cg/job/memory.max": str(8 * 1024**3), "/cg/job/memory.current": str(1024**3)}
        files.update(changes or {})
        def read(name):
            if name not in files or files[name] is None:
                raise FileNotFoundError(name)
            return files[name]
        return resources.evaluate(affinity=set(range(8)), cpu_count=8,
            meminfo=f"MemAvailable: {available} kB\n", membership=membership,
            mountinfo="1 0 0:1 / /cg rw - cgroup2 cgroup rw\n", read_text=read)

    def test_visible_unlimited_root_still_requires_host_memory(self):
        self.assertTrue(self.observe(membership="0::/\n")["eligible"])
        self.assertFalse(self.observe(membership="0::/\n", available=4*1024**2-1)["eligible"])

    def test_finite_ancestor_limits_dominate_leaf(self):
        self.assertTrue(self.observe()["eligible"])
        self.assertFalse(self.observe({"/cg/cpu.max": "399999 100000"})["eligible"])
        self.assertFalse(self.observe({"/cg/memory.max": str(4*1024**3),
                                       "/cg/memory.current": "1"})["eligible"])

    def test_unknown_active_limit_refuses_and_hybrid_cannot_hide_v1(self):
        self.assertFalse(self.observe({"/cg/job/cpu.max": None})["eligible"])
        self.assertFalse(self.observe(membership="5:cpu,cpuacct:/limited\n4:memory:/limited\n0::/\n")["eligible"])

    def test_root_missing_interfaces_are_observed_not_assumed_leaf_capacity(self):
        value = self.observe({"/cg/cpu.max": None, "/cg/memory.max": None}, membership="0::/\n")
        self.assertTrue(value["eligible"])
        self.assertEqual(value["cgroup"]["levels"][0]["cpu.max_missing_reason"],
                         "visible_hierarchy_root_has_no_limit_interface")


class OwnedProcessControls(unittest.TestCase):
    def exercise(self, *, returncode=0, waiting=False, lost=False, signal_error=None):
        events = []
        process = mock.Mock(pid=987654, returncode=None)
        def wait(timeout):
            events.append("reap")
            process.returncode = returncode
            return returncode
        process.wait.side_effect = wait
        process.poll.side_effect = AssertionError("poll would reap the reserved owner")
        def waitid(*args):
            events.append("observe_unreaped")
            self.assertTrue(args[2] & os.WNOWAIT)
            if lost:
                raise ChildProcessError("synthetic external reap")
            return None if waiting else SimpleNamespace(si_pid=process.pid, si_code=os.CLD_EXITED, si_status=returncode)
        def killpg(pid, number):
            events.append("signal_group")
            self.assertEqual((pid, number), (process.pid, signal.SIGKILL))
            if signal_error is not None:
                raise signal_error
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(mock.patch.object(recovery.subprocess, "Popen", return_value=process))
            stack.enter_context(mock.patch.object(recovery.os, "waitid", side_effect=waitid))
            stack.enter_context(mock.patch.object(recovery.os, "killpg", side_effect=killpg))
            stack.enter_context(mock.patch.object(recovery.signal, "getsignal", return_value=signal.SIG_DFL))
            stack.enter_context(mock.patch.object(recovery, "_RUN_DEADLINE", None))
            error = None
            try:
                recovery.run_command(Path(directory), "synthetic", ["never-executed"], timeout=0 if waiting else 1)
            except BaseException as failure:
                error = failure
            record = json.loads((Path(directory)/"synthetic.command.json").read_bytes())
        process.wait.assert_called_once()
        process.poll.assert_not_called()
        return events, error, record

    def test_success_and_failure_clean_group_before_single_reap(self):
        for code in (0, 1):
            with self.subTest(code=code):
                events, error, record = self.exercise(returncode=code)
                self.assertEqual(events, ["observe_unreaped", "signal_group", "reap"])
                self.assertEqual(error is None, code == 0)
                self.assertIsNone(record["owned_group_cleanup"]["all_engine_shutdown_receipts"])

    def test_timeout_is_retained_when_cleanup_also_fails(self):
        events, error, record = self.exercise(waiting=True, returncode=-9, signal_error=PermissionError("synthetic cleanup refusal"))
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(events[-2:], ["signal_group", "reap"])
        self.assertEqual(record["owned_group_cleanup"]["errors"][0]["operation"], "kill_owned_group")

    def test_lost_owner_anchor_never_signals_reusable_numeric_group(self):
        events, error, record = self.exercise(lost=True)
        self.assertIsInstance(error, ChildProcessError)
        self.assertNotIn("signal_group", events)
        self.assertFalse(record["owned_group_cleanup"]["unreaped_owner_anchor"])


class ArtifactControls(unittest.TestCase):
    def setUp(self):
        self.deadline = mock.patch.object(recovery, "_RUN_DEADLINE", None)
        self.deadline.start()
        self.addCleanup(self.deadline.stop)

    def test_inventory_refuses_model_payloads_and_symlinks(self):
        for name in ("model.gguf", "model.gguf.partial", "llama-server", "installer.deb"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                (path/name).write_bytes(b"synthetic")
                with self.assertRaises(ValueError):
                    recovery.evidence_inventory(path)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/"alias").symlink_to("/not-read")
            with self.assertRaises(ValueError):
                recovery.evidence_inventory(path)

    def test_partial_staging_retains_safe_raw_and_marks_rejected_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source=root/"raw"; source.mkdir()
            (source/"CELL.json").write_text('{"status":"synthetic"}\n')
            (source/"model.gguf").write_bytes(b"not uploaded")
            (source/"alias").symlink_to("/not-read")
            result=recovery.stage_artifact(source,root/"artifact")
            self.assertFalse(result["complete"])
            self.assertEqual(len(result["rejected"]),2)
            self.assertEqual((root/"artifact/CELL.json").read_bytes(),(source/"CELL.json").read_bytes())
            self.assertFalse((root/"artifact/model.gguf").exists())
            self.assertFalse((root/"artifact/alias").exists())

    def test_staging_failure_never_grants_publication_eligibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/"raw"; source.mkdir()
            (source/"model.gguf").write_bytes(b"synthetic forbidden payload")
            summary={"complete_valid_coverage":True,"errors":[],
                     "descriptive_cross_family_gates":{"maintenance":True,"upgrade":True}}
            recovery.stage_artifact(source,root/"artifact",summary)
            value=recovery.read(root/"artifact/RECOVERY_RESULT.json")
            self.assertFalse(value["publication_evidence_qualified"])
            self.assertEqual(value["qualified_descriptive_cross_family_gates"],{"maintenance":False,"upgrade":False})
            self.assertFalse(value["general_agent_advantage_claim"])

    def test_incomplete_finalization_preserves_zero_observations_without_subprocess(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            output=Path(directory)/"evidence"; output.mkdir()
            stack.enter_context(mock.patch.object(recovery,"retain_definitions",
                side_effect=lambda evidence,protocol: recovery.save(evidence/"DEFINITION_RETENTION.json",{"synthetic_control":True})))
            blocked=stack.enter_context(mock.patch.object(recovery.subprocess,"Popen",side_effect=AssertionError("no subprocess permitted")))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(recovery.finalize(output),0)
            blocked.assert_not_called()
            value=recovery.read(Path(directory)/"hepta-agent-recovery-artifact/RECOVERY_RESULT.json")
            self.assertFalse(value["complete_valid_coverage"])
            self.assertFalse(value["independent_readout_available"])
            self.assertIsNone(value["audited_totals"])
            self.assertEqual([row["unattempted_or_no_terminal_cell_receipt"] for row in value["models"]],[12,12])
            self.assertTrue((output/"ARTIFACT_MANIFEST.json").is_file())


if __name__ == "__main__":
    unittest.main()
