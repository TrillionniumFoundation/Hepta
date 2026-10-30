"""Real one-shot transport controls, not qualification of an NDU implementation.

The small executable fixtures deliberately emit the ranking wire envelope so
these tests can exercise process and file identity without claiming upstream
NDU provenance, safety evidence or measured optimization benefit.
"""
from __future__ import annotations

import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_ndu_optimizer import ROOT, OptimizationRejected, _bytes, _native_rank


_READER = r'''
import json
import sys
from hepta.hia_ndu_optimizer import OptimizationRejected, _bridge_identity
try:
    _bridge_identity(json.loads(sys.argv[1]))
except OptimizationRejected as error:
    print(str(error))
else:
    raise AssertionError("nonregular file admitted")
'''


@unittest.skipUnless(sys.platform == "linux", "sealed ranking transport requires Linux; NOT qualified")
class NDUOptimizerTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-ranking-transport-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "bridge"
        self.receipt = self.root / "build-receipt.json"
        self.marker = self.root / "executed-image"
        self.backup = self.root / "admitted-original"
        self.locked = json.loads((ROOT / "rust/hia-ndu-bridge/upstream.json").read_bytes())
        self.request = {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": "1" * 64,
                        "generation": 1, "candidates": [
                            {"id": "abstain", "hard_violation": False},
                            {"id": "unproved", "hard_violation": True}]}
        self.bridge = {"binary": str(self.binary), "build_receipt": str(self.receipt)}
        self.write_fixture()

    def image_bytes(self, label="admitted", *, action="", response_changes=None):
        response = {"schema": "hepta.hia.ndu-response.v1",
                    "upstream_commit": self.locked["commit"],
                    "entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
                    "objective_sha256": self.request["objective_sha256"],
                    "generation": self.request["generation"],
                    "request_sha256": sha256(_bytes(self.request)).hexdigest(),
                    "authority": "ADVISORY_ONLY", "proves_program_safety": False,
                    "global_optimality_established": False,
                    "evaluation_digest_v2": "2" * 64,
                    "evaluation_policy_digest": "3" * 64,
                    "utility_profile_digest": "4" * 64,
                    "advisory_recommendation": "abstain"}
        response.update(response_changes or {})
        # Both controls restore the pathname before returning a valid wire
        # response. A post-execution pathname hash alone cannot detect ABA.
        return (f"#!{sys.executable}\n"
                "import os, sys, time\n"
                "from pathlib import Path\n"
                "sys.stdin.buffer.read()\n"
                f"backup = Path({str(self.backup)!r})\n"
                f"if backup.exists(): os.replace(backup, {str(self.binary)!r})\n"
                f"Path({str(self.marker)!r}).write_text({label!r})\n"
                f"{action}\n"
                f"sys.stdout.buffer.write({_bytes(response)!r})\n").encode()

    def write_fixture(self, **kwargs):
        raw = self.image_bytes(**kwargs)
        self.binary.write_bytes(raw)
        self.binary.chmod(0o700)
        adapter = ROOT / "rust/hia-ndu-bridge"
        inputs = {str(p.relative_to(adapter)): sha256(p.read_bytes()).hexdigest()
                  for p in sorted(adapter.rglob("*")) if p.is_file()}
        receipt = {"schema": "hepta.hia.ndu-build.v1", "upstream": self.locked,
                   "original_rust_sources_unchanged": True,
                   "all_original_non_manifest_inputs_unchanged": True,
                   "build_inputs_unchanged": True, "locked_dependencies": True,
                   "isolated_production_manifests": True, "production_activation": False,
                   "adapter_files": inputs, "cargo_lock_sha256": inputs["Cargo.lock"],
                   "builder_sha256": sha256((ROOT / "tools/build_hia_ndu_bridge.py").read_bytes()).hexdigest(),
                   "binary_sha256": sha256(raw).hexdigest(), "build_inputs": {"fixture": True}}
        self.receipt.write_bytes(_bytes(receipt))
        return raw

    def invoke(self, **kwargs):
        return _native_rank(self.bridge, self.request, timeout_s=kwargs.get("timeout", 2))

    def test_aba_path_replacement_cannot_execute_unadmitted_bytes(self):
        original = self.binary.read_bytes()
        substitute = self.root / "substitute"
        substitute.write_bytes(self.image_bytes("replacement"))
        substitute.chmod(0o700)
        real_popen = subprocess.Popen

        def swap_then_spawn(*args, **kwargs):
            os.replace(self.binary, self.backup)
            os.replace(substitute, self.binary)
            return real_popen(*args, **kwargs)

        with patch("subprocess.Popen", side_effect=swap_then_spawn) as launch:
            response, identity = self.invoke()
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(self.binary.read_bytes(), original)
        self.assertEqual(identity["binary_sha256"], sha256(original).hexdigest())
        self.assertEqual(response["advisory_recommendation"], "abstain")
        self.assertEqual(self.marker.read_text(), "admitted", "the ABA replacement actually executed")

    def assert_fifo_rejected(self, field):
        fifo = self.root / "unwritten-fifo"
        os.mkfifo(fifo)
        bridge = {**self.bridge, field: str(fifo)}
        try:
            observed = subprocess.run([sys.executable, "-c", _READER, json.dumps(bridge)],
                                      cwd=ROOT, capture_output=True, text=True, timeout=2, check=False)
        except subprocess.TimeoutExpired:
            self.fail("identity reader blocked opening a FIFO before its regular-file check")
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(observed.stderr, "")
        self.assertIn("bounded regular file", observed.stdout)

    def test_binary_fifo_without_writer_rejects_without_blocking(self):
        self.assert_fifo_rejected("binary")

    def test_receipt_fifo_without_writer_rejects_without_blocking(self):
        self.assert_fifo_rejected("build_receipt")

    def test_admitted_image_uses_required_kernel_seals_and_closes_descriptor(self):
        import fcntl
        real_popen = subprocess.Popen
        descriptors = []

        def inspect_then_spawn(command, **kwargs):
            self.assertRegex(command[0], r"^/proc/self/fd/[0-9]+$")
            fd = int(command[0].rsplit("/", 1)[1])
            self.assertEqual(kwargs["pass_fds"], (fd,))
            self.assertEqual(fcntl.fcntl(fd, getattr(fcntl, "F_GET_SEALS", 1034)) & 15, 15)
            self.assertEqual(os.pread(fd, self.binary.stat().st_size, 0), self.binary.read_bytes())
            with self.assertRaises(OSError) as write_error:
                os.write(fd, b"changed")
            self.assertEqual(write_error.exception.errno, errno.EPERM)
            descriptors.append(fd)
            return real_popen(command, **kwargs)

        with patch("subprocess.Popen", side_effect=inspect_then_spawn):
            self.invoke()
        self.assertEqual(self.marker.read_text(), "admitted")
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError) as closed:
            os.fstat(descriptors[0])
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_missing_sealing_capability_rejects_before_execution(self):
        with patch("os.memfd_create", side_effect=OSError(errno.ENOSYS, "unavailable")), \
                patch("subprocess.Popen") as launch:
            with self.assertRaisesRegex(OptimizationRejected, "sealed"):
                self.invoke()
            launch.assert_not_called()
        self.assertFalse(self.marker.exists())

    def test_missing_required_seal_readback_rejects_before_execution(self):
        import fcntl
        real_fcntl = fcntl.fcntl

        def missing_write_seal(fd, operation, *args):
            if operation == getattr(fcntl, "F_GET_SEALS", 1034):
                return 7
            return real_fcntl(fd, operation, *args)

        with patch("fcntl.fcntl", side_effect=missing_write_seal), \
                patch("subprocess.Popen") as launch:
            with self.assertRaisesRegex(OptimizationRejected, "sealed"):
                self.invoke()
            launch.assert_not_called()
        self.assertFalse(self.marker.exists())

    def test_actual_stdout_and_stderr_overflow_are_stopped_at_the_output_bound(self):
        for stream in (1, 2):
            with self.subTest(stream=stream):
                self.write_fixture(action=f"os.write({stream}, b'x' * (1024 * 1024 + 4096)); time.sleep(30)")
                with self.assertRaisesRegex(OptimizationRejected, "bounded output budget"):
                    self.invoke(timeout=1)
                self.assertEqual(self.marker.read_text(), "admitted")

    def test_actual_deadline_kills_and_reaps_leader(self):
        self.write_fixture(action="time.sleep(30)")
        processes = []
        real_popen = subprocess.Popen

        def remember_child(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            processes.append(child)
            return child

        with patch("subprocess.Popen", side_effect=remember_child):
            with self.assertRaisesRegex(OptimizationRejected, "deadline"):
                self.invoke(timeout=0.3)
        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0].returncode, -signal.SIGKILL)
        with self.assertRaises(ChildProcessError):
            os.waitpid(processes[0].pid, os.WNOHANG)
        fd = int(processes[0].args[0].rsplit("/", 1)[1])
        with self.assertRaises(OSError) as closed:
            os.fstat(fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_changed_original_path_after_admitted_execution_still_refuses(self):
        self.write_fixture(action=f"Path({str(self.binary)!r}).write_bytes(b'changed')")
        with self.assertRaisesRegex(OptimizationRejected, "changed during invocation"):
            self.invoke()
        self.assertEqual(self.marker.read_text(), "admitted")

    def test_actual_nonzero_exit_remains_a_refusal(self):
        self.write_fixture(action="raise SystemExit(7)")
        with self.assertRaisesRegex(OptimizationRejected, "native evaluator failed"):
            self.invoke()
        self.assertEqual(self.marker.read_text(), "admitted")

    def test_response_identity_and_advisory_boundaries_remain_required(self):
        for changes in ({"request_sha256": "0" * 64}, {"upstream_commit": "0" * 40},
                        {"proves_program_safety": True}, {"global_optimality_established": True},
                        {"evaluation_digest_v2": "not-a-digest"},
                        {"advisory_recommendation": "unproved"}):
            with self.subTest(changes=changes):
                self.write_fixture(response_changes=changes)
                with self.assertRaises(OptimizationRejected):
                    self.invoke()
                self.assertEqual(self.marker.read_text(), "admitted")

    def test_changed_binary_refuses_before_execution(self):
        self.binary.write_bytes(self.image_bytes("unrecorded"))
        with patch("subprocess.Popen") as launch:
            with self.assertRaisesRegex(OptimizationRejected, "recorded build"):
                self.invoke()
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
