"""Exact-byte Rust HIA shadow runner admission and forged-report controls.

These are protocol/identity tests with explicit fake scripts, NOT native Rust
compiler tests or evidence of whole-language memory safety.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
import signal
import time
from pathlib import Path
import platform
import sys
import tempfile
import unittest

from hepta.hia_rust_crosscheck import (HIARustCrosscheckRejected,
                                       crosscheck_rust_shadow)


def scalar_program():
    return {
        "schema": "hepta.hia.program.v1", "module": "scalar_shadow_gate",
        "functions": [{
            "name": "identity", "params": [{"name": "v", "type": "u32"}],
            "returns": ["u32"], "effects": [], "entry": "entry",
            "blocks": [{
                "id": "entry", "params": [{"name": "v", "type": "u32"}],
                "ops": [], "term": {"op": "ret", "values": ["v"]},
            }],
        }],
    }


def owned_program():
    return {
        "schema": "hepta.hia.program.v1", "module": "owned_shadow_gate",
        "functions": [{
            "name": "allocate_release", "params": [{"name": "n", "type": "usize"}],
            "returns": [], "effects": ["alloc", "trap"], "entry": "entry",
            "blocks": [{
                "id": "entry", "params": [{"name": "n", "type": "usize"}],
                "ops": [{"op": "buffer.new", "args": ["n"],
                         "out": [{"name": "owner", "type": "buffer"}], "attrs": {}},
                        {"op": "owner.drop", "args": ["owner"], "out": [], "attrs": {}}],
                "term": {"op": "ret", "values": []},
            }],
        }],
    }


@unittest.skipUnless(platform.system() == "Linux", "Linux exact-file execution required")
class RustShadowCrosscheckProtocol(unittest.TestCase):
    def make_fake(self, root: Path, *, mode: str = "valid", profile: str = "owned"):
        claims = {
            "scalar": {
                "scalar_ssa_and_cfg_checked": True,
                "resource_provenance_verified": False,
                "full_hia_verifier_replaced": False,
                "whole_language_soundness_proved": False,
                "backend_refinement_proved": False,
                "ffi_supported": False,
                "native_executed": False,
            },
            "owned": {
                "finite_owner_loan_cfg_checked": True,
                "cross_block_owner_loan_state_checked": True,
                "v2_v6_bulk_byte_opcode_types_loans_and_effects_checked": True,
                "interprocedural_resource_calls_checked": True,
                "recursion_or_stack_bounds_proved": False,
                "general_memory_provenance_proved": False,
                "full_source_to_core_refinement_proved": False,
                "llvm_backend_refinement_proved": False,
                "whole_language_soundness_proved": False,
                "native_execution_qualified": False,
                "rust_is_production_admission_authority": False,
            },
        }
        script = f'''#!{sys.executable}
import sys, json, hashlib, time
mode = {mode!r}
profile = {profile!r}
data = sys.stdin.buffer.read()
doc = json.loads(data)
claims = {claims[profile]!r}
if mode == 'sleep': time.sleep(2)
if mode == 'flood':
    sys.stdout.write('X' * 500000)
    sys.stdout.flush()
    sys.exit(0)
if mode == 'stderr':
    sys.stderr.write('unexpected report diagnostics')
if mode == 'proof_promoted': claims['whole_language_soundness_proved'] = 0
if mode == 'extra_claim': claims['future_claim'] = False
result = {{
    'schema': 'hepta.hia.rust-owner-shadow.v1' if profile == 'owned' else 'hepta.hia.rust-scalar-shadow.v1',
    'ok': True,
    'program_sha256': hashlib.sha256(data).hexdigest() if mode != 'wrong_digest' else '0' * 64,
    'functions_checked': len(doc['functions']),
    'blocks_checked': sum(len(fn['blocks']) for fn in doc['functions']),
    'claims': claims,
}}
if profile == 'scalar': result['source_required'] = False
if mode == 'duplicate':
    sys.stdout.write('{{"schema":"x","schema":"y"}}\\n')
else:
    print(json.dumps(result, sort_keys=True))
'''
        path = root / f"test-shadow-{mode}-{profile}"
        path.write_text(script, encoding="utf-8")
        path.chmod(0o700)
        return path, sha256(path.read_bytes()).hexdigest()

    def test_pinned_scalar_and_owned_hia_witnesses_are_corroborated(self):
        for profile, factory in (("scalar", scalar_program), ("owned", owned_program)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as td:
                exe, digest = self.make_fake(Path(td), profile=profile)
                result = crosscheck_rust_shadow(factory(), exe, executable_sha256=digest,
                                                profile=profile)
                self.assertEqual(result["status"], "shadow_corroborated_not_authority")
                self.assertIs(result["claims"]["rust_is_production_admission_authority"], False)
                self.assertIs(result["claims"]["native_backend_refinement_proved"], False)

    def test_forged_claims_wrong_digest_and_extra_metadata_refuse(self):
        for mode in ("proof_promoted", "wrong_digest", "extra_claim", "duplicate"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                exe, digest = self.make_fake(Path(td), mode=mode)
                with self.assertRaises(HIARustCrosscheckRejected):
                    crosscheck_rust_shadow(owned_program(), exe,
                                           executable_sha256=digest)

    def test_exact_executable_identity_is_required(self):
        with tempfile.TemporaryDirectory() as td:
            exe, digest = self.make_fake(Path(td))
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "SHA-256"):
                crosscheck_rust_shadow(owned_program(), exe,
                                       executable_sha256="0" * 64)
            symlink = Path(td) / "shadow-link"
            symlink.symlink_to(exe)
            with self.assertRaises(HIARustCrosscheckRejected):
                crosscheck_rust_shadow(owned_program(), symlink,
                                       executable_sha256=digest)
            with self.assertRaises(HIARustCrosscheckRejected):
                crosscheck_rust_shadow(owned_program(), exe,
                                       executable_sha256="0" * 64, profile="both")

    def test_child_cannot_spool_unbounded_output_or_hide_stderr(self):
        for mode in ("flood", "stderr"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                exe, digest = self.make_fake(Path(td), mode=mode)
                with self.assertRaises(HIARustCrosscheckRejected):
                    crosscheck_rust_shadow(owned_program(), exe,
                                           executable_sha256=digest)

    def test_deadline_is_enforced_without_success_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            exe, digest = self.make_fake(Path(td), mode="sleep")
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "deadline"):
                crosscheck_rust_shadow(owned_program(), exe, executable_sha256=digest,
                                       timeout=0.1)

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "Linux /proc required")
    def test_postexit_child_inheriting_pipes_is_killed(self):
        """Leader exit must not suppress cleanup of its live session children.

        The child holds the inherited stdout/stderr pipes open after the
        immediate launcher exits. An old proc.poll()-guarded finally block
        missed this group because the leader had already been reaped.
        """
        from hepta.hia_rust_crosscheck import _run_bounded_shadow

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "child.pid"
            launcher = root / "leader.py"
            child_code = (
                "import os,time;from pathlib import Path;"
                f"Path({str(marker)!r}).write_text(str(os.getpid()));"
                "time.sleep(30)"
            )
            launcher.write_text(
                f"import subprocess,sys\n"
                f"subprocess.Popen([sys.executable,'-c',{child_code!r}])\n",
                encoding="utf-8",
            )
            pid = None

            def still_running(child_pid):
                try:
                    # Reparented children may briefly remain as harmless zombies.
                    state = Path(f"/proc/{child_pid}/stat").read_text().rsplit(")", 1)[1]
                    return state.split()[0] != "Z"
                except FileNotFoundError:
                    return False

            try:
                with self.assertRaisesRegex(HIARustCrosscheckRejected, "deadline"):
                    _run_bounded_shadow([sys.executable, str(launcher)], b"", timeout=5.0)
                self.assertTrue(marker.is_file(), "test child never started")
                pid = int(marker.read_text(encoding="utf-8"))
                end = time.monotonic() + 2.0
                while still_running(pid) and time.monotonic() < end:
                    time.sleep(0.02)
                self.assertFalse(still_running(pid),
                                 "post-exit child survived shadow transport refusal")
            finally:
                # The negative-control implementation leaks the child; even
                # when this regression fails, clean up before leaving the test.
                if pid is None and marker.exists():
                    pid = int(marker.read_text(encoding="utf-8"))
                if pid is not None and still_running(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(hasattr(os, "WNOWAIT") and Path("/proc/self/stat").exists(),
                         "Linux waitid and /proc required")
    def test_successful_shadow_must_cleanup_pipe_closing_descendant(self):
        """A valid leader report may not strand a live child in its session.

        The child closes all standard FDs before sleeping, so the transport
        can see EOF + exit code zero. A cleanup rule only on timeout misses it.
        """
        from hepta.hia_rust_crosscheck import _run_bounded_shadow

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "sleeping.pid"
            launcher = root / "launcher.py"
            child_code = (
                "import os,time;from pathlib import Path;"
                f"Path({str(marker)!r}).write_text(str(os.getpid()));"
                "os.close(0);os.close(1);os.close(2);time.sleep(30)"
            )
            launcher.write_text(
                "import subprocess,sys,time\nfrom pathlib import Path\n"
                f"subprocess.Popen([sys.executable,'-c',{child_code!r}])\n"
                f"marker = Path({str(marker)!r})\n"
                "for _ in range(500):\n"
                "    if marker.is_file(): break\n"
                "    time.sleep(0.005)\n"
                "assert marker.is_file()\n"
                "print('qualified', flush=True)\n",
                encoding="utf-8",
            )
            pid = None

            def still_running(child_pid):
                try:
                    state = Path(f"/proc/{child_pid}/stat").read_text().rsplit(")", 1)[1]
                    return state.split()[0] != "Z"
                except FileNotFoundError:
                    return False

            try:
                stdout, stderr, returncode = _run_bounded_shadow(
                    [sys.executable, str(launcher)], b"", timeout=5.0)
                self.assertEqual((stdout, stderr, returncode), (b"qualified\n", b"", 0))
                self.assertTrue(marker.is_file(), "child never started")
                pid = int(marker.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 2
                while still_running(pid) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertFalse(still_running(pid),
                                 "successful shadow transport stranded a child process")
            finally:
                if pid is None and marker.is_file():
                    pid = int(marker.read_text(encoding="utf-8"))
                if pid is not None and still_running(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

if __name__ == "__main__":
    unittest.main()
