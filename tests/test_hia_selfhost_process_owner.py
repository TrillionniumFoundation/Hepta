"""Harmless ordinary Python children exercise cold owner lifecycle only.

No HIA machine artifact, ELF metadata change, native compiler or remote process
is involved. Session changes model the normal linker capture implementation.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_selfhost_process_owner as owner


FAMILY = r'''
import json,os,subprocess,sys,time
from pathlib import Path
folder=Path(sys.argv[1]); mode=sys.argv[2]
def record(role):
    raw=(json.dumps({'role':role,'pid':os.getpid(),'ppid':os.getppid(),
                     'pgid':os.getpgid(0),'sid':os.getsid(0)})+'\n').encode()
    fd=os.open(folder/'family.jsonl',os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
    os.write(fd,raw);os.close(fd)
record('leader')
child=os.fork()
if child==0:
    os.setsid()
    record('new_session_child')
    grandchild=os.fork()
    if grandchild==0:
        os.setsid()
        record('new_session_grandchild')
        (folder/'ready').write_text('ready')
        time.sleep(20)
        raise SystemExit(0)
    time.sleep(20)
    raise SystemExit(0)
deadline=time.monotonic()+3
while not (folder/'ready').exists():
    if time.monotonic()>=deadline: raise RuntimeError('fake family readiness deadline')
    time.sleep(.005)
os.write(1,b'family-ready\n')
if mode=='timeout':time.sleep(20)
raise SystemExit(7 if mode=='failure' else 0)
'''


@unittest.skipUnless(sys.platform == "linux", "cold owner is explicitly Linux-only")
class ColdProcessOwnerTests(unittest.TestCase):
    observations = []

    def run_command(self, folder, command, *, seconds=5, cleanup=3):
        root = Path(folder)
        result = owner.run_owned(command, cwd=root, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdout_path=root / "stdout.log", stderr_path=root / "stderr.log",
            receipt_path=root / "owner.json", qualification_seconds=seconds, cleanup_seconds=cleanup)
        self.observations.append({"test": self.id(), "result": result,
            "files_hex": {p.name: p.read_bytes().hex() for p in root.iterdir()
                          if p.is_file() and not p.is_symlink()}})
        return result

    def assert_gone(self, report):
        self.assertTrue(report["cleanup"]["complete"], report)
        self.assertTrue(report["cleanup"]["observed_echild"])
        self.assertTrue(report["cleanup"]["leader_reaped"])
        self.assertEqual(report["cleanup"]["remaining_direct_children"], [])
        for item in report["direct_and_adopted_children"]:
            self.assertFalse(Path("/proc/%d" % item["pid"]).exists(), item)

    def test_default_qualification_and_cleanup_budgets_are_distinct(self):
        self.assertEqual(owner.QUALIFICATION_SECONDS, 180)
        self.assertEqual(owner.CLEANUP_SECONDS, 3)

    def test_normal_raw_streams_and_parent_subreaper_unchanged(self):
        libc = ctypes.CDLL(None)
        before, after = ctypes.c_int(), ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(before), 0, 0, 0), 0)
        with tempfile.TemporaryDirectory(prefix="hia-owner-normal-") as folder:
            command = [sys.executable, "-I", "-S", "-B", "-c",
                       "import os;os.write(1,b'out\\x00\\r\\n');os.write(2,b'err\\xff')"]
            result = self.run_command(folder, command)
            self.assertEqual(result["status"], "OWNED_PROCESS_COMPLETED", result)
            self.assertEqual(result["returncode"], 0)
            self.assert_gone(result)
            self.assertEqual((Path(folder) / "stdout.log").read_bytes(), b"out\x00\r\n")
            self.assertEqual((Path(folder) / "stderr.log").read_bytes(), b"err\xff")
        self.assertEqual(libc.prctl(37, ctypes.byref(after), 0, 0, 0), 0)
        self.assertEqual(after.value, before.value)

    def run_family(self, mode):
        with tempfile.TemporaryDirectory(prefix="hia-owner-family-") as folder:
            result = self.run_command(folder, [sys.executable, "-I", "-S", "-B", "-c", FAMILY, folder, mode],
                                      seconds=1.5 if mode == "timeout" else 5)
            records = [json.loads(line) for line in (Path(folder) / "family.jsonl").read_bytes().splitlines()]
            self.assertEqual({r["role"] for r in records}, {"leader", "new_session_child", "new_session_grandchild"})
            self.assertEqual(len({r["sid"] for r in records}), 3)
            self.assertEqual((Path(folder) / "stdout.log").read_bytes(), b"family-ready\n")
            self.assert_gone(result)
            self.assertEqual({r["pid"] for r in records}, {r["pid"] for r in result["direct_and_adopted_children"]})
            reaped = [r for r in result["events"] if r["kind"] == "owned_child_reaped"]
            self.assertEqual({r["pid"] for r in reaped}, {r["pid"] for r in records})
            self.assertFalse(result["historical_descendant_inventory_complete"])
            return result

    def test_timeout_reaps_normal_cross_session_child_and_grandchild(self):
        result = self.run_family("timeout")
        self.assertEqual(result["status"], "QUALIFICATION_TIMEOUT", result)
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["exit_observed_before_deadline"])
        self.assertEqual(result["returncode"], -9)

    def test_zero_exit_does_not_leave_cross_session_descendants_running(self):
        result = self.run_family("success")
        self.assertEqual(result["status"], "OWNED_PROCESS_COMPLETED", result)
        self.assertEqual(result["returncode"], 0)
        self.assertTrue(result["exit_observed_before_deadline"])

    def test_nonzero_exit_retains_original_status_and_cleans_descendants(self):
        result = self.run_family("failure")
        self.assertEqual(result["status"], "QUALIFICATION_FAILED", result)
        self.assertEqual(result["returncode"], 7)

    def test_unconfirmed_cleanup_cannot_be_completed(self):
        # The only child has already exited before cleanup. A deliberately
        # exhausted one-nanosecond cleanup budget must still refuse admission.
        with tempfile.TemporaryDirectory(prefix="hia-owner-tail-limit-") as folder:
            result = self.run_command(folder, [sys.executable, "-I", "-S", "-B", "-c", "pass"], cleanup=1e-9)
            self.assertEqual(result["status"], "CLEANUP_HOLD", result)
            self.assertFalse(result["cleanup"]["complete"])
            self.assertTrue(result["cleanup"]["deadline_exceeded"])
            self.assertTrue(result["exit_observed_before_deadline"])
            # Its sole terminal child is reaped on disposal; no executing fake
            # descendant is deliberately left behind by this negative control.
            self.assertFalse(Path("/proc/%d" % result["qualification_pid"]).exists())

    def test_empty_truncated_and_nonobject_receipts_hold_without_cleanup_claim(self):
        # Real harmless replacement supervisors model quota-interrupted writes.
        # They launch no qualification child and exit7 after publishing exactly
        # the selected malformed bytes. No cold success is synthesized.
        actual_launch = owner.subprocess.Popen
        script = ("import json,sys;from pathlib import Path;"
                  "r=json.loads(Path(sys.argv[1]).read_bytes());"
                  "Path(r['receipt_path']).write_bytes(bytes.fromhex(sys.argv[2]));"
                  "sys.exit(7)")
        for payload in (b'', b'{\"schema\":', b'[]', b'null', b'\xff'):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory(prefix="hia-owner-invalid-receipt-") as folder:
                def substituted(command, **kwargs):
                    request_path = command[command.index('--request') + 1]
                    return actual_launch([sys.executable, '-I', '-S', '-B', '-c', script,
                                          request_path, payload.hex()], **kwargs)
                with patch.object(owner.subprocess, 'Popen', side_effect=substituted):
                    result = self.run_command(folder, [sys.executable, '-c', 'pass'])
                self.assertEqual(result['status'], 'OWNER_RECEIPT_INVALID_HOLD')
                self.assertEqual(result['supervisor_returncode'], 7)
                self.assertIsNone(result['returncode'])
                self.assertFalse(result['cleanup']['complete'])
                self.assertEqual(result['receipt_bytes'], len(payload))
                self.assertEqual((Path(folder) / 'owner.json').read_bytes(), payload)

    def test_platform_and_budget_refuse_before_launch(self):
        with tempfile.TemporaryDirectory(prefix="hia-owner-refuse-") as folder, \
                patch.object(owner.subprocess, "Popen") as launch:
            with patch.object(owner.sys, "platform", "darwin"), self.assertRaises(owner.OwnerFailure):
                self.run_command(folder, [sys.executable, "-c", "pass"])
            for seconds in (True, 0, -1, float("nan"), float("inf"), 181):
                with self.subTest(seconds=seconds), self.assertRaises(owner.OwnerFailure):
                    self.run_command(folder, [sys.executable, "-c", "pass"], seconds=seconds)
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
