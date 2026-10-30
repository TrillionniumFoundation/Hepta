"""Actual failure-path controls for the prospective native experiment owner."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from tools import qualify_stb_context_opportunity as study

class NativeFailureOwnership(unittest.TestCase):
    def test_second_seal_failure_releases_first_memfd(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);host=root/"host-image";host.write_bytes(b"failure-path-control")
            before=len(os.listdir("/proc/self/fd"))
            with self.assertRaises(FileNotFoundError):
                study.observation(host,root/"missing-library",1,2,32,1,root,[])
            self.assertEqual(len(os.listdir("/proc/self/fd")),before)
    def test_timeout_retains_partial_output_and_reaps_owned_group(self):
        with tempfile.TemporaryDirectory() as name:
            rows=[]
            with self.assertRaises(TimeoutError):
                study.run([sys.executable,"-c","import time;print('partial-before-timeout',flush=True);time.sleep(3)"],
                    Path(name),rows,timeout=0.75)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]["status"],"timed_out")
            self.assertIn("partial-before-timeout",rows[0]["stdout"])
            self.assertTrue(rows[0]["owned_group_signalled"])
            self.assertTrue(rows[0]["leader_reaped"])
            self.assertGreater(rows[0]["wall_ns"],0)
            with self.assertRaises(ChildProcessError):
                os.waitid(os.P_PID,rows[0]["pid"],os.WEXITED|os.WNOHANG|os.WNOWAIT)
    def test_failed_child_keeps_exact_exit_and_output_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            rows=[]
            with self.assertRaises(RuntimeError):
                study.run([sys.executable,"-c","import sys;print('known-failure');sys.exit(7)"],Path(name),rows)
            self.assertEqual(rows[0]["returncode"],7)
            self.assertEqual(rows[0]["stdout"],"known-failure\n")
            self.assertTrue(rows[0]["leader_reaped"])

if __name__=="__main__":unittest.main()
