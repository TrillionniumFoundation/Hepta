"""Positive and adversarial subprocess checks for the C2Hepta Clang driver."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from tools.clang_transport import ClangOutputLimit, run_clang


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux process accounting")
class ClangTransportTests(unittest.TestCase):
    def test_output_and_empty_stdin(self):
        cmd = [sys.executable, "-c", "import sys;print(sys.stdin.read() == '')"]
        r = run_clang(cmd, input=b"", timeout=3, text=True, check=True)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "True\n", ""))

    def test_failure_check_preserves_exit_code(self):
        with self.assertRaises(subprocess.CalledProcessError) as ctx:
            run_clang([sys.executable, "-c", "raise SystemExit(7)"], timeout=3, check=True)
        self.assertEqual(ctx.exception.returncode, 7)

    def test_output_is_bounded_before_full_capture(self):
        with self.assertRaises(ClangOutputLimit):
            run_clang([sys.executable, "-c", "print('a'*100000)"], timeout=3, max_output=2048)

    def test_timeout_kills_grandchild_after_parent_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / "child-pid"
            code = ("import subprocess,sys; child=subprocess.Popen("
                    "[sys.executable,'-c','import time;time.sleep(30)']); "
                    "open(sys.argv[1],'w').write(str(child.pid))")
            cmd = [sys.executable, "-c", code, str(pidfile)]
            with self.assertRaises(subprocess.TimeoutExpired):
                run_clang(cmd, timeout=1.0)
            self.assertTrue(pidfile.exists())
            child = int(pidfile.read_text())
            def not_running():
                try:
                    return Path(f"/proc/{child}/stat").read_text().split()[2] == "Z"
                except FileNotFoundError:
                    return True
            for _ in range(20):
                if not_running():
                    break
                time.sleep(.05)
            if not not_running():
                os.kill(child, signal.SIGKILL)
            self.assertTrue(not_running(), "orphan descendant remained live after timeout")


if __name__ == "__main__":
    unittest.main()
