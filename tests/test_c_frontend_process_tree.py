"""A bounded C frontend may not leave a live compiler descendant on timeout."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta import c_frontend


class FrontendProcessTreeTests(unittest.TestCase):
    def test_normal_capture(self):
        output = c_frontend._capture([sys.executable, '-c', 'print("ok")'])
        self.assertEqual(output, 'ok\n')

    @unittest.skipUnless(os.name == 'posix' and Path('/proc').is_dir(),
                         'requires POSIX process groups and procfs')
    def test_timeout_terminates_descendant_even_if_parent_exited(self):
        # Child inherits the driver's stdout/stderr, keeping the pipes open.
        # Previous _capture() killed only the driver, leaving this child alive.
        with tempfile.TemporaryDirectory() as tmp:
            pid_path = Path(tmp) / 'child.pid'
            command = ("import subprocess,sys,pathlib; "
                       "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(15)']); "
                       f"pathlib.Path({str(pid_path)!r}).write_text(str(p.pid))")
            child_pid = None
            observed_exit = False
            try:
                with patch.object(c_frontend, 'TIMEOUT', 2):
                    with self.assertRaises(c_frontend.FrontendError) as error:
                        c_frontend._capture([sys.executable, '-c', command])
                self.assertEqual(error.exception.code, 'E_C_FRONTEND_TIMEOUT')
                child_pid = int(pid_path.read_text())
                state = Path(f'/proc/{child_pid}/stat')
                # SIGKILL delivery is asynchronous. Observe only our recorded
                # child for a bounded interval, treating procfs removal as exit.
                deadline = time.monotonic() + 2
                while True:
                    try:
                        child_state = state.read_text().split(') ', 1)[1][0]
                    except FileNotFoundError:
                        observed_exit = True
                        break
                    if child_state == 'Z':
                        observed_exit = True
                        break
                    if time.monotonic() >= deadline:
                        self.fail('Own compiler descendant remained live: ' + child_state)
                    time.sleep(0.01)
            finally:
                # Clean up the child even when exercising the vulnerable code.
                if child_pid is None and pid_path.exists():
                    child_pid = int(pid_path.read_text())
                if child_pid is not None and not observed_exit:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()
