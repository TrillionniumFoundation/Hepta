"""Real subprocess stdout/stderr quota and failure controls."""
import sys
import tempfile
import unittest
from pathlib import Path
from hepta.bounded_process import BoundedProcessError, run_bounded

class BoundedCaptureTests(unittest.TestCase):
    def launch(self, code, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            return run_bounded([sys.executable, '-c', code], Path(tmp), **kw)

    def test_normal_stdout(self):
        p = self.launch("print('hi')", stdout_limit=1024)
        self.assertEqual(p.stdout, 'hi\n')
        self.assertEqual(p.returncode, 0)

    def test_bounded_stderr_tail(self):
        p = self.launch("import sys;sys.stderr.write('x'*10000+'FINAL')", stderr_tail_limit=20)
        self.assertEqual(p.stderr_tail, 'x'*15+'FINAL')

    def test_stdout_limit_process_terminated(self):
        with self.assertRaisesRegex(BoundedProcessError, 'STDOUT_LIMIT'):
            self.launch("import sys;sys.stdout.buffer.write(b'x'*500000);sys.stdout.flush()", stdout_limit=1000)

    def test_timeout(self):
        with self.assertRaisesRegex(BoundedProcessError, 'TIMEOUT'):
            self.launch("import time;time.sleep(5)", timeout=0.1)

    def test_stdin_propagation(self):
        p = self.launch("import sys;print(sys.stdin.read())", stdin='text')
        self.assertEqual(p.stdout, 'text\n')

    def test_input_limit(self):
        with self.assertRaisesRegex(BoundedProcessError, 'STDIN_LIMIT'):
            self.launch("pass", stdin='a'*40, input_limit=8)

    def test_nonzero_exit_preserves_tail(self):
        p = self.launch("import sys;sys.stderr.write('ERROR');sys.exit(7)")
        self.assertEqual(p.returncode, 7)
        self.assertIn('ERROR', p.stderr_tail)

    def test_invalid_utf8_rejected(self):
        with self.assertRaisesRegex(BoundedProcessError, 'STDOUT_ENCODING'):
            self.launch("import sys;sys.stdout.buffer.write(b'\\xff')")

if __name__ == '__main__': unittest.main()
