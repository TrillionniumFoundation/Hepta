"""End-to-end C-project Clang stream capture regression tests."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from hepta.c_migrate import MigrationRejected
from hepta.c_project import invoke


class CProjectBoundedCaptureTests(unittest.TestCase):
    def test_actual_clang_preprocessor_stdin(self):
        clang = shutil.which('clang')
        if clang is None:
            self.skipTest('Clang executable is needed for this native test')
        with tempfile.TemporaryDirectory() as temp:
            output = invoke([clang, '-E', '-P', '-x', 'c', '-'], Path(temp),
                            stdin='#define HEPTA_VALUE 7\nHEPTA_VALUE\n')
        self.assertEqual(output.strip(), '7')

    def test_compiler_failure_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(MigrationRejected) as caught:
                invoke([sys.executable, '-c',
                        "import sys;sys.stderr.write('rejected');sys.exit(9)"], Path(temp))
        self.assertEqual(caught.exception.code, 'E_C_BUILD_TOOL')
        self.assertIn('rejected', str(caught.exception))

    def test_large_compiler_output_refused_before_allocation(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(MigrationRejected) as caught:
                invoke([sys.executable, '-c',
                        "import sys;sys.stdout.buffer.write(b'x'*34000000);sys.stdout.flush()"], Path(temp))
        self.assertEqual(caught.exception.code, 'E_C_BUILD_SIZE')

    def test_early_nonzero_cannot_be_mistaken_for_success(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(MigrationRejected) as caught:
                invoke([sys.executable, '-c', 'raise SystemExit(2)'], Path(temp))
        self.assertEqual(caught.exception.code, 'E_C_BUILD_TOOL')

if __name__ == '__main__': unittest.main()
