"""Integration checks against real rustc and a native C compiler.

Portable frontend tests do not need a toolchain; these tests explicitly skip
when it is absent instead of pretending that generated source was executed.
"""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from tools.validate import Runner, compile_benchmarks, kernel_correctness, native_abi, no_std_objects, rustc_path, safe_borrowed


@unittest.skipUnless(sys.platform.startswith("linux") and rustc_path() and shutil.which("gcc"),
                     "native ABI integration requires Linux, rustc and gcc")
class NativeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hepta-test-native-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.runner = Runner(rustc_path())

    def test_bidirectional_c_abi_and_layout(self):
        report = native_abi(self.runner, self.root)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["native_staticlib"]["bidirectional_c_calls"])
        self.assertTrue(report["layout"]["layout_compared"])

    def test_no_std_object_has_no_allocator_or_scheduler_dependencies(self):
        report = no_std_objects(self.runner, self.root)
        self.assertEqual(report["targets"]["host"]["status"], "passed")

    def test_kernels_match_independent_rust_and_c(self):
        binaries = compile_benchmarks(self.runner, self.root)
        report = kernel_correctness(self.runner, binaries)
        self.assertEqual(report["status"], "passed")

    def test_safe_borrowed_kernels_match_rust(self):
        report = safe_borrowed(self.runner, self.root)
        self.assertEqual(report["status"], "passed")


if __name__ == "__main__":
    unittest.main()
