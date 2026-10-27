"""Compiler selection must preserve rustup dispatch and actual binary identity."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from hepta import backend
from hepta.ast import HeptaError


class ToolchainSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real_compiler = backend.find_rustc()
        backend.toolchain_info(cls.real_compiler)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-compiler-selection-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        environment = dict(os.environ)
        environment.pop("RUSTC", None)
        self.environment = mock.patch.dict(os.environ, environment, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def executable(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o755)
        return path

    def proxy(self, target=None, *, response=None, status=0, hardlink=False):
        # This is an explicit argv[0]-dispatch fixture, not an upstream-rustup
        # execution. The selected target below is a real pinned native rustc.
        manager = self.directory / "dispatch/rustup"
        output = (str(target or self.real_compiler) + "\n") if response is None else response
        self.executable(manager,
            "import os, sys\nfrom pathlib import Path\n"
            "if sys.argv[1:] == ['which', 'rustc']:\n"
            "    assert os.environ['RUSTUP_AUTO_INSTALL'] == '0'\n"
            "    sys.stdout.write(" + repr(output) + ")\n"
            "    raise SystemExit(" + repr(status) + ")\n"
            "if Path(sys.argv[0]).name == 'rustc':\n"
            "    os.execv(" + repr(self.real_compiler) + ", [" + repr(self.real_compiler) + "] + sys.argv[1:])\n"
            "print('rustup 1.29.1 (selection fixture)')\n")
        compiler = manager.with_name("rustc")
        if compiler.exists() or compiler.is_symlink():
            compiler.unlink()
        if hardlink:
            os.link(manager, compiler)
        else:
            compiler.symlink_to(manager.name)
        return compiler, manager

    def test_symlink_dispatch_resolves_and_executes_actual_native_compiler(self):
        compiler, _ = self.proxy()
        with self.assertRaises(HeptaError) as rejected:
            backend.toolchain_info(str(compiler.resolve()))
        self.assertEqual(rejected.exception.diagnostic.code, "E_TOOLCHAIN_IDENTITY")
        selected = backend.find_rustc(str(compiler))
        self.assertEqual(selected, self.real_compiler)
        info = backend.toolchain_info(selected)
        self.assertEqual(info["executable_sha256"], hashlib.sha256(Path(selected).read_bytes()).hexdigest())
        built = backend.compile_rust("fn main() { assert_eq!(6 * 7, 42); }", rustc=str(compiler),
                                     crate_type="bin", output=self.directory / "native")
        self.assertTrue(built["ok"], built)
        self.assertEqual(subprocess.run([built["artifact"]], capture_output=True, timeout=10).returncode, 0)

    def test_hardlink_proxy_records_the_real_compiler(self):
        compiler, manager = self.proxy(hardlink=True)
        self.assertTrue(os.path.samefile(compiler, manager))
        self.assertEqual(backend.find_rustc(str(compiler)), self.real_compiler)

    def test_bootstrap_precedes_path_proxy(self):
        compiler, _ = self.proxy(response="invalid\n")
        bootstrap = self.directory / "toolchains/rust-1.90.0/bin/rustc"
        bootstrap.parent.mkdir(parents=True)
        bootstrap.symlink_to(self.real_compiler)
        with mock.patch.object(backend, "__file__", str(self.directory / "repo/hepta/backend.py")), \
             mock.patch.object(backend.shutil, "which", return_value=str(compiler)):
            self.assertEqual(backend.find_rustc(), self.real_compiler)

    def test_path_proxy_works_without_bootstrap(self):
        compiler, _ = self.proxy()
        with mock.patch.object(backend, "__file__", str(self.directory / "repo/hepta/backend.py")), \
             mock.patch.object(backend.shutil, "which", return_value=str(compiler)):
            self.assertEqual(backend.find_rustc(), self.real_compiler)

    def test_explicit_and_environment_selection_never_fall_back(self):
        missing = str(self.directory / "absent-rustc")
        with mock.patch.dict(os.environ, {"RUSTC": missing}):
            with self.assertRaises(HeptaError):
                backend.find_rustc()
            self.assertEqual(backend.find_rustc(self.real_compiler), self.real_compiler)
        with mock.patch.dict(os.environ, {"RUSTC": self.real_compiler}):
            with self.assertRaises(HeptaError):
                backend.find_rustc(missing)

    def test_malformed_manager_responses_fail_closed(self):
        cases = [("", 0), ("/a\n/b\n", 0), ("relative/rustc\n", 0),
                 (str(self.directory / "absent") + "\n", 0),
                 (self.real_compiler + "\n", 9), ("/tmp/invalid\x00path\n", 0)]
        for response, status in cases:
            with self.subTest(response=repr(response), status=status):
                compiler, _ = self.proxy(response=response, status=status)
                with self.assertRaises(HeptaError) as rejected:
                    backend.find_rustc(str(compiler))
                self.assertEqual(rejected.exception.diagnostic.code, "E_TOOLCHAIN")

    def test_proxy_recursion_and_unavailable_execution_fail_closed(self):
        compiler, manager = self.proxy()
        compiler, _ = self.proxy(target=manager)
        with self.assertRaises(HeptaError):
            backend.find_rustc(str(compiler))
        with mock.patch.object(backend.subprocess, "run", side_effect=subprocess.TimeoutExpired("rustup", 30)):
            with self.assertRaises(HeptaError):
                backend.find_rustc(str(compiler))

    def test_selected_toolchain_still_requires_pinned_complete_identity(self):
        wrong = self.executable(self.directory / "other/bin/rustc",
            "print('rustc 1.89.0\\nbinary: rustc\\ncommit-hash: fixture\\nhost: x86_64-unknown-linux-gnu\\nrelease: 1.89.0')\n")
        compiler, _ = self.proxy(target=wrong)
        self.assertEqual(backend.find_rustc(str(compiler)), str(wrong))
        with self.assertRaises(HeptaError) as rejected:
            backend.toolchain_info(backend.find_rustc(str(compiler)))
        self.assertEqual(rejected.exception.diagnostic.code, "E_TOOLCHAIN_IDENTITY")


if __name__ == "__main__":
    unittest.main()
