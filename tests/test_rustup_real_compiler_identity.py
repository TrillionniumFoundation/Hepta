"""Mock rustup dispatch tests: pin and hash the concrete compiler, not a shim."""
import hashlib
import os
from pathlib import Path
import shlex
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import RUST_VERSION, find_rustc, toolchain_info


@unittest.skipUnless(os.name == "posix", "rustup Unix symlink behavior")
class RustupCompilerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-rustup-proxy-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.compiler = root / "toolchains" / RUST_VERSION / "bin" / "rustc"
        self.compiler.parent.mkdir(parents=True)
        self.compiler.write_text(
            "#!/bin/sh\n"
            "printf 'rustc 1.90.0\\nbinary: rustc\\nrelease: 1.90.0\\n"
            "host: x86_64-unknown-linux-gnu\\ncommit-hash: abcdef0123\\n'\n")
        self.compiler.chmod(0o755)
        self.manager = root / "rustup"
        self.shim = root / "rustc"
        self.shim.symlink_to(self.manager)

    def make_rustup(self, output=None, *, exit_code=0):
        if output is None:
            output = str(self.compiler)
        self.manager.write_text(
            "#!/bin/sh\n"
            f'[ "$1" = which ] && [ "$2" = --toolchain ] && '
            f'[ "$3" = {shlex.quote(RUST_VERSION)} ] && [ "$4" = rustc ] '
            "|| exit 25\n"
            f"printf '%s\\n' {shlex.quote(output)}\n"
            f"exit {exit_code}\n")
        self.manager.chmod(0o755)

    def test_rustup_proxy_resolves_to_pinned_compiler_and_hashes_compiler(self):
        self.make_rustup()
        selected = find_rustc(str(self.shim))
        self.assertEqual(selected, str(self.compiler.resolve()))
        result = toolchain_info(selected)
        self.assertEqual(result["path"], selected)
        self.assertEqual(
            result["executable_sha256"],
            hashlib.sha256(self.compiler.read_bytes()).hexdigest())
        self.assertNotEqual(
            result["executable_sha256"],
            hashlib.sha256(self.manager.read_bytes()).hexdigest())

    def test_rustup_missing_pinned_toolchain_fails_closed(self):
        self.make_rustup(exit_code=1)
        with self.assertRaises(HeptaError) as failure:
            find_rustc(str(self.shim))
        self.assertIn("E_TOOLCHAIN", str(failure.exception))

    def test_rustup_rejects_relative_or_multiline_compiler(self):
        for value in ("rustc", str(self.compiler) + "\n" + str(self.compiler)):
            with self.subTest(value=value):
                self.make_rustup(output=value)
                with self.assertRaises(HeptaError):
                    find_rustc(str(self.shim))

    def test_rustup_refuses_manager_or_missing_executable(self):
        for value in (str(self.manager), str(self.manager.parent / "missing-rustc")):
            with self.subTest(value=value):
                self.make_rustup(output=value)
                with self.assertRaises(HeptaError):
                    find_rustc(str(self.shim))

    def test_wrong_rust_version_still_rejected_after_real_path_selection(self):
        self.make_rustup()
        self.compiler.write_text(
            "#!/bin/sh\n"
            "printf 'rustc 1.91.0\\nbinary: rustc\\nrelease: 1.91.0\\n"
            "host: x86_64-unknown-linux-gnu\\ncommit-hash: abcdef0123\\n'\n")
        self.compiler.chmod(0o755)
        with self.assertRaises(HeptaError) as failure:
            toolchain_info(find_rustc(str(self.shim)))
        self.assertIn("E_TOOLCHAIN_IDENTITY", str(failure.exception))

    def test_direct_real_rustc_path_stays_unchanged(self):
        self.make_rustup()
        self.assertEqual(find_rustc(str(self.compiler)), str(self.compiler.resolve()))


if __name__ == "__main__":
    unittest.main()
