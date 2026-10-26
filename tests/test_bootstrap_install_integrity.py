"""A successful installer process cannot hide failed or redirected file copies."""
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.bootstrap_toolchain import verify_installed_package


class InstalledToolchainIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-bootstrap-integrity-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package, self.prefix = self.root / "package", self.root / "prefix"
        self.component = self.package / "rustc"
        (self.component / "bin").mkdir(parents=True)
        (self.component / "lib").mkdir()
        (self.package / "components").write_text("rustc\n")
        (self.component / "manifest.in").write_text("file:bin/rustc\ndir:lib\n")
        (self.component / "bin/rustc").write_bytes(b"reviewed compiler payload")
        (self.component / "bin/rustc").chmod(0o755)
        (self.component / "lib/std.rlib").write_bytes(b"reviewed standard library")
        (self.component / "lib/alias.rlib").symlink_to("std.rlib")
        shutil.copytree(self.component, self.prefix, symlinks=True)

    def test_complete_payload_and_relative_symlink_are_checked(self):
        result = verify_installed_package(self.package, self.prefix)
        self.assertEqual(result["verified_payloads"], 3)
        self.assertEqual(result["components"], ["rustc"])
        self.assertEqual(len(result["installed_payload_inventory_sha256"]), 64)

    def test_enospc_style_empty_or_partial_copy_is_rejected(self):
        for payload in (b"", b"reviewed", b"different standard library"):
            with self.subTest(payload=payload):
                (self.prefix / "lib/std.rlib").write_bytes(payload)
                with self.assertRaisesRegex(RuntimeError, "Incomplete|modified"):
                    verify_installed_package(self.package, self.prefix)

    def test_missing_payload_rejected(self):
        (self.prefix / "bin/rustc").unlink()
        with self.assertRaisesRegex(RuntimeError, "Missing"):
            verify_installed_package(self.package, self.prefix)

    def test_execute_permission_required(self):
        (self.prefix / "bin/rustc").chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "execute permissions"):
            verify_installed_package(self.package, self.prefix)

    def test_installed_symlink_cannot_escape_prefix(self):
        outside = self.root / "outside.rlib"
        outside.write_bytes((self.component / "lib/std.rlib").read_bytes())
        (self.prefix / "lib/alias.rlib").unlink()
        (self.prefix / "lib/alias.rlib").symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "escapes"):
            verify_installed_package(self.package, self.prefix)

    def test_same_bytes_at_redirected_regular_file_are_not_accepted(self):
        destination = self.prefix / "bin/rustc"
        destination.unlink()
        destination.symlink_to(self.component / "bin/rustc")
        with self.assertRaisesRegex(RuntimeError, "escapes|Missing"):
            verify_installed_package(self.package, self.prefix)

    def test_manifest_traversal_rejected(self):
        (self.component / "manifest.in").write_text("file:../escape\n")
        with self.assertRaisesRegex(RuntimeError, "Invalid"):
            verify_installed_package(self.package, self.prefix)

    def test_unknown_manifest_entry_rejected(self):
        (self.component / "manifest.in").write_text("script:install-again\n")
        with self.assertRaisesRegex(RuntimeError, "Unsupported"):
            verify_installed_package(self.package, self.prefix)


if __name__ == "__main__":
    unittest.main()
