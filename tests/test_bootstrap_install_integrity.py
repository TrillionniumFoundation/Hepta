"""A successful installer process cannot hide failed or redirected file copies."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import bootstrap_toolchain
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


class HostCargoBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-bootstrap-cargo-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix = self.root / "installed"
        self.downloads = {}
        self.lock = []
        for component in ("rustc", "cargo", "rust-std"):
            name = component + "-1.90.0-" + bootstrap_toolchain.HOST
            payload = "lib/std.rlib" if component == "rust-std" else "bin/" + component
            files = {"components": component + "\n", "install.sh": "#!/bin/sh\n",
                     component + "/manifest.in": "file:" + payload + "\n",
                     component + "/" + payload: "reviewed " + component + " payload"}
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
                for relative, content in files.items():
                    data = content.encode()
                    info = tarfile.TarInfo(name + "/" + relative)
                    info.size = len(data)
                    info.mode = 0o755 if "/bin/" in relative else 0o644
                    archive.addfile(info, io.BytesIO(data))
            data = buffer.getvalue()
            url = "https://static.rust-lang.org/dist/" + name + ".tar.xz"
            self.downloads[url] = data
            self.lock.append({"package": name, "url": url,
                              "sha256": hashlib.sha256(data).hexdigest()})
        self.lock_path = self.root / "toolchain-lock.json"
        self.lock_path.write_text(json.dumps(self.lock))

    def _run(self, *, corrupt_cargo=False):
        def install(argv, check):
            self.assertTrue(check)
            self.assertIn("--prefix=" + str(self.prefix), argv)
            package = Path(argv[1]).parent
            for component in (package / "components").read_text().splitlines():
                shutil.copytree(package / component, self.prefix, dirs_exist_ok=True)
                if component == "cargo" and corrupt_cargo:
                    (self.prefix / "bin/cargo").write_bytes(b"partial copy")

        output = io.StringIO()
        with patch.object(bootstrap_toolchain, "ROOT", self.root), \
             patch.object(bootstrap_toolchain.platform, "system", return_value="Linux"), \
             patch.object(bootstrap_toolchain.platform, "machine", return_value="x86_64"), \
             patch.object(bootstrap_toolchain.urllib.request, "urlopen",
                          side_effect=lambda url, timeout: io.BytesIO(self.downloads[url])), \
             patch.object(bootstrap_toolchain.subprocess, "run", side_effect=install), \
             patch("sys.argv", ["bootstrap_toolchain.py", "--prefix", str(self.prefix), "--targets"]), \
             redirect_stdout(output):
            bootstrap_toolchain.main()
        return json.loads(output.getvalue()[output.getvalue().index("{"):])

    def test_host_install_includes_same_version_cargo_and_verified_payload(self):
        report = self._run()
        self.assertEqual(report["cargo"], str(self.prefix / "bin/cargo"))
        self.assertEqual({item["package"] for item in report["components"]},
                         {item["package"] for item in self.lock})
        cargo = [item for item in report["installation_verification"]
                 if item["package"].startswith("cargo-")]
        self.assertEqual(len(cargo), 1)
        self.assertEqual(cargo[0]["components"], ["cargo"])
        self.assertEqual(cargo[0]["verified_payloads"], 1)
        self.assertEqual((self.prefix / "bin/cargo").read_bytes(), b"reviewed cargo payload")

    def test_successful_installer_cannot_hide_corrupt_cargo_payload(self):
        with self.assertRaisesRegex(RuntimeError, "Incomplete|modified"):
            self._run(corrupt_cargo=True)

    def test_missing_cargo_lock_does_not_silently_reuse_runner_cargo(self):
        self.lock_path.write_text(json.dumps([item for item in self.lock
                                             if not item["package"].startswith("cargo-")]))
        with self.assertRaises(SystemExit) as raised:
            self._run()
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse((self.prefix / "bin/cargo").exists())


if __name__ == "__main__":
    unittest.main()
