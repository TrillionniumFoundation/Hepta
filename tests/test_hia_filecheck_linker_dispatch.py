"""Actual argv/identity wiring fixtures; these do not qualify LLVM or native LTO."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.test_hia_filecheck_target_profile import _elf_lto_linker_profile


FIXTURE = r'''
import json
from pathlib import Path
import sys
print(json.dumps({"argv": sys.argv, "executable": str(Path(sys.argv[0]).resolve())}))
if Path(sys.argv[0]).name != "ld.lld":
    print("fixture generic driver requires an ELF invocation name", file=sys.stderr)
    raise SystemExit(1)
'''


class FilecheckLinkerDispatchTests(unittest.TestCase):
    def fixture(self, directory, name):
        path = directory / name
        path.write_text("#!" + sys.executable + "\n" + FIXTURE)
        path.chmod(0o700)
        return path

    def invoke(self, argv):
        process = subprocess.run(argv, text=True, capture_output=True, timeout=10)
        row = {"argv": argv, "returncode": process.returncode,
               "stdout": process.stdout, "stderr": process.stderr}
        print(json.dumps({"synthetic_linker_argv_execution": row}, sort_keys=True))
        return process, json.loads(process.stdout)

    def test_generic_driver_probe_and_link_arguments_keep_the_configured_binary(self):
        for name in ("rust-lld", "lld"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                selected = self.fixture(root, name)
                expected_digest = sha256(selected.read_bytes()).hexdigest()
                rejected, _ = self.invoke([str(selected), "--version"])
                self.assertEqual(rejected.returncode, 1)
                aliases = root / "private aliases"
                aliases.mkdir()
                profile = _elf_lto_linker_profile(selected, aliases)
                alias = Path(profile["invocation_path"])
                self.assertTrue(alias.is_symlink())
                self.assertTrue(alias.samefile(selected))
                self.assertEqual(alias.name, "ld.lld")
                self.assertEqual(profile["sha256"], expected_digest)
                self.assertEqual(profile["resolved_executable"], str(selected.resolve()))
                self.assertTrue(profile["alias_applied"])
                probe, observed = self.invoke(profile["version_argv"])
                self.assertEqual(probe.returncode, 0)
                self.assertEqual(observed["argv"], profile["version_argv"])
                # Exercise the exact executable selected by the Clang flag.
                # This argv fixture does not execute Clang or emit a library.
                flag, = profile["driver_flags"]
                prefix = "-fuse-ld="
                self.assertTrue(flag.startswith(prefix))
                driver_target = flag[len(prefix):]
                self.assertEqual(driver_target, profile["version_argv"][0])
                linker_args = ["-shared", "-o", "output with spaces.so", "input.bc"]
                linked, observed = self.invoke([driver_target, *linker_args])
                self.assertEqual(linked.returncode, 0)
                self.assertEqual(observed["argv"], [str(alias), *linker_args])
                self.assertEqual(observed["executable"], str(selected.resolve()))
                self.assertEqual(sha256(selected.read_bytes()).hexdigest(), expected_digest)

    def test_existing_elf_driver_keeps_its_original_invocation_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selected = self.fixture(root, "ld.lld")
            aliases = root / "unused aliases"
            profile = _elf_lto_linker_profile(selected, aliases)
            self.assertFalse(profile["alias_applied"])
            self.assertFalse(aliases.exists())
            self.assertEqual(profile["invocation_path"], str(selected))
            self.assertEqual(profile["driver_flags"], ["-fuse-ld=" + str(selected)])
            probe, observed = self.invoke(profile["version_argv"])
            self.assertEqual(probe.returncode, 0)
            self.assertEqual(observed["executable"], str(selected.resolve()))


if __name__ == "__main__":
    unittest.main()
