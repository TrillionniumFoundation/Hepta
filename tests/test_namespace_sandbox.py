"""Configuration regressions; the separate qualifier runs the real boundaries."""
import os
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

from experiments.agent_eval import sandbox
from experiments.agent_eval.sandbox_qualification import qualify_sandbox
from hepta.backend import compile_rust, find_rustc


class NamespaceConfigurationTests(unittest.TestCase):
    def test_empty_proc_preserves_namespace_and_network_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(sandbox, "probe_sandbox", return_value={"available": True}):
                argv = sandbox.wrap_command(["/bin/true"], Path(temporary))
        self.assertIn("--unshare-all", argv)
        for option in ("--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-net"):
            self.assertIn(option, argv)
        self.assertIn("--new-session", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertIn(["--cap-drop", "ALL"], [argv[i:i + 2] for i in range(len(argv) - 1)])
        self.assertNotIn("--share-net", argv)
        self.assertNotIn("--proc", argv)
        self.assertIn(["--dir", "/proc"], [argv[i:i + 2] for i in range(len(argv) - 1)])

    def test_system_alias_cannot_expand_the_system_mount_allowlist(self):
        with patch.object(sandbox.Path, "is_symlink", lambda path: str(path) == "/bin"):
            with patch.object(sandbox.os, "readlink", return_value="/home/private"):
                with self.assertRaisesRegex(ValueError, "E_SANDBOX_SYSTEM_PATH"):
                    sandbox._base_bwrap()

    def test_loader_path_comes_only_from_explicit_read_only_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            toolchain = root / "trusted_toolchain"
            (toolchain / "lib" / "rustlib").mkdir(parents=True)
            with patch.object(sandbox, "probe_sandbox", return_value={"available": True}):
                with patch.dict(os.environ, {"LD_LIBRARY_PATH": "/candidate/untrusted"}):
                    argv = sandbox.wrap_command(["/bin/true"], root, read_only=[toolchain])
                    clean = sandbox.clean_environment()
            self.assertNotIn("LD_LIBRARY_PATH", clean)
            self.assertNotIn("/candidate/untrusted", argv)
            offset = argv.index("LD_LIBRARY_PATH")
            self.assertEqual(argv[offset - 1:offset + 2],
                             ["--setenv", "LD_LIBRARY_PATH", str(toolchain / "lib")])

    def test_unavailable_namespaces_cannot_be_relabelled_available(self):
        blocked = {"available": False, "reason": "kernel denied namespaces"}
        with patch.object(sandbox, "probe_sandbox", return_value=blocked):
            with self.assertRaisesRegex(ValueError, "E_SANDBOX_UNAVAILABLE"):
                sandbox.wrap_command(["/bin/true"], Path("/tmp/capsule"))

    def test_qualification_leaves_unexecuted_checks_not_run(self):
        with patch("experiments.agent_eval.sandbox_qualification.probe_sandbox",
                   return_value={"available": False, "reason": "kernel denied namespaces"}):
            report = qualify_sandbox()
        self.assertFalse(report["qualified"])
        self.assertFalse(report["ai_comparison_eligible"])
        self.assertEqual(report["status"], "environment_blocked")
        self.assertEqual(report["checks"]["startup"]["status"], "failed")
        self.assertTrue(all(item["status"] == "not_run" for name, item in report["checks"].items()
                            if name != "startup"))

    def test_nonstandard_host_wrapper_keeps_compiler_sysroot_discovery(self):
        rustc = find_rustc()
        with tempfile.TemporaryDirectory(prefix="hepta-rust-wrapper-") as temporary:
            wrapper = Path(temporary) / "rustc-wrapper"
            wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(rustc) + ' "$@"\n')
            wrapper.chmod(0o700)
            result = compile_rust("pub fn marker() -> u8 { 7 }", rustc=str(wrapper), check_only=True)
        self.assertTrue(result["ok"], result)
        self.assertIsNone(result["sysroot"])
        self.assertEqual(result["toolchain"]["sysroot_discovery"], "compiler_default")
        self.assertFalse(any(flag.startswith("sysroot=") for flag in result["flags"]))


if __name__ == "__main__":
    unittest.main()
