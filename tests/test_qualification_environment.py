"""Exercise real workflow environment persistence without executing compilers."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RISCV_TOOLS = (
    ("CLANG", "CLANG", "clang"),
    ("HEPTA_LLD", "LINKER", "ld.lld"),
    ("HEPTA_LLVM_READOBJ", "READOBJ", "llvm-readobj"),
    ("HEPTA_QEMU_RISCV64", "QEMU", "qemu-riscv64"),
)


def workflow_step():
    workflow = (ROOT / ".github/workflows/hepta-qualification.yml").read_text()
    name = "      - name: Export verification tools for every qualification step\n"
    if workflow.count(name) != 1:
        raise AssertionError("unique verification export step required")
    if not (workflow.index("      - name: Install SHA-256-locked Lean and QEMU tools\n")
            < workflow.index(name)
            < workflow.index("      - name: Run all current native and experiment qualification gates\n")
            < workflow.index("      - name: Qualify the standalone HIA interpreter and direct native paths\n")):
        raise AssertionError("both qualifications require the installed environment")
    return textwrap.dedent(workflow.split(name, 1)[1].split("\n      - name:", 1)[0]
                          .split("        run: |\n", 1)[1])


def load_test(name):
    spec = importlib.util.spec_from_file_location("qualification_environment_probe_" + name,
                                                ROOT / "tests" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QualificationEnvironmentTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        workspace = root / "workspace with spaces" / "Hepta"
        workspace.mkdir(parents=True)
        runner = root / "runner temporary with spaces"
        runner.mkdir()
        prefix = workspace.parent / "toolchains"
        tools = {"lean": prefix / "lean-4.19.0/bin/lean",
                 "qemu-aarch64": prefix / "qemu-8.2.2/qemu-aarch64-static",
                 "qemu-riscv64": prefix / "qemu-8.2.2/qemu-riscv64-static",
                 "ld.lld": prefix / "rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld",
                 "llvm-readobj": runner / "test-only-llvm-readobj",
                 "rustc": prefix / "rust-1.90.0/bin/rustc",
                 "clang": runner / "test-only-clang"}
        for path in tools.values():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\nexit 94\n")
            path.chmod(0o755)
        github_env, github_path = root / "github-env", root / "github-path"
        github_env.touch()
        github_path.touch()
        environment = dict(os.environ, GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(runner),
                           GITHUB_ENV=str(github_env), GITHUB_PATH=str(github_path),
                           RUSTC=str(tools["rustc"]))
        environment.pop("LEAN", None)
        environment.pop("HEPTA_LLD", None)
        environment.pop("HEPTA_QEMU_AARCH64", None)
        return tools, environment, github_env, github_path

    def export(self, environment):
        return subprocess.run([shutil.which("bash"), "--noprofile", "--norc", "-e", "-c", workflow_step()],
                              env=environment, capture_output=True, text=True, timeout=10)

    def next_step(self, environment, github_env, github_path):
        result = dict(environment)
        result.update(line.split("=", 1) for line in github_env.read_text().splitlines())
        result["PATH"] = os.pathsep.join(github_path.read_text().splitlines() + [result["PATH"]])
        return result

    def test_workflow_exports_actual_aliases_and_lean_to_both_following_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            tools, env, exported, paths = self.fixture(directory)
            env["HEPTA_CLANG"] = "/ambient/unused clang"
            result = self.export(env)
            self.assertEqual(result.returncode, 0, result.stderr)
            following = self.next_step(env, exported, paths)
            self.assertEqual(Path(following["LEAN"]).resolve(), tools["lean"])
            self.assertEqual(following["CLANG"], "/usr/lib/llvm-20/bin/clang")
            # Read the persisted environment in a real subsequent process.
            # Both names must select the same compiler, even with a stale
            # inherited native-graph override in the original environment.
            child = subprocess.run([sys.executable, "-c",
                "import json,os; print(json.dumps({k:os.environ.get(k) for k in ('CLANG','HEPTA_CLANG')}))"],
                env=following, capture_output=True, text=True, timeout=10, check=True)
            self.assertEqual(json.loads(child.stdout), {
                "CLANG": following["CLANG"], "HEPTA_CLANG": following["CLANG"]})
            for name in ("lean", "qemu-aarch64", "ld.lld"):
                resolved = shutil.which(name, path=following["PATH"])
                self.assertIsNotNone(resolved)
                self.assertEqual(Path(resolved).resolve(), tools[name])
            self.assertTrue(Path(shutil.which("qemu-aarch64", path=following["PATH"])).is_symlink())
            self.assertTrue(Path(shutil.which("ld.lld", path=following["PATH"])).is_symlink())

    def test_missing_installed_executable_fails_before_export(self):
        for missing in ("lean", "qemu-aarch64", "ld.lld"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                tools, env, exported, paths = self.fixture(directory)
                tools[missing].unlink()
                self.assertNotEqual(self.export(env).returncode, 0)
                self.assertEqual(exported.read_bytes(), b"")
                self.assertEqual(paths.read_bytes(), b"")

    def test_native_controls_select_the_configured_tools_outside_developer_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            tools, env, exported, paths = self.fixture(directory)
            self.assertEqual(self.export(env).returncode, 0)
            following = self.next_step(env, exported, paths)
            following["CLANG"] = str(tools["clang"])
            with patch.dict(os.environ, following, clear=True):
                bulk = load_test("test_hia_composite_bulk_native")
                study = load_test("test_hia_edit_study")
            self.assertFalse(getattr(bulk.CompositeBulkNativeTests, "__unittest_skip__", False))
            self.assertFalse(getattr(study.StudyActualNativeControlTests, "__unittest_skip__", False))
            self.assertEqual(bulk.CLANG, str(tools["clang"]))
            self.assertEqual(Path(bulk.LINKER).resolve(), tools["ld.lld"])
            self.assertEqual(Path(bulk.QEMU).resolve(), tools["qemu-aarch64"])
            self.assertEqual(study.CLANG, str(tools["clang"]))
            self.assertEqual(study.RUSTC, str(tools["rustc"]))

    def test_missing_explicit_tool_never_uses_an_available_path_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            tools, env, exported, paths = self.fixture(directory)
            self.assertEqual(self.export(env).returncode, 0)
            following = self.next_step(env, exported, paths)
            following["CLANG"] = str(tools["clang"])
            missing = str(Path(directory) / "unavailable-explicit-lld")
            following["HEPTA_LLD"] = missing
            with patch.dict(os.environ, following, clear=True):
                self.assertIsNotNone(shutil.which("ld.lld"))
                bulk = load_test("test_hia_composite_bulk_native")
            self.assertEqual(bulk.LINKER, missing)
            self.assertTrue(bulk.CompositeBulkNativeTests.__unittest_skip__)

    def test_edit_study_path_defaults_become_explicit_executable_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            tools, env, exported, paths = self.fixture(directory)
            aliases = Path(directory) / "native aliases with spaces"
            aliases.mkdir()
            for name in ("clang", "rustc"):
                (aliases / name).symlink_to(tools[name])
                env.pop(name.upper(), None)
            env["PATH"] = str(aliases) + os.pathsep + env["PATH"]
            with patch.dict(os.environ, env, clear=True):
                study = load_test("test_hia_edit_study")
            self.assertFalse(getattr(study.StudyActualNativeControlTests, "__unittest_skip__", False))
            self.assertEqual(Path(study.CLANG).resolve(), tools["clang"])
            self.assertEqual(Path(study.RUSTC).resolve(), tools["rustc"])

    def riscv_environment(self, directory):
        tools, environment, _, _ = self.fixture(directory)
        aliases = Path(directory) / "RV64 PATH aliases with spaces"
        aliases.mkdir()
        for variable, _, name in RISCV_TOOLS:
            (aliases / name).symlink_to(tools[name])
            environment.pop(variable, None)
        environment["PATH"] = str(aliases)
        return tools, environment, aliases

    def test_riscv_native_controls_use_path_defaults_and_explicit_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            tools, environment, aliases = self.riscv_environment(directory)
            with patch.dict(os.environ, environment, clear=True):
                native = load_test("test_hia_riscv64")
            self.assertFalse(getattr(native.Riscv64NativeTests, "__unittest_skip__", False))
            for _, attribute, name in RISCV_TOOLS:
                self.assertEqual(getattr(native, attribute), str(aliases / name))

            for variable, _, name in RISCV_TOOLS:
                environment[variable] = str(tools[name])
            with patch.dict(os.environ, environment, clear=True):
                native = load_test("test_hia_riscv64")
            self.assertFalse(getattr(native.Riscv64NativeTests, "__unittest_skip__", False))
            for _, attribute, name in RISCV_TOOLS:
                self.assertEqual(getattr(native, attribute), str(tools[name]))

    def test_riscv_missing_explicit_tool_cannot_fall_back_to_path(self):
        with tempfile.TemporaryDirectory() as directory:
            _, environment, aliases = self.riscv_environment(directory)
            for variable, attribute, name in RISCV_TOOLS:
                missing = str(Path(directory) / ("unavailable-explicit-" + name))
                with self.subTest(variable=variable):
                    selected = dict(environment, **{variable: missing})
                    with patch.dict(os.environ, selected, clear=True):
                        self.assertEqual(shutil.which(name), str(aliases / name))
                        native = load_test("test_hia_riscv64")
                    self.assertEqual(getattr(native, attribute), missing)
                    self.assertTrue(native.Riscv64NativeTests.__unittest_skip__)

    def test_lean_file_alone_is_insufficient_until_workflow_environment_is_inherited(self):
        with tempfile.TemporaryDirectory() as directory:
            tools, env, exported, paths = self.fixture(directory)
            formal = load_test("test_hia_selected_formal")
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(unittest.SkipTest):
                    formal.SelectedFormalKernelTests.setUpClass()
            self.assertEqual(self.export(env).returncode, 0)
            following = self.next_step(env, exported, paths)
            # Exercise real setUpClass through its tool-selection boundary,
            # stopping at the qualifier rather than compiling any proof.
            try:
                with patch.dict(os.environ, following, clear=True), \
                        patch.object(formal.formal, "qualify", return_value={}) as qualifier:
                    formal.SelectedFormalKernelTests.setUpClass()
                    self.assertEqual(Path(qualifier.call_args.args[0]).resolve(), tools["lean"])
                    self.assertEqual(qualifier.call_args.kwargs["clang"], following["CLANG"])
            finally:
                formal.SelectedFormalKernelTests.doClassCleanups()


if __name__ == "__main__":
    unittest.main()
