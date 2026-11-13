"""Actual ordinary native builds, pinned-byte refusals and installed execution.

The fixture is a development bootstrap unless its compiler is supplied from a
separate run. It does not manufacture a source-matched cold qualification.
"""
from __future__ import annotations

from contextlib import redirect_stderr
import copy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program_selfhost as native
from tests.test_hia_agent_entry import fixture

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return sha256(path.read_bytes()).hexdigest()


def _test_executable(code):
    """Explicit synthetic process-owner control, never a compiler observation."""
    raw = bytearray(176) + code
    raw[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16,
        2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", raw, 64,
        1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
    struct.pack_into("<IIQQQQQQ", raw, 120,
        0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    return bytes(raw)


class SelfhostBuildSourceTests(unittest.TestCase):
    def test_cli_rejects_unpaired_and_meaningless_selection_before_input_read(self):
        from hepta.cli import hia_main
        variants = [
            ["--backend", "selfhost"],
            ["--backend", "selfhost", "--selfhost-manifest", "missing"],
            ["--backend", "selfhost", "--selfhost-manifest-sha256", "0" * 64],
            ["--backend", "native", "--selfhost-manifest", "missing"],
            ["--selfhost-manifest-sha256", "0" * 64],
        ]
        for extra in variants:
            with self.subTest(extra=extra), redirect_stderr(io.StringIO()), \
                    patch("hepta.hia_program.verify_program", side_effect=AssertionError("input read")):
                with self.assertRaises(SystemExit) as caught:
                    hia_main(["build", "missing", "-o", "missing-output", *extra])
                self.assertEqual(caught.exception.code, 2)

    def test_profiles_and_nonfinite_budgets_refuse_without_execution(self):
        choices = [dict(kind="shared"), dict(target="aarch64-unknown-linux-gnu"),
                   dict(machine_plan={}), dict(foreign_buffer_exports=(("calculate", 8),)),
                   dict(timeout_seconds=True), dict(timeout_seconds=float("nan")),
                   dict(timeout_seconds=0), dict(timeout_seconds=float("inf"))]
        with patch("subprocess.Popen", side_effect=AssertionError("unexpected child")):
            for kwargs in choices:
                with self.subTest(kwargs=kwargs), self.assertRaises(native.SelfhostBuildRejected):
                    native.build_program_selfhost(fixture(), "/missing/output",
                        manifest="/missing/manifest", manifest_sha256="0" * 64, **kwargs)

    def test_actual_kernel_seals_prevent_executable_mutation(self):
        raw = _test_executable(bytes.fromhex("b83c00000031ff0f05"))
        fd, seals = native._sealed_executable(raw)
        try:
            self.assertEqual(seals & native.REQUIRED_SEALS, native.REQUIRED_SEALS)
            self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
            with self.assertRaises(OSError):
                os.pwrite(fd, b"X", 0)
            with self.assertRaises(OSError):
                os.ftruncate(fd, 1)
        finally:
            os.close(fd)

    def test_original_deadline_kills_and_reaps_actual_looping_child(self):
        raw = _test_executable(b"\xeb\xfe")
        fd, _ = native._sealed_executable(raw)
        children = []
        popen = subprocess.Popen
        def launch(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child
        try:
            with tempfile.TemporaryDirectory() as temp, patch.object(native.subprocess, "Popen", launch):
                with self.assertRaises(native.SelfhostBuildRejected) as caught:
                    native._run(fd, b"x", 0.05, temp)
            self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_TIMEOUT")
            self.assertTrue(caught.exception.capture["leader_reaped"])
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].returncode)
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0].pid, os.WNOHANG)
            with self.assertRaises(ProcessLookupError):
                os.killpg(children[0].pid, 0)
        finally:
            os.close(fd)

    def test_actual_output_limit_is_not_a_successful_truncated_object(self):
        # write(1, payload, 65536) forever. This intentionally is not a compiler.
        code = bytes.fromhex("b801000000bf01000000488d3509000000ba000001000f05eb e6")
        code += bytes(65536)
        raw = _test_executable(code)
        fd, _ = native._sealed_executable(raw)
        try:
            with tempfile.TemporaryDirectory() as temp:
                with self.assertRaises(native.SelfhostBuildRejected) as caught:
                    native._run(fd, b"x", 2, temp)
            self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_OUTPUT_LIMIT")
            self.assertTrue(caught.exception.capture["leader_reaped"])
            self.assertLessEqual(caught.exception.capture["stdout_bytes_retained"], native.MAX_OBJECT_BYTES + 1)
            self.assertFalse(caught.exception.capture["stdout_complete"])
        finally:
            os.close(fd)


class SelfhostBuildNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_program import execute_program, verify_program
        cls.program = fixture()
        cls.expected = {}
        checked = verify_program(cls.program)
        for function in ("calculate", "caller"):
            for argument in (0, 1, 4294967295):
                result = execute_program(checked, function, [argument])
                if result["status"] != "returned":
                    raise AssertionError(result)
                cls.expected[function, argument] = result["values"][0]
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-selfhost-build-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        from tools.qualify_hia_selfhost import compile_stage, invoke
        cold = os.environ.get("HEPTA_HIA_SOURCE_BUILD_COLD_REPORT")
        provided = os.environ.get("HEPTA_HIA_SELFHOST_BUILD_DEVELOPMENT_COMPILER")
        if cold and provided or not cold and not provided:
            raise ValueError("select exactly one matching HEPTA_HIA_SOURCE_BUILD_COLD_REPORT "
                             "or explicit HEPTA_HIA_SELFHOST_BUILD_DEVELOPMENT_COMPILER")
        cls.cold_report = Path(cold) if cold else None
        if cold:
            outer = json.loads(cls.cold_report.read_bytes())
            inner = json.loads(Path(outer["nested_report"]).read_bytes())
            cls.compiler = Path(inner["generations"][-1]["produced_image"])
            from tools.build_hia_core_json_cli import build
            cls.executable = build(cls.folder / "qualified", cls.compiler,
                                   cls.cold_report, output_profile="elf")
            cls.manifest_value = json.loads(
                (cls.executable.parent / "compiler-manifest.json").read_bytes())
            return
        cls.compiler = cls.folder / "provided-development-compiler.bin"
        cls.compiler.write_bytes(Path(provided).read_bytes())
        frontend, _ = compile_stage(cls.folder, "frontend", cls.compiler,
            (ROOT / "examples/hia_bootstrap/core_json_frontend.hepta").read_bytes())
        packer, _ = compile_stage(cls.folder, "packer", cls.compiler,
            (ROOT / "examples/hia_bootstrap/core_json_cli_packer.hepta").read_bytes())
        from tools.generate_hia_core_json_cli import MAGIC
        front, compiler = frontend.read_bytes(), cls.compiler.read_bytes()
        frame = struct.pack("<4Q", MAGIC, len(front), len(compiler), 1) + front + compiler
        result, output = invoke(cls.folder, "pack", packer, frame)
        if result["status"] != "returned" or result["abi_status"] != 0:
            raise AssertionError(result)
        cls.executable = cls.folder / "hia-core-json"
        cls.executable.write_bytes(output[:result["core_u32"]])
        cls.executable.chmod(0o500)
        cls.manifest_value = native.manifest_value(cls.executable,
            compiler_sha256=sha256(compiler).hexdigest(), frontend_sha256=sha256(front).hexdigest(),
            packer_sha256=sha256(packer.read_bytes()).hexdigest(),
            source_sha256={name: sha256((ROOT / name).read_bytes()).hexdigest()
                           for name in native.SOURCE_FILES}, cold_report_sha256=None)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.folder, prefix="case-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "compiler-manifest.json"
        shutil.copyfile(self.executable, self.root / self.executable.name)
        self.pin = _write_json(self.manifest, self.manifest_value)

    def build(self, value=None, output=None, **kwargs):
        return native.build_program_selfhost(self.program if value is None else value,
            self.root / "result.o" if output is None else output,
            manifest=self.manifest, manifest_sha256=self.pin, **kwargs)

    def test_actual_native_build_with_python_emitter_forbidden_and_typed_execution(self):
        with (patch("hepta.hia_program_native._Emitter.render", side_effect=AssertionError("Python emitter")),
              patch("hepta.hia_machine_elf.write_elf_object", side_effect=AssertionError("Python ELF"))):
            receipt = self.build()
        data = (self.root / "result.o").read_bytes()
        self.assertEqual(receipt["artifact_sha256"], sha256(data).hexdigest())
        self.assertEqual(receipt["exports"], ["calculate", "caller"])
        self.assertEqual(receipt["profile"], native.PROFILE)
        self.assertEqual(receipt["compiler_cold_report_sha256"],
                         self.manifest_value["cold_report_sha256"])
        self.assertFalse(receipt["claims"]["python_emitter_used"])
        self.assertFalse(receipt["claims"]["whole_native_delivery_qualified"])
        self.assertEqual(receipt["capture"]["returncode"], 0)
        self.assertTrue(receipt["capture"]["stdout_complete"])
        self.assertTrue(receipt["capture"]["stderr_complete"])
        self.assertTrue(receipt["capture"]["leader_reaped"])
        source = self.root / "caller.c"
        checks = []
        for (function, argument), expected in self.expected.items():
            checks.append("if (%s(UINT32_C(%d)) != UINT32_C(%d)) return %d;" %
                          (function, argument, expected, len(checks) + 1))
        source.write_text("#include <stdint.h>\nextern uint32_t calculate(uint32_t);\n"
                          "extern uint32_t caller(uint32_t);\nint main(void) {\n" +
                          "\n".join(checks) + "\nreturn 0;\n}\n")
        executable = self.root / "caller"
        subprocess.run(["cc", "-std=c11", "-Werror", str(source), str(self.root / "result.o"),
                        "-Wl,-z,defs,-z,noexecstack", "-o", str(executable)],
                       check=True, capture_output=True, timeout=20)
        result = subprocess.run([str(executable)], capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))

    def test_explicit_export_subset_and_new_path_publication(self):
        value = {**self.program, "exports": ["calculate"]}
        result = self.build(value)
        self.assertEqual(result["binary_inventory"]["defined"], ["calculate"])
        before = (self.root / "result.o").read_bytes()
        with self.assertRaises(native.SelfhostBuildRejected):
            self.build(value)
        self.assertEqual((self.root / "result.o").read_bytes(), before)

    def test_wrong_pin_modified_executable_and_symlinks_refuse_before_child(self):
        with patch("subprocess.Popen", side_effect=AssertionError("unexpected child")):
            with self.assertRaises(native.SelfhostBuildRejected):
                native.build_program_selfhost(self.program, self.root / "badpin.o",
                    manifest=self.manifest, manifest_sha256="0" * 64)
            binary = self.root / self.executable.name
            binary.write_bytes(binary.read_bytes()[:-1] + b"X")
            with self.assertRaises(native.SelfhostBuildRejected):
                self.build()
            binary.unlink()
            binary.symlink_to(self.executable)
            with self.assertRaises(OSError):
                self.build()
            binary.unlink()
            shutil.copyfile(self.executable, binary)
            alias = self.root / "manifest-alias"
            alias.symlink_to(self.manifest)
            with self.assertRaises(OSError):
                native.build_program_selfhost(self.program, self.root / "symlink.o",
                    manifest=alias, manifest_sha256=self.pin)
            directory_alias = self.root / "directory-alias"
            directory_alias.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(OSError):
                native.build_program_selfhost(self.program, self.root / "parentlink.o",
                    manifest=directory_alias / self.manifest.name, manifest_sha256=self.pin)
        self.assertFalse((self.root / "result.o").exists())

    def test_changed_installed_source_refuses_and_native_semantic_failure_has_no_fallback(self):
        copies = self.root / "sources"
        copies.mkdir()
        paths = {}
        for index, name in enumerate(native.SOURCE_FILES):
            target = copies / str(index)
            shutil.copyfile(ROOT / name, target)
            paths[name] = target
        paths[native.SOURCE_FILES[0]].write_bytes(b"changed")
        with (patch.object(native, "_source_resource_path", lambda name: paths[name]),
              patch("subprocess.Popen", side_effect=AssertionError("unexpected child"))):
            with self.assertRaises(native.SelfhostBuildRejected) as caught:
                self.build()
            self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_SOURCE")
        value = copy.deepcopy(self.program)
        value["functions"][0]["blocks"][0]["ops"].insert(0,
            {"op": "call", "args": ["x"], "out": [{"name": "recursive", "type": "u32"}],
             "attrs": {"function": "calculate"}})
        with patch("hepta.hia_program_native.emit_program_machine", side_effect=AssertionError("fallback")):
            with self.assertRaises(native.SelfhostBuildRejected) as caught:
                self.build(value)
        self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_COMPILE")
        self.assertEqual(caught.exception.capture["returncode"], 2)
        self.assertFalse((self.root / "result.o").exists())

    def test_primitive_old_schema_does_not_claim_native_v8_support(self):
        old = {**self.program, "schema": "hepta.hia.program.v7"}
        with patch("subprocess.Popen", side_effect=AssertionError("unexpected child")):
            with self.assertRaises(native.SelfhostBuildRejected) as caught:
                self.build(old)
        self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_PROFILE")
        self.assertFalse((self.root / "result.o").exists())

    def test_selection_mutation_after_execution_prevents_publication(self):
        original = native._run
        def altered(*args, **kwargs):
            result = original(*args, **kwargs)
            self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
            return result
        with patch.object(native, "_run", altered):
            with self.assertRaises(native.SelfhostBuildRejected):
                self.build()
        self.assertFalse((self.root / "result.o").exists())

    def test_parent_substitution_during_execution_cannot_redirect_output_effects(self):
        destination = self.root / "output"
        destination.mkdir()
        alternate = self.root / "alternate"
        alternate.mkdir()
        moved = self.root / "original-output"
        original = native._run
        def altered(*args, **kwargs):
            result = original(*args, **kwargs)
            destination.rename(moved)
            destination.symlink_to(alternate, target_is_directory=True)
            return result
        with patch.object(native, "_run", altered):
            with self.assertRaises((native.SelfhostBuildRejected, OSError)):
                self.build(output=destination / "result.o")
        self.assertEqual(list(alternate.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_postpublication_selection_failure_withdraws_only_our_link(self):
        original = native.publish_verified
        def altered(*args, **kwargs):
            receipt = original(*args, **kwargs)
            self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
            return receipt
        with patch.object(native, "publish_verified", altered):
            with self.assertRaises(native.SelfhostBuildRejected):
                self.build()
        self.assertFalse((self.root / "result.o").exists())

    def test_actual_native_publication_uses_captured_parent_and_rolls_back_own_link(self):
        from tools.build_hia_artifact_publication import build, current_sources, SOURCES, OPERATIONS
        from tools.hia_selfhost_contract import PROFILE
        from tools.qualify_hia_selfhost import compile_stage, invoke
        from tools.generate_hia_artifact_publication import MAGIC
        publication = self.root / "publication"
        if self.cold_report:
            executable = build(publication, self.compiler, self.cold_report)
        else:
            publication.mkdir()
            images = {}
            for name in ("artifact_publication_policy", "artifact_publication_packer", "sha256_stream"):
                images[name], _ = compile_stage(publication, name, self.compiler,
                    (ROOT / "examples/hia_bootstrap" / (name + ".hepta")).read_bytes())
            policy = images["artifact_publication_policy"].read_bytes()
            digest = images["sha256_stream"].read_bytes()
            frame = struct.pack("<3Q", MAGIC, len(policy), len(digest)) + policy + digest
            result, packed = invoke(publication, "pack", images["artifact_publication_packer"], frame)
            self.assertEqual((result["status"], result["abi_status"]), ("returned", 0))
            executable = publication / "hia-artifact"
            executable.write_bytes(packed[:result["core_u32"]])
            executable.chmod(0o500)
            _write_json(publication / "build.json", {
                "schema": "hepta.hia.artifact-publication-build.v1",
                "status": "NATIVE_ARTIFACT_PUBLICATION_BUILT", "profile": PROFILE,
                "source_manifest": current_sources(), "operations": OPERATIONS,
                "executable_path": "hia-artifact", "executable_sha256": sha256(executable.read_bytes()).hexdigest(),
                "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES},
                "development_only": True, "matching_source_cold_qualified": False})
        environment = {"HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST": str(publication / "build.json")}
        with (patch.dict(os.environ, environment),
              patch("hepta.artifact_publication._read_exact", side_effect=AssertionError("host publication"))):
            receipt = self.build()
            self.assertEqual(receipt["artifact_sha256"], sha256((self.root / "result.o").read_bytes()).hexdigest())
            destination, moved, alternate = (self.root / name for name in ("output", "moved", "alternate"))
            destination.mkdir()
            alternate.mkdir()
            original = native.publish_verified
            def altered(*args, **kwargs):
                result = original(*args, **kwargs)
                destination.rename(moved)
                destination.symlink_to(alternate, target_is_directory=True)
                return result
            with patch.object(native, "publish_verified", altered):
                with self.assertRaises((native.SelfhostBuildRejected, OSError)):
                    self.build(output=destination / "result.o")
            self.assertEqual(list(alternate.iterdir()), [])
            self.assertEqual(list(moved.iterdir()), [])

    def test_actual_cli_and_installed_wheel_forbid_host_codegen_and_authoring_imports(self):
        source = self.root / "program.hepta"
        _write_json(source, self.program)
        child = r'''
import importlib.abc,json,sys
sys.path.insert(0,sys.argv[1])
class RefuseCodegen(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name == 'tools' or name.startswith('tools.') or name in {
            'hepta.hia_program_native','hepta.hia_machine_x64','hepta.hia_machine_elf'}:
            raise AssertionError('host codegen or authoring import: '+name)
sys.meta_path.insert(0,RefuseCodegen())
from hepta.cli import hia_main
raise SystemExit(hia_main(json.loads(sys.argv[2])))
'''
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("HEPTA_") and key != "PYTHONPATH"}
        environment["PATH"] = ""
        def invoke(root, output):
            args = ["build", str(source), "--backend", "selfhost", "--selfhost-manifest",
                    str(self.manifest), "--selfhost-manifest-sha256", self.pin, "-o", str(output)]
            return subprocess.run([sys.executable, "-I", "-S", "-B", "-c", child,
                                   str(root), json.dumps(args)], cwd=self.root,
                                  env=environment, capture_output=True, text=True, timeout=30)
        current = invoke(ROOT, self.root / "cli.o")
        self.assertEqual(current.returncode, 0, (current.stdout, current.stderr))
        self.assertEqual(json.loads(current.stdout)["profile"], native.PROFILE)
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        resources = (tuple("docs/" + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES
        package = self.root / "package"
        package.mkdir()
        shutil.copytree(ROOT / "hepta", package / "hepta", ignore=shutil.ignore_patterns("__pycache__"))
        for name in (*resources, "setup.py", "pyproject.toml", "MANIFEST.in"):
            target = package / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        wheels, installed = self.root / "wheels", self.root / "installed"
        steps = [
            [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheels), str(package)],
        ]
        for command in steps:
            result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        wheel, = wheels.glob("*.whl")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
            "--target", str(installed), str(wheel)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        for name in native.SOURCE_FILES:
            self.assertEqual((installed / "hepta/_data" / name).read_bytes(), (ROOT / name).read_bytes())
        observed = invoke(installed, self.root / "installed.o")
        self.assertEqual(observed.returncode, 0, (observed.stdout, observed.stderr))
        self.assertEqual((self.root / "installed.o").read_bytes(), (self.root / "cli.o").read_bytes())
        (installed / "hepta/_data" / native.SOURCE_FILES[2]).write_bytes(b"changed installed packer")
        refused = invoke(installed, self.root / "changed-installed.o")
        self.assertEqual(refused.returncode, 2, (refused.stdout, refused.stderr))
        self.assertFalse((self.root / "changed-installed.o").exists())


if __name__ == "__main__":
    unittest.main()
