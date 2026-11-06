"""Boundary and no-fallback tests for the configured-kernel compiler wrapper.

These are deterministic unit tests for routing, receipts and failure handling.
Native instruction semantics are tested separately by semantic_mutations.py.
Run from the checkout root:
  python3 -m unittest discover -s tools/hia_system/tests -p test_wrapper.py -v
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_system as hia


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class ClassificationTests(unittest.TestCase):
    def test_pinned_kbuild_c_and_dependency_command(self):
        argv = ["-Wp,-MMD,drivers/.sample.o.d", "-nostdinc", "-I/source/include",
                "-D__KERNEL__", "-std=gnu11", "-O2", "-c", "-o",
                "drivers/sample.o", "/source/drivers/sample.c"]
        result = hia.classify(argv)
        self.assertEqual(result["kind"], "target_c")
        self.assertEqual(result["dependency"], "drivers/.sample.o.d")
        self.assertTrue(result["dependency_requested"])

    def test_pinned_kbuild_assembly_command(self):
        result = hia.classify(["-D__ASSEMBLY__", "-c", "-o",
                               "arch/x86/entry/entry_64.o", "/source/entry_64.S"])
        self.assertEqual(result["kind"], "target_assembly")
        self.assertEqual(result["language"], "assembler-with-cpp")

    def test_kbuild_cc_option_and_as_instr_probes(self):
        samples = [
            ["-Werror", "-O2", "-c", "-x", "c", "/dev/null", "-o", ".tmp_31761/tmp"],
            ["-Werror", "-Wa,--fatal-warnings", "-c", "-x", "assembler-with-cpp",
             "-o", ".tmp_42/tmp", "-"],
        ]
        for argv in samples:
            with self.subTest(argv=argv):
                result = hia.classify(argv)
                self.assertEqual(result["kind"], "compiler_capability_probe")
                self.assertEqual(result["probe"]["output_boundary"], "kbuild-try-run-temporary")

    def test_version_stdin_preprocessing_is_explicit_probe(self):
        result = hia.classify(["-E", "-P", "-x", "c", "-"])
        self.assertEqual(result["kind"], "compiler_capability_probe")
        self.assertEqual(result["probe"]["output_boundary"], "stdout")
        self.assertFalse(result["probe"]["force_discard_output"])

    def test_implicit_stdin_output_is_forced_to_discard(self):
        result = hia.classify(["-c", "-xc", "-"])
        self.assertTrue(result["probe"]["force_discard_output"])

    def test_temporary_name_alone_does_not_make_target_a_probe(self):
        result = hia.classify(["-c", "-o", ".tmp_42/tmp", "real.c"])
        self.assertEqual(result["kind"], "target_c")
        with self.assertRaises(hia.SystemCompileError):
            hia.classify(["-c", "-xc", "-", "-o", "/tmp/probe.o"])
        with self.assertRaises(hia.SystemCompileError):
            hia.classify(["-c", "-xc", "-", "-o", ".tmp_not_a_pid/tmp"])

    def test_devnull_with_real_target_cannot_bypass_hia(self):
        for language, kind in [("c", "target_c"), ("assembler", "target_assembly")]:
            with self.subTest(language=language):
                result = hia.classify(["-c", "-x", language, "/dev/null",
                                       "-o", "kernel/real.o"])
                self.assertEqual(result["kind"], kind)

    def test_unknown_extension_with_explicit_language_is_payload(self):
        result = hia.classify(["-c", "-xc", "/source/payload.blob", "-o", "payload.o"])
        self.assertEqual(result["inputs"], ["/source/payload.blob"])
        self.assertEqual(result["kind"], "target_c")

    def test_unknown_extension_and_incoming_ir_fail_closed(self):
        for argv in [
            ["-c", "payload.blob", "-o", "payload.o"],
            ["payload.blob", "-o", "linked"],
            ["-c", "incoming.bc", "-o", "payload.o"],
            ["-c", "incoming.ll", "-o", "payload.o"],
            ["payload.c", "-o", "linked"],
            ["-c", "-xc", "-", "-o", "kernel/real.o"],
            ["-c", "one.c", "two.c", "-o", "both.o"],
            ["-c", "host.cpp", "-o", "host.o"],
            ["-c", "source.c", "-o", "/dev/null"],
        ]:
            with self.subTest(argv=argv), self.assertRaises(hia.SystemCompileError):
                hia.classify(argv)

    def test_x_language_applies_at_each_input_not_to_previous_inputs(self):
        result = hia.classify(["-x", "c", "payload.unknown", "-x", "none",
                               "-c", "-o", "payload.o"])
        self.assertEqual(result["language"], "c")
        result = hia.classify(["-xc", "opaque.o", "-c", "-o", "real.o"])
        self.assertEqual(result["kind"], "target_c")

    def test_only_object_inputs_have_object_link_route(self):
        self.assertEqual(hia.classify(["a.o", "lib.a", "-o", "linked"])["kind"], "object_link")
        with self.assertRaises(hia.SystemCompileError):
            hia.classify(["a.o", "not_known.input", "-o", "linked"])

    def test_queries_are_explicit_and_empty_payload_is_rejected(self):
        self.assertEqual(hia.classify(["-print-file-name=include"])["kind"], "compiler_query")
        self.assertEqual(hia.classify(["--version"])["kind"], "compiler_query")
        for argv in [[], ["-unknown"], ["-c", "-o", "missing.o"]]:
            with self.subTest(argv=argv), self.assertRaises(hia.SystemCompileError):
                hia.classify(argv)

    def test_preprocessor_and_dependency_scan_routes(self):
        self.assertEqual(hia.classify(["-E", "layout.S", "-o", "layout.lds"])["kind"],
                         "preprocess")
        self.assertEqual(hia.classify(["-M", "file.c"])["kind"], "dependency_scan")

    def test_output_options_are_not_confused_with_o_prefix_options(self):
        argv = ["-opt-record-file", "remarks.yaml", "-object-file-name=debug.o",
                "-object-file-name", "other-debug.o", "-objcmt-migrate-literals",
                "-c", "file.c", "--output=result.o"]
        result = hia.classify(argv)
        self.assertEqual(result["output"], "result.o")
        self.assertEqual(result["inputs"], ["file.c"])
        phase = hia.change_phase(argv, "/source/file.c", "/stage/frontend.bc", "-c")
        self.assertIn("-opt-record-file", phase)
        self.assertIn("remarks.yaml", phase)
        self.assertIn("-object-file-name=debug.o", phase)

    def test_duplicate_output_and_dependency_keys_are_rejected(self):
        for argv in [
            ["-c", "file.c", "-o", "a.o", "-ob.o"],
            ["-c", "file.c", "-oa.o", "--output=b.o"],
            ["-c", "file.c", "-o", "a.o", "-MMD", "-MF", "a.d", "-MFb.d"],
            ["-c", "file.c", "-o", "a.o", "-Wp,-MMD,a.d", "-MF", "b.d"],
            ["-c", "file.c", "-o", "a.o", "-Wp,-MMD"],
            ["-c", "file.c", "-o", "a.o", "-Xclang", "-emit-obj"],
        ]:
            with self.subTest(argv=argv), self.assertRaises(hia.SystemCompileError):
                hia.classify(argv)


class PhaseTests(unittest.TestCase):
    def test_backend_optimization_enum_is_closed_and_defaults_to_original(self):
        self.assertEqual(hia.backend_optimization({}), "original")
        for policy in ("original", "O2", "O3", "Os"):
            self.assertEqual(hia.backend_optimization({"backend_optimization": policy}), policy)
        for policy in ("Ofast", "O0", "", None, 3):
            with self.subTest(policy=policy), self.assertRaises(hia.SystemCompileError):
                hia.backend_optimization({"backend_optimization": policy})

    def test_frontend_keeps_source_semantics_and_binds_original_dependency_target(self):
        argv = ["-O2", "-std=gnu11", "-D__KERNEL__", "-I/source/include",
                "-mcmodel=kernel", "-Wp,-MMD,kernel/.a.o.d", "-c",
                "/source/a.c", "-o", "kernel/a.o"]
        phase = hia.change_phase(argv, "/source/a.c", "/ledger/frontend.bc", "-c",
                                 dependency_output="/ledger/frontend.d")
        self.assertIn("-O2", phase)
        self.assertIn("-std=gnu11", phase)
        self.assertIn("-D__KERNEL__", phase)
        self.assertIn("-mcmodel=kernel", phase)
        self.assertNotIn("-Wp,-MMD,kernel/.a.o.d", phase)
        self.assertEqual(phase[phase.index("-MF") + 1], "/ledger/frontend.d")
        self.assertEqual(phase[phase.index("-MQ") + 1], "kernel/a.o")
        self.assertEqual(phase[-4:], ["-c", "/source/a.c", "-o", "/ledger/frontend.bc"])

    def test_wp_md_and_explicit_targets_preserve_preprocessor_arguments(self):
        argv = ["-Wp,-MD,old.d,-DOTHER=1", "-MT", "first", "-MQ", "second target",
                "-c", "file.c", "-o", "object.o"]
        phase = hia.change_phase(argv, "file.c", "front.bc", "-c")
        self.assertIn("-Wp,-DOTHER=1", phase)
        self.assertIn("-MD", phase)
        self.assertEqual(phase[phase.index("-MF") + 1], "old.d")
        self.assertEqual(phase[phase.index("-MT") + 1], "first")
        self.assertEqual(phase[phase.index("-MQ") + 1], "second target")

    def test_default_md_filename_comes_from_original_output(self):
        result = hia.classify(["-MD", "-c", "file.c", "-o", "kernel/file.o"])
        self.assertEqual(result["dependency"], "kernel/file.d")

    def test_backend_has_only_reconstructed_input_and_no_preprocessor_dependency_phase(self):
        argv = ["-O2", "-std=gnu11", "-I/source/include", "-DNAME=1", "-include", "config.h",
                "-Wp,-MMD,a.d", "-c", "-xc", "no-extension", "-o", "a.o"]
        phase = hia.change_phase(argv, "/ledger/lowered.bc", "/build/a.o", "-c", backend=True)
        self.assertEqual(phase.count("/ledger/lowered.bc"), 1)
        self.assertNotIn("no-extension", phase)
        self.assertNotIn("-std=gnu11", phase)
        self.assertNotIn("-DNAME=1", phase)
        self.assertNotIn("config.h", phase)
        self.assertFalse(any(item.startswith("-Wp,") for item in phase))
        self.assertNotIn("-MF", phase)
        self.assertNotIn("-disable-llvm-passes", phase)
        self.assertIn("-O2", phase)
        self.assertEqual(phase[phase.index("-x") + 1], "ir")

    def test_preprocessed_c_language_is_preserved(self):
        phase = hia.change_phase(["-c", "file.i", "-o", "file.o"], "file.i", "front.bc", "-c")
        self.assertEqual(phase[phase.index("-x") + 1], "cpp-output")

    def test_assembler_backend_keeps_include_search_paths(self):
        phase = hia.change_phase(["-I", "data", "-D__ASSEMBLY__", "-Wa,--noexecstack",
                                  "-c", "start.S", "-o", "start.o"],
                                 "lowered.s", "start.o", "-c", backend=True, assembly=True)
        self.assertIn("-I", phase)
        self.assertIn("data", phase)
        self.assertIn("-Wa,--noexecstack", phase)
        self.assertNotIn("-D__ASSEMBLY__", phase)
        self.assertEqual(phase[phase.index("-x") + 1], "assembler")


class JsonAndAssemblyTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected_at_any_depth(self):
        for data in [b'{"mode":"import","mode":"replay"}',
                     b'{"module":{"inline_asm_hex":"","inline_asm_hex":"00"}}',
                     b'{"value":NaN}']:
            with self.subTest(data=data), self.assertRaises(hia.SystemCompileError):
                hia.strict_json(data)

    def test_assembly_roundtrip_is_byte_exact(self):
        for data in [b"", b"\n", b".text\r\n\tret\r\n",
                     b'.ascii "#not a comment"; .byte 0xff # comment\n',
                     b'1: nop; .Lx:\tret',
                     '.ascii "unicode \u03bb"\n'.encode()]:
            with self.subTest(data=data):
                self.assertEqual(hia.emit_assembly(hia.assembly_program(data)), data)

    def test_forged_assembly_token_or_statement_is_rejected(self):
        for field, value in [("kind", "empty"), ("extra", "ignored")]:
            program = hia.assembly_program(b".text\n")
            program["statements"][0][field] = value
            with self.subTest(field=field), self.assertRaises(hia.SystemCompileError):
                hia.emit_assembly(program)
        program = hia.assembly_program(b".text\n")
        program["statements"][0]["tokens"][0]["kind"] = "number"
        with self.assertRaises(hia.SystemCompileError):
            hia.emit_assembly(program)

    def test_only_actual_hia_assembly_fields_supply_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.bin").write_bytes(b"one")
            (root / "two.bin").write_bytes(b"two")
            program = {"schema": hia.SYSTEM_SCHEMA,
                       "module": {"inline_asm_hex": b'.incbin "one.bin"\n'.hex()},
                       "functions": [{"operands": [
                           {"kind": "inline_asm", "assembly_hex": b'.incbin "two.bin"\n'.hex(),
                            "constraints": '.incbin "must-not-be-read.bin"'}]}],
                       "metadata": ['.incbin "also-not-read.bin"'],
                       "arbitrary_string": '.include "not-an-assembly-field.s"'}
            result = hia.system_assembly_inputs(program, root)
            self.assertEqual({Path(item["path"]).name for item in result}, {"one.bin", "two.bin"})

    def test_assembly_dependency_lexer_handles_labels_comments_strings_and_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data").mkdir()
            (root / "data" / "payload#x.bin").write_bytes(b"\x00\xff")
            text = (b'# .include "missing.s"\n'
                    b'/* .incbin "missing.bin" */\n'
                    b'.ascii ".incbin \\"missing.bin\\""; label: .incbin "payload#x.bin", 0, 1\n'
                    b".byte '#'; .incbin \"payload#x.bin\"\n"
                    b'1: .incbin "payload#x.bin"\n')
            result = hia.external_assembly_inputs(text, root, ["-I", "data"])
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["sha256"], hashlib.sha256(b"\x00\xff").hexdigest())

    def test_dynamic_incbin_and_nested_include_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            for text in ['.include "child.s"\n', '.incbin \\name\n',
                         '.incbin "bad\\040name.bin"\n']:
                with self.subTest(text=text), self.assertRaises(hia.SystemCompileError):
                    hia.external_assembly_inputs(text, Path(tmp))


class ReplayBoundaryTests(unittest.TestCase):
    def test_dependency_sidecar_is_required_bound_and_restored_as_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sidecar = root / "deps.gz"
            original = b"/old/build/a.o: /old/build/generated.h source.c\n"
            sidecar.write_bytes(gzip.compress(original, mtime=0))
            meta = {"dependency": hia.binding(sidecar), "original_build_root": "/old/build"}
            classification = {"dependency_requested": True}
            restored = hia.replay_dependency(meta, classification, {"build_root": "/new/build"})
            self.assertEqual(restored, b"/new/build/a.o: /new/build/generated.h source.c\n")
            destination = root / "out" / "a.d"
            hia.restore_dependency(destination, restored)
            self.assertEqual(destination.read_bytes(), restored)
            with self.assertRaises(hia.SystemCompileError):
                hia.replay_dependency({"original_build_root": "/old/build"}, classification,
                                      {"build_root": "/new/build"})
            sidecar.write_bytes(b"changed")
            with self.assertRaises(hia.SystemCompileError):
                hia.replay_dependency(meta, classification, {"build_root": "/new/build"})

    def test_external_dependency_set_is_complete_and_content_bound(self):
        item = {"kind": "binary_data", "path": "/old/build/data.bin", "bytes": 3, "sha256": "a" * 64}
        meta = {"original_build_root": "/old/build", "external_inputs": [item]}
        current = [{**item, "path": "/new/build/data.bin"}]
        manifest = {"build_root": "/new/build"}
        hia.validate_replay_external_inputs(meta, current, manifest)
        for invalid in [[], [{**current[0], "sha256": "b" * 64}],
                        current + [{**current[0], "path": "/new/build/extra.bin"}]]:
            with self.subTest(invalid=invalid), self.assertRaises(hia.SystemCompileError):
                hia.validate_replay_external_inputs(meta, invalid, manifest)
        self.assertEqual(hia.relocated_path("/old/build-sibling/a", "/old/build", "/new/build"),
                         "/old/build-sibling/a")


class FakePhases:
    """Controlled compiler/codec responses for orchestration failure tests."""
    def __init__(self, target, *, fail=None, mismatched=False):
        self.target, self.fail, self.mismatched, self.calls = target, fail, mismatched, []

    def run(self, record, directory, name, argv, **kwargs):
        self.calls.append((name, list(map(str, argv))))
        record["commands"].append({"name": name, "argv": list(map(str, argv)), "exit_code": 0})
        if name == self.fail:
            record["commands"][-1]["exit_code"] = 9
            raise hia.SystemCompileError("injected phase failure")
        args = list(map(str, argv))
        if name == "clang-c-frontend-only":
            Path(args[args.index("-o") + 1]).write_bytes(b"original-bitcode")
            if "-MF" in args:
                dependency = Path(args[args.index("-MF") + 1])
                dependency.write_bytes((str(self.target) + ": original.c generated.h\n").encode())
        elif name == "encode-typed-hia":
            Path(args[-1]).write_bytes(hia.canonical(
                {"schema": hia.SYSTEM_SCHEMA, "module": {"inline_asm_hex": ""},
                 "functions": []}))
        elif name == "decode-hia-fresh-module":
            Path(args[-1]).write_bytes(b"reconstructed-bitcode")
        elif name == "hia-native-codegen":
            self.target.parent.mkdir(parents=True, exist_ok=True)
            self.target.write_bytes(b"unit-test-object-not-native-validation")
        return record["commands"][-1]

    def canonical(self, llvm_dis, bitcode, output, record, directory, stage):
        output.write_bytes(b"; ModuleID = 'staged'\ndefine void @f() { ret void }\n")
        return ("b" if self.mismatched and stage == "inspect-reconstructed-ir" else "a") * 64


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.build, self.source = self.root / "build", self.root / "source"
        self.build.mkdir()
        self.source.mkdir()
        self.cfile = self.source / "test.c"
        self.cfile.write_text("void f(void) {}\n")
        self.target = self.build / "kernel" / "test.o"
        self.target.parent.mkdir()
        self.dep = self.build / "kernel" / ".test.o.d"
        self.manifest = {
            "mode": "import", "source_commit": "test-commit",
            "source_root": str(self.source), "build_root": str(self.build),
            "program_root": str(self.root / "programs"), "ledger_root": str(self.root / "ledger"),
            "tools": {name: {"path": "/bound/" + name}
                      for name in ("clang", "clangxx", "codec", "llvm_dis")}}
        Path(self.manifest["ledger_root"]).mkdir()
        self.argv = ["-O2", "-Wp,-MMD," + str(self.dep),
                     "-c", str(self.cfile), "-o", str(self.target)]
        self.classification = hia.classify(self.argv)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, identity, phases, *, manifest=None):
        directory = Path(self.manifest["ledger_root"]) / identity
        directory.mkdir()
        (directory / "keep.stdout").write_bytes(b"log")
        record = {"id": identity, "classification": self.classification, "commands": [],
                  "cwd": str(self.build), "argv": self.argv}
        with working_directory(self.build), patch.object(hia, "run_command", phases.run), \
                patch.object(hia, "canonical_ir", phases.canonical):
            hia.compile_payload(self.argv, self.classification, manifest or self.manifest,
                                record, directory)
        return record, directory

    def test_success_prunes_only_regenerable_intermediates_and_replay_uses_no_frontend(self):
        phases = FakePhases(self.target)
        record, directory = self.invoke("import", phases)
        self.assertTrue(record["canonical_roundtrip_equal"])
        self.assertFalse(record["fallback_c_compilation"])
        self.assertTrue(self.dep.is_file())
        self.assertTrue(Path(record["retained_program"]["path"]).is_file())
        self.assertTrue(Path(record["retained_dependency"]["path"]).is_file())
        self.assertTrue((directory / "keep.stdout").is_file())
        self.assertGreaterEqual(len(record["pruned_intermediates"]), 5)
        for item in record["pruned_intermediates"]:
            self.assertFalse(Path(item["path"]).exists())
            self.assertEqual(len(item["sha256"]), 64)
            self.assertEqual(item["retained_program"], record["retained_program"])
        expected_dependencies = self.dep.read_bytes()
        self.dep.unlink()
        replay = FakePhases(self.target)
        replay_record, _ = self.invoke("replay", replay,
                                     manifest={**self.manifest, "mode": "replay"})
        self.assertEqual(self.dep.read_bytes(), expected_dependencies)
        self.assertEqual([name for name, _ in replay.calls],
                         ["decode-hia-fresh-module", "hia-native-codegen"])
        self.assertEqual(replay_record["dependency_output"]["sha256"], hia.sha(self.dep))

    def test_explicit_optimization_changes_only_c_backend_and_binds_replay_variant(self):
        phases = FakePhases(self.target)
        record, _ = self.invoke("O3-import", phases,
                               manifest={**self.manifest, "backend_optimization": "O3"})
        frontend = next(argv for name, argv in phases.calls if name == "clang-c-frontend-only")
        backend = next(argv for name, argv in phases.calls if name == "hia-native-codegen")
        self.assertIn("-O2", frontend)
        self.assertNotIn("-O3", frontend)
        self.assertEqual(backend[-1], "-O3")
        self.assertEqual(record["backend_optimization"], "O3")
        index = hia.strict_json(Path(record["program_index"]["path"]).read_bytes())
        self.assertEqual(index["backend_optimization"], "O3")
        wrong = FakePhases(self.target)
        with self.assertRaises(hia.SystemCompileError):
            self.invoke("wrong-policy-replay", wrong,
                        manifest={**self.manifest, "mode": "replay"})
        self.assertEqual(wrong.calls, [])

    def test_explicit_optimization_does_not_modify_machine_assembly(self):
        assembly = self.source / "raw.s"
        assembly.write_text(".text\\nret\\n".replace("\\n", "\n"))
        self.argv = ["-c", str(assembly), "-o", str(self.target)]
        self.classification = hia.classify(self.argv)
        phases = FakePhases(self.target)
        record, _ = self.invoke("asm-Os", phases,
                               manifest={**self.manifest, "backend_optimization": "Os"})
        backend = next(argv for name, argv in phases.calls if name == "hia-native-codegen")
        self.assertNotIn("-Os", backend)
        self.assertEqual(record["backend_optimization"], "original")
        self.assertEqual(record["requested_backend_optimization"], "Os")

    def test_missing_replay_never_invokes_frontend_or_codegen(self):
        phases = FakePhases(self.target)
        with self.assertRaises(hia.SystemCompileError):
            self.invoke("missing", phases, manifest={**self.manifest, "mode": "replay"})
        self.assertEqual(phases.calls, [])

    def test_roundtrip_failure_has_no_codegen_and_keeps_failure_artifacts(self):
        phases = FakePhases(self.target, mismatched=True)
        with self.assertRaises(hia.SystemCompileError):
            self.invoke("mismatch", phases)
        self.assertNotIn("hia-native-codegen", [name for name, _ in phases.calls])
        directory = Path(self.manifest["ledger_root"]) / "mismatch"
        for name in ("frontend.bc", "program.hia.json", "lowered.bc", "frontend.d"):
            self.assertTrue((directory / name).is_file(), name)
        self.assertFalse(self.target.exists())

    def test_codec_failure_has_no_native_fallback(self):
        phases = FakePhases(self.target, fail="decode-hia-fresh-module")
        with self.assertRaises(hia.SystemCompileError):
            self.invoke("decode-failure", phases)
        self.assertEqual([name for name, _ in phases.calls],
                         ["clang-c-frontend-only", "encode-typed-hia", "decode-hia-fresh-module"])
        self.assertTrue((Path(self.manifest["ledger_root"]) / "decode-failure" / "frontend.bc").exists())
        self.assertFalse(self.target.exists())

    def test_backend_failure_keeps_all_staging_inputs(self):
        self.target.write_bytes(b"stale original object must not be reused")
        phases = FakePhases(self.target, fail="hia-native-codegen")
        with self.assertRaises(hia.SystemCompileError):
            self.invoke("backend-failure", phases)
        directory = Path(self.manifest["ledger_root"]) / "backend-failure"
        self.assertTrue((directory / "program.hia.json").is_file())
        self.assertTrue((directory / "lowered.bc").is_file())
        self.assertTrue((directory / "frontend.d").is_file())
        self.assertFalse(self.target.exists())

    def test_corrupt_program_and_missing_dependencies_reject_replay(self):
        record, _ = self.invoke("import-for-corruption", FakePhases(self.target))
        index = Path(record["program_index"]["path"])
        original_meta = hia.strict_json(index.read_bytes())
        meta = copy.deepcopy(original_meta)
        del meta["dependency"]
        index.write_bytes(hia.canonical(meta))
        replay = FakePhases(self.target)
        with self.assertRaises(hia.SystemCompileError):
            self.invoke("missing-sidecar", replay, manifest={**self.manifest, "mode": "replay"})
        self.assertEqual(replay.calls, [])
        index.write_bytes(hia.canonical(original_meta))
        Path(original_meta["program"]["path"]).write_bytes(b"corrupt gzip program")
        replay = FakePhases(self.target)
        with self.assertRaises(hia.SystemCompileError):
            self.invoke("corrupt-program", replay, manifest={**self.manifest, "mode": "replay"})
        self.assertEqual(replay.calls, [])

    def test_probe_nonzero_exit_is_recorded_without_payload_failure(self):
        self.manifest["backend_optimization"] = "Os"
        manifest_path = self.root / "manifest.json"
        manifest_path.write_bytes(b"{}")
        captured = []

        def command(record, directory, name, argv, **kwargs):
            captured.append((argv, kwargs.get("input_bytes")))
            item = {"name": name, "argv": argv, "exit_code": 17}
            record["commands"].append(item)
            return item

        stdin = type("Input", (), {"buffer": io.BytesIO(b"int probe;\n")})()
        with patch.object(hia, "load_manifest", return_value=(manifest_path, self.manifest)), \
                patch.object(hia, "run_command", command), patch.object(hia.sys, "stdin", stdin):
            code = hia.main(["-c", "-xc", "-"])
        self.assertEqual(code, 17)
        self.assertEqual(captured[0][0][-2:], ["-o", "/dev/null"])
        self.assertNotIn("-Os", captured[0][0])
        self.assertEqual(captured[0][1], b"int probe;\n")
        receipts = list(Path(self.manifest["ledger_root"]).glob("*/RESULT.json"))
        result = hia.strict_json(receipts[0].read_bytes())
        self.assertEqual(result["status"], "COMPILER_REJECTED")
        self.assertFalse(result["payload_failure"])
        self.assertEqual(result["classification"]["kind"], "compiler_capability_probe")

    def test_host_cpp_is_explicitly_logged_and_original_argv_is_forwarded(self):
        self.manifest["backend_optimization"] = "O3"
        manifest_path = self.root / "manifest.json"
        manifest_path.write_bytes(b"{}")
        source = self.source / "host.cpp"
        source.write_text("int main() { return 0; }\n")
        output = self.build / "host-tool"
        argv = ["-O2", str(source), "-o", str(output)]
        seen = []

        def command(record, directory, name, command, **kwargs):
            seen.append(command)
            output.write_bytes(b"host object")
            item = {"name": name, "argv": command, "exit_code": 0}
            record["commands"].append(item)
            return item

        with patch.object(hia, "load_manifest", return_value=(manifest_path, self.manifest)), \
                patch.object(hia, "run_command", command):
            code = hia.host_main("clangxx", argv)
        self.assertEqual(code, 0)
        self.assertEqual(seen, [["/bound/clangxx", "--driver-mode=g++", *argv]])
        result = hia.strict_json(next(Path(self.manifest["ledger_root"]).glob("*/RESULT.json")).read_bytes())
        self.assertEqual(result["role"], "host_tool")
        self.assertEqual(result["host_toolchain"], "clangxx")
        self.assertEqual(result["host_driver_mode"], "g++")
        self.assertEqual(result["backend_optimization"], "original")
        self.assertEqual(result["requested_backend_optimization"], "O3")
        self.assertEqual(result["classification"]["kind"], "host_tool")
        self.assertEqual(result["compiler_output"], hia.binding(output))
        self.assertNotIn("retained_program", result)


if __name__ == "__main__":
    unittest.main()
