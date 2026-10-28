"""Original parameter types must not lose VLA evaluation during migration."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hepta import c_parameter_types as parameter_types
from hepta.c_migrate import migrate_c_project
from hepta.clang_capture import CaptureResult, run_bounded


class OriginalParameterTypeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-original-parameter-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clang = shutil.which("clang")
        self.assertIsNotNone(self.clang, "Clang is required for original parameter type admission")
        self.contracts = {"schema": "hepta.c-contracts.v1", "functions": {
            "probe": {"slices": {"data": {"length": "n", "access": "read"}}}}}

    def project(self, source, name="input.c"):
        (self.root / name).write_text(source)
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(self.root), "file": name,
            "arguments": ["clang", "-std=c11", "-O0", "-c", name, "-o", "input.o"]}]))
        return database

    def migrate(self, database, output, **kwargs):
        return migrate_c_project(database, output, contracts=self.contracts,
                                 clang=self.clang, rustc=os.environ.get("RUSTC"), **kwargs)

    def original_result(self, name, *, flags=()):
        artifact = self.root / (name + ".so")
        command = [self.clang, "-std=c11", "-O0", *flags,
                   "-shared", "-fPIC", "input.c", "-o", str(artifact)]
        compiled = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        return self.call(artifact)

    def call(self, artifact):
        library = ctypes.CDLL(str(artifact))
        library.probe.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
        library.probe.restype = ctypes.c_uint
        data = (ctypes.c_uint * 8)(*range(8))
        return int(library.probe(7, data))

    def test_vla_entry_effects_reject_including_pragma_macro_and_typeof(self):
        sources = (
            ("plain", "", "const unsigned int data[++n]", ()),
            ("pragma", '#pragma clang diagnostic ignored "-Wvla"\n',
             "const unsigned int data[++n]", ("-Werror=vla",)),
            ("macro", "#define EXTENT (++n)\n", "const unsigned int data[EXTENT]", ()),
            ("typeof", "", "__typeof__(const unsigned int[++n]) data", ()),
        )
        for name, prefix, parameter, flags in sources:
            with self.subTest(form=name):
                database = self.project(prefix + "unsigned int probe(unsigned int n, "
                                        + parameter + ") { return n; }\n")
                self.assertEqual(self.original_result(name, flags=flags), 8)
                output = self.root / (name + "-converted")
                report = self.migrate(database, output)
                self.assertFalse(report["ok"], report)
                self.assertFalse(output.exists())
                if name == "typeof":
                    # The inherited physical spelling gate refuses computed
                    # type syntax before any independent type probe can admit it.
                    self.assertIn("E_C_PARAMETER_DECLARATOR", [x["code"] for x in report["diagnostics"]], report)
                    continue
                self.assertIn("E_C_VLA_PARAMETER", [x["code"] for x in report["diagnostics"]], report)
                receipt = report["source_type_admission"][0]
                self.assertEqual(receipt["capture_sha256"], report["build"]["sha256"])
                self.assertEqual(receipt["functions"][0]["parameters"][1]["state"], "variable")
                self.assertEqual(receipt["reader"]["version"], report["build"]["compiler"]["version"])

    def test_fixed_array_and_pointer_parameters_preserve_native_results(self):
        for index, parameter in enumerate(("const unsigned int *data",
                                           "const unsigned int data[8]",
                                           "const unsigned int data[]")):
            with self.subTest(parameter=parameter):
                database = self.project("unsigned int probe(unsigned int n, "
                                        + parameter + ") { return n + data[0]; }\n")
                original = self.original_result("fixed-" + str(index))
                output = self.root / ("fixed-" + str(index))
                report = self.migrate(database, output, verify_native=True)
                self.assertTrue(report["ok"], report)
                self.assertEqual(original, 7)
                self.assertEqual(self.call(output / "libtranslated.so"), original)
                receipt = report["source_type_admission"][0]
                self.assertEqual(receipt["cwd"], str(self.root))
                self.assertIn("input.c", receipt["argv"])
                self.assertEqual(receipt["functions"][0]["parameters"][1]["state"], "fixed")
                self.assertRegex(receipt["reader"]["sha256"], r"^[a-f0-9]{64}$")
                self.assertRegex(receipt["serialized_ast"]["sha256"], r"^[a-f0-9]{64}$")
                self.assertEqual(receipt["schema"], "hepta.c-original-parameter-types.v2")
                self.assertEqual(receipt["functions"][0]["result"]["shape"]["kind"], "UInt")
                original = receipt["functions"][0]["parameters"][1]
                self.assertEqual(original["shape"]["kind"], ("Pointer", "ConstantArray", "IncompleteArray")[index])
                binding = original["binding"]
                self.assertEqual(binding["file"], str(self.root / "input.c"))
                self.assertLess(binding["begin"]["offset"], binding["offset"])
                self.assertGreater(binding["end"]["offset"], binding["offset"])

    def test_symlink_temporary_root_preserves_fixed_and_vla_type_admission(self):
        physical = self.root / "physical temporary root"
        physical.mkdir()
        alias = self.root / "temporary root alias"
        alias.symlink_to(physical, target_is_directory=True)

        def linked_temporary_directory(*args, **kwargs):
            return tempfile.TemporaryDirectory(*args, dir=alias, **kwargs)

        for name, extent, expected_kind in (("fixed", "8", "ConstantArray"),
                                             ("vla", "++n", "VariableArray")):
            with self.subTest(shape=name):
                database = self.project(
                    "unsigned int probe(unsigned int n, const unsigned int data[" + extent
                    + "]) { return n; }\n")
                observed = []

                def observe(argv, **kwargs):
                    result = run_bounded(argv, **kwargs)
                    if argv[-1] == "--worker" and result.returncode == 0:
                        observed.append((json.loads(kwargs["input_text"]), json.loads(result.stdout)))
                    return result

                destination = self.root / ("linked-" + name)
                with patch.object(parameter_types, "tempfile", SimpleNamespace(
                        TemporaryDirectory=linked_temporary_directory)), \
                        patch("hepta.clang_capture.run_bounded", side_effect=observe):
                    report = self.migrate(database, destination, verify_native=False)
                if name == "fixed":
                    self.assertTrue(report["ok"], report["diagnostics"])
                else:
                    self.assertFalse(report["ok"], report)
                    self.assertFalse(destination.exists())
                    self.assertIn("E_C_VLA_PARAMETER", [row["code"] for row in report["diagnostics"]],
                                  report["diagnostics"])
                self.assertEqual(len(observed), 1)
                request, receipt = observed[0]
                self.assertEqual(request["argv"][-1], request["serialized_ast"]["path"])
                self.assertEqual(Path(request["argv"][-1]).parents[1], physical.resolve(strict=True))
                self.assertEqual(request["argv"][-3], "input.c")
                self.assertEqual(receipt["argv"], request["argv"])
                self.assertEqual(receipt["serialized_ast"], request["serialized_ast"])
                self.assertEqual(receipt["limits"], parameter_types._limits())
                original = receipt["functions"][0]["parameters"][1]
                self.assertEqual(original["shape"]["kind"], expected_kind)
                if name == "fixed":
                    self.assertEqual(original["shape"]["extent"], 8)
                else:
                    self.assertEqual(original["state"], "variable")

    def test_record_view_rewrite_cannot_hide_original_vla_parameter(self):
        database = self.project(
            "struct State { unsigned int *data; unsigned int length; };\n"
            "unsigned int probe(unsigned int n, const struct State ctx[++n]) { return n; }\n")
        contracts = {"schema": "hepta.c-record-views.v1",
            "records": {"State": {"buffers": {"data": {"length_field": "length", "add": 0}}}},
            "functions": {"probe": {"slices": {}, "records": {"ctx": {"access": "read"}}}}}
        output = self.root / "record-vla"
        report = migrate_c_project(database, output, contracts=contracts, clang=self.clang)
        self.assertFalse(report["ok"], report)
        self.assertFalse(output.exists())
        self.assertIn("E_C_VLA_PARAMETER", [x["code"] for x in report["diagnostics"]], report)
        self.assertEqual(report["source_type_admission"][0]["functions"][0]
                         ["parameters"][1]["state"], "variable")

    def test_probe_preserves_lexical_source_operand_and_header_binding(self):
        (self.root / "extent.h").write_text("#define EXTENT 8\n")
        source = ('#include "extent.h"\n'
                  'unsigned int probe(unsigned int n, const unsigned int data[EXTENT]) {\n'
                  '#if __has_include(__FILE__)\nreturn n + data[0];\n'
                  '#else\nreturn n + 2u;\n#endif\n}\n')
        self.project(source, "source.c")
        (self.root / "alias.c").symlink_to("source.c")
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(self.root), "file": "alias.c",
            "arguments": ["clang", "-std=c11", "-O0", "-c", "alias.c", "-o", "input.o"]}]))
        report = self.migrate(database, self.root / "alias-converted", verify_native=True)
        self.assertTrue(report["ok"], report)
        receipt = report["source_type_admission"][0]
        self.assertEqual(receipt["argv"][-3], "alias.c")
        self.assertEqual(receipt["cwd"], str(self.root))
        self.assertEqual(self.call(self.root / "alias-converted/libtranslated.so"), 7)
        self.assertEqual(receipt["functions"][0]["declaration"]["file"], str(self.root / "source.c"))

    def test_changed_dependency_after_probe_rejects_without_publication(self):
        header = self.root / "extent.h"
        header.write_text("#define EXTENT 8\n")
        database = self.project('#include "extent.h"\n'
            'unsigned int probe(unsigned int n, const unsigned int data[EXTENT]) { return n; }\n')

        def changed(argv, **kwargs):
            result = run_bounded(argv, **kwargs)
            if argv[-1] == "--worker":
                header.write_text("#define EXTENT 9\n")
            return result

        output = self.root / "changed"
        with patch("hepta.clang_capture.run_bounded", side_effect=changed):
            report = self.migrate(database, output)
        self.assertFalse(report["ok"], report)
        self.assertFalse(output.exists())
        self.assertIn("E_C_BUILD_CHANGED", [x["code"] for x in report["diagnostics"]], report)

    def test_incomplete_or_mismatched_probe_receipt_rejects(self):
        database = self.project("unsigned int probe(unsigned int n, const unsigned int *data) { return n; }\n")
        for mutation in ("missing", "duplicate", "command", "limits", "serialized_ast", "unknown_type"):
            with self.subTest(mutation=mutation):
                def altered(argv, **kwargs):
                    result = run_bounded(argv, **kwargs)
                    if argv[-1] != "--worker" or result.returncode:
                        return result
                    value = json.loads(result.stdout)
                    if mutation == "missing":
                        value["functions"] = []
                    elif mutation == "duplicate":
                        value["functions"] *= 2
                    elif mutation == "command":
                        value["argv"][-3] = str(self.root / "input.c")
                    elif mutation == "limits":
                        value["limits"]["compiler_seconds"] = 34
                    elif mutation == "serialized_ast":
                        value["serialized_ast"]["sha256"] = "0" * 64
                    else:
                        value["functions"][0]["parameters"][1]["state"] = "unmodeled"
                    return CaptureResult(result.returncode, json.dumps(value), result.stderr)

                output = self.root / ("forged-" + mutation)
                with patch("hepta.clang_capture.run_bounded", side_effect=altered):
                    report = self.migrate(database, output)
                self.assertFalse(report["ok"], report)
                self.assertFalse(output.exists())
                self.assertIn("E_C_ORIGINAL_TYPE", [x["code"] for x in report["diagnostics"]], report)
                if mutation in {"command", "limits", "serialized_ast"}:
                    failure = next(row for row in report["diagnostics"] if row["code"] == "E_C_ORIGINAL_TYPE")
                    details = json.loads(failure["message"].split(
                        "original-type AST command/budget identity mismatch: ", 1)[1])
                    for field in ("serialized_ast", "argv", "limits"):
                        changed = field == {"command": "argv", "limits": "limits",
                                            "serialized_ast": "serialized_ast"}[mutation]
                        self.assertIs(details["matches"][field], not changed)
                        for side in ("expected", "actual"):
                            preview = details[side][field]
                            self.assertLessEqual(len(preview["json_prefix"]), 4096)
                            self.assertIs(preview["truncated"], False)
                            json.loads(preview["json_prefix"])

    def test_failed_emission_retains_returncode_missing_ast_and_both_streams(self):
        database = self.project("unsigned int probe(unsigned int n, const unsigned int data[8]) { return n; }\n")

        def refused(argv, **kwargs):
            if argv[-1] == "--emit-ast":
                return CaptureResult(23, "compiler stdout marker", "")
            return run_bounded(argv, **kwargs)

        destination = self.root / "failed-emission"
        with patch("hepta.clang_capture.run_bounded", side_effect=refused):
            report = self.migrate(database, destination)
        self.assertFalse(report["ok"], report)
        self.assertFalse(destination.exists())
        failure = next(row for row in report["diagnostics"] if row["code"] == "E_C_ORIGINAL_TYPE")
        details = json.loads(failure["message"].split("serialized AST emission failed: ", 1)[1])
        self.assertEqual(details["returncode"], 23)
        self.assertIs(details["ast_present"], False)
        self.assertIs(details["ast_regular_file"], False)
        self.assertIsNone(details["ast_bytes"])
        self.assertEqual(details["stdout_tail"], "compiler stdout marker")
        self.assertEqual(details["stderr_tail"], "")
        self.assertEqual(details["stdout_characters"], len("compiler stdout marker"))
        self.assertEqual(details["stderr_characters"], 0)
        self.assertEqual(details["ast_byte_limit"], parameter_types.MAX_AST_BYTES)
        self.assertEqual(details["argv"][0], str(Path(self.clang).resolve()))
        self.assertEqual(details["argv"][-5:],
                         ["-Werror", "-emit-ast", "input.c", "-o", details["ast_path"]])
        self.assertEqual(details["argv_count"], len(details["argv"]))
        self.assertIs(details["argv_truncated"], False)

    def test_scalar_only_functions_and_all_result_types_are_captured(self):
        database = self.project("typedef unsigned int Word;\n"
            "Word scalar(Word n) { return n; }\nvoid done(void) { return; }\n"
            "struct Pair { unsigned int n; };\n"
            "struct Pair keep(struct Pair p) { return p; }\n")
        report = migrate_c_project(database, self.root / "scalar-types", clang=self.clang)
        self.assertTrue(report["ok"], report)
        functions = {row["declaration"]["name"]: row for row in report["source_type_admission"][0]["functions"]}
        self.assertEqual(set(functions), {"scalar", "done", "keep"})
        self.assertEqual({name: row["result"]["shape"]["kind"] for name, row in functions.items()},
                         {"scalar": "UInt", "done": "Void", "keep": "Record"})
        self.assertEqual(functions["scalar"]["result"]["spelling"], "Word")
        self.assertEqual(functions["scalar"]["parameters"][0]["spelling"], "Word")

    def test_physical_parameter_return_shape_and_tool_identity_are_bound(self):
        database = self.project("unsigned int probe(unsigned int n, const unsigned int data[8]) { return n; }\n")
        def changed_parameter(value):
            return value["functions"][0]["parameters"][1]
        mutations = {
            "file": lambda v: changed_parameter(v)["binding"].update(file=str(self.root / "other.h")),
            "offset": lambda v: changed_parameter(v)["binding"].update(offset=1),
            "range_bool": lambda v: changed_parameter(v)["binding"]["begin"].update(offset=True),
            "parameter_name": lambda v: changed_parameter(v).update(name="different"),
            "result_type": lambda v: v["functions"][0]["result"].update(spelling="int"),
            "result_shape": lambda v: v["functions"][0]["result"]["shape"].update(kind="Void"),
            "extent_bool": lambda v: changed_parameter(v)["shape"].update(extent=True),
            "contradictory_state": lambda v: changed_parameter(v).update(state="variable"),
            "python": lambda v: v["python"].update(sha256="0" * 64),
            "worker": lambda v: v["worker"].update(sha256="0" * 64),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                def altered(argv, **kwargs):
                    result = run_bounded(argv, **kwargs)
                    if argv[-1] == "--worker" and result.returncode == 0:
                        value = json.loads(result.stdout)
                        mutate(value)
                        return CaptureResult(0, json.dumps(value), result.stderr)
                    return result
                destination = self.root / ("bound-" + name)
                with patch("hepta.clang_capture.run_bounded", side_effect=altered):
                    report = self.migrate(database, destination)
                self.assertFalse(report["ok"], report)
                self.assertFalse(destination.exists())
                self.assertIn("E_C_ORIGINAL_TYPE", [row["code"] for row in report["diagnostics"]])

    def test_vla_kind_cannot_be_relabelled_by_a_fixed_shape(self):
        database = self.project("unsigned int probe(unsigned int n, const unsigned int data[++n]) { return n; }\n")
        def altered(argv, **kwargs):
            result = run_bounded(argv, **kwargs)
            if argv[-1] != "--worker" or result.returncode:
                return result
            value = json.loads(result.stdout)
            parameter = value["functions"][0]["parameters"][1]
            self.assertEqual(parameter["kind"], "VariableArray")
            parameter["state"] = "fixed"
            parameter["shape"].update(kind="ConstantArray", extent=8)
            return CaptureResult(0, json.dumps(value), result.stderr)
        destination = self.root / "forged-fixed"
        with patch("hepta.clang_capture.run_bounded", side_effect=altered):
            report = self.migrate(database, destination)
        self.assertFalse(report["ok"], report)
        self.assertFalse(destination.exists())
        self.assertIn("E_C_ORIGINAL_TYPE", [row["code"] for row in report["diagnostics"]])

    def test_matching_reader_identity_is_real_and_bound(self):
        from hepta.c_parameter_types import original_type_reader_identity
        from hashlib import sha256
        result = original_type_reader_identity(self.clang)
        self.assertEqual(result["schema"], "hepta.c-original-type-reader-identity.v1")
        self.assertEqual(result["compiler"]["version"], result["reader"]["version"])
        for name in ("reader", "worker", "python"):
            self.assertEqual(result[name]["sha256"], sha256(Path(result[name]["path"]).read_bytes()).hexdigest())


class OriginalTypeEmissionProcessTests(unittest.TestCase):
    """Real host subprocess checks, not a claim of Windows host execution."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-ast-process-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def request(self):
        compiler = parameter_types._digest_file(sys.executable)
        argv = [compiler["path"], "-Werror", "-emit-ast", "translation unit.c",
                "-o", str(self.root / "output with spaces.ast")]
        return {"compiler": {"path": compiler["path"], "executable_sha256": compiler["sha256"]},
                "arguments": [], "source_argument": "translation unit.c", "argv": argv,
                "directory": str(Path.cwd()), "worker": parameter_types._digest_file(parameter_types.__file__),
                "python": parameter_types._digest_file(sys.executable)}

    def test_real_wait_preserves_exit_status_streams_and_quoted_arguments(self):
        folder = self.root / "compiler fixture with spaces"
        folder.mkdir()
        child = folder / "child script.py"
        child.write_text("import ctypes,json,os,sys\nfrom pathlib import Path\n"
                         "Path(sys.argv[1]).write_text(json.dumps(sys.argv[3:]))\n"
                         "print('actual compiler stdout',flush=True)\n"
                         "print('actual compiler stderr',file=sys.stderr,flush=True)\n"
                         "if os.name == 'nt':\n"
                         "    exit_process=ctypes.WinDLL('kernel32',use_last_error=True).ExitProcess\n"
                         "    exit_process.argtypes=[ctypes.c_uint32]\n"
                         "    exit_process.restype=None\n"
                         "    exit_process(int(sys.argv[2]))\n"
                         "raise SystemExit(int(sys.argv[2]))\n")
        wrapper = ("import runpy,sys; worker=runpy.run_path(sys.argv[1]); "
                   "raise SystemExit(worker['_wait_for_ast_compiler'](sys.argv[2:]))")
        arguments = ['input with spaces.c', '-DNAME="quoted value"', 'literal trailing\\']
        statuses = ((0, 23, 0x7fffffff, 0x80000000, 0xc0000409, 0xc0000005, 0xffffffff)
                    if os.name == "nt" else (0, 23, 127, 255))
        for status in statuses:
            with self.subTest(status=status):
                output = folder / (str(status) + " output.ast")
                result = run_bounded([sys.executable, "-I", "-c", wrapper,
                    str(Path(parameter_types.__file__).resolve()), sys.executable,
                    str(child), str(output), str(status), *arguments], timeout=10)
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stdout, "actual compiler stdout\n")
                self.assertEqual(result.stderr, "actual compiler stderr\n")
                self.assertEqual(json.loads(output.read_text()), arguments)
                if status == 0:
                    parameter_types._check_emitted_ast(result, output)
                else:
                    with self.assertRaises(ValueError) as failed:
                        parameter_types._check_emitted_ast(result, output)
                    details = json.loads(str(failed.exception).split(": ", 1)[1])
                    self.assertEqual(details["returncode"], status)
                    self.assertEqual(details["ast_bytes"], output.stat().st_size)
                    self.assertIs(details["ast_present"], True)
                    self.assertEqual(details["stdout_tail"], result.stdout)
                    self.assertEqual(details["stderr_tail"], result.stderr)

    def test_windows_dispatch_waits_with_inherited_io_and_no_exec_or_shell(self):
        request = self.request()
        for actual, forwarded in ((23, 23), (0x80000000, -2147483648),
                                  (0xc0000409, -1073740791),
                                  (0xc0000005, -1073741819), (0xffffffff, -1)):
            with self.subTest(actual=actual):
                process = Mock()
                process.wait.return_value = actual
                windows = SimpleNamespace(name="nt", execv=Mock())
                with patch.object(parameter_types, "os", windows), \
                        patch.object(parameter_types.subprocess, "Popen", return_value=process) as launch:
                    with self.assertRaises(SystemExit) as stopped:
                        parameter_types._emit_ast(request)
                self.assertEqual(stopped.exception.code, forwarded)
                launch.assert_called_once_with(request["argv"], shell=False)
                process.wait.assert_called_once_with()
                windows.execv.assert_not_called()

    def test_stale_tool_or_command_identity_is_rejected_before_launch(self):
        for field in ("compiler", "worker", "python", "directory", "argv"):
            with self.subTest(field=field):
                request = self.request()
                if field == "compiler":
                    request[field]["executable_sha256"] = "0" * 64
                elif field in {"worker", "python"}:
                    request[field]["sha256"] = "0" * 64
                elif field == "directory":
                    request[field] = str(self.root)
                else:
                    request[field][-3] = "other source.c"
                with patch.object(parameter_types, "os", SimpleNamespace(name="nt", execv=Mock())), \
                        patch.object(parameter_types.subprocess, "Popen") as launch:
                    with self.assertRaisesRegex(ValueError, "input identity mismatch"):
                        parameter_types._emit_ast(request)
                launch.assert_not_called()

    def test_zero_exit_does_not_admit_missing_empty_or_oversize_ast(self):
        missing, empty, excessive = (self.root / name for name in ("missing.ast", "empty.ast", "excessive.ast"))
        empty.write_bytes(b"")
        with excessive.open("wb") as stream:
            stream.truncate(parameter_types.MAX_AST_BYTES + 1)
        for output, present, size in ((missing, False, None), (empty, True, 0),
                                      (excessive, True, parameter_types.MAX_AST_BYTES + 1)):
            with self.subTest(output=output):
                result = CaptureResult(0, "out" * 2000, "err" * 2000)
                with self.assertRaises(ValueError) as failed:
                    parameter_types._check_emitted_ast(result, output)
                details = json.loads(str(failed.exception).split(": ", 1)[1])
                self.assertEqual(details["returncode"], 0)
                self.assertIs(details["ast_present"], present)
                self.assertEqual(details["ast_bytes"], size)
                self.assertEqual(details["stdout_characters"], 6000)
                self.assertEqual(details["stderr_characters"], 6000)
                self.assertEqual(details["stdout_tail"], result.stdout[-4000:])
                self.assertEqual(details["stderr_tail"], result.stderr[-4000:])
        arguments = ["compiler with spaces", "x" * 1025, *["argument"] * 127]
        with self.assertRaises(ValueError) as failed:
            parameter_types._check_emitted_ast(result, missing, argv=arguments)
        details = json.loads(str(failed.exception).split(": ", 1)[1])
        self.assertEqual(details["argv_count"], len(arguments))
        self.assertEqual(details["argv"], [argument[:1024] for argument in arguments[:128]])
        self.assertIs(details["argv_truncated"], True)
        self.assertEqual(details["argv_argument_limit"], 128)
        self.assertEqual(details["argv_character_limit"], 1024)


if __name__ == "__main__":
    unittest.main()
