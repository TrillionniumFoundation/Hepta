"""Host selection and refusal controls; synthetic files do not qualify macOS."""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import preflight_c_original_types as preflight


class OriginalTypeHostPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-host-reader-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.installation = self.root / "Xcode test.app" / "Toolchains" / "Selected.xctoolchain" / "usr"
        self.compiler = self.installation / "bin" / "clang"
        self.library = self.installation / "lib" / "libclang.dylib"
        self.compiler.parent.mkdir(parents=True)
        self.library.parent.mkdir()
        self.compiler.write_bytes(b"synthetic selected compiler identity")
        self.library.write_bytes(b"synthetic selected reader identity")
        self.version = "Apple clang version 17.0.0 (test-only)"
        self.target = "arm64-apple-darwin-test"

    def identity(self):
        def file(path):
            return {"path": str(path), "bytes": path.stat().st_size, "sha256": preflight.sha(path)}
        return {"schema": "hepta.c-original-type-reader-identity.v1",
                "compiler": {"path": str(self.compiler), "executable_sha256": preflight.sha(self.compiler),
                             "version": self.version, "target": self.target},
                "reader": {**file(self.library), "version": self.version},
                "worker": file(Path(preflight.__file__)), "python": file(Path(__file__))}

    def test_xcrun_selects_one_actual_installation_without_guessing_xcode_version(self):
        calls = []
        def invoke(argv):
            calls.append(argv)
            return str(self.compiler) + "\n"
        chosen = preflight.select_clang("clang", "Darwin", invoke)
        self.assertEqual(chosen, self.compiler)
        self.assertEqual(calls, [["/usr/bin/xcrun", "--find", "clang"]])
        preflight.check_identity(self.identity(), chosen, self.version + "\n", self.target + "\n", "Darwin")

    def test_missing_or_ambiguous_xcrun_output_never_falls_back_to_global_clang(self):
        for output in ("", "relative/clang\n", str(self.compiler) + "\n/other/clang\n",
                       str(self.root / "missing") + "\n"):
            with self.subTest(output=output), patch.object(preflight.shutil, "which") as which:
                with self.assertRaises(ValueError):
                    preflight.select_clang("clang", "Darwin", lambda argv: output)
                which.assert_not_called()
        with patch.object(preflight.shutil, "which", return_value=str(self.root / "other-clang")):
            with self.assertRaisesRegex(ValueError, "differs from the active Xcode"):
                preflight.select_clang("other-clang", "Darwin", lambda argv: str(self.compiler) + "\n")

    def test_same_version_global_reader_cannot_replace_selected_installation(self):
        identity = self.identity()
        global_reader = self.root / "global-libclang.dylib"
        global_reader.write_bytes(self.library.read_bytes())
        identity["reader"]["path"] = str(global_reader)
        with self.assertRaisesRegex(ValueError, "selected Xcode installation"):
            preflight.check_identity(identity, self.compiler, self.version, self.target, "Darwin")

    def test_changed_compiler_reader_and_mismatched_version_are_refused(self):
        identity = self.identity()
        self.compiler.write_bytes(b"changed compiler")
        with self.assertRaisesRegex(ValueError, "selected compiler bytes"):
            preflight.check_identity(identity, self.compiler, self.version, self.target, "Darwin")
        identity = self.identity()
        self.library.write_bytes(b"changed reader")
        with self.assertRaisesRegex(ValueError, "identity bytes changed"):
            preflight.check_identity(identity, self.compiler, self.version, self.target, "Darwin")
        identity = self.identity()
        identity["reader"]["version"] = "other version"
        with self.assertRaisesRegex(ValueError, "version or target differs"):
            preflight.check_identity(identity, self.compiler, self.version, self.target, "Darwin")

    def case_report(self, name):
        identity = self.identity()
        work = self.root / name
        work.mkdir()
        (work / "input.c").write_text(preflight.CASES[name])
        fixed = name == "fixed_array"
        parameter = {"name": "data", "state": "fixed" if fixed else "variable",
                     "shape": {"kind": "ConstantArray" if fixed else "VariableArray",
                               "extent": 8 if fixed else None, "element": {"kind": "UInt", "const": True}},
                     "binding": {"file": str(work / "input.c"), "offset": preflight.CASES[name].index("data")}}
        receipt = {"schema": "hepta.c-original-parameter-types.v2", "capture_sha256": "captured",
                   **{k: identity[k] for k in ("compiler", "reader", "worker", "python")},
                   "functions": [{"declaration": {"name": "probe", "file": str(work / "input.c")},
                                  "parameters": [{"name": "n"}, parameter]}]}
        result = {"ok": fixed, "native_validation": "not_run", "build": {"sha256": "captured"},
                  "source_type_admission": [receipt],
                  "diagnostics": [] if fixed else [{"code": "E_C_VLA_PARAMETER"}]}
        return result, identity, work

    def test_fixed_extent_and_variable_shape_must_have_the_expected_actual_outcome(self):
        for name in preflight.CASES:
            report, identity, work = self.case_report(name)
            self.assertTrue(preflight.check_case(name, report, identity, work)["passed"])
            qualified_array = copy.deepcopy(report)
            shape = qualified_array["source_type_admission"][0]["functions"][0]["parameters"][1]["shape"]
            shape["const"], shape["element"]["const"] = True, False
            self.assertTrue(preflight.check_case(name, qualified_array, identity, work)["passed"])
            shape["const"] = False
            with self.assertRaisesRegex(ValueError, "const unsigned element"):
                preflight.check_case(name, qualified_array, identity, work)
            altered = copy.deepcopy(report)
            if name == "fixed_array":
                altered["source_type_admission"][0]["functions"][0]["parameters"][1]["shape"]["extent"] = True
            else:
                altered["diagnostics"] = [{"code": "E_C_ORIGINAL_TYPE"}]
            with self.assertRaises(ValueError):
                preflight.check_case(name, altered, identity, work)
            altered = copy.deepcopy(report)
            altered["source_type_admission"] = []
            with self.assertRaisesRegex(ValueError, "missing original-type"):
                preflight.check_case(name, altered, identity, work)

    def test_failed_preflight_retains_structured_error_without_exporting_compiler(self):
        output, env = self.root / "failure", self.root / "github-env"
        env.write_text("PREEXISTING=kept\n")
        with patch.object(preflight.platform, "system", return_value="Darwin"), \
             patch.object(preflight, "select_clang", side_effect=ValueError("actual lookup failed")), \
             redirect_stdout(io.StringIO()):
            status = preflight.main(["--expected-system", "Darwin", "--output-directory", str(output),
                                     "--github-env", str(env)])
        self.assertEqual(status, 1)
        report = json.loads((output / "qualification.json").read_text())
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"]["message"], "actual lookup failed")
        self.assertEqual(env.read_text(), "PREEXISTING=kept\n")
        self.assertFalse(report["claims"]["original_type_guard_bypassed"])

if __name__ == "__main__":
    unittest.main()
