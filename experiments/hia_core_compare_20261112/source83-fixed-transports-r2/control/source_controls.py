"""Four source-only controls for the two fixed foreign transport templates.

The original 62-generator / 83-method qualification is a separate, unexecuted
request. These controls cannot grant native, installed, cold, or assembler-oracle
qualification.
"""
from __future__ import annotations
import ast
from contextlib import ExitStack, redirect_stdout
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("artifact_publication", "release_install")
CASE_ROOT = None
ATTEMPTS = []
MODULES = {}
EXPECTED_PREFIX = {
    "artifact_publication": (4154, "aee4763503dbc2cccdefd99cb99f4879f55c38654ae8fd3069863682f25d65a0",
                             {"policy_initial_hole": 425, "policy_hole": 3751, "sha_hole": 3797}),
    "release_install": (3623, "253a2dc0bd1d404c6ece73f9ee5c1afdb828714daca55c21281473a54a0b2ecb",
                       {"policy_initial_hole": 389, "policy_hole": 3500, "sha_hole": 3546}),
}


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def blocked(*args, **kwargs):
    ATTEMPTS.append("native/compiler/subprocess-attempt")
    raise AssertionError("fixed transport source control attempted native/compiler/subprocess execution")


def body(text, node):
    return "".join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def cases(test, name):
    root = CASE_ROOT / test / name
    (root / "tools").mkdir(parents=True, exist_ok=False)
    (root / "examples/hia_bootstrap").mkdir(parents=True, exist_ok=False)
    source = ROOT / "reference/tools" / ("hia_" + name + "_syscalls.S")
    save(root / "tools" / source.name, source.read_bytes())
    return root


class FixedTransportSourceTests(unittest.TestCase):
    def test_assembler_oracle_and_hia_algorithms_are_preserved(self):
        for name in NAMES:
            old = (ROOT / "reference/tools" / ("generate_hia_" + name + ".py")).read_text()
            new = (ROOT / "inputs/tools" / ("generate_hia_" + name + ".py")).read_text()
            old_tree, new_tree = ast.parse(old), ast.parse(new)
            old_functions = {node.name: node for node in old_tree.body if isinstance(node, ast.FunctionDef)}
            new_functions = {node.name: node for node in new_tree.body if isinstance(node, ast.FunctionDef)}
            for function, node in old_functions.items():
                if function == "template":
                    self.assertEqual(body(new, new_functions["assembled_template"]).replace(
                        "def assembled_template():", "def template():", 1), body(old, node))
                else:
                    self.assertEqual(body(new, new_functions[function]), body(old, node), (name, function))
            for node in old_tree.body:
                if isinstance(node, ast.Assign):
                    target = ast.dump(node.targets[0], include_attributes=False)
                    matches = [item for item in new_tree.body if isinstance(item, ast.Assign)
                               and ast.dump(item.targets[0], include_attributes=False) == target]
                    self.assertEqual(len(matches), 1)
                    self.assertEqual(body(new, matches[0]), body(old, node))
        projection = json.loads((ROOT / "ORACLE-IMPORT-PROJECTION.json").read_text())
        for row in projection:
            old = (ROOT / "reference" / row["path"]).read_text()
            new = (ROOT / "inputs" / row["path"]).read_text()
            restored = new
            for change in reversed(row["replacements"]):
                self.assertEqual(restored.count(change["after"]), 1)
                restored = restored.replace(change["after"], change["before"], 1)
            self.assertEqual(restored, old)
            before = [node.name for node in ast.walk(ast.parse(old))
                      if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]
            after = [node.name for node in ast.walk(ast.parse(new))
                     if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]
            self.assertEqual(after, before)

    def test_literal_transport_and_holes_match_frozen_packer(self):
        for name in NAMES:
            root = cases(self._testMethodName, name)
            with patch.object(MODULES[name], "ROOT", root):
                prefix, holes = MODULES[name].template()
            length, digest, expected_holes = EXPECTED_PREFIX[name]
            self.assertEqual(len(prefix), length)
            self.assertEqual(hashlib.sha256(prefix).hexdigest(), digest)
            self.assertEqual(prefix, (ROOT / "reference" / (name + ".prefix.bin")).read_bytes())
            self.assertEqual(holes, expected_holes)
            for offset in holes.values():
                self.assertEqual(prefix[offset - 1:offset + 4], b"\xe8\0\0\0\0")
            save(root / "actual.prefix.bin", prefix)
            save(root / "actual.holes.json", (json.dumps(holes, sort_keys=True) + "\n").encode())

    def test_source_transport_and_hole_drift_are_refused(self):
        for name in NAMES:
            module = MODULES[name]
            root = cases(self._testMethodName, name)
            source = root / "tools" / ("hia_" + name + "_syscalls.S")
            original = source.read_bytes()
            observed = []
            with patch.object(module, "ROOT", root):
                source.write_bytes(original + b"\n")
                with self.assertRaisesRegex(ValueError, "syscall source changed") as failure:
                    module.template()
                observed.append({"case": "source_changed", "error": str(failure.exception)})
                source.write_bytes(original)
                wrong = module.TRANSPORT[:-1] + bytes([module.TRANSPORT[-1] ^ 1])
                with patch.object(module, "TRANSPORT", wrong):
                    with self.assertRaisesRegex(ValueError, "transport bytes changed") as failure:
                        module.template()
                    observed.append({"case": "transport_changed", "error": str(failure.exception)})
                holes = dict(module.TRANSPORT_HOLES)
                holes["policy_hole"] += 1
                with patch.object(module, "TRANSPORT_HOLES", holes):
                    with self.assertRaisesRegex(ValueError, "transport holes changed") as failure:
                        module.template()
                    observed.append({"case": "hole_changed", "error": str(failure.exception)})
                self.assertEqual(module.template()[0], (ROOT / "reference" / (name + ".prefix.bin")).read_bytes())
            save(root / "refusals.json", (json.dumps(observed, indent=2, sort_keys=True) + "\n").encode())

    def test_all_four_hia_outputs_reproduce_with_external_entries_poisoned(self):
        outputs = []
        for name in NAMES:
            root = cases(self._testMethodName, name)
            stdout = io.StringIO()
            with patch.object(MODULES[name], "ROOT", root), redirect_stdout(stdout):
                MODULES[name].main()
            save(root / "authoring.stdout.log", stdout.getvalue().encode())
            for kind in ("policy", "packer"):
                relative = Path("examples/hia_bootstrap") / (name + "_" + kind + ".hiaasm")
                actual = (root / relative).read_bytes()
                expected = (ROOT / "reference" / relative).read_bytes()
                self.assertEqual(actual, expected, str(relative))
                outputs.append({"path": str(relative), "bytes": len(actual),
                                "sha256": hashlib.sha256(actual).hexdigest()})
        self.assertEqual(ATTEMPTS, [])
        save(CASE_ROOT / self._testMethodName / "OUTPUTS.json",
             (json.dumps(outputs, indent=2, sort_keys=True) + "\n").encode())


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_ids = []

    def startTest(self, test):
        self.executed_ids.append(test.id())
        super().startTest(test)


def main():
    global CASE_ROOT
    if len(sys.argv) != 6:
        raise ValueError("expected source-root, actual-root, result-json, request, request-sha256")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import files
    request_raw, request_pin = files.read(sys.argv[4])
    files.require(hashlib.sha256(request_raw).hexdigest() == sys.argv[5], "source control request differs")
    request = json.loads(request_raw)
    source = Path(sys.argv[1]).resolve(strict=True)
    files.require(str(source) == request["source_root"], "source root differs")
    CASE_ROOT = Path(sys.argv[2])
    result_path = Path(sys.argv[3])
    CASE_ROOT.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(source))
    report = {
        "schema": "hepta.hia.fixed-transport-source-controls.v1", "status": "HOLD",
        "expected_methods": 4, "expected_ids": [], "loaded_ids": [], "executed_ids": [],
        "failures": [], "errors": [], "skipped": [], "expectedFailures": [], "unexpectedSuccesses": [],
        "native_or_compiler_or_process_attempts": ATTEMPTS,
        "native_executed": False, "assembler_oracle_executed": False,
        "source83_executed": False, "runtime": sys.version,
    }
    start = time.monotonic()
    result = None
    before = None
    def inputs():
        return [files.read(row["path"], row)[1] for row in request["input_pins"]]
    try:
        before = inputs()
        save(CASE_ROOT / "INPUTS-BEFORE.json", (json.dumps(before, indent=2, sort_keys=True) + "\n").encode())
        import tools
        from tools import qualify_hia_selfhost as compiler
        from hepta import hia_json_preflight_native as images
        with ExitStack() as scope:
            scope.enter_context(patch.object(subprocess, "Popen", blocked))
            scope.enter_context(patch.object(images.NativeHiaJsonImage, "__init__", blocked))
            scope.enter_context(patch.object(compiler, "compile_stage", blocked))
            scope.enter_context(patch.object(compiler, "build_seed", blocked))
            for name in ("CDLL", "PyDLL", "CFUNCTYPE", "PYFUNCTYPE"):
                scope.enter_context(patch.object(ctypes, name, blocked))
            for name in NAMES:
                qualified = "tools.generate_hia_" + name
                path = ROOT / "inputs/tools" / ("generate_hia_" + name + ".py")
                specification = importlib.util.spec_from_file_location(qualified, path)
                module = importlib.util.module_from_spec(specification)
                sys.modules[qualified] = module
                setattr(tools, "generate_hia_" + name, module)
                specification.loader.exec_module(module)
                MODULES[name] = module
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(FixedTransportSourceTests)
            report["expected_ids"] = [
                "__main__.FixedTransportSourceTests." + name
                for name in sorted(key for key in vars(FixedTransportSourceTests) if key.startswith("test_"))
            ]
            report["loaded_ids"] = [test.id() for test in suite]
            if report["expected_ids"] != report["loaded_ids"] or len(report["loaded_ids"]) != 4:
                raise AssertionError("four loaded IDs differ")
            with (CASE_ROOT / "unittest.log").open("x") as stream:
                runner = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result)
                result = runner.run(suite)
            report["executed_ids"] = result.executed_ids
            for key in ("failures", "errors", "skipped", "expectedFailures"):
                report[key] = [[test.id(), detail] for test, detail in getattr(result, key)]
            report["unexpectedSuccesses"] = [test.id() for test in result.unexpectedSuccesses]
            if report["executed_ids"] != report["expected_ids"] or result.testsRun != 4:
                raise AssertionError("four executed IDs differ")
            if not result.wasSuccessful() or any(report[key] for key in (
                    "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")):
                raise AssertionError("source controls failed")
            if ATTEMPTS:
                raise AssertionError("forbidden execution attempted")
            report["status"] = "SOURCE_CONTROLS_PASS"
    except BaseException:
        report["status"] = "HOLD"
        report["error"] = traceback.format_exc()
    finally:
        try:
            after = inputs()
            save(CASE_ROOT / "INPUTS-AFTER.json", (json.dumps(after, indent=2, sort_keys=True) + "\n").encode())
            files.require(before is not None and before == after, "source inputs changed")
            report["source_inputs_stable"] = True
            report["request_sha256"] = request_pin["sha256"]
        except BaseException:
            report["status"] = "HOLD"
            report["preservation_error"] = traceback.format_exc()
        report["seconds"] = time.monotonic() - start
        save(result_path, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"status": report["status"], "seconds": report["seconds"],
                      "loaded": len(report["loaded_ids"]), "executed": len(report["executed_ids"])}))
    return 0 if report["status"] == "SOURCE_CONTROLS_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

