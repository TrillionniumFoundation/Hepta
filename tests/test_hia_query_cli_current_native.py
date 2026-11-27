"""Current v9 leaf conformance and explicit component-install preparation.

The original 29 methods remain a separately reported corpus. This module adds
actual current word-memory inputs and validates complete immutable historical
source bytes; it does not manufacture a matching cold or public wheel claim.
"""
from __future__ import annotations
import ast
import base64
from copy import deepcopy
from hashlib import sha256
import io
import itertools
import json
import os
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from tests import test_hia_agent_query_native as query_cases
from tests import test_hia_cli_inspect_native as inspect_cases
from tools.hia_word_memory_cases import acyclic_program, owned_program

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "tests/fixtures/hia_query_cli_component_install_preparation_v1.json"
FIXTURE_SHA256 = "03133866b6ed37ecd1647280719f603b7fd1b5ce03f349c1263882f9e4b238a8"
ARCHIVE_SHA256 = "e3f3fb7479cf57218a4f8128dc88b2e941a5f5b40618e0bd764b47189ba9b865"
INSTALL_METHODS = {
    "AgentQueryIntegrationTests.test_actual_sdist_wheel_and_worker_bundle_need_no_per_call_environment",
    "CliInspectNativeTests.test_real_sdist_wheel_installed_cli_uses_package_owned_source",
}


def _pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _restored(record, raw):
    if _pin(raw) != record["current"]:
        raise ValueError("current complete test source identity differs")
    prior = raw
    shift, positioned = 0, []
    for splice in record["splices"]:
        before = base64.b64decode(splice["before"], validate=True)
        after = base64.b64decode(splice["after"], validate=True)
        positioned.append((splice["offset"] + shift, before, after))
        shift += len(after) - len(before)
    for at, before, after in reversed(positioned):
        if prior[at:at + len(after)] != after:
            raise ValueError("complete inverse splice differs")
        prior = prior[:at] + before + prior[at + len(after):]
    if _pin(prior) != record["original"]:
        raise ValueError("complete historical test source identity differs")
    replay = prior
    for splice in reversed(record["splices"]):
        before = base64.b64decode(splice["before"], validate=True)
        after = base64.b64decode(splice["after"], validate=True)
        at = splice["offset"]
        if replay[at:at + len(before)] != before:
            raise ValueError("complete forward splice differs")
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise ValueError("complete forward replay differs")
    return prior


def _methods(raw):
    return {
        cls.name + "." + method.name: method
        for cls in ast.parse(raw).body if isinstance(cls, ast.ClassDef)
        for method in cls.body
        if isinstance(method, ast.FunctionDef) and method.name.startswith("test_")
    }


class QueryCliPreparationSourceTests(unittest.TestCase):
    def test_complete_original_and_current_methods_have_exact_inverse(self):
        fixture_raw = (ROOT / FIXTURE).read_bytes()
        self.assertEqual(sha256(fixture_raw).hexdigest(), FIXTURE_SHA256)
        fixture = json.loads(fixture_raw)
        self.assertFalse(fixture["public_native_distribution_qualified"])
        archive_raw = (ROOT / fixture["original_archive"]).read_bytes()
        self.assertEqual(sha256(archive_raw).hexdigest(), ARCHIVE_SHA256)
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:gz") as archive:
            members = {item.name: archive.extractfile(item).read()
                       for item in archive.getmembers() if item.isfile()}
        methods, changed = 0, set()
        for row in fixture["files"]:
            raw = (ROOT / row["path"]).read_bytes()
            prior = _restored(row, raw)
            self.assertEqual(prior, members[row["path"]])
            old, new = _methods(prior), _methods(raw)
            self.assertEqual(old.keys(), new.keys())
            methods += len(old)
            for name in old:
                if ast.dump(old[name], include_attributes=False) != ast.dump(new[name], include_attributes=False):
                    changed.add(name)
                    self.assertIn(name, INSTALL_METHODS)
                    # Every original assertion call remains an exact AST in order.
                    def assertions(node):
                        return [ast.dump(item, include_attributes=False)
                                for item in ast.walk(node)
                                if isinstance(item, ast.Call)
                                and isinstance(item.func, ast.Attribute)
                                and isinstance(item.func.value, ast.Name)
                                and item.func.value.id == "self"
                                and item.func.attr.startswith(("assert", "fail"))]
                    position = 0
                    actual = assertions(new[name])
                    for expected in assertions(old[name]):
                        position = actual.index(expected, position) + 1
            for method in row["changed_test_methods"]:
                name = method["method"]
                self.assertEqual(ast.get_source_segment(prior.decode(), old[name]), method["original"])
                self.assertEqual(ast.get_source_segment(raw.decode(), new[name]), method["current"])
        self.assertEqual(methods, 29)
        self.assertEqual(changed, INSTALL_METHODS)

    def test_unknown_or_changed_whole_source_cannot_use_preparation(self):
        fixture = json.loads((ROOT / FIXTURE).read_bytes())
        for record in fixture["files"]:
            raw = (ROOT / record["path"]).read_bytes()
            for changed in (b"", raw + b"\n", b"\n" + raw, raw[:-1]):
                with self.subTest(path=record["path"], size=len(changed)):
                    with self.assertRaises(ValueError):
                        _restored(record, changed)
            invalid = deepcopy(record)
            invalid["original"]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                _restored(invalid, raw)


def _word_cases():
    result = []
    for store, load in itertools.product(("le", "be"), repeat=2):
        document = acyclic_program()
        ops = document["functions"][0]["blocks"][0]["ops"]
        ops[5]["op"] = "buffer.store.u64." + store
        ops[6]["op"] = "buffer.load.u64." + load
        result.append((store + "-" + load, document))
    return result


class QueryCliCurrentNativeTests(query_cases.AgentQueryFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from hepta.hia_cli_inspect_native import SOURCE, SCHEMA, NativeCliInspect
        if cls.cold is not None:
            from tools.build_hia_cli_inspect import build
            cls.inspect_manifest = build(cls.folder / "inspect-qualified", cls.compiler, cls.cold)
            manifest = json.loads(cls.inspect_manifest.read_bytes())
            image = cls.inspect_manifest.parent / manifest["image_path"]
        else:
            from tools.qualify_hia_selfhost import compile_stage
            image, receipt = compile_stage(cls.folder, "inspect-current-development",
                                           cls.compiler, SOURCE.read_bytes())
            cls.inspect_manifest = cls.folder / "inspect-manifest.json"
            manifest = {"schema": SCHEMA, "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
                        "compiler_sha256": sha256(cls.compiler.read_bytes()).hexdigest(),
                        "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest()}
            query_cases.record(cls.inspect_manifest, manifest)
            query_cases.record(cls.folder / "inspect-development-compile.json",
                               {"receipt": receipt, "current_source_cold_qualified": False})
        cls.inspect_native = NativeCliInspect(image.read_bytes(), manifest["image_sha256"])

    def _query(self, document, **selection):
        from hepta import hia_agent_query_native as adapter
        from hepta.hia_edit_query import prepare_edit
        with patch.dict(os.environ, {adapter.SELECTOR: str(self.manifest)}), \
                patch.object(adapter, "installed_agent_query", return_value=self.native):
            return prepare_edit(document, **selection)

    def _inspect(self, document):
        from hepta import hia_cli_inspect_native as adapter
        from hepta.hia_program_tools import inspect_program
        with patch.dict(os.environ, {adapter.SELECTOR: str(self.inspect_manifest)}), \
                patch.object(adapter, "installed_cli_inspect", return_value=self.inspect_native):
            return inspect_program(document)

    def test_v9_all_word_orders_all_field_orders_preserve_complete_query(self):
        observations = []
        for label, document in _word_cases():
            for output in ("value", "result"):
                for size in (1, 2, 3):
                    for fields in itertools.permutations(("op", "args", "attrs"), size):
                        selection = dict(function="probe", block="entry", output=output, fields=fields)
                        expected = query_cases.original_query(document, **selection)
                        with self.subTest(case=label, output=output, fields=fields), \
                                query_cases.poisoned_query_construction(), \
                                query_cases.observe_entry(self.native) as calls:
                            actual = self._query(document, **selection)
                        self.assertEqual(actual, expected)
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(calls[0]["input"], calls[0]["input_after"])
                        self.assertGreater(calls[0]["return"], 64)
                        observations.append({"case": label, "output": output, "fields": fields,
                            "request_sha256": sha256(calls[0]["input"]).hexdigest(),
                            "query_wire_sha256": sha256(calls[0]["output"][64:calls[0]["return"]]).hexdigest()})
        self.assertEqual(len(observations), 120)
        query_cases.record(self.directory() / "actual-word-query-calls.json", observations)

    def test_v9_scalar_word_and_looping_reports_use_complete_native_inspection(self):
        values = [("scalar-v9", inspect_cases.scalar(9)),
                  *_word_cases(), ("looping-word-memory", owned_program())]
        observations = []
        from hepta import hia_program_tools as ordinary
        def absent(*args, **kwargs):
            raise AssertionError("host report assembly used by selected current native")
        for label, document in values:
            expected = inspect_cases.reference(document)
            with self.subTest(case=label), \
                    patch.object(ordinary, "function_signature", side_effect=absent), \
                    inspect_cases.observe(self.inspect_native) as calls:
                actual = self._inspect(document)
            self.assertEqual(actual, expected)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["request"], calls[0]["after"])
            self.assertFalse(actual["claims"]["whole_language_soundness_proved"])
            observations.append({"case": label, "request_sha256": sha256(calls[0]["request"]).hexdigest(),
                                 "complete_output_sha256": sha256(calls[0]["published"]).hexdigest()})
        self.assertEqual(len(observations), 6)
        query_cases.record(self.directory() / "actual-word-inspect-calls.json", observations)

    def test_invalid_current_word_inputs_keep_complete_first_verifier(self):
        bad = []
        base = acyclic_program()
        for version in range(1, 9):
            document = deepcopy(base)
            document["schema"] = "hepta.hia.program.v" + str(version)
            bad.append(("old-version-" + str(version), document))
        for kind in ("read-effect", "write-effect", "load-attributes", "store-attributes", "offset-type"):
            document = deepcopy(base)
            fn = document["functions"][0]
            if kind.endswith("effect"):
                fn["effects"].remove(kind.split("-")[0])
            elif kind == "offset-type":
                fn["blocks"][0]["ops"][6]["args"][1] = "value"
            else:
                fn["blocks"][0]["ops"][6 if kind.startswith("load") else 5]["attrs"] = {"unchecked": True}
            bad.append((kind, document))
        observations = []
        for name, document in bad:
            def outcome(call):
                try:
                    call()
                except Exception as error:
                    return (type(error).__module__, type(error).__name__,
                            getattr(error, "code", None), str(error))
                self.fail("invalid WordMemory source unexpectedly admitted")
            expected = outcome(lambda: verify_program(document))
            with self.subTest(case=name), query_cases.observe_entry(self.native) as query_calls, \
                    inspect_cases.observe(self.inspect_native) as inspect_calls:
                self.assertEqual(outcome(lambda: self._query(document, function="probe",
                    block="entry", output="value", fields=["attrs"])), expected)
                self.assertEqual(outcome(lambda: self._inspect(document)), expected)
            self.assertEqual(query_calls, [])
            self.assertEqual(inspect_calls, [])
            observations.append({"case": name, "first_refusal": expected, "native_entries": 0})
        self.assertEqual(len(observations), 13)
        query_cases.record(self.directory() / "first-verifier-refusals.json", observations)
