"""Whole-build coverage boundaries, independent of the LLVM codec tests."""
import json
from pathlib import Path
import tempfile
import unittest

from tools import hia_linux_full_inventory as full
from tools import qualify_hia_linux_baseline as baseline


class FullBuildCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-full-coverage-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build, self.source, self.ledger, self.output = (self.root / name for name in ("build", "source", "ledger", "output"))
        for path in (self.build, self.source, self.ledger, self.output):
            path.mkdir()
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text("{}")
        self.wrappers = {kind: self.root / name for kind, name in
                         (("target", "target-driver.py"), ("host_c", "host-c.py"), ("host_cxx", "host-cxx.py"))}
        self.add_target("c01", "target_c", "main.c", "main.o")
        self.add_target("a01", "target_assembly", "entry.S", "entry.o")

    def add_target(self, identifier, kind, source, output, *, canonical=True, fallback=False, mode="import"):
        directory = self.ledger / identifier
        directory.mkdir()
        path = self.build / output
        path.write_bytes(b"object " + identifier.encode())
        program = self.root / (identifier + ".hia.json.gz")
        program.write_bytes(b"retained source")
        record = {
            "schema": "hepta.hia.system-compiler-invocation.v1", "id": identifier, "status": "PASS",
            "classification": {"kind": kind}, "manifest": baseline.identity(self.manifest),
            "canonical_roundtrip_equal": canonical, "fallback_c_compilation": fallback,
            "commands": [{"name": "hia-native-codegen"}] +
                        ([{"name": "decode-hia-fresh-module"}] if kind == "target_c" else []),
            "retained_program": baseline.identity(program), "compiler_output": baseline.identity(path),
            "source": {"path": str(self.source / source)}, "program_key": identifier, "mode": mode,
        }
        (directory / "INTENT.json").write_text("{}")
        (directory / "RESULT.json").write_text(json.dumps(record))
        (self.build / ("." + output + ".cmd")).write_text(
            "savedcmd_" + output + " := " + str(self.wrappers["target"]) + " -c -o " + output + " " + str(self.source / source) + "\n")

    def collect(self):
        return full.collect(self.build, self.source, self.ledger, self.manifest, self.wrappers, self.output)[1]

    def edit_record(self, identifier, change):
        path = self.ledger / identifier / "RESULT.json"
        record = json.loads(path.read_text())
        change(record)
        path.write_text(json.dumps(record))

    def test_c_assembly_and_later_link_derivative_close(self):
        (self.build / "linked.o").write_bytes(b"linked object")
        (self.build / ".linked.o.cmd").write_text("savedcmd_linked.o := /tool/ld.lld -r -o linked.o main.o entry.o\n")
        result = self.collect()
        self.assertEqual(result["counts"]["target_c"], 1)
        self.assertEqual(result["counts"]["target_assembly"], 1)
        self.assertEqual(result["fallback_c_units"], 0)
        self.assertEqual(result["counts"]["objects"], 3)

    def test_unregistered_direct_target_compiler_is_rejected(self):
        (self.build / ".main.o.cmd").write_text("savedcmd_main.o := /tool/clang -c -o main.o main.c\n")
        with self.assertRaisesRegex(ValueError, "unregistered compiler"):
            self.collect()

    def test_same_object_suffix_does_not_establish_provenance(self):
        (self.build / "hidden.o").write_bytes(b"unaccounted object")
        with self.assertRaisesRegex(ValueError, "no compiler or derivation provenance"):
            self.collect()

    def test_missing_terminal_receipt_is_rejected(self):
        (self.ledger / "c01" / "RESULT.json").unlink()
        with self.assertRaisesRegex(ValueError, "no terminal receipt"):
            self.collect()

    def test_false_semantic_roundtrip_is_rejected(self):
        self.edit_record("c01", lambda record: record.update(canonical_roundtrip_equal=False))
        with self.assertRaisesRegex(ValueError, "exact semantic roundtrip"):
            self.collect()

    def test_original_c_fallback_is_rejected(self):
        self.edit_record("c01", lambda record: record.update(fallback_c_compilation=True))
        with self.assertRaisesRegex(ValueError, "compiler fallback"):
            self.collect()

    def test_replay_c_frontend_invocation_is_rejected(self):
        def change(record):
            record["mode"] = "replay"
            record["commands"].append({"name": "clang-c-frontend-only"})
        self.edit_record("c01", change)
        with self.assertRaisesRegex(ValueError, "original source frontend"):
            self.collect()

    def test_retained_hia_drift_is_rejected(self):
        (self.root / "c01.hia.json.gz").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "retained HIA"):
            self.collect()

    def test_expected_negative_probe_is_not_payload_fallback(self):
        directory = self.ledger / "probe01"
        directory.mkdir()
        record = {
            "schema": "hepta.hia.system-compiler-invocation.v1", "id": "probe01",
            "manifest": baseline.identity(self.manifest),
            "classification": {"kind": "compiler_capability_probe"}, "status": "COMPILER_REJECTED",
            "payload_failure": False,
            "commands": [{"name": "trusted-compiler_capability_probe", "exit_code": 1}],
        }
        (directory / "INTENT.json").write_text("{}")
        (directory / "RESULT.json").write_text(json.dumps(record))
        self.assertEqual(self.collect()["counts"]["compiler_capability_probe"], 1)

    def test_postprocessing_is_not_confused_with_cc_output(self):
        (self.build / "main.o").write_bytes(b"objtool modified the compiler result")
        result = self.collect()
        self.assertTrue(result["final_cc_object_hash_is_not_assumed_equal_after_objtool_or_record_mcount"])
        self.assertEqual(result["counts"]["objects"], 2)


if __name__ == "__main__":
    unittest.main()
