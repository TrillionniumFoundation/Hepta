"""Receipt mutation controls run without a compiler, VM or native executable."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import hia_semantic_gate_receipts as intake


def ledger():
    return {"allocation_attempts": 3, "allocations": 3, "frees": 3,
            "owners_created": 5, "owners_dropped": 5, "live_owners": 0,
            "live_bytes": 0, "peak_bytes": 14, "loans_started": 2, "loans_ended": 2,
            "live_local_loans": 0, "chains_created": 0, "chains_consumed": 0,
            "live_chains": 0, "chain_nodes_created": 0, "chain_nodes_dropped": 0,
            "live_chain_nodes": 0}


def rust_execution():
    return {"schema": "hepta.hia.rust-byte-owner-execution.v1",
            "profile": "bounded-cfg-byte-owner-bulk-v3", "function": "partial_case",
            "program_sha256": "a" * 64, "status": "returned", "values": [177],
            "steps": 60, "max_steps": 100000, "max_heap_bytes": 16777216,
            "max_call_depth": 32, "allocation_fail_at": None, "resources": ledger(),
            "claims": deepcopy(intake._RUST_CLAIMS)}


class SemanticReceiptObservations(unittest.TestCase):
    def test_integer_counts_cannot_be_replaced_with_boolean_json_values(self):
        intake._equal({"counts": [0, 1]}, {"counts": [0, 1]}, "control")
        for candidate in ({"counts": [False, 1]}, {"counts": [0, True]}):
            with self.assertRaises(ValueError):
                intake._equal(candidate, {"counts": [0, 1]}, "control")

    def test_duplicate_and_nonfinite_raw_observations_are_rejected(self):
        self.assertEqual(intake._json(b'{"result":177}'), {"result": 177})
        for raw in (b'{"result":1,"result":177}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError):
                intake._json(raw)

    def test_resource_conservation_and_independent_allocator_counts_are_required(self):
        expected = {"attempts": 3, "allocations": 3, "frees": 3, "live_bytes": 0,
                    "peak_bytes": 14, "logical_owners": 5}
        intake._ledger(ledger(), returned=True, expected=expected)
        for field, value in (("peak_bytes", 15), ("live_bytes", 1), ("live_owners", 1),
                             ("allocations", 4), ("owners_dropped", 4), ("loans_ended", 1),
                             ("live_chains", False), ("chain_nodes_dropped", -1)):
            with self.subTest(field=field):
                changed = ledger()
                changed[field] = value
                with self.assertRaises(ValueError):
                    intake._ledger(changed, returned=True, expected=expected)

    def test_execution_envelope_cannot_change_policy_or_scope(self):
        options = {"max_steps": 100000, "max_heap_bytes": 16777216}
        def validate(report):
            intake._execution(report, rust=True, core_sha="a" * 64, input_sha=None,
                              function="partial_case", options=options, returned=True, result=177)
        validate(rust_execution())
        mutations = [lambda r: r.update(schema="invented"), lambda r: r.update(profile="proved"),
                     lambda r: r.update(status="unknown"), lambda r: r.update(steps=True),
                     lambda r: r.update(max_call_depth=True), lambda r: r.update(allocation_fail_at=1),
                     lambda r: r.update(values=[176]), lambda r: r.update(error={"code": "heap"}),
                     lambda r: r["claims"].update(production_admission_authorized=True)]
        for mutate in mutations:
            changed = rust_execution()
            mutate(changed)
            with self.assertRaises(ValueError):
                validate(changed)

    def test_budget_reason_is_not_a_returned_value_or_an_unrelated_stop(self):
        report = rust_execution()
        report.update(status="budget_exceeded", steps=4, max_steps=3, error={"code": "steps"})
        del report["values"]
        def validate(value):
            intake._execution(value, rust=True, core_sha="a" * 64, input_sha=None,
                              function="partial_case", options={"max_steps": 3, "max_heap_bytes": 16777216},
                              returned=False, error="steps")
        validate(report)
        for mutation in ({"error": {"code": "heap"}}, {"values": [177]}, {"result": 177}):
            with self.assertRaises(ValueError):
                validate(dict(report, **mutation))


class SemanticReceiptProcesses(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-receipt-control-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.argv = ["/actual/clang", "observer.c", "candidate.o", "-o", "candidate"]
        for suffix, data in (("stdout", b'{"result":177}\n'), ("stderr", b""), ("stdin", b"core")):
            (self.directory / ("process-0000." + suffix)).write_bytes(data)
        def descriptor(suffix):
            path = self.directory / ("process-0000." + suffix)
            raw = path.read_bytes()
            return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        self.process = {"argv": self.argv, "status": "completed", "returncode": 0, "seconds": 0.01,
                        "stream_encoding": "utf8_universal_newlines", "stdout": descriptor("stdout"),
                        "stderr": descriptor("stderr"), "stdin": descriptor("stdin")}

    def validate(self, process=None, index=0):
        reader = intake._Retained(self.directory, [process or self.process])
        return reader.process(index, argv=self.argv, stdin=b"core")

    def test_actual_command_identity_includes_compiler_flags_inputs_and_output(self):
        self.assertEqual(self.validate(), b'{"result":177}\n')
        for position, text in ((0, "/other/compiler"), (1, "other.c"), (2, "original.o"), (4, "other")):
            changed = deepcopy(self.process)
            changed["argv"][position] = text
            with self.assertRaises(ValueError):
                self.validate(changed)
        changed = deepcopy(self.process)
        changed["argv"].append("unreported-original.o")
        with self.assertRaises(ValueError):
            self.validate(changed)

    def test_exit_and_index_types_and_stream_byte_bindings_are_exact(self):
        for mutation in ({"returncode": False}, {"seconds": True}, {"seconds": float("inf")},
                         {"status": "running"}):
            with self.assertRaises(ValueError):
                self.validate(dict(self.process, **mutation))
        with self.assertRaises(ValueError):
            self.validate(index=False)
        (self.directory / "process-0000.stdout").write_bytes(b'{"result":178}\n')
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_or_differently_named_stream_is_not_substituted(self):
        changed = deepcopy(self.process)
        changed["stdout"]["path"] = str(self.directory / "other.stdout")
        (self.directory / "other.stdout").write_bytes(b'{"result":177}\n')
        with self.assertRaises(ValueError):
            self.validate(changed)
        (self.directory / "process-0000.stdin").unlink()
        with self.assertRaises((ValueError, OSError)):
            self.validate()

    def test_elf_role_requires_exact_executable_file_and_header(self):
        reader = intake._Retained(self.directory, [self.process])
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        header[16:20] = b"\x03\x00\x3e\x00"
        (self.directory / "candidate").write_bytes(header)
        descriptor = reader.descriptor("candidate")
        reader.executable("candidate", descriptor)
        with self.assertRaises(ValueError):
            reader.executable("other", descriptor)
        (self.directory / "not-elf").write_bytes(b"true\n")
        with self.assertRaises(ValueError):
            reader.executable("not-elf", reader.descriptor("not-elf"))


if __name__ == "__main__":
    unittest.main()
