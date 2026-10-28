"""Independent v2--v7 resource execution, plus finite real native controls.

All vectors below are fixed prospectively; there is no random seed or favorable
case selection. Rust receives canonical Core bytes, never Python results. The
Python VM is a separate oracle, supplemented by explicit byte/ledger assertions
and the recursive-chain qualifier's independent arithmetic specification.

Set HEPTA_RUST_OWNED_EVIDENCE_DIR to a NEW directory to retain requests, complete
responses, canonical programs, actual native artifacts and negative controls.
Budget-stop ledgers compare the two interpreters only: native abort does not
pretend to execute normal-path cleanup. These finite tests are not refinement
or whole-language soundness proofs.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.clang_capture import run_bounded
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import (
    HIAProgramBudgetExceeded, HIAProgramTrap, execute_program,
)
from tests.test_hia_program import b, branch, c, f, i, m, ret
from tests.test_hia_bulk_memory import bulk_program
from tests.test_hia_overlap_move import move_program, empty_program as empty_move_program
from tests.test_hia_swap_v4 import swap_program
from tests.test_hia_offset_copy_v5 import copy_program
from tests.test_hia_range_fill_v6 import fill_program
from tests.test_hia_rust_owned_vm import active_child_alias_call
from tools.qualify_hia_recursive_chain import (
    EXAMPLES, independent_spec, load_examples, vm_ledger,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"
_CLANG_REQUEST = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")
CLANG = shutil.which(_CLANG_REQUEST) or _CLANG_REQUEST
SCHEMA_V7 = "hepta.hia.program.v7"
U64_MAX = (1 << 64) - 1
BYTES = (11, 22, 33, 44, 55)
MOVE_CASES = ((1, 0, 4), (0, 1, 4), (2, 2, 3), (5, 5, 0))
SWAP_CASES = ((0, 4), (4, 0), (2, 2))
COPY_CASES = ((0, 0, 5), (1, 2, 2), (2, 1, 2), (5, 5, 0))
FILL_CASES = ((1, 3, 7), (0, 5, 255), (5, 0, 99))
RANGE_FAILURES = ((6, 0, 0), (0, 6, 0), (5, 0, 1), (0, 5, 1),
                  (4, 0, 2), (0, 4, 2), (0, 0, U64_MAX),
                  (U64_MAX, 0, 0), (0, U64_MAX, 0))
CHAIN_LENGTHS = (0, 1, 3, 17)
CHAIN_FAILURES = tuple(range(1, 9))
PIPELINE_BUDGETS = (1, 4, 20, 25, 30, 35, 40, 45, 50, 60)


def versioned(document, version):
    document = copy.deepcopy(document)
    document["schema"] = f"hepta.hia.program.v{version}"
    return document


def empty_bulk_program():
    return versioned(m(f("empty_bulk", [("size", "usize")], ["u8"],
        ["alloc", "read", "write", "trap"], [
            b("entry", [("size", "usize")], [
                c("zero", "usize", 0), c("byte", "u8", 91),
                i("buffer.new", ["size"], [("source", "buffer")]),
                i("buffer.new", ["size"], [("destination", "buffer")]),
                i("borrow.mut", ["source"], [("writer", "mutbuf")]),
                i("buffer.fill", ["writer", "byte"]), i("loan.end", ["writer"]),
                i("borrow.read", ["source"], [("reader", "readbuf")]),
                i("borrow.mut", ["destination"], [("target", "mutbuf")]),
                i("buffer.copy", ["target", "reader", "zero"]),
                i("loan.end", ["target"]), i("loan.end", ["reader"]),
                i("owner.drop", ["source"]), i("owner.drop", ["destination"]),
            ], ret("byte")),
        ])), 2)


def chain_observation_program(action):
    """Trap at a declared observation point; no invented exceptional cleanup."""
    operations = [
        c("size", "usize", 1), i("chain.empty", out=[("empty", "chain")]),
        i("buffer.new", ["size"], [("payload", "buffer")]),
        i("chain.try_push", ["empty", "payload"],
          [("owned", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
    ]
    if action == "pop":
        operations += [
            i("owner.drop", ["fallback"]),
            i("chain.pop", ["owned"],
              [("tail", "chain"), ("popped", "buffer"), ("present", "bool")]),
            i("borrow.read", ["popped"], [("view", "readbuf")]),
            c("zero", "usize", 0),
            i("buffer.load", ["view", "zero"], [("byte", "u8")]),
        ]
    elif action != "push":
        raise ValueError("unknown observation point")
    return versioned(m(f("observe", [], [], ["alloc", "read", "trap"], [
        b("entry", [], operations, {"op": "trap", "code": "user"}),
    ])), 7)


def two_node_drop_program(payload_size=1):
    # Call-entry tick=1; drop instruction=11; node ticks=12,13; return=15.
    return versioned(m(f("destroy", [], ["u8"], ["alloc", "trap"], [
        b("entry", [], [
            c("size", "usize", payload_size),
            i("chain.empty", out=[("empty", "chain")]),
            i("buffer.new", ["size"], [("first", "buffer")]),
            i("chain.try_push", ["empty", "first"],
              [("one", "chain"), ("fallback1", "buffer"), ("ok1", "bool")]),
            i("owner.drop", ["fallback1"]),
            i("buffer.new", ["size"], [("second", "buffer")]),
            i("chain.try_push", ["one", "second"],
              [("two", "chain"), ("fallback2", "buffer"), ("ok2", "bool")]),
            i("owner.drop", ["fallback2"]),
            i("owner.move", ["two"], [("moved", "chain")]),
            i("owner.drop", ["moved"]), c("answer", "u8", 73),
        ], ret("answer")),
    ])), 7)


def nil_program(head=None):
    operations = [i("chain.empty", out=[("empty", "chain")])]
    if head is not None:
        operations.append(i(head, ["empty"], [("view", "mutbuf" if head.endswith("mut") else "readbuf")]))
        return versioned(m(f("nil", [], [], ["read", "trap"], [
            b("entry", [], operations, {"op": "trap", "code": "user"}),
        ])), 7)
    operations += [
        i("chain.pop", ["empty"], [("tail", "chain"), ("payload", "buffer"), ("ok", "bool")]),
        i("buffer.len", ["payload"], [("size", "usize")]),
        i("owner.drop", ["tail"]), i("owner.drop", ["payload"]),
    ]
    return versioned(m(f("nil", [], ["bool", "usize"], ["alloc"], [
        b("entry", [], operations, ret("ok", "size")),
    ])), 7)


def chain_bulk_pipeline():
    """Distinct chain/buffer roots intentionally have the same numeric id.

    The chain owns buffer #1; independent source is buffer #2; pushed chain is
    chain #2. Root provenance must remain distinct from storage and id numbers.
    Both a suspended mutable parent and its child cross the CFG edge. Callee
    formals exercise all six bulk opcodes, then aliased readonly formals use a
    child while their sibling remains live.
    """
    transform = f("transform", [("dst", "mutbuf"), ("src", "readbuf")], [],
        ["read", "write", "trap"], [b("entry", [("dst", "mutbuf"), ("src", "readbuf")], [
            c("zero", "usize", 0), c("one", "usize", 1), c("two", "usize", 2),
            c("four", "usize", 4), c("five", "usize", 5), c("byte", "u8", 7),
            i("buffer.fill", ["dst", "byte"]),
            i("buffer.copy", ["dst", "src", "five"]),
            i("buffer.copy_range", ["dst", "src", "one", "zero", "four"]),
            i("buffer.move_within", ["dst", "zero", "one", "four"]),
            i("buffer.swap", ["dst", "zero", "four"]),
            i("buffer.fill_range", ["dst", "one", "two", "byte"]),
        ], ret())])
    reader = copy.deepcopy(active_child_alias_call()["functions"][0])
    setup = [
        c("size", "usize", 5), i("chain.empty", out=[("empty", "chain")]),
        i("buffer.new", ["size"], [("payload", "buffer")]),
        i("buffer.new", ["size"], [("source", "buffer")]),
        i("borrow.mut", ["source"], [("writer", "mutbuf")]),
    ]
    for index, byte in enumerate(BYTES):
        setup += [c("index" + str(index), "usize", index), c("byte" + str(index), "u8", byte),
                  i("buffer.store", ["writer", "index" + str(index), "byte" + str(index)])]
    setup += [
        i("loan.end", ["writer"]),
        i("chain.try_push", ["empty", "payload"],
          [("chain", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["fallback"]),
        i("chain.head_mut", ["chain"], [("parent", "mutbuf")]),
        i("borrow.mut", ["parent"], [("child", "mutbuf")]),
        i("borrow.read", ["source"], [("reader", "readbuf")]),
    ]
    body = [i("call", ["destination", "source_view"], function="transform"),
            i("loan.end", ["destination"])]
    for index in range(5):
        body += [c("at" + str(index), "usize", index),
                 i("buffer.load", ["head", "at" + str(index)], [("out" + str(index), "u8")])]
    body += [
        i("call", ["head", "head"], [("aliased_sum", "u8")], function="reader"),
        i("loan.end", ["head"]), i("loan.end", ["source_view"]),
        i("owner.drop", ["root"]), i("owner.drop", ["source_owner"]),
    ]
    edge = ("join", "chain", "source", "parent", "child", "reader")
    outer = f("pipeline", [("condition", "bool")], ["u8"] * 6,
        ["alloc", "read", "write", "trap"], [
            b("entry", [("condition", "bool")], setup, branch("condition", edge, edge)),
            b("join", [("root", "chain"), ("source_owner", "buffer"), ("head", "mutbuf"),
                       ("destination", "mutbuf"), ("source_view", "readbuf")],
              body, ret("out0", "out1", "out2", "out3", "out4", "aliased_sum")),
        ])
    return versioned(m(transform, reader, outer), 7)


def chain_cases():
    cases = []
    for size in CHAIN_LENGTHS:
        cases += [(name, size, 0, 0) for name in
                  ("chain_checksum", "chain_cancel", "chain_head_update", "chain_empty_payloads")]
        cases += [("chain_recover", size, 0, failure) for failure in (0, 2 * size + 2)]
    for failure in CHAIN_FAILURES:
        cases += [(name, 3, 0, failure) for name in
                  ("chain_checksum", "chain_cancel", "chain_head_update")]
    cases += [("chain_empty_payloads", 3, 0, failure) for failure in (1, 2, 3, 4)]
    for size in (0, 3):
        for mode in (0, 1, 2):
            cases += [("chain_task", size, mode, failure) for failure in (0, 1, 2, 7)]
    cases += [("chain_stored_loan", 3, 0, failure) for failure in (0, 1, 2, 7)]
    cases.append(("chain_empty_pop", 0, 0, 0))
    return cases


def descriptor(path):
    path = Path(path)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: NO v2-v7 resource qualification")
class RustOwnedVmExtensions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = 0
        cls.evidence = None
        requested = os.environ.get("HEPTA_RUST_OWNED_EVIDENCE_DIR")
        if requested:
            cls.evidence = Path(requested).absolute()
            cls.evidence.mkdir(parents=True, exist_ok=False)
            (cls.evidence / "cores").mkdir()
            (cls.evidence / "artifacts").mkdir()
            cls._write_json("plan.json", {
                "schema": "hepta.test.rust-owned-extensions-plan.v1", "random_seed": None,
                "selection": "fixed vectors; all unsuccessful attempts retained",
                "bytes": BYTES, "move_cases": MOVE_CASES, "swap_cases": SWAP_CASES,
                "copy_cases": COPY_CASES, "fill_cases": FILL_CASES,
                "range_failures": RANGE_FAILURES, "chain_cases": chain_cases(),
                "pipeline_budgets": PIPELINE_BUDGETS, "drop_budgets": list(range(10, 16)),
                "test_source": descriptor(__file__),
                "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            })
        command = ["cargo", "build", "--locked", "--offline", "--manifest-path", str(MANIFEST)]
        built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=240)
        if cls.evidence:
            cls._write_json("rust-build.json", {"argv": command, "returncode": built.returncode,
                                               "stdout": built.stdout, "stderr": built.stderr})
        if built.returncode:
            raise AssertionError("Rust build failed:\n" + built.stderr[-6000:])
        metadata = subprocess.run([
            "cargo", "metadata", "--no-deps", "--format-version", "1", "--locked", "--offline",
            "--manifest-path", str(MANIFEST),
        ], cwd=ROOT, capture_output=True, text=True, check=True, timeout=30)
        cls.executable = Path(json.loads(metadata.stdout)["target_directory"]) / "debug" / "hia-core-shadow"
        cls.binary = descriptor(cls.executable)
        cls.programs = load_examples()
        if cls.evidence:
            cls._write_json("rust-binary.json", cls.binary)

    @classmethod
    def _write_json(cls, name, value):
        with (cls.evidence / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")

    @classmethod
    def tearDownClass(cls):
        if cls.evidence:
            cls._write_json("execution-finished.json", {
                "schema": "hepta.test.rust-owned-extensions-finished.v1", "records": cls.records,
                "rust_binary_unchanged": descriptor(cls.executable) == cls.binary,
                "meaning": "test class finished; unittest terminal report determines pass/fail",
            })

    def record(self, kind, value, core=None):
        cls = type(self)
        cls.records += 1
        if cls.evidence is None:
            return
        if core is not None:
            path = cls.evidence / "cores" / (core.sha256 + ".json")
            if not path.exists():
                with path.open("xb") as stream:
                    stream.write(core.canonical_bytes)
            value = {"core_sha256": core.sha256, **value}
        cls._write_json(f"case-{cls.records:05d}.json", {"kind": kind, "test": self.id(), **value})

    def retain(self, path):
        identity = descriptor(path)
        if self.evidence:
            destination = self.evidence / "artifacts" / (identity["sha256"] + "-" + Path(path).name)
            if not destination.exists():
                with destination.open("xb") as stream:
                    stream.write(Path(path).read_bytes())
            identity["retained_path"] = str(destination.relative_to(self.evidence))
        return identity

    def rust_process(self, document, function, args, options=None):
        raw = document if isinstance(document, bytes) else json.dumps(document).encode()
        argv = [str(self.executable), "--owned-run", function, json.dumps(args)]
        if options is not None:
            argv.append(json.dumps(options))
        try:
            return subprocess.run(argv, input=raw, cwd=ROOT, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            self.record("rust-timeout", {"argv": argv, "timeout_seconds": 30,
                "input_sha256": hashlib.sha256(raw).hexdigest(),
                "stdout": (error.stdout or b"").decode(errors="replace"),
                "stderr": (error.stderr or b"").decode(errors="replace")})
            raise

    def assert_parity(self, document, function, args, **options):
        core = verify_program(document)
        options = {"max_steps": 100_000, "max_heap_bytes": 16 * 1024 * 1024, **options}
        observed = self.rust_process(core.canonical_bytes, function, args, options)
        try:
            python = execute_program(core, function, args, max_call_depth=32, **options)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            python = stopped.report
        self.record("rust-python", {
            "function": function, "arguments": args, "options": options,
            "returncode": observed.returncode, "stdout": observed.stdout.decode(errors="replace"),
            "stderr": observed.stderr.decode(errors="replace"), "python": python,
        }, core)
        self.assertEqual(observed.returncode, 0, observed.stderr.decode(errors="replace"))
        rust = json.loads(observed.stdout)
        self.assertEqual(rust["schema"], "hepta.hia.rust-owned-execution.v2")
        self.assertEqual(rust["program_schema"], core.as_dict()["schema"])
        for field in ("status", "steps", "resources", "program_sha256"):
            self.assertEqual(rust[field], python[field], field)
        if rust["status"] == "returned":
            self.assertEqual(rust["values"], python["values"])
        else:
            self.assertEqual(rust["error"]["code"], python["error"]["code"])
        for claim in ("finite_primitive_resource_execution", "primitive_v1_v7_resource_execution",
                      "recursive_buffer_chains_supported"):
            self.assertTrue(rust["claims"][claim])
        for claim in ("production_admission_authorized", "whole_language_soundness_proved",
                      "native_backend_refinement_proved"):
            self.assertFalse(rust["claims"][claim])
        self.assertNotIn("finite_v1_byte_resource_execution", rust["claims"])
        self.assertNotIn("later_isa_versions_supported", rust["claims"])
        return rust

    def assert_clean(self, report):
        data = report["resources"]
        for name in ("live_bytes", "live_owners", "live_local_loans"):
            self.assertEqual(data[name], 0, name)
        self.assertEqual(data["allocations"], data["frees"])
        self.assertEqual(data["owners_created"], data["owners_dropped"])
        if "live_chains" in data:
            self.assertEqual(data["live_chains"], 0)
            self.assertEqual(data["live_chain_nodes"], 0)
            self.assertEqual(data["chains_created"], data["chains_consumed"])

    def assert_resources(self, report, **expected):
        for name, value in expected.items():
            self.assertEqual(report["resources"][name], value, name)

    def assert_refused(self, document, function="pipeline", args=None):
        with self.assertRaises(HIAProgramRejected):
            verify_program(document)
        observed = self.rust_process(document, function, [] if args is None else args)
        self.record("admission-negative", {"document": document, "function": function,
            "arguments": [] if args is None else args, "returncode": observed.returncode,
            "stdout": observed.stdout.decode(errors="replace"), "stderr": observed.stderr.decode(errors="replace")})
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(observed.stdout, b"")
        self.assertIn(b"E_HIA", observed.stderr)

    def test_all_six_bulk_operations_keep_introduction_and_later_version_meanings(self):
        cases = ((bulk_program, 2, "bulk", [5, 5, 197], 197),
                 (move_program, 3, "move_bytes", [5, 1, 0, 4, 2], 22),
                 (swap_program, 4, "swap_bytes", [5, 0, 4, 0], 55),
                 (copy_program, 5, "copy_offset", [5, 1, 2, 2, 1], 33),
                 (fill_program, 6, "fill_range", [5, 1, 3, 7, 2], 7))
        for factory, minimum, function, args, expected in cases:
            for version in range(minimum, 8):
                with self.subTest(function=function, version=version):
                    report = self.assert_parity(versioned(factory(), version), function, args)
                    self.assertEqual(report["values"], [expected])
                    self.assert_clean(report)
                    self.assertEqual("live_chains" in report["resources"], version == 7)
            for version in range(1, minimum):
                with self.subTest(refused_function=function, version=version):
                    self.assert_refused(versioned(factory(), version), function, args)

    def test_v2_fill_copy_zero_length_bounds_refusal_and_stopped_budgets(self):
        for args, value in (([1, 1, 255], 255), ([5, 0, 91], 0), ([5, 3, 91], 91)):
            report = self.assert_parity(bulk_program(), "bulk", args)
            self.assertEqual(report["values"], [value])
            self.assert_resources(report, allocation_attempts=2, allocations=2, frees=2, peak_bytes=2 * args[0])
        empty = self.assert_parity(empty_bulk_program(), "empty_bulk", [0])
        self.assertEqual(empty["values"], [91])
        self.assert_resources(empty, allocation_attempts=0, allocations=0, frees=0, owners_created=2, owners_dropped=2)
        for count in (6, U64_MAX):
            report = self.assert_parity(bulk_program(), "bulk", [5, count, 7])
            self.assertEqual(report["error"]["code"], "bounds")
            self.assert_resources(report, live_owners=2, live_local_loans=2, frees=0)
        for failure in (1, 2, 3):
            report = self.assert_parity(bulk_program(), "bulk", [5, 5, 7], allocation_fail_at=failure)
            if failure <= 2:
                self.assertEqual(report["error"]["code"], "allocation")
                self.assert_resources(report, allocation_attempts=failure, allocations=failure - 1,
                                      live_owners=failure - 1, frees=0)
            else:
                self.assert_clean(report)
        for limit in (2, 3, 8, 16):
            self.assert_parity(bulk_program(), "bulk", [5, 5, 7], max_steps=limit)
        stopped = self.assert_parity(bulk_program(), "bulk", [5, 5, 7], max_heap_bytes=9)
        self.assertEqual(stopped["error"]["code"], "heap")
        self.assert_resources(stopped, allocation_attempts=1, allocations=1, live_bytes=5, frees=0)

    def test_v3_memmove_checks_every_result_byte_and_overflow_safe_ranges(self):
        for destination, source, count in MOVE_CASES:
            expected = list(BYTES)
            expected[destination:destination + count] = list(BYTES)[source:source + count]
            for probe, byte in enumerate(expected):
                with self.subTest(destination=destination, source=source, count=count, probe=probe):
                    report = self.assert_parity(move_program(), "move_bytes", [5, destination, source, count, probe])
                    self.assertEqual(report["values"], [byte])
                    self.assert_clean(report)
        empty = self.assert_parity(empty_move_program(), "empty", [0])
        self.assert_resources(empty, allocations=0, frees=0, owners_created=1, owners_dropped=1)
        for destination, source, count in RANGE_FAILURES:
            report = self.assert_parity(move_program(), "move_bytes", [5, destination, source, count, 0])
            self.assertEqual(report["error"]["code"], "bounds")
            self.assert_resources(report, live_bytes=5, live_local_loans=1, frees=0)

    def test_v4_swap_distinct_identical_and_out_of_range_indices(self):
        for left, right in SWAP_CASES:
            expected = list(BYTES)
            expected[left], expected[right] = expected[right], expected[left]
            for probe, byte in enumerate(expected):
                report = self.assert_parity(swap_program(), "swap_bytes", [5, left, right, probe])
                self.assertEqual(report["values"], [byte])
                self.assert_clean(report)
        for left, right in ((5, 0), (0, 5), (U64_MAX, 0), (0, U64_MAX)):
            report = self.assert_parity(swap_program(), "swap_bytes", [5, left, right, 0])
            self.assertEqual(report["error"]["code"], "bounds")
            self.assert_resources(report, live_bytes=5, frees=0)

    def test_v5_distinct_owner_copy_offsets_zero_length_and_bounds(self):
        for destination, source, count in COPY_CASES:
            expected = [0] * 5
            expected[destination:destination + count] = BYTES[source:source + count]
            for probe, byte in enumerate(expected):
                report = self.assert_parity(copy_program(), "copy_offset", [5, destination, source, count, probe])
                self.assertEqual(report["values"], [byte])
                self.assert_clean(report)
        for destination, source, count in RANGE_FAILURES:
            report = self.assert_parity(copy_program(), "copy_offset", [5, destination, source, count, 0])
            self.assertEqual(report["error"]["code"], "bounds")
            self.assert_resources(report, live_bytes=10, live_local_loans=2, frees=0)

    def test_v6_partial_fill_and_empty_owner_preserve_untouched_bytes(self):
        for offset, count, byte in FILL_CASES:
            expected = [0] * 5
            expected[offset:offset + count] = [byte] * count
            for probe, value in enumerate(expected):
                report = self.assert_parity(fill_program(), "fill_range", [5, offset, count, byte, probe])
                self.assertEqual(report["values"], [value])
                self.assert_clean(report)
        empty = self.assert_parity(fill_program(read=False), "fill_range", [0, 0, 0, 7, 0])
        self.assertEqual(empty["values"], [9])
        self.assert_resources(empty, allocation_attempts=0, allocations=0, frees=0)
        for size, offset, count in ((0, 1, 0), (5, 6, 0), (5, 4, 2), (5, 2, U64_MAX), (5, U64_MAX, 0)):
            report = self.assert_parity(fill_program(read=False), "fill_range", [size, offset, count, 7, 0])
            self.assertEqual(report["error"]["code"], "bounds")

    def test_chain_and_buffer_id_collision_cross_cfg_call_and_alias_formals(self):
        for condition in (False, True):
            report = self.assert_parity(chain_bulk_pipeline(), "pipeline", [condition])
            self.assertEqual(report["values"], [44, 7, 7, 44, 11, 88])
            self.assert_clean(report)
            self.assert_resources(report, allocations=3, frees=3, peak_bytes=34,
                                  chain_nodes_created=1, chain_nodes_dropped=1,
                                  loans_started=5, loans_ended=5)
        for limit in PIPELINE_BUDGETS:
            self.assert_parity(chain_bulk_pipeline(), "pipeline", [True], max_steps=limit)
        for failure in (1, 2, 3):
            report = self.assert_parity(chain_bulk_pipeline(), "pipeline", [True], allocation_fail_at=failure)
            self.assertEqual(report["status"], "trapped")
            self.assertEqual(report["error"]["code"], "bounds" if failure == 3 else "allocation")

    def test_v1_aliased_readonly_formals_keep_independent_child_scope(self):
        for shared in (False, True):
            for nested in (False, True):
                for cross_block in (False, True):
                    report = self.assert_parity(active_child_alias_call(
                        shared_actual=shared, nested=nested, cross_block=cross_block), "outer", [])
                    self.assertEqual(report["values"], [82])
                    self.assert_resources(report, loans_started=3 if shared else 2,
                                          live_local_loans=0, frees=1)
                    self.assertNotIn("live_chains", report["resources"])

    def test_chain_success_fallback_and_failed_header_internal_empty_owner(self):
        success = self.assert_parity(chain_observation_program("push"), "observe", [])
        self.assertEqual(success["error"]["code"], "user")
        self.assert_resources(success, allocation_attempts=2, allocations=2, frees=0,
            owners_created=3, owners_dropped=0, live_owners=3, live_bytes=25,
            chains_created=2, chains_consumed=1, live_chains=1, live_chain_nodes=1)
        failed = self.assert_parity(chain_observation_program("push"), "observe", [], allocation_fail_at=2)
        self.assertEqual(failed["error"]["code"], "user")
        self.assert_resources(failed, allocation_attempts=2, allocations=1, frees=0,
            owners_created=2, owners_dropped=1, live_owners=1, live_bytes=1,
            chains_created=2, chains_consumed=1, live_chains=1, live_chain_nodes=0)
        heap = self.assert_parity(chain_observation_program("push"), "observe", [], max_heap_bytes=24)
        self.assertEqual(heap["error"]["code"], "heap")
        self.assert_resources(heap, allocation_attempts=1, owners_created=1, owners_dropped=0,
                              live_bytes=1, chains_created=1, chains_consumed=0, live_chains=1)

    def test_pop_frees_only_header_and_nil_creates_real_empty_capabilities(self):
        popped = self.assert_parity(chain_observation_program("pop"), "observe", [])
        self.assertEqual(popped["error"]["code"], "user")
        self.assert_resources(popped, allocations=2, frees=1, live_bytes=1, live_owners=1,
            owners_created=3, owners_dropped=2, chains_created=3, chains_consumed=2,
            live_chains=1, chain_nodes_created=1, chain_nodes_dropped=1,
            loans_started=1, loans_ended=0, live_local_loans=1)
        empty = self.assert_parity(nil_program(), "nil", [])
        self.assertEqual(empty["values"], [False, 0])
        self.assertEqual(empty["steps"], 7)
        self.assert_resources(empty, allocation_attempts=0, allocations=0, frees=0,
            owners_created=1, owners_dropped=1, chains_created=2, chains_consumed=2)
        self.assert_clean(empty)
        for operation in ("chain.head_read", "chain.head_mut"):
            trapped = self.assert_parity(nil_program(operation), "nil", [])
            self.assertEqual(trapped["error"]["code"], "bounds")
            self.assert_resources(trapped, loans_started=0, live_local_loans=0,
                                  live_chains=1, allocation_attempts=0)

    def test_iterative_drop_budget_stops_preserve_partial_header_and_payload_ledger(self):
        for payload_size in (0, 1):
            for limit in range(10, 16):
                report = self.assert_parity(two_node_drop_program(payload_size), "destroy", [], max_steps=limit)
                destroyed = 0 if limit <= 11 else 1 if limit == 12 else 2
                consumed = 2 if limit == 10 else 3
                self.assert_resources(report,
                    owners_created=6, owners_dropped=2 + 2 * destroyed,
                    live_owners=4 - 2 * destroyed,
                    allocations=2 + 2 * bool(payload_size),
                    frees=destroyed * (1 + bool(payload_size)),
                    live_bytes=(2 - destroyed) * (24 + payload_size),
                    peak_bytes=2 * (24 + payload_size), chains_created=3,
                    chains_consumed=consumed, live_chains=3 - consumed,
                    chain_nodes_created=2, chain_nodes_dropped=destroyed,
                    live_chain_nodes=2 - destroyed)
                self.assertEqual(report["steps"], min(limit + 1, 15))
                self.assertEqual(report["status"], "returned" if limit == 15 else "budget_exceeded")
                if limit == 15:
                    self.assertEqual(report["values"], [73])
                    self.assert_clean(report)
                else:
                    self.assertEqual(report["error"]["code"], "steps")
        for limit, attempts, bytes_live, nodes in ((24, 1, 1, 0), (25, 2, 25, 1), (49, 3, 26, 1)):
            stopped = self.assert_parity(two_node_drop_program(), "destroy", [], max_heap_bytes=limit)
            self.assertEqual(stopped["error"]["code"], "heap")
            self.assert_resources(stopped, allocation_attempts=attempts, live_bytes=bytes_live,
                                  live_chain_nodes=nodes, frees=0)

    def test_fixed_chain_and_composite_corpus_matches_independent_arithmetic_spec(self):
        for function, size, mode, failure in chain_cases():
            selected = "composite_v2" if function in {"chain_task", "chain_stored_loan"} else "core_v7"
            args = [] if function == "chain_empty_pop" else [size, mode] if function == "chain_task" else [size]
            with self.subTest(function=function, size=size, mode=mode, failure=failure):
                report = self.assert_parity(self.programs[selected], function, args, allocation_fail_at=failure or None)
                ledger = vm_ledger({**report, "result": report["values"][0]})
                self.assertEqual(ledger, independent_spec(function, size, mode, failure))
                self.assert_clean(report)

    def test_old_versions_effect_forgery_and_borrowed_chain_consumption_refuse(self):
        for version in range(1, 7):
            self.assert_refused(versioned(two_node_drop_program(), version), "destroy", [])
        self.assert_refused(versioned(bulk_program(), 8), "bulk", [5, 5, 7])
        for mutation in ("missing_effect", "forged_attribute", "copy_alias", "suspended_parent", "borrowed_chain_drop", "uncalled_bad_body"):
            document = chain_bulk_pipeline()
            transform, _, outer = document["functions"]
            if mutation == "missing_effect":
                transform["effects"].remove("write")
            elif mutation == "forged_attribute":
                transform["blocks"][0]["ops"][-1]["attrs"]["assumed_in_bounds"] = True
            elif mutation == "copy_alias":
                next(op for op in transform["blocks"][0]["ops"] if op["op"] == "buffer.copy")["args"][1] = "dst"
            elif mutation == "suspended_parent":
                outer["blocks"][1]["ops"][0]["args"][0] = "head"
            elif mutation == "borrowed_chain_drop":
                outer["blocks"][1]["ops"].insert(0, i("owner.drop", ["root"]))
            else:
                document["functions"].append(f("unreached", [], [], [], [
                    b("entry", [], [i("foreign.unchecked")], ret()),
                ]))
            with self.subTest(mutation=mutation):
                self.assert_refused(document, args=[True])

    def native_run(self, argv, *, expected=None, scope="finite native execution"):
        run = run_bounded([str(value) for value in argv], timeout=60,
                          stdout_limit=1_000_000, stderr_limit=1_000_000)
        # Retain generated test artifacts, not installed toolchain payloads.
        executable = (descriptor(argv[0]) if Path(argv[0]).resolve() == Path(CLANG).resolve()
                      else self.retain(argv[0]))
        self.record("native", {"argv": [str(value) for value in argv],
            "executable": executable, "expected": expected, "scope": scope,
            "returncode": run.returncode, "stdout": run.stdout, "stderr": run.stderr})
        return run

    @unittest.skipUnless(shutil.which(CLANG) and platform.system() == "Linux" and
                         platform.machine() in {"x86_64", "amd64"}, "No actual Linux x86-64 Clang: NO native qualification")
    def test_real_native_bulk_values_zero_ranges_and_bounds_abort(self):
        from hepta.hia_program_llvm import build_program_native
        documents = [bulk_program(), move_program(), swap_program(), copy_program(), fill_program(), empty_bulk_program()]
        core = verify_program({"schema": SCHEMA_V7, "module": "native_resource_extensions",
                               "functions": [copy.deepcopy(doc["functions"][0]) for doc in documents]})
        driver_text = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
uint8_t bulk(uint64_t,uint64_t,uint8_t);
uint8_t move_bytes(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
uint8_t swap_bytes(uint64_t,uint64_t,uint64_t,uint64_t);
uint8_t copy_offset(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
uint8_t fill_range(uint64_t,uint64_t,uint64_t,uint8_t,uint64_t);
uint8_t empty_bulk(uint64_t);
int main(int argc,char **argv) {
    struct rlimit no_core={0,0}; setrlimit(RLIMIT_CORE,&no_core);
    if(argc!=7) return 64;
    uint64_t a[5]; for(int k=0;k<5;k++) a[k]=strtoull(argv[k+2],0,10);
    uint8_t result;
    if(!strcmp(argv[1],"bulk")) result=bulk(a[0],a[1],(uint8_t)a[2]);
    else if(!strcmp(argv[1],"move_bytes")) result=move_bytes(a[0],a[1],a[2],a[3],a[4]);
    else if(!strcmp(argv[1],"swap_bytes")) result=swap_bytes(a[0],a[1],a[2],a[3]);
    else if(!strcmp(argv[1],"copy_offset")) result=copy_offset(a[0],a[1],a[2],a[3],a[4]);
    else if(!strcmp(argv[1],"fill_range")) result=fill_range(a[0],a[1],a[2],(uint8_t)a[3],a[4]);
    else if(!strcmp(argv[1],"empty_bulk")) result=empty_bulk(a[0]);
    else return 65;
    printf("%u\n",(unsigned)result); return 0;
}
'''
        positive = [("bulk", [5, 5, 197], 197), ("bulk", [5, 0, 197], 0), ("empty_bulk", [0], 91)]
        for destination, source, count in MOVE_CASES:
            values = list(BYTES)
            values[destination:destination + count] = BYTES[source:source + count]
            positive += [("move_bytes", [5, destination, source, count, probe], byte) for probe, byte in enumerate(values)]
        for left, right in SWAP_CASES:
            values = list(BYTES)
            values[left], values[right] = values[right], values[left]
            positive += [("swap_bytes", [5, left, right, probe], byte) for probe, byte in enumerate(values)]
        for destination, source, count in COPY_CASES:
            values = [0] * 5
            values[destination:destination + count] = BYTES[source:source + count]
            positive += [("copy_offset", [5, destination, source, count, probe], byte) for probe, byte in enumerate(values)]
        for offset, count, byte in FILL_CASES:
            values = [0] * 5
            values[offset:offset + count] = [byte] * count
            positive += [("fill_range", [5, offset, count, byte, probe], value) for probe, value in enumerate(values)]
        negative = (("bulk", [5, 6, 7]), ("move_bytes", [5, 6, 0, 0, 0]),
                    ("move_bytes", [5, 0, 0, U64_MAX, 0]), ("swap_bytes", [5, 0, 5, 0]),
                    ("copy_offset", [5, 0, 6, 0, 0]), ("copy_offset", [5, 0, 0, U64_MAX, 0]),
                    ("fill_range", [5, 6, 0, 7, 0]), ("fill_range", [5, 2, U64_MAX, 7, 0]))
        with tempfile.TemporaryDirectory(prefix="hia-owned-extension-native-") as temporary:
            folder = Path(temporary)
            obj, driver, binary = folder / "bulk.o", folder / "driver.c", folder / "bulk-driver"
            build = build_program_native(core, obj, clang=CLANG, kind="object")
            self.record("native-build", {"receipt": build, "artifact": self.retain(obj)}, core)
            driver.write_text(driver_text)
            self.retain(driver)
            linked = self.native_run([CLANG, "-O2", driver, obj, "-o", binary], scope="compile actual emitted object and independent C caller")
            self.assertEqual(linked.returncode, 0, linked.stderr)
            for function, args, expected in positive:
                report = self.assert_parity(core, function, args)
                self.assertEqual(report["values"], [expected])
                observed = self.native_run([binary, function, *args, *([0] * (5 - len(args)))], expected=expected)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertEqual(int(observed.stdout), expected)
            for function, args in negative:
                report = self.assert_parity(core, function, args)
                self.assertEqual(report["error"]["code"], "bounds")
                observed = self.native_run([binary, function, *args, *([0] * (5 - len(args)))],
                    expected="SIGABRT", scope="bounds abort only; no native stopped-budget or cleanup ledger inferred")
                self.assertEqual(observed.returncode, -signal.SIGABRT)

    @unittest.skipUnless(shutil.which(CLANG) and platform.system() == "Linux" and
                         platform.machine() in {"x86_64", "amd64"}, "No actual Linux x86-64 Clang: NO chain allocator qualification")
    def test_real_native_chain_allocator_and_executed_missing_free_controls(self):
        from hepta.hia_program_llvm import build_program_native, emit_program_llvm
        cases = (("chain_checksum", 3, 0, 0), ("chain_checksum", 3, 0, 1),
                 ("chain_checksum", 3, 0, 2), ("chain_checksum", 3, 0, 6),
                 ("chain_cancel", 3, 0, 0), ("chain_recover", 3, 0, 8),
                 ("chain_empty_payloads", 3, 0, 2), ("chain_empty_pop", 0, 0, 0),
                 ("chain_task", 3, 0, 0), ("chain_task", 3, 1, 0),
                 ("chain_task", 3, 2, 0), ("chain_stored_loan", 3, 0, 0))
        with tempfile.TemporaryDirectory(prefix="hia-owned-chain-native-") as temporary:
            folder = Path(temporary)
            objects = {}
            for name, core in self.programs.items():
                obj = folder / (name + ".o")
                build = build_program_native(core, obj, clang=CLANG, kind="object")
                objects[name] = obj
                self.record("native-build", {"receipt": build, "artifact": self.retain(obj)}, core)
            driver = folder / "allocator_driver.c"
            # Existing independent observer; no Python/Rust runtime implementation is shared.
            driver.write_bytes((EXAMPLES / "allocator_driver.c").read_bytes())
            self.retain(driver)
            flags = ["-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free"]
            binary = folder / "chain-driver"
            linked = self.native_run([CLANG, *flags, driver, objects["core_v7"], objects["composite_v2"], "-o", binary])
            self.assertEqual(linked.returncode, 0, linked.stderr)
            for function, size, mode, failure in cases:
                expected = independent_spec(function, size, mode, failure)
                selected = "composite_v2" if function in {"chain_task", "chain_stored_loan"} else "core_v7"
                args = [] if function == "chain_empty_pop" else [size, mode] if function == "chain_task" else [size]
                rust = self.assert_parity(self.programs[selected], function, args, allocation_fail_at=failure or None)
                self.assertEqual(vm_ledger({**rust, "result": rust["values"][0]}), expected)
                observed = self.native_run([binary, function, size, mode, failure], expected=expected)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertEqual(json.loads(observed.stdout), expected)
            original = emit_program_llvm(self.programs["core_v7"]).text
            for label, needle, remaining_bytes in (
                ("missing-header-free", "  call void @free(ptr %head) nobuiltin", 72),
                ("missing-payload-free", "  call void @free(ptr %payload_ptr) nobuiltin", 3),
            ):
                self.assertIn(needle, original)
                mutant, executable = folder / (label + ".ll"), folder / label
                mutant.write_text(original.replace(needle, "  ; deliberately removed free for negative control"))
                self.retain(mutant)
                compiled = self.native_run([CLANG, *flags, driver, mutant, objects["composite_v2"], "-o", executable],
                    scope="deliberately corrupted emitted LLVM; never submitted for production admission")
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                observed = self.native_run([executable, "chain_cancel", 3, 0, 0],
                    expected={"unchanged_result": 1, "live_bytes": remaining_bytes},
                    scope="executed leak mutant must be detected by independent allocator ledger")
                self.assertEqual(observed.returncode, 0, observed.stderr)
                actual = json.loads(observed.stdout)
                self.assertEqual(actual["result"], 1)
                self.assertEqual(actual["live_bytes"], remaining_bytes)
                self.assertNotEqual(actual, independent_spec("chain_cancel", 3))


if __name__ == "__main__":
    unittest.main()
