"""One Rust Machine for chains, v8 returned loans, and exact stopped ledgers.

The typed-root collision pipeline adapts the independent PR334 donor fixture;
v8 extends it with returned-child transfer, nested formal scope and scalar
observation. Native controls can execute the same public scalar entry.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from tests import test_hia_returned_loans as returned
from tests import test_hia_rust_owned_cfg as cfg
from tests import test_hia_rust_returned_loans as v8_tests
from tests.test_hia_rust_owned_memory import recursive_chain
from tests.test_hia_program import b, c, f, i, ret, jump, branch
from tools.qualify_hia_returned_loans_cross import (
    corpus_document, case_plan, trap_plan, independent_spec, vm_projection,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "bounded-cfg-owned-memory-v5"
PIPELINE_BYTES = (44, 7, 7, 44, 11, 88, 5)
PIPELINE_RESULT = sum(value << (8 * index) for index, value in enumerate(PIPELINE_BYTES))


def chain_bulk_pipeline(construction="child", *, version=8):
    """Chain #2 encloses owner #1 while independent source is byte owner #2.

    Both a suspended chain-head parent and its mutable child cross the CFG.
    The bulk helper returns its declared parameter or direct child in v8.
    A final aliased reader uses the sibling formal while a shared child lives.
    The seven independently known output bytes fit one scalar u64 for native
    wrappers, with the payload extent occupying the last byte.
    """
    if construction not in ("forward", "child") or version not in (7, 8):
        raise ValueError("finite chain pipeline construction/version")
    params = [("dst", "mutbuf"), ("src", "readbuf")]
    operations = [c("zero", "usize", 0), c("one", "usize", 1), c("two", "usize", 2),
        c("four", "usize", 4), c("five", "usize", 5), c("byte", "u8", 7),
        i("buffer.fill", ["dst", "byte"]), i("buffer.copy", ["dst", "src", "five"]),
        i("buffer.copy_range", ["dst", "src", "one", "zero", "four"]),
        i("buffer.move_within", ["dst", "zero", "one", "four"]),
        i("buffer.swap", ["dst", "zero", "four"]),
        i("buffer.fill_range", ["dst", "one", "two", "byte"])]
    if version == 8 and construction == "child":
        operations += [i("borrow.mut", ["dst"], [("result", "mutbuf")])]
    transform = f("transform", params, ["mutbuf"] if version == 8 else [],
                  ["read", "write", "trap"], [b("entry", params, operations,
                  ret("result" if construction == "child" else "dst") if version == 8 else ret())])
    if version == 8:
        transform["return_loans"] = ["dst"]
    reader = deepcopy(cfg.aliased_read_call()["functions"][0])
    setup = [c("size", "usize", 5), i("chain.empty", out=[("empty", "chain")]),
        i("buffer.new", ["size"], [("payload", "buffer")]),
        i("buffer.new", ["size"], [("source", "buffer")]),
        i("borrow.mut", ["source"], [("writer", "mutbuf")])]
    for index, byte in enumerate((11, 22, 33, 44, 55)):
        setup += [c("index" + str(index), "usize", index), c("byte" + str(index), "u8", byte),
                  i("buffer.store", ["writer", "index" + str(index), "byte" + str(index)])]
    setup += [i("loan.end", ["writer"]),
        i("chain.try_push", ["empty", "payload"],
          [("chain", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["fallback"]), i("chain.head_mut", ["chain"], [("parent", "mutbuf")]),
        i("borrow.mut", ["parent"], [("child", "mutbuf")]),
        i("borrow.read", ["source"], [("reader", "readbuf")])]
    output = [("returned", "mutbuf")] if version == 8 else []
    body = [i("call", ["destination", "source_view"], output, function="transform")]
    view = "returned" if version == 8 else "destination"
    body += [i("buffer.len", [view], [("extent", "usize")])]
    for index in range(5):
        body += [c("at" + str(index), "usize", index),
                 i("buffer.load", [view, "at" + str(index)], [("out" + str(index), "u8")])]
    if version == 8:
        body += [i("loan.end", ["returned"])]
    body += [i("loan.end", ["destination"]),
        i("call", ["head", "head"], [("aliased_sum", "u8")], function=reader["name"]),
        i("loan.end", ["head"]), i("loan.end", ["source_view"]),
        i("owner.drop", ["root"]), i("owner.drop", ["source_owner"]), c("zero_result", "u64", 0)]
    prior = "zero_result"
    for index, value in enumerate(["out" + str(n) for n in range(5)] + ["aliased_sum", "extent"]):
        body += [i("int.cast", [value], [("wide" + str(index), "u64")], mode="checked"),
                 c("scale" + str(index), "u64", 1 << (8 * index)),
                 i("int.mul.wrap", ["wide" + str(index), "scale" + str(index)], [("part" + str(index), "u64")]),
                 i("int.add.wrap", [prior, "part" + str(index)], [("sum" + str(index), "u64")])]
        prior = "sum" + str(index)
    edge = ("join", "chain", "source", "parent", "child", "reader")
    outer = f("pipeline", [("condition", "bool")], ["u64"], ["alloc", "read", "write", "trap"], [
        b("entry", [("condition", "bool")], setup, branch("condition", edge, edge)),
        b("join", [("root", "chain"), ("source_owner", "buffer"), ("head", "mutbuf"),
                   ("destination", "mutbuf"), ("source_view", "readbuf")], body, ret(prior))])
    document = returned.document(transform, reader, outer)
    document["schema"] = f"hepta.hia.program.v{version}"
    document["exports"] = ["pipeline"]
    return document


def shared_chain_returns(construction="mixed"):
    """Duplicate actuals retain distinct formal/result handles on a chain head."""
    source = returned.multiple_shared(construction)
    operations = source["functions"][-1]["blocks"][0]["ops"]
    where = next(n for n, op in enumerate(operations) if op["op"] == "borrow.mut")
    operations[where:where] = [i("chain.empty", out=[("empty", "chain")]),
        i("chain.try_push", ["empty", "owner"],
          [("chain", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["fallback"])]
    for op in operations:
        if op["op"] == "borrow.mut" and op["args"] == ["owner"]:
            op["op"], op["args"] = "chain.head_mut", ["chain"]
        elif op["op"] == "owner.drop" and op["args"] == ["owner"]:
            op["args"] = ["chain"]
    return source


def recursive_chain_head(*, depth=3, construction="recursive"):
    source = returned.loan_program("mut", construction)
    operations = source["functions"][-1]["blocks"][0]["ops"]
    where = next(n for n, op in enumerate(operations) if op["op"] == "borrow.mut"
                 and op["out"][0]["name"] == "parent")
    operations[where:where] = [i("chain.empty", out=[("empty", "chain")]),
        i("chain.try_push", ["empty", "owner"],
          [("chain", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["fallback"])]
    for op in operations:
        if op["op"] == "borrow.mut" and op["out"][0]["name"] == "parent":
            op["op"], op["args"] = "chain.head_mut", ["chain"]
        elif op["op"] == "owner.drop" and op["args"] == ["owner"]:
            op["args"] = ["chain"]
        elif op["op"] == "const" and op["out"][0]["name"] == "depth":
            op["attrs"]["value"] = depth
    return source


@unittest.skipUnless(shutil.which("cargo"), "Rust toolchain required")
class RustReturnedChainsParity(unittest.TestCase):
    raw_run = cfg.RustByteOwnerCfgParity.raw_run
    wire = staticmethod(v8_tests.RustReturnedLoansParity.wire)
    shadow = v8_tests.RustReturnedLoansParity.shadow

    @classmethod
    def setUpClass(cls):
        cfg.RustByteOwnerCfgParity.setUpClass.__func__(cls)
        cls.rejections = []

    @classmethod
    def tearDownClass(cls):
        print(f"Rust v5 chain/returned-loan full-ledger observations: {len(cls.observations)}; "
              f"independent refusals: {len(cls.rejections)}")

    def reject_both(self, document):
        raw = self.wire(document)
        error = None
        try:
            verify_program(document)
        except HIAProgramRejected as rejected:
            error = str(rejected)
        entry = document["exports"][0]
        function = next(fn for fn in document["functions"] if fn["name"] == entry)
        arguments = [False if p["type"] == "bool" else 0 for p in function["params"]]
        shadow = self.shadow(document)
        run = self.raw_run(raw, entry, arguments, steps=1, heap=0, fail=1)
        process = lambda p: {"argv": p.args, "returncode": p.returncode,
                             "stdout": p.stdout.decode(), "stderr": p.stderr.decode()}
        row = {"case": self._testMethodName, "raw_input_utf8": raw.decode(),
               "raw_input_sha256": sha256(raw).hexdigest(), "python_error": error,
               "rust_shadow": process(shadow), "rust_execution": process(run)}
        type(self).rejections.append(row)
        self.assertIsNotNone(error, "canonical Python unexpectedly admitted an invalid fixture")
        for result in (shadow, run):
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertTrue(result.stderr.startswith(b"E_HIA_"), result.stderr)
        row["rejected"] = True

    def parity(self, document, entry, arguments, *, steps=10000, heap=32768, fail=None):
        core = verify_program(document)
        type(self).sources[core.sha256] = core.as_dict()
        executed = self.raw_run(core.canonical_bytes, entry, arguments, steps=steps, heap=heap, fail=fail)
        try:
            python = execute_program(core, entry, arguments, max_steps=steps,
                                     max_heap_bytes=heap, allocation_fail_at=fail, max_call_depth=32)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            python = stopped.report
        row = {"test": self.id(), "program_sha256": core.sha256, "entry": entry, "arguments": arguments,
               "policy": {"max_steps": steps, "max_heap_bytes": heap, "allocation_fail_at": fail,
                          "max_call_depth": 32}, "python": python,
               "rust_process": {"argv": executed.args, "returncode": executed.returncode,
                                "stdout": executed.stdout.decode(), "stderr": executed.stderr.decode()}}
        type(self).observations.append(row)
        self.assertEqual(executed.returncode, 0, executed.stderr.decode())
        self.assertEqual(executed.stderr, b"")
        rust = json.loads(executed.stdout)
        row["rust"] = rust
        self.assertEqual(rust["profile"], PROFILE)
        self.assertEqual(rust["schema"], "hepta.hia.rust-byte-owner-execution.v1")
        self.assertEqual(rust["program_sha256"], core.sha256)
        for name in ("status", "steps", "resources"):
            self.assertEqual(json.dumps(rust[name], sort_keys=True), json.dumps(python[name], sort_keys=True), name)
        self.assertEqual(json.dumps(rust.get("values")), json.dumps(python.get("values")))
        self.assertEqual(rust.get("error", {}).get("code"), python.get("error", {}).get("code"))
        for name in ("production_admission_authorized", "native_backend_refinement_proved",
                     "whole_language_soundness_proved", "general_resource_execution"):
            self.assertIs(rust["claims"][name], False)
        for name in ("chain_execution", "interprocedural_chain_execution",
                     "separate_logical_and_storage_identities", "distinct_call_formal_loan_identities"):
            self.assertIs(rust["claims"][name], True)
        if document["schema"] == "hepta.hia.program.v8":
            self.assertIs(rust["claims"]["parameter_bound_returned_loans_execution"], True)
        else:
            self.assertNotIn("parameter_bound_returned_loans_execution", rust["claims"])
        row["matched"] = True
        return rust

    def test_exact_cross_target_corpus_and_independent_allocator_oracles(self):
        source = corpus_document()
        for case in case_plan():
            report = self.parity(source, case["function"], case["arguments"], fail=case["failure"] or None)
            expected = independent_spec(case)
            self.assertEqual(report["values"], [expected["result"]])
            projected = vm_projection({**report, "result": report["values"][0]})
            self.assertEqual(projected, {key: expected[key] for key in projected})
        for case in trap_plan():
            report = self.parity(source, case["function"], case["arguments"], fail=case["failure"] or None)
            self.assertEqual(report["status"], "trapped")
            self.assertEqual(report["error"]["code"], case["trap_code"])

    def test_chain_storage_id_collision_bulk_return_and_readonly_alias_scope(self):
        for version in (7, 8):
            for construction in ("forward", "child") if version == 8 else ("forward",):
                for condition in (False, True):
                    report = self.parity(chain_bulk_pipeline(construction, version=version), "pipeline", [condition])
                    self.assertEqual(report["values"], [PIPELINE_RESULT])
                    self.assertEqual(report["resources"]["peak_bytes"], 34)
                    self.assertEqual(report["resources"]["allocations"], 3)
                    self.assertEqual(report["resources"]["frees"], 3)
                    self.assertEqual(report["resources"]["loans_started"], 6 if version == 8 else 5)

    def test_all_step_cuts_and_allocation_or_heap_stops_preserve_real_ledgers(self):
        for construction in ("forward", "child"):
            source = chain_bulk_pipeline(construction)
            complete = self.parity(source, "pipeline", [True])
            for limit in range(1, complete["steps"] + 1):
                self.parity(source, "pipeline", [True], steps=limit)
            for heap in (0, 4, 5, 9, 10, 33, 34):
                for fail in (None, 1, 2, 3, 4):
                    self.parity(source, "pipeline", [True], heap=heap, fail=fail)

    def test_shared_formal_forward_direct_and_mixed_results_remain_independent(self):
        for construction in ("forward", "children", "mixed"):
            source = shared_chain_returns(construction)
            complete = self.parity(source, "shared", [71])
            self.assertEqual(complete["values"], [142])
            self.assertEqual(complete["resources"]["loans_started"], 3)
            for limit in range(1, complete["steps"] + 1):
                self.parity(source, "shared", [71], steps=limit)
            for fail in (1, 2, 3):
                self.parity(source, "shared", [71], fail=fail)

    def test_original_parameter_identity_across_chain_head_recursion(self):
        for construction in ("forward", "child", "cfg", "recursive"):
            for depth in (0, 1, 4, 30, 31):
                source = recursive_chain_head(depth=depth, construction=construction)
                report = self.parity(source, source["exports"][0], [1, 250])
                if construction == "recursive" and depth >= 31:
                    self.assertEqual(report["error"]["code"], "calls")
                    self.assertEqual(report["resources"]["live_local_loans"], 1)
                    self.assertEqual(report["resources"]["live_chain_nodes"], 1)
                else:
                    self.assertEqual(report["values"], [255])
                    self.assertEqual(report["resources"]["loans_started"], 3)
        source = recursive_chain_head(depth=3)
        complete = self.parity(source, source["exports"][0], [1, 250])
        for limit in range(1, complete["steps"] + 1):
            self.parity(source, source["exports"][0], [1, 250], steps=limit)

    def test_owner_chain_recursion_and_interrupted_destructors_still_share_machine(self):
        source = recursive_chain()
        source["schema"] = "hepta.hia.program.v8"
        for depth in (0, 1, 30, 31):
            for fail in (None, 1, 2):
                self.parity(source, "chain_recursion", [depth], fail=fail)
        complete = self.parity(source, "chain_recursion", [1])
        for limit in range(1, complete["steps"] + 1):
            self.parity(source, "chain_recursion", [1], steps=limit)

    def test_returned_chain_child_prevents_shape_change_parent_use_and_aliasing(self):
        operations = [i("owner.drop", ["root"]), i("owner.move", ["root"], [("moved", "chain")]),
            i("chain.pop", ["root"], [("tail", "chain"), ("payload", "buffer"), ("ok", "bool")]),
            i("loan.end", ["head"]), i("loan.end", ["destination"]),
            i("buffer.load", ["head", "invalid_index"], [("bad", "u8")])]
        for operation in operations:
            source = chain_bulk_pipeline()
            body = source["functions"][-1]["blocks"][1]["ops"]
            body[1:1] = [c("invalid_index", "usize", 0), operation]
            self.reject_both(source)
        source = chain_bulk_pipeline()
        source["functions"][-1]["blocks"][1]["ops"][0]["args"] = ["destination", "destination"]
        self.reject_both(source)
        for origin in ("src", "missing", None):
            source = chain_bulk_pipeline()
            source["functions"][0]["return_loans"] = [origin]
            self.reject_both(source)
        source = shared_chain_returns()
        source["functions"][0]["return_loans"] = ["right", "left"]
        self.reject_both(source)

    def test_legacy_unknown_and_public_capability_boundaries_remain_closed(self):
        for version in range(1, 8):
            source = chain_bulk_pipeline()
            source["schema"] = f"hepta.hia.program.v{version}"
            self.reject_both(source)
        for version in range(1, 7):
            source = chain_bulk_pipeline(version=7)
            source["schema"] = f"hepta.hia.program.v{version}"
            self.reject_both(source)
        source = chain_bulk_pipeline()
        source["functions"].append(f("hidden", [], [], [], [b("entry", [], [i("chain.future")], ret())]))
        self.reject_both(source)
        source = chain_bulk_pipeline()
        source["exports"].append("transform")
        self.reject_both(source)


if __name__ == "__main__":
    unittest.main()
