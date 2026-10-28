"""Independent Rust v8 admission and full-ledger returned-loan execution.

These tests use the real Rust binary and the canonical Python implementation.
They do not pass a Python admission receipt into the independent Rust parser.
"""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from tests import test_hia_returned_loans as returned
from tests import test_hia_rust_owned_cfg as cfg
from tests import test_hia_rust_bulk_vm as bulk
from tests.test_hia_program import b, c, f, i, ret, jump, branch

ROOT = Path(__file__).resolve().parents[1]


def changed_origin_join(*, returns_loan=True):
    """Both edges agree on the graph but only one preserves original source."""
    params = [("left", "readbuf"), ("right", "readbuf"), ("which", "bool")]
    fn = f("choose", params, ["readbuf"] if returns_loan else [], [], [
        b("entry", params, [], branch("which", ("joined", "left"), ("joined", "right"))),
        b("joined", [("selected", "readbuf")], [], ret("selected") if returns_loan else ret()),
    ])
    if returns_loan:
        fn["return_loans"] = ["left"]
    return returned.document(fn)


def returned_loop():
    get = returned.helper("mut", "child")
    fields = [("owner", "buffer"), ("parent", "mutbuf"), ("count", "u32"), ("index", "usize")]
    fn = f("loop", [("iterations", "u32")], ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", [("iterations", "u32")], [
            c("size", "usize", 1), c("index", "usize", 0),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("parent", "mutbuf")]),
        ], jump("condition", "owner", "parent", "iterations", "index")),
        b("condition", [("c_" + n, t) for n, t in fields], [
            c("zero", "u32", 0), i("compare.eq", ["c_count", "zero"], [("done", "bool")]),
        ], branch("done", ("finished", "c_owner", "c_parent", "c_index"),
                            ("body", "c_owner", "c_parent", "c_count", "c_index"))),
        b("body", [("b_" + n, t) for n, t in fields], [
            i("call", ["b_parent"], [("child", "mutbuf")], function=get["name"]),
            i("buffer.load", ["child", "b_index"], [("prior", "u8")]), c("add", "u8", 7),
            i("int.add.wrap", ["prior", "add"], [("next", "u8")]),
            i("buffer.store", ["child", "b_index", "next"]), i("loan.end", ["child"]),
            c("one", "u32", 1), i("int.sub.checked", ["b_count", "one"], [("remaining", "u32")]),
        ], jump("condition", "b_owner", "b_parent", "remaining", "b_index")),
        b("finished", [("f_owner", "buffer"), ("f_parent", "mutbuf"), ("f_index", "usize")], [
            i("buffer.load", ["f_parent", "f_index"], [("answer", "u8")]),
            i("loan.end", ["f_parent"]), i("owner.drop", ["f_owner"]),
        ], ret("answer")),
    ])
    source = returned.document(get, fn)
    source["exports"] = ["loop"]
    return source


@unittest.skipUnless(shutil.which("cargo"), "Rust toolchain required")
class RustReturnedLoansParity(unittest.TestCase):
    execution_profile = "bounded-cfg-byte-owner-loan-returns-v4"
    raw_run = cfg.RustByteOwnerCfgParity.raw_run
    parity = cfg.RustByteOwnerCfgParity.parity

    @classmethod
    def setUpClass(cls):
        cfg.RustByteOwnerCfgParity.setUpClass.__func__(cls)
        cls.rejections = []

    @staticmethod
    def wire(source):
        return json.dumps(source, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def tearDownClass(cls):
        print(f"Rust v8 returned-loan/Python full-ledger parity observations: {len(cls.observations)}")

    def shadow(self, source):
        raw = self.wire(source)
        return subprocess.run([self.executable, "--owned-shadow"], input=raw,
                              capture_output=True, timeout=15, cwd=ROOT)

    def reject_both(self, source):
        with self.assertRaises(HIAProgramRejected) as python:
            verify_program(source)
        raw = self.wire(source)
        rejected = self.shadow(source)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, b"")
        # Even a budget/failure policy that would stop immediately cannot hide
        # a bad uncalled function, malformed annotation or aliasing suffix.
        entry = source.get("exports", [source["functions"][-1]["name"]])[0]
        fn = next(fn for fn in source["functions"] if fn["name"] == entry)
        arguments = [False if p["type"] == "bool" else None if p["type"] == "unit" else 0
                     for p in fn["params"]]
        executed = self.raw_run(raw, entry, arguments, steps=1, fail=1)
        self.assertNotEqual(executed.returncode, 0)
        self.assertEqual(executed.stdout, b"")
        type(self).rejections.append({
            "case": self._testMethodName, "raw_input_utf8": raw.decode(),
            "raw_input_sha256": sha256(raw).hexdigest(), "python_error": str(python.exception),
            "rust_shadow": {"argv": rejected.args, "returncode": rejected.returncode,
                            "stdout": rejected.stdout.decode(), "stderr": rejected.stderr.decode()},
            "rust_execution": {"argv": executed.args, "returncode": executed.returncode,
                               "stdout": executed.stdout.decode(), "stderr": executed.stderr.decode()},
        })

    def test_forward_child_cfg_recursive_and_exact_result_permissions(self):
        for mode in ("read", "mut"):
            for construction in ("forward", "child", "cfg", "recursive"):
                source = returned.loan_program(mode, construction)
                for length, byte in ((1, 0), (2, 37), (19, 253)):
                    with self.subTest(mode=mode, construction=construction, length=length):
                        report = self.parity(source, source["exports"][0], [length, byte])
                        self.assertEqual(report["values"], [(byte + (5 if mode == "mut" else 0)) & 255])
                        self.assertEqual(report["resources"]["loans_started"], 3)
                        self.assertIs(report["claims"]["parameter_bound_returned_loans_execution"], True)

    def test_shared_actual_aliases_and_independent_mutable_origins(self):
        for construction in ("forward", "children", "mixed"):
            for byte in (0, 37, 255):
                report = self.parity(returned.multiple_shared(construction), "shared", [byte])
                self.assertEqual(report["values"], [(2 * byte) & 255])
                self.assertEqual(report["resources"]["loans_started"], 3)
        self.assertEqual(self.parity(returned.swapped_mutable(), "swapped", [])["values"], [28])
        source = returned.loan_program("read", "child")
        get = source["functions"][0]
        get["params"][0]["type"] = get["blocks"][0]["params"][0]["type"] = "mutbuf"
        parent = next(op for op in source["functions"][1]["blocks"][0]["ops"] if op["op"] == "borrow.read")
        parent["op"], parent["out"][0]["type"] = "borrow.mut", "mutbuf"
        self.assertEqual(self.parity(source, source["exports"][0], [1, 37])["values"], [37])

    def test_every_step_cut_keeps_actual_resources_before_and_after_return(self):
        for source, entry, args in (
                (returned.loan_program("mut"), "entry_mut_forward", [1, 37]),
                (returned.loan_program("read", "recursive"), "entry_read_recursive", [1, 37]),
                (returned.multiple_shared("children"), "shared", [37]),
                (returned_loop(), "loop", [3])):
            completed = self.parity(source, entry, args)
            for budget in range(1, completed["steps"] + 1):
                with self.subTest(entry=entry, budget=budget):
                    result = self.parity(source, entry, args, steps=budget)
                    self.assertEqual(result["status"], "returned" if budget == completed["steps"] else "budget_exceeded")

    def test_allocation_heap_failure_partial_returns_and_explicit_traps(self):
        for fail in (None, 1, 2, 3):
            for heap in (0, 1, 2, 4):
                self.parity(returned.fallible_return_program(), "fallible_entry", [], heap=heap, fail=fail)
        source = returned.multiple_shared("children")
        get = source["functions"][0]
        get["effects"] = ["alloc", "trap"]
        get["blocks"][0]["ops"][1:1] = [c("temporary_size", "usize", 1),
            i("buffer.new", ["temporary_size"], [("temporary_owner", "buffer")]),
            i("owner.drop", ["temporary_owner"])]
        report = self.parity(source, "shared", [37], fail=2)
        self.assertEqual(report["resources"]["live_local_loans"], 2)
        self.assertEqual(report["resources"]["frees"], 0)
        for after_return in (False, True):
            source = returned.loan_program("read", "child")
            fn = source["functions"][1 if after_return else 0]
            fn["effects"] = sorted(set(fn["effects"]) | {"trap"})
            block = fn["blocks"][0]
            if after_return:
                call = next(n for n, op in enumerate(block["ops"]) if op["op"] == "call")
                block["ops"] = block["ops"][:call + 1]
            block["term"] = {"op": "trap", "code": "user"}
            report = self.parity(source, source["exports"][0], [1, 37])
            self.assertEqual(report["status"], "trapped")
            self.assertEqual(report["resources"]["live_local_loans"], 2)

    def test_loops_recursion_limit_and_bulk_operations_compose(self):
        for iterations in (0, 1, 9, 40):
            report = self.parity(returned_loop(), "loop", [iterations])
            self.assertEqual(report["values"], [(iterations * 7) & 255])
            self.assertEqual(report["resources"]["loans_started"], iterations + 1)
        for depth in (0, 1, 28, 29, 30, 31, 100):
            source = returned.loan_program("mut", "recursive")
            depth_op = next(op for op in source["functions"][1]["blocks"][0]["ops"]
                            if op["out"] and op["out"][0]["name"] == "depth")
            depth_op["attrs"]["value"] = depth
            report = self.parity(source, source["exports"][0], [1, 37])
            self.assertEqual(report["status"], "returned" if depth <= 30 else "budget_exceeded")
        source = returned.loan_program("mut", "child")
        main = source["functions"][1]["blocks"][0]
        call = next(n for n, op in enumerate(main["ops"]) if op["op"] == "call")
        main["ops"][call + 1:call + 1] = [i("buffer.fill", ["returned", "byte"])]
        self.parity(source, source["exports"][0], [37, 91])
        for factory, entry, args in ((bulk.bulk_program, "bulk", [5, 5, 17]),):
            source = factory(); source["schema"] = "hepta.hia.program.v8"
            self.parity(source, entry, args)

    def test_contract_shapes_sources_permissions_and_legacy_refusal(self):
        for annotation in (None, [], [None], ["missing"], ["input", None], [["input"]], [{"input": True}], [True]):
            source = returned.loan_program()
            if annotation is None:
                del source["functions"][0]["return_loans"]
            else:
                source["functions"][0]["return_loans"] = annotation
            self.reject_both(source)
        source = returned.loan_program(); source["functions"][0]["return_loans"] = None
        self.reject_both(source)
        source = returned.loan_program(); source["functions"][0]["returns"] = ["mutbuf"]
        self.reject_both(source)
        source = returned.loan_program(); source["functions"][1]["return_loans"] = ["length"]
        self.reject_both(source)
        for version in range(1, 8):
            source = returned.loan_program(); source["schema"] = f"hepta.hia.program.v{version}"
            self.reject_both(source)
            del source["functions"][0]["return_loans"]
            self.reject_both(source)

    def test_owner_escape_deeper_children_duplicate_results_and_wrong_origins(self):
        source = returned.multiple_shared(); source["functions"][0]["return_loans"] = ["right", "left"]
        self.reject_both(source)
        source = returned.multiple_shared(); source["functions"][0]["blocks"][0]["term"] = ret("left", "left")
        self.reject_both(source)
        for kind in ("owner", "deeper", "active_child"):
            source = returned.loan_program("read", "child"); fn = source["functions"][0]
            operations = fn["blocks"][0]["ops"]
            if kind == "owner":
                fn["effects"] = ["alloc", "trap"]
                operations[:] = [c("size", "usize", 1), i("buffer.new", ["size"], [("local", "buffer")]),
                                 i("borrow.read", ["local"], [("child", "readbuf")])]
            elif kind == "deeper":
                operations += [i("borrow.read", ["child"], [("deeper", "readbuf")])]
                fn["blocks"][0]["term"] = ret("deeper")
            else:
                fn["blocks"][0]["term"] = ret("input")
            self.reject_both(source)

    def test_caller_aliases_parent_access_and_early_end_are_rejected(self):
        source = returned.swapped_mutable()
        call = next(op for op in source["functions"][1]["blocks"][0]["ops"] if op["op"] == "call")
        call["args"] = ["left", "left"]
        self.reject_both(source)
        for op in (i("loan.end", ["parent"]), i("owner.drop", ["owner"]),
                   i("owner.move", ["owner"], [("illegal_move", "buffer")]),
                   i("buffer.store", ["parent", "index", "byte"]),
                   i("buffer.load", ["parent", "index"], [("illegal_read", "u8")])):
            source = returned.loan_program("mut")
            ops = source["functions"][1]["blocks"][0]["ops"]
            call = next(n for n, ins in enumerate(ops) if ins["op"] == "call") + 1
            ops.insert(call, op)
            self.reject_both(source)

    def test_original_parameter_identity_survives_cfg_joins_without_old_restriction(self):
        self.reject_both(changed_origin_join())
        for version in range(1, 9):
            source = changed_origin_join(returns_loan=False)
            source["schema"] = f"hepta.hia.program.v{version}"
            verify_program(source)
            result = self.shadow(source)
            self.assertEqual(result.returncode, 0, result.stderr)
        source = returned.loan_program()
        source["functions"][1]["return_loans"] = [None]
        self.parity(source, source["exports"][0], [1, 37])

    def test_unknown_hidden_ops_scalar_mode_and_public_capabilities_still_refuse(self):
        source = returned.loan_program()
        source["functions"].append(f("hidden_chain", [], ["chain"], [], [
            b("entry", [], [i("chain.future", [], [("empty", "chain")])], ret("empty"))]))
        self.reject_both(source)
        result = self.raw_run(self.wire(source), source["exports"][0], [1, 37], steps=1, fail=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.startswith(b"E_HIA_RUST_UNSUPPORTED:"), result.stderr)
        self.assertEqual(result.stdout, b"")
        source = returned.loan_program()
        result = subprocess.run([self.executable], input=json.dumps(source).encode(), capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        source["exports"].append(source["functions"][0]["name"])
        self.reject_both(source)
        source = returned.loan_program(); del source["exports"]
        result = self.raw_run(json.dumps(source).encode(), source["functions"][0]["name"], [0], steps=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.startswith(b"E_HIA_INPUT:"), result.stderr)


if __name__ == "__main__":
    unittest.main()
