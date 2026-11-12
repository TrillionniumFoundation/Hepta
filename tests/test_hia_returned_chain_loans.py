"""Recursive-chain head loans compose with v8 internal return contracts."""
import json
import subprocess
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from tests.test_hia_program import b, c, f, i, jump, ret
from tests.test_hia_returned_loans import CLANG, build_allocator_observer, document, helper


def chain_program(mode, construction):
    typ = mode + "buf"
    get = helper(mode, construction)
    name = "chain_" + mode + "_" + construction
    prepare = [c("size", "usize", 1), c("index", "usize", 0),
        i("buffer.new", ["size"], [("payload", "buffer")]),
        i("borrow.mut", ["payload"], [("initial", "mutbuf")]),
        i("buffer.store", ["initial", "index", "byte"]), i("loan.end", ["initial"]),
        i("chain.empty", out=[("empty", "chain")]),
        i("chain.try_push", ["empty", "payload"], [("built", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["fallback"]), i("chain.head_" + mode, ["built"], [("parent", typ)]),
        i("call", ["parent"], [("returned", typ)], function=get["name"])]
    use = []
    if mode == "mut":
        use += [c("delta", "u8", 5), i("int.add.wrap", ["byte_again", "delta"], [("changed", "u8")]),
                i("buffer.store", ["child_again", "index_again", "changed"])]
    use += [i("buffer.load", ["child_again", "index_again"], [("observed", "u8")]),
            i("loan.end", ["child_again"]), i("loan.end", ["parent_again"]),
            i("owner.move", ["chain_again"], [("moved", "chain")])]
    if construction == "forward":
        use += [i("chain.pop", ["moved"], [("rest", "chain"), ("popped", "buffer"), ("present", "bool")]),
                i("borrow.read", ["popped"], [("read_back", "readbuf")]),
                i("buffer.load", ["read_back", "index_again"], [("persisted", "u8")]),
                i("loan.end", ["read_back"]), i("owner.drop", ["popped"]), i("owner.drop", ["rest"]),
                i("int.add.wrap", ["observed", "persisted"], [("answer", "u8")])]
        result = "answer"
    else:
        use += [i("owner.drop", ["moved"])]
        result = "observed"
    main = f(name, [("byte", "u8")], ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", [("byte", "u8")], prepare, jump("use", "built", "parent", "returned", "byte", "index")),
        b("use", [("chain_again", "chain"), ("parent_again", typ), ("child_again", typ),
                  ("byte_again", "u8"), ("index_again", "usize")], use, ret(result))])
    result = document(get, main)
    result["exports"] = [name]
    return result


class ReturnedChainLoans(unittest.TestCase):
    def test_head_loans_cross_calls_cfg_move_pop_and_nonempty_drop(self):
        for mode in ("read", "mut"):
            for construction in ("forward", "child"):
                with self.subTest(mode=mode, construction=construction):
                    source = chain_program(mode, construction)
                    result = execute_program(source, source["exports"][0], [37])
                    self.assertEqual(result["result"], (37 if mode == "read" else 42) * (2 if construction == "forward" else 1))
                    ledger = result["resources"]
                    for field in ("live_bytes", "live_owners", "live_chains", "live_chain_nodes", "live_local_loans"):
                        self.assertEqual(ledger[field], 0)
                    for field in ("allocation_attempts", "allocations", "frees"):
                        self.assertEqual(ledger[field], 2)
                    self.assertEqual(ledger["chain_nodes_created"], ledger["chain_nodes_dropped"])
                    self.assertEqual(ledger["chain_nodes_created"], 1)
                    self.assertEqual(ledger["loans_started"], 4 if construction == "forward" else 3)
                    self.assertEqual(ledger["loans_started"], ledger["loans_ended"])

    def test_live_returned_child_refuses_chain_drop_move_pop_and_parent_end(self):
        for mode in ("read", "mut"):
            for operation in (i("owner.drop", ["chain_again"]),
                              i("owner.move", ["chain_again"], [("illegal", "chain")]),
                              i("chain.pop", ["chain_again"], [("illegal_rest", "chain"), ("illegal_payload", "buffer"), ("illegal_present", "bool")]),
                              i("loan.end", ["parent_again"])):
                source = chain_program(mode, "child")
                source["functions"][1]["blocks"][1]["ops"].insert(0, operation)
                with self.subTest(mode=mode, operation=operation["op"]), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                    verify_program(source)

    @unittest.skipUnless(CLANG, "actual native Clang required")
    def test_actual_native_allocations_and_deallocations_match_vm(self):
        programs = [chain_program(mode, form) for mode in ("read", "mut") for form in ("forward", "child")]
        source = document(*(fn for program in programs for fn in program["functions"]))
        source["exports"] = [program["exports"][0] for program in programs]
        calls = {name: ("uint8_t", name + "(37)") for name in source["exports"]}
        with tempfile.TemporaryDirectory() as temporary:
            binary, _ = build_allocator_observer(source, temporary, calls)
            for name, expected_result in zip(source["exports"], (74, 37, 84, 42)):
                result = subprocess.run([str(binary), name, "0"], check=True, capture_output=True, text=True, timeout=10)
                native = json.loads(result.stdout)
                expected = {"result": expected_result, "attempts": 2, "allocations": 2, "frees": 2,
                            "node_allocations": 1, "node_frees": 1, "payload_allocations": 1, "payload_frees": 1,
                            "live_bytes": 0, "peak_bytes": 25, "null_frees": 0, "bad_frees": 0, "unknown_sizes": 0}
                self.assertEqual(native, expected)
                vm = execute_program(source, name, [37])
                for observed, field in (("attempts", "allocation_attempts"), ("allocations", "allocations"),
                                        ("frees", "frees"), ("node_allocations", "chain_nodes_created"),
                                        ("node_frees", "chain_nodes_dropped"), ("live_bytes", "live_bytes"), ("peak_bytes", "peak_bytes")):
                    self.assertEqual(native[observed], vm["resources"][field])


if __name__ == "__main__":
    unittest.main()
