"""Independent full-width signed/unsigned/unit semantics and unchanged boundaries."""
import unittest
from tools.hia_selfhost_signed_cases import independent_reference,unbatched_cases,trap_cases,refusals,SIGNED_WIDTHS
from tools.hia_selfhost_scalar_casts import independent_reference as cast_reference,unbatched_cases as cast_cases,WIDTHS


class SelfhostSignedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signed=independent_reference()
        cls.casts=cast_reference()

    def test_every_source_observation_survives_batching_once_with_all_bits_observed(self):
        for actual,expected in ((self.signed,unbatched_cases()),(self.casts,cast_cases())):
            observed=[row for case in actual["cases"] for row in case["input_cases"]]
            self.assertEqual(len(observed),len(expected))
            self.assertEqual({r["id"] for r in observed},{r["id"] for r in expected})
            self.assertEqual(len({r["id"] for r in observed}),len(expected))
            for case in actual["cases"]:
                from hepta.hia_agent_assembly import assemble_program
                document=assemble_program(case["source"].encode()).as_dict()
                for function in document["functions"]:
                    values=[p["name"] for b in function["blocks"] for p in b["params"]]
                    values += [p["name"] for b in function["blocks"] for op in b["ops"] for p in op["out"]]
                    self.assertTrue(all(int(v[1:])<2048 for v in values))
                self.assertEqual(case["reference_result"]["values"],[0,*bytes.fromhex(case["expected_hex"])])
        self.assertFalse(self.signed["all_input_correctness_proved"])
        self.assertFalse(self.casts["all_input_correctness_proved"])

    def test_batched_programs_share_only_identical_typed_constants(self):
        from collections import Counter
        from hepta.hia_agent_assembly import assemble_program
        from tools.hia_selfhost_signed_cases import cases
        from tools.hia_selfhost_batch import batch_cases
        originals = {c["id"]: c for c in unbatched_cases()}
        for case in cases():
            ops = assemble_program(case["source"].encode()).as_dict()["functions"][0]["blocks"][0]["ops"]
            expected = Counter()
            for witness in case["input_cases"]:
                source_ops = assemble_program(originals[witness["id"]]["source"].encode()).as_dict()["functions"][0]["blocks"][0]["ops"]
                expected.update(op["op"] for op in source_ops if op["op"] != "const")
            self.assertEqual(Counter(op["op"] for op in ops if op["op"] != "const"), expected)
            self.assertIn("share-identical-typed-constants-only", case["fixture_transform"])

    def test_signed_types_cover_all_integer_operations_select_literals_and_unit_calls(self):
        programs={r["program"] for r in unbatched_cases()}
        operations={"int.add.wrap","int.sub.wrap","int.mul.wrap","int.add.checked","int.sub.checked",
            "int.mul.checked","int.div.checked","int.rem.checked","int.neg.checked","int.shl.checked",
            "int.shr.checked","bit.and","bit.or","bit.xor","bit.not","compare.eq","compare.ne",
            "compare.lt","compare.le","compare.gt","compare.ge","select","literal","unit-tuple"}
        for typ in SIGNED_WIDTHS:
            self.assertTrue({typ+"-"+op for op in operations}<=programs)
        self.assertIn("unit-select-and-call",programs)
        self.assertEqual(len(self.signed["traps"]),100)
        self.assertEqual(len({r["id"] for r in trap_cases()}),len(trap_cases()))
        self.assertEqual(len(self.signed["refusals"]),len(refusals()))

    def test_every_signed_involving_integer_conversion_pair_has_both_modes(self):
        names={r["program"] for r in cast_cases()}
        expected={a+"-"+b+"-"+mode for a in WIDTHS for b in WIDTHS
            if a.startswith("i") or b.startswith("i") for mode in ("wrap","checked")}
        self.assertEqual(names,expected)
        self.assertTrue(self.casts["traps"])
        self.assertTrue(all(r["reference_result"]["error"]["code"]=="overflow" for r in self.casts["traps"]))


if __name__=="__main__":
    unittest.main()
