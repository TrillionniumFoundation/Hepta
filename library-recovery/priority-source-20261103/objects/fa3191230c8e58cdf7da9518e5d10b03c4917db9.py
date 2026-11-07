import copy
import json
import unittest
from hia_candidate import Refused,verify,run,SCHEMA,catalog,catalog_digest
from hia_candidate.builders import op,scalar
from hia_candidate.optimizer import eliminate_wrapping_add_zero

class CoreTests(unittest.TestCase):
    def test_catalog_single_source(self):
        c=catalog()
        self.assertEqual(c["core_schema"],SCHEMA)
        self.assertEqual(len({o["name"] for o in c["operations"]}),len(c["operations"]))
        self.assertEqual(len(catalog_digest()),64)

    def test_source_identity_immutable(self):
        original=scalar()
        v=verify(original)
        original["function"]["params"][0]["type"]="bad"
        self.assertEqual(run(v,[123]).results,(123,))
        self.assertEqual(v.core_digest,verify(v.unpack()).core_digest)

    def test_strict_json_duplicate(self):
        with self.assertRaisesRegex(Refused,"E_DUPLICATE_FIELD"):
            verify('{"schema":"x","schema":"y"}')

    def test_float_boolean_domain(self):
        with self.assertRaisesRegex(Refused,"E_FLOAT"):
            verify('{"schema":1.0}')
        with self.assertRaisesRegex(Refused,"E_INVOCATION"):
            run(verify(scalar()),[True])

    def test_wrap_and_checked_overflow_distinct(self):
        a=op("int.add.wrap",["x","y"],[("z","u8")])
        d=scalar(args=[("x","u8"),("y","u8")],ops=[a],
                 results=["u8"],returns=["z"])
        self.assertEqual(run(verify(d),[255,1]).results,(0,))
        d["function"]["ops"][0]["op"]="int.add.checked"
        d["function"]["effects"]=["trap"]
        self.assertEqual(run(verify(d),[255,1]).code,"overflow")

    def test_allocation_loan_write_and_explicit_drop(self):
        ops=[
            op("const",results=[("at","u32")],value=0),
            op("const",results=[("byte","u8")],value=137),
            op("buffer.new",["n"],[("buf","buffer")]),
            op("borrow.mut",["buf"],[("loan","mutbuf")]),
            op("buffer.store",["loan","at","byte"]),
            op("buffer.load",["loan","at"],[("readback","u8")]),
            op("loan.end",["loan"]),
            op("owner.drop",["buf"])
        ]
        d=scalar(args=[("n","u32")],ops=ops,results=["u8"],returns=["readback"],
                 effects=["alloc","trap","write","read","free"])
        v=verify(d);r=run(v,[4])
        self.assertEqual((r.status,r.results,r.live_bytes),("return",(137,),0))
        self.assertEqual(r.peak_bytes,4)
        exhausted=run(v,[0]); self.assertEqual((exhausted.status,exhausted.code),("trap","bounds"))
        self.assertEqual(exhausted.events[-1],"trap:bounds")
        self.assertEqual(exhausted.allocations,1)
        fault=run(v,[4],fail_allocation_at=1)
        self.assertEqual((fault.status,fault.code),("trap","allocation"))
        self.assertEqual(fault.live_bytes,0)
        limited=run(v,[4],max_ticks=4)
        self.assertEqual((limited.status,limited.live_bytes),("budget_stop",4))
        self.assertIn("loan_mut",limited.events)

    def test_try_alloc_failure_is_a_value_and_cleanup(self):
        d=scalar(args=[("n","u32")],ops=[
            op("buffer.try_new",["n"],[("buf","buffer"),("ok","bool")]),
            op("owner.drop",["buf"])],results=["bool"],returns=["ok"],
            effects=["alloc","free"])
        v=verify(d)
        self.assertEqual(run(v,[100],fail_allocation_at=1).results,(False,))
        self.assertEqual(run(v,[100],max_heap_bytes=10).results,(False,))
        self.assertEqual(run(v,[100]).results,(True,))

    def test_conflicting_loans_refused(self):
        d=scalar(args=[("n","u32")],ops=[
            op("buffer.new",["n"],[("buf","buffer")]),
            op("borrow.read",["buf"],[("r","readbuf")]),
            op("borrow.mut",["buf"],[("m","mutbuf")]),
            op("loan.end",["m"]),op("loan.end",["r"]),op("owner.drop",["buf"])],
            results=["u32"],returns=["n"],effects=["alloc","trap","free"])
        with self.assertRaisesRegex(Refused,"E_ALIAS"):
            verify(d)

    def test_double_drop_and_move_use_after(self):
        d=scalar(args=[("n","u32")],ops=[
            op("buffer.new",["n"],[("buf","buffer")]),
            op("owner.move",["buf"],[("moved","buffer")]),
            op("buffer.len",["buf"],[("len","u32")]),
            op("owner.drop",["moved"])],returns=["len"],effects=["alloc","trap","free"])
        with self.assertRaisesRegex(Refused,"E_OWNER"):
            verify(d)
        d["function"]["ops"][2]=op("owner.drop",["moved"])
        d["function"]["ops"].pop()
        d["function"]["end"]["args"]=["n"]
        self.assertEqual(run(verify(d),[2]).results,(2,))

    def test_missing_drop_and_forged_effect_refused(self):
        d=scalar(args=[("n","u32")],ops=[op("buffer.new",["n"],[("buf","buffer")])],
                 returns=["n"],effects=["alloc","trap"])
        with self.assertRaisesRegex(Refused,"E_RESOURCE_EXIT"):
            verify(d)
        d["function"]["ops"].append(op("owner.drop",["buf"]))
        with self.assertRaisesRegex(Refused,"E_EFFECT"):
            verify(d)

    def test_cancel_after_cleanup(self):
        d=scalar(args=[("n","u32")],ops=[
            op("buffer.new",["n"],[("buf","buffer")]),
            op("owner.drop",["buf"])],results=[],returns=[],effects=["alloc","trap","free","cancel"])
        d["function"]["end"]={"op":"cancel","args":[],"code":"user_cancelled"}
        r=run(verify(d),[10]);self.assertEqual((r.status,r.live_bytes),("cancel",0))

    def test_optimizer_only_exact_zero(self):
        d=scalar(ops=[op("const",results=[("z","u32")],value=0),
                      op("int.add.wrap",["x","z"],[("res","u32")])],returns=["res"])
        source=verify(d)
        candidate=eliminate_wrapping_add_zero(source)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.rule,"uN_wrapping_add_zero")
        self.assertGreater(candidate.test_vectors,0)
        for x in [0,1,2**32-1]:
            self.assertEqual(run(source,[x]).results,run(candidate.candidate,[x]).results)
        d["function"]["ops"][0]["value"]=1
        self.assertIsNone(eliminate_wrapping_add_zero(verify(d)))

if __name__=="__main__": unittest.main()
