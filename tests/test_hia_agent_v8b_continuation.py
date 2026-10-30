"""Zero-generation admission/resource controls for the prospective v8 pilot."""
from copy import deepcopy
from pathlib import Path
from hashlib import sha256
import json
import re
import os
import shutil
import tempfile
import unittest

from tools.hia_agent_v8b_evaluator import (
    TASK_MODULE,TASKS,LANGUAGES,candidate_constraints,evaluate,execute_hia_contract,public_feedback)
from tools.qualify_hia_agent_v8b_continuation import catalog,parse_action,public_prompt
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program import verify_program

class PublicProtocolTests(unittest.TestCase):
    def test_new_gcd_and_five_unexposed_prompt_identities(self):
        expected=json.loads((Path(__file__).resolve().parents[1]/"experiments/hia_agent_v8_continuation_20261030/FREEZE.json").read_text())["prompts"]
        from tools.hia_agent_codex_transport import canonical
        first=TASKS[0]
        self.assertEqual(first["id"],"unsigned_euclid_gcd")
        self.assertEqual([TASK_MODULE.oracle(first["id"],*pair) for pair in first["public"]],
                         [0,4294967295,4294967295,6,65535,1])
        for current in TASKS[1:]:
            for lang in LANGUAGES:
                self.assertEqual(sha256(canonical(public_prompt(current,lang))).hexdigest(),expected[current["id"]+":"+lang])

    def test_selected_complete_catalog_and_executable_example(self):
        from hepta.hia_opcodes import opcode_catalog
        value=catalog("hia-v8-text")
        self.assertEqual(value["catalog"],opcode_catalog("hepta.hia.program.v8"))
        assemble_program(value["example"])
        self.assertNotIn("endblock"," ".join(value["grammar"]))
        for task in TASKS:
            for lang in LANGUAGES:
                text=str(public_prompt(task,lang))
                self.assertNotIn("3764901283",text)
                self.assertNotIn("formal-y:",text)
                self.assertNotIn("RUST_REFERENCES",text)
                if task["interface"]=="task_step" and lang=="hia-v8-text":
                    wrapper=public_prompt(task,lang)["trusted_wrapper"]
                    self.assertNotIn("fn task_step(",wrapper)

    def test_rpc_type_errors_are_repairable(self):
        for text in ('{"action":[]}','{"action":"final","candidate_digest":[]}',
                     '{"action":"check","candidate":{}}','{"action":"unknown"}',
                     '{"action":"catalog","extra":1}'):
            with self.subTest(text=text),self.assertRaises(ValueError):parse_action(text)
        self.assertEqual(parse_action('{"action":"catalog"}'),{"action":"catalog"})

    def test_no_hidden_or_development_feedback(self):
        for phase in ("formal","development"):
            with self.assertRaises(ValueError):
                public_feedback({"phase":phase,"hidden_evaluated":phase=="formal"},None)

    def test_formal_generation_requires_explicit_admission(self):
        for task in TASKS:
            with self.assertRaises(ValueError):
                TASK_MODULE.cases(task,phase="formal",seed=123)
        self.assertEqual(len(TASK_MODULE.cases(TASKS[0],phase="development",seed=12648430)),32)

    def test_hia_alpha_renaming_and_returned_origin(self):
        for name in ("unsigned_euclid_gcd","mutate_borrow","return_borrow"):
            task=TASK_MODULE.task_for(name)
            text=TASK_MODULE.reference(name,"hia-v8-text")
            for old,new in (("view","incoming"),("x","first_input"),("y","second_input")):
                text=re.sub(r"\b"+old+r"\b",new,text)
            document=candidate_constraints(task,"hia-v8-text",text)
            verified=verify_program(TASK_MODULE.combine_candidate(document,name))
            for pair in task["public"]:
                execute_hia_contract(verified,task,pair)

    def test_hia_scalar_shortcut_and_dead_helper_rejected(self):
        task=TASK_MODULE.task_for("conditional_release")
        original=TASK_MODULE.reference_core(task["id"])
        cheated=deepcopy(original)
        # Keep allocation/release and compute the exact values, but remove the
        # actual live-path store/load. Put those operations in a dead helper.
        success=cheated["functions"][0]["blocks"][2]
        success["ops"]=[op for op in success["ops"] if op["op"] not in {"buffer.store","buffer.load"}]
        for op in success["ops"]:
            op["args"]=["byte" if a=="observed" else a for a in op["args"]]
        helper=TASK_MODULE.reference_core("mutate_borrow")["functions"][0]
        helper["name"]="dead_resource_helper";cheated["functions"].append(helper)
        verified=verify_program(cheated)
        with self.assertRaisesRegex(ValueError,"write/readback"):
            execute_hia_contract(verified,task,[0,2])
        # Also ensure the ordinary verifier refuses a wrong returned origin.
        returned=TASK_MODULE.reference("return_borrow","hia-v8-text").replace('return_loans(["view"])','return_loans(["x"])')
        with self.assertRaises(ValueError):candidate_constraints(TASK_MODULE.task_for("return_borrow"),"hia-v8-text",returned)

class RustNativeResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected=os.environ.get("RUSTC") or shutil.which("rustc")
        if not selected or not Path(selected).is_file():
            raise RuntimeError("native development controls require RUSTC or rustc on PATH; no silent skip")
        cls.development_tools={"rustc":str(Path(selected).resolve())}

    def check(self,name,source):
        with tempfile.TemporaryDirectory(prefix="hia-v8-native-dev-") as temp:
            return evaluate(TASK_MODULE.task_for(name),"rust",Path(temp)/"evaluation",
                            candidate=source,phase="public",development_tools=self.development_tools)

    def test_real_implicit_drop_and_borrow_controls(self):
        for name in ("conditional_release","mutate_borrow","return_borrow"):
            with self.subTest(task=name):
                result=self.check(name,TASK_MODULE.reference(name,"rust"))
                self.assertTrue(result["accepted"],result)
                self.assertTrue(result["resource_audit"]["accepted"])
                self.assertEqual(len(result["resource_audit"]["ledgers"]),6)

    def test_rust_scalar_comment_and_dead_helper_do_not_satisfy_buffer(self):
        source="fn target(x:u32,y:u32)->u32 { /* vec![0u8;8]; drop(data); data[0] */ if y&1!=0 {0} else {256*(8+x%9)+(x^y)%256} }"
        for candidate in (source,source+"\nfn unused_helper(){let mut a=vec![0u8;8];a[0]=1;let _=a[0];drop(a);}"):
            with self.subTest(source=candidate):
                result=self.check("conditional_release",candidate)
                self.assertFalse(result["accepted"])
                self.assertIn("E_V8_RELEASE_CONTRACT",result["execution"]["stderr"])

    def test_rust_wrong_length_index_and_owner_substitution(self):
        samples=[
            ("conditional_release","fn target(x:u32,y:u32)->u32 {let n=(8+x%9) as usize;let mut a=vec![0u8;4294967295usize];if y&1!=0{return 0;}a[n-1]=(x^y) as u8;256*n as u32+a[n-1] as u32}"),
            ("mutate_borrow","fn task_step(view:&mut Vec<u8>,x:u32,y:u32)->u32 {let mut other=vec![0u8;view.len()];other[0]=1;other[0] as u32}"),
            ("return_borrow","fn task_step<'a>(view:&'a mut Vec<u8>,x:u32,y:u32)->&'a mut Vec<u8> {view[0]=x.wrapping_add(y.wrapping_mul(3)) as u8;view}")]
        for name,source in samples:
            with self.subTest(task=name):
                result=self.check(name,source)
                self.assertFalse(result["accepted"],result)

    def test_same_native_address_space_cap_actually_refuses_large_allocation(self):
        source="fn target(x:u32,y:u32)->u32 {let huge=\"x\".repeat(536870912usize);let mut total=0u32;for byte in huge.bytes(){total=total.wrapping_add(byte as u32);}total}"
        result=self.check("unsigned_euclid_gcd",source)
        self.assertFalse(result["accepted"],result)
        self.assertEqual(result["native_limits"]["observed"]["after"],
                         {"RLIMIT_AS":[268435456,268435456],"RLIMIT_CORE":[0,0]})
        self.assertNotEqual(result["execution"]["returncode"],0)
        self.assertIn("memory allocation",result["execution"]["stderr"])

    def test_rust_alpha_renaming(self):
        source=TASK_MODULE.reference("return_borrow","rust")
        for old,new in (("view","incoming"),("x","first_input"),("y","second_input")):
            source=re.sub(r"\b"+old+r"\b",new,source)
        self.assertTrue(self.check("return_borrow",source)["accepted"])

if __name__=="__main__":unittest.main()
