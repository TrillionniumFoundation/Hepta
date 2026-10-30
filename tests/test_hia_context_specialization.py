"""Meaningful safety controls for the new closed specialization relation."""
import copy, unittest
from hepta.hia_context_specialization import (selected_leaf, propose_context_specialization,
    verify_context_specialization, ContextSpecializationRejected)
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_scalar_lowering_check import verify_scalar_lowering


def base():
    params=[{"name":"a","type":"i32"},{"name":"d","type":"i32"}]
    return {"schema":"hepta.hia.program.v8","module":"context_test","exports":["divide"],
      "functions":[{"name":"divide","params":params,"returns":["i32"],"effects":["trap"],"entry":"entry",
      "blocks":[{"id":"entry","params":params,"ops":[{"op":"int.div.checked","args":["a","d"],
      "out":[{"name":"q","type":"i32"}],"attrs":{}}],"term":{"op":"ret","values":["q"]}}]}]}

class ContextSafety(unittest.TestCase):
    def setUp(self):
        self.base=selected_leaf(base(),"divide")
        self.hot=propose_context_specialization(self.base,parameter=1,value=1009)
    def test_all_input_relation_and_actual_lowering(self):
        proof=verify_context_specialization(self.base,self.hot)
        self.assertTrue(proof["verified"])
        self.assertEqual(proof["all_i32_input_pairs"],1<<64)
        self.assertEqual(proof["external_preconditions"],[])
        self.assertTrue(verify_scalar_lowering(self.hot)["verified"])
    def test_hits_misses_and_extreme_values(self):
        observations=0
        for a in [-2147483648,-2147483647,-1009,-1,0,1,1009,2147483647]:
            for d in [-2147483648,-1009,-2,1,2,3,1008,1009,1010,2147483647]:
                left=execute_program(self.base,"divide",[a,d],max_heap_bytes=0)
                right=execute_program(self.hot,"divide",[a,d],max_heap_bytes=0)
                self.assertEqual(left["result"],right["result"])
                self.assertEqual(left["resources"],right["resources"])
                self.assertTrue(all(v==0 for v in right["resources"].values()))
                observations+=1
        self.assertEqual(observations,80)
    def test_exact_traps_preserved_on_guard_misses(self):
        for args in ([7,0],[-2147483648,-1]):
            errors=[]
            for program in (self.base,self.hot):
                with self.assertRaises(HIAProgramTrap) as caught:
                    execute_program(program,"divide",args,max_heap_bytes=0)
                errors.append(caught.exception.report)
            self.assertEqual(errors[0]["error"],errors[1]["error"])
            self.assertEqual(errors[0]["resources"],errors[1]["resources"])
    def test_guard_reversal_rejected(self):
        doc=self.hot.as_dict();doc["functions"][0]["blocks"][0]["ops"][1]["op"]="compare.ne"
        with self.assertRaises(ContextSpecializationRejected):verify_context_specialization(self.base,doc)
    def test_hot_context_mismatch_rejected(self):
        doc=self.hot.as_dict();doc["functions"][0]["blocks"][1]["ops"][0]["attrs"]["value"]=1013
        with self.assertRaises(ContextSpecializationRejected):verify_context_specialization(self.base,doc)
    def test_wrong_fallback_rejected(self):
        doc=self.hot.as_dict();doc["functions"][0]["blocks"][2]["ops"][0]["op"]="int.rem.checked"
        with self.assertRaises(ContextSpecializationRejected):verify_context_specialization(self.base,doc)
    def test_guard_transfer_corruption_rejected(self):
        doc=self.hot.as_dict();doc["functions"][0]["blocks"][0]["term"]["else"]["args"].reverse()
        with self.assertRaises(ContextSpecializationRejected):verify_context_specialization(self.base,doc)
    def test_unsupported_context_rejected(self):
        for value in (0,1,-1):
            candidate=propose_context_specialization(self.base,parameter=1,value=value)
            with self.assertRaises(ContextSpecializationRejected):verify_context_specialization(self.base,candidate)
    def test_erased_public_exports_rejected(self):
        doc=self.hot.as_dict();doc["exports"]=[]
        with self.assertRaises(ContextSpecializationRejected):verify_context_specialization(self.base,doc)
    def test_silent_semantic_version_change_rejected(self):
        doc=self.hot.as_dict();doc["schema"]="hepta.hia.program.v7"
        with self.assertRaises(ContextSpecializationRejected):verify_context_specialization(self.base,doc)
    def test_resource_operation_rejected(self):
        doc=base();doc["functions"][0]["effects"].append("heap")
        with self.assertRaises(Exception):selected_leaf(doc,"divide")
    def test_wrong_native_division_lowering_refuted(self):
        llvm=emit_program_llvm(self.hot).text
        changed=llvm.replace("sdiv i32", "add i32")
        self.assertNotEqual(llvm,changed)
        self.assertEqual(verify_scalar_lowering(self.hot,llvm_text=changed)["status"],"refuted")

if __name__=="__main__":unittest.main()
