"""Runtime bootstrap qualification, separate from the unchanged static Source3.

New gate budgets are explicit; no old caller body, test ID or limit is changed.
A failure of independent-budget-B-retirement is a real blocking failure.
"""
from __future__ import annotations
from hashlib import sha256
import os
from pathlib import Path
import sys
import unittest
from tests import hia_service_bootstrap_support as support
from tests.hia_service_bootstrap_controls import (
    ROOT,COLD,DEV,EVIDENCE,SOURCE_EVIDENCE,invocation,build_images,manifest_pins)
from tools.qualify_hia_service_bootstrap_finite import originals,compare_candidate

_NATIVE_AUTHORITY=None
_NATIVE_AUTHORITY_PIN=None

def child(directory,label,filename,arguments,seconds):
    command=[sys.executable,"-I","-B",str(ROOT/filename),*map(str,arguments),
             "--output",str(Path(directory)/label)]
    result,report,raw=support.run_child(directory,label,command,seconds=seconds)
    if report["argv"]!=command[3:] or result["stderr"]["bytes"]!=0:
        raise AssertionError("child report/complete stderr differs")
    support.exact_reread(Path(directory)/label/"report.json",raw)
    return result,report

def native_authority():
    global _NATIVE_AUTHORITY,_NATIVE_AUTHORITY_PIN
    if _NATIVE_AUTHORITY is not None:return _NATIVE_AUTHORITY
    cold,dev=os.environ.get(COLD),os.environ.get(DEV)
    if (cold is None)==(dev is None) or cold=="" or dev=="":
        raise ValueError("bootstrap Native gates require exactly one cold/DEV construction authority")
    root=invocation(EVIDENCE,"native")
    before=support.source_snapshot()
    # These fresh processes admit and execute complete originals before any
    # compiler/build/import of a candidate owner in this authority.
    authority,authority_pin=originals(root/"originals")
    manifests=build_images(root)
    manifest_list=root/"manifest-list.json"
    support.write_json(manifest_list,{name:str(path.resolve()) for name,path in manifests.items()})
    images=manifest_pins(manifests)
    _NATIVE_AUTHORITY_PIN=support.write_json(root/"authority.json",{
        "schema":"hepta.hia.service-bootstrap-component-authority.v1",
        "source_before":before,"originals":{"path":str(authority),"pin":authority_pin},
        "manifest_list":support.file_pin(manifest_list),"images":images,
        "construction":support.file_pin(root/"construction.json"),
        "scope":"MATCHING_SOURCE_COLD" if cold is not None else "DEVELOPMENT_ONLY",
        "new_outer_budget_seconds":1800,"whole_native_stack_qualified":False})
    _NATIVE_AUTHORITY=(root,before,authority,authority_pin,manifests,manifest_list,images)
    return _NATIVE_AUTHORITY

class ServiceBootstrapQualificationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=invocation(SOURCE_EVIDENCE,"source")
        cls.before=support.source_snapshot()
        cls.authority,cls.authority_pin=originals(cls.root/"originals")
    @classmethod
    def tearDownClass(cls):
        after=support.source_snapshot()
        support.write_json(cls.root/"source-custody.json",{"before":cls.before,"after":after})
        if not support.same(cls.before,after):
            raise AssertionError("bootstrap Source source changed")
    def test_01_generated_complete_graph_original_sources_and_actual_profile_limits(self):
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from tools import generate_hia_service_bootstrap as generator
        from tests import hia_service_bootstrap_oracle as oracle
        source=(ROOT/"examples/hia_bootstrap/service_bootstrap.hepta").read_bytes()
        self.assertEqual(source,render_assembly(generator.document()).encode())
        program=assemble_program(source).as_dict()
        self.assertLessEqual(len(source),1<<20)
        self.assertLessEqual(len(source.splitlines()),16384)
        self.assertLessEqual(len(program["functions"]),128)
        self.assertLessEqual(sum(len(f["blocks"]) for f in program["functions"]),1536)
        self.assertLessEqual(sum(len(b["ops"]) for f in program["functions"] for b in f["blocks"]),8192)
        for function in program["functions"]:
            self.assertLessEqual(len(function["blocks"]),256)
            names={p["name"] for p in function["params"]}
            for block in function["blocks"]:
                self.assertLessEqual(len(block["params"]),16)
                names.update(p["name"] for p in block["params"])
                names.update(value["name"] for op in block["ops"] for value in op["out"])
            self.assertLessEqual(len(names),2048)
        cases,_=oracle.cases()
        self.assertEqual(len(cases),232)
        self.assertEqual(len({case["id"] for case in cases}),232)
    def test_02_complete_prior_originals_and_all_derived_faults_through_VM(self):
        report=compare_candidate(self.authority,self.authority_pin,self.root/"complete-vm",lane="vm")
        self.assertEqual(report["status"],"PASS_FINITE_ONLY")
        self.assertGreaterEqual(report["count"],232)
        self.assertIs(report["full_raw_byte_equality"],True)
        self.assertIs(report["complete_late_byte_equality"],True)
    def test_03_complete_unselected_public_domain_and_lazy_empty_refusal(self):
        report=compare_candidate(self.authority,self.authority_pin,self.root/"complete-unselected",lane="unselected")
        self.assertEqual(report["status"],"PASS_FINITE_ONLY")
        _,control=child(self.root,"lazy","tests/hia_service_bootstrap_controls.py",
            ["--action","lazy"],180)
        self.assertEqual(control["status"],"PASS_CONTROL_ONLY")
        self.assertEqual(control["observation"]["empty_provider_effects"],0)
        self.assertIs(control["observation"]["absent_imported_owner"],False)

class _BootstrapNativeAuthority(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (cls.root,cls.before,cls.authority,cls.authority_pin,cls.manifests,
         cls.manifest_list,cls.images)=native_authority()
    @classmethod
    def tearDownClass(cls):
        after=support.source_snapshot();images=manifest_pins(cls.manifests)
        support.write_json(cls.root/(cls.__name__+"-custody.json"),{
            "source_before":cls.before,"source_after":after,
            "images_before":cls.images,"images_after":images,"runtime":sys.version})
        if not support.same(cls.before,after) or not support.same(cls.images,images):
            raise AssertionError("complete bootstrap Native source/image custody changed")
    def control(self,action):
        _,report=child(self.root,"control-"+action,"tests/hia_service_bootstrap_controls.py",
            ["--action",action,"--manifest-list",self.manifest_list],180)
        self.assertEqual(report["status"],"PASS_CONTROL_ONLY")
        self.assertEqual(report["action"],action)
        self.assertTrue(support.same(report["source_before"],report["source_after"]))
        self.assertTrue(support.same(report["images_before"],report["images_after"]))
        return report["observation"]

class ServiceBootstrapNativeTests(_BootstrapNativeAuthority):
    def test_01_all232_and_every_original_derived_fault_actual_public_native(self):
        report=compare_candidate(self.authority,self.authority_pin,self.root/"complete-native",
                                 lane="native",manifest=self.manifests["bootstrap"])
        self.assertEqual(report["status"],"PASS_FINITE_ONLY")
        self.assertIs(report["full_raw_byte_equality"],True)
        self.assertIs(report["complete_late_byte_equality"],True)
    def test_02_all_five_actual_public_codes_and_retained_body_poison(self):
        value=self.control("public")
        self.assertIs(value["all_five_methods"],True)
        self.assertIs(value["retained_poisoned"],True)
        self.assertEqual(len(value["rows"]),5)
    def test_03_complete_request_output_state_independent_VM_and_replay(self):
        value=self.control("packets")
        self.assertIs(value["complete_request_output_state_bytes"],True)
        self.assertEqual(value["provider_effects"],0)
        self.assertEqual(value["fresh_machine_limits"],[4_000_000,16<<20,128])
    def test_04_safe_preparation_and_actual_native_handoff_loss(self):
        value=self.control("loss")
        self.assertEqual(len(value["rows"]),8)
        self.assertIs(value["exception_class_is_not_loss_evidence"],True)
    def test_05_thread_fork_completed_reentry_and_fresh_Context(self):
        self.assertEqual(len(self.control("ownership")["controls"]),5)
    def test_06_exact_manifest_image_source_drift_refusal(self):
        self.assertEqual(self.control("loader")["controls"],
                         ["source_sha256","image_sha256","schema","image_path"])
    def test_07_actual_pinned_worker_scope_and_terminal_refusal(self):
        value=self.control("pinned")
        self.assertIs(value["exact_image"],True)
        self.assertEqual(value["controls"],["undeclared-copy","nested-worker","worker-thread",
                                           "binding-after-scope","unselected-worker"])
    def test_08_real_installed_wheel_worker_and_all_five_public_methods(self):
        _,report=child(self.root,"installed","tests/hia_service_bootstrap_installed.py",
                      ["--manifest-list",self.manifest_list],1800)
        self.assertEqual(report["status"],"PASS_INSTALLED_ONLY")
        self.assertIs(report["all_repeated_worker_expected_flags"],True)
        self.assertIs(report["all_five_public_methods_selected"],True)
        self.assertIs(report["whole_native_stack_qualified"],False)
        self.assertIs(report["independent_budget_B_selected"],False)

class ServiceBootstrapResourceTests(_BootstrapNativeAuthority):
    def resources(self,indexes):
        from tests.hia_service_bootstrap_resources import RESOURCE_IDS
        for index in indexes:
            name=RESOURCE_IDS[index]
            with self.subTest(case=name):
                _,report=child(self.root,"resource-"+name,"tests/hia_service_bootstrap_resources.py",
                    ["--manifest-list",self.manifest_list,"--case",name],180)
                self.assertEqual(report["status"],"PASS_CONTROL_ONLY")
                self.assertEqual(report["case"],name)
                self.assertIs(report["validated"],True)
                self.assertTrue(report["owner_entries"])
    def test_01_actual_child_loss_confirmation_replacement_and_ordinary_error(self):
        self.resources((0,1,2,3))
    def test_02_terminal_ACK_resource_identity_Context_and_healthy_other_Store(self):
        self.resources((4,5,6,7))
    def test_03_nested_confirmation_constructor_boundaries_and_independent_budget_B(self):
        self.resources((8,9,10,11,12,13))
    def test_04_actual_generator_first_second_loss_and_confirmed_yield_retirement(self):
        self.resources((14,15,16))

if __name__=="__main__":unittest.main()
