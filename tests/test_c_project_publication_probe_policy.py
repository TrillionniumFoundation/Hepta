"""Compiler-free controls for private evidence, native oracle and workflow order."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import shutil
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import c_project_probe_workspace as workspace
from tools import probe_c_project_publication as native


class PlacementTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.archive=self.root/'archive';self.private=[]
        self.receipt=workspace.control_root(self.archive)/'archive-placement.json'
    def invoke(self,root,confirmed=True):
        self.private.append(root)
        (root/'report.json').write_text(json.dumps({'actual_path':str(root/'real-bundle')})+'\n')
        workspace.write(root/'owned-process-receipt.json',{'cleanup':{'confirmed':confirmed}})
        return 0
    def tearDown(self):
        # These are inert local fixture roots: no worker/process was launched.
        for root in self.private:
            if root.exists():shutil.rmtree(root)
    def test_private_archive_preserves_report_and_explicit_mapping(self):
        status=workspace.run_private(self.archive,self.invoke,limit=100000)
        self.assertEqual(status,0);self.assertEqual(len(self.private),1)
        receipt=json.loads(self.receipt.read_text())
        self.assertTrue(receipt['qualified_archive']);self.assertTrue(receipt['private_removed'])
        report=json.loads((self.archive/'report.json').read_text())
        self.assertEqual(report['actual_path'],str(self.private[0]/'real-bundle'))
        self.assertNotIn(str(self.archive),report['actual_path'])
        for name,record in receipt['files'].items():
            self.assertEqual(record['before'],record['after_source'])
            self.assertEqual(record['before'],record['after_archive'])
            self.assertEqual(record['before']['sha256'],hashlib.sha256((self.archive/name).read_bytes()).hexdigest())
    def test_unknown_process_cleanup_unsealed_snapshot_and_root_retained(self):
        status=workspace.run_private(self.archive,lambda r:self.invoke(r,False),limit=100000)
        self.assertEqual(status,1)
        receipt=json.loads(self.receipt.read_text())
        self.assertFalse(receipt['qualified_archive']);self.assertTrue(receipt['archive_snapshot_only'])
        self.assertTrue(self.private[0].exists())
    def test_stale_archive_never_invokes_worker(self):
        self.archive.mkdir()
        with self.assertRaises(ValueError):workspace.run_private(self.archive,self.invoke,limit=100000)
        self.assertFalse(self.private)
    def test_admission_failure_no_worker_no_fallback(self):
        roots=[]
        def denied(root):roots.append(root);raise ValueError('synthetic unsupported parent')
        with patch.object(workspace,'admission',side_effect=denied):
            self.assertEqual(workspace.run_private(self.archive,self.invoke,limit=100000),1)
        self.assertEqual(len(roots),1);self.assertFalse(self.private)
        self.private.extend(roots)
        receipt=json.loads(self.receipt.read_text())
        self.assertEqual(receipt['worker_invocations'],0)
    def test_archive_symlink_refused_without_follow(self):
        src=self.root/'source';src.mkdir();(src/'bad').symlink_to('/nonexistent-audit-sentinel')
        with self.assertRaises(ValueError):workspace.copy_archive(src,self.archive,1000)
        self.assertFalse(self.archive.exists())
    def test_archive_budget_checked_before_copy(self):
        src=self.root/'source';src.mkdir();(src/'large').write_bytes(b'x'*100)
        with self.assertRaises(ValueError):workspace.copy_archive(src,self.archive,50)
        self.assertFalse(self.archive.exists())
    def test_archive_digest_mismatch_rejected(self):
        src=self.root/'source';src.mkdir();(src/'data').write_bytes(b'data')
        original=workspace.publisher._digest_fd;calls=[]
        def digest(fd,size):
            value=original(fd,size);calls.append(True)
            if len(calls)==2:value=dict(value,sha256='0'*64)
            return value
        with patch.object(workspace.publisher,'_digest_fd',side_effect=digest):
            with self.assertRaises(ValueError):workspace.copy_archive(src,self.archive,1000)
    def test_worker_path_argument_required(self):
        with self.assertRaises(ValueError):workspace.worker_root(['probe','--worker'])
        with self.assertRaises(ValueError):workspace.worker_root(['probe','--work-root','/tmp/x','--work-root','/tmp/y'])
    def test_synthetic_admission_denial_no_retry_or_worker(self):
        roots=[]
        def denied(root):roots.append(root);raise PermissionError('synthetic admission denial')
        with patch.object(workspace,'admission',side_effect=denied),patch('builtins.print'):
            self.assertEqual(workspace.run_private(self.archive,self.invoke,limit=100000),1)
        self.assertEqual(len(roots),1);self.assertFalse(self.private);self.private.extend(roots)
    def test_archive_growth_is_bounded(self):
        src=self.root/'source';src.mkdir();p=src/'data';p.write_bytes(b'valid bytes')
        original=workspace.publisher._digest_fd;calls=[]
        def digest(fd,size):
            value=original(fd,size);calls.append(True)
            if len(calls)==1:p.write_bytes(b'x'*(2*1024*1024))
            return value
        with patch.object(workspace.publisher,'_digest_fd',side_effect=digest):
            with self.assertRaises(ValueError):workspace.copy_archive(src,self.archive,1000)
        self.assertLessEqual((self.archive/'data').stat().st_size,len(b'valid bytes'))
    def test_archive_mkdir_after_effect_denial_never_retried(self):
        original=Path.mkdir;calls=[]
        def mkdir(path,*args,**kwargs):
            if path==self.archive:
                calls.append(True)
                original(path,*args,**kwargs)
                raise PermissionError('synthetic mkdir denial after effect')
            return original(path,*args,**kwargs)
        with patch.object(Path,'mkdir',mkdir):
            self.assertEqual(workspace.run_private(self.archive,self.invoke,limit=100000),1)
        self.assertEqual(len(calls),1)
        self.assertFalse(json.loads(self.receipt.read_text())['qualified_archive'])
    def test_reserved_archive_receipt_name_refused_without_overwriting_source(self):
        raw=b'{"original":"preserve"}\n'
        def invoke(root):
            status=self.invoke(root);(root/'archive-placement.json').write_bytes(raw);return status
        self.assertEqual(workspace.run_private(self.archive,invoke,limit=100000),1)
        self.assertEqual((self.private[0]/'archive-placement.json').read_bytes(),raw)
        receipt=json.loads(self.receipt.read_text())
        self.assertFalse(receipt['qualified_archive']);self.assertTrue(receipt['private_root_retained'])
    def test_evidence_budget_refused_before_any_digest(self):
        root=self.root/'data';root.mkdir();(root/'oversized').write_bytes(b'x'*32)
        with patch.object(workspace.publisher,'_digest_fd',side_effect=AssertionError('must not hash')):
            with self.assertRaises(ValueError):workspace.evidence_files(root,16)
    def test_evidence_file_count_refused_before_any_digest(self):
        root=self.root/'data';root.mkdir()
        for n in range(3):(root/str(n)).write_bytes(b'')
        with patch.object(workspace,'MAX_FILES',2),\
             patch.object(workspace.publisher,'_digest_fd',side_effect=AssertionError('must not hash')):
            with self.assertRaises(ValueError):workspace.evidence_files(root,1000)
    def test_native_supervisor_budget_refused_before_hash(self):
        out=self.root/'worker';out.mkdir();(out/'oversized').write_bytes(b'x'*32)
        result={'exit_code':0,'cleanup':{'confirmed':True},'stdout':b'','stderr':b''}
        with patch.object(native.owner,'supervise',return_value=result),\
             patch.object(native.owner,'sha',side_effect=AssertionError('must not hash')),\
             patch.object(native,'LIMIT',16):
            with self.assertRaises(ValueError):native._private_main(out)


class NativeOracleTests(unittest.TestCase):
    def setUp(self):
        self.files={name:{'bytes':2,'sha256':'a'*64} for name in
            ('source.hepta','bridge.rs','generated.rs','libtranslated.so','migration.json')}
        self.report={'ok':True,'status':'native_built_not_equivalence_proved',
                     'frontend_validation':'passed','native_validation':'passed','diagnostics':[],
                     'artifacts':{n:v for n,v in self.files.items() if n!='migration.json'}}
        self.kw={'source_unchanged':True,'outside_unchanged':True,
                 'outputs':{'original':'7 123\n','generated':'7 123\n'}}
    def oracle(self,report=None,manifest=None,files=None,**kw):
        return native.bundle_oracle(self.report if report is None else report,
            self.report if manifest is None else manifest,self.files if files is None else files,
            **(self.kw|kw))
    def test_positive_dictionary_not_a_native_claim(self):self.assertTrue(self.oracle())
    def test_manifest_mismatch_refused(self):self.assertFalse(self.oracle(manifest=dict(self.report,extra=True)))
    def test_missing_native_library_refused(self):
        files=dict(self.files);del files['libtranslated.so'];self.assertFalse(self.oracle(files=files))
    def test_native_build_not_run_refused(self):
        report=dict(self.report,native_validation='not_run');self.assertFalse(self.oracle(report=report,manifest=report))
    def test_wrong_digest_refused(self):
        files=copy.deepcopy(self.files);files['generated.rs']['sha256']='b'*64;self.assertFalse(self.oracle(files=files))
    def test_wrong_execution_output_refused(self):self.assertFalse(self.oracle(outputs={'original':'7 123\n','generated':'7 124\n'}))
    def test_source_or_outside_mutation_refused(self):
        self.assertFalse(self.oracle(source_unchanged=False));self.assertFalse(self.oracle(outside_unchanged=False))


class ScalarAbiTests(unittest.TestCase):
    def setUp(self):
        self.report={'functions':[{'name':'identity','key':'identity','hepta_name':'c_identity',
                     'external_symbol':True,'return':'u32','params':[{'name':'x','type':'u32','pointer':False,'mode':'value'}]}],
                     'build':{'configurations':[{'model':{'char_unsigned':False,'long_bits':64,'pointer_bits':64}}]}}
        self.bridge='#[export_name = "identity"]\npub unsafe extern "C" fn __hepta_c_export_0(b_x: u32) -> u32 { b_x }\n'
    def admit(self,report=None,bridge=None,generated=None):
        bridge=self.bridge if bridge is None else bridge
        return native.scalar_abi_admission(self.report if report is None else report,bridge,bridge if generated is None else generated)
    def test_expected_u32_signature_accepts_without_execution(self):self.assertEqual(self.admit()['return'],'u32')
    def test_wrong_width_report_and_bridge_rejected(self):
        r=copy.deepcopy(self.report);r['functions'][0]['return']='u64';r['functions'][0]['params'][0]['type']='u64'
        with self.assertRaises(RuntimeError):self.admit(report=r,bridge=self.bridge.replace('u32','u64'))
    def test_signed_bridge_rejected(self):
        with self.assertRaises(RuntimeError):self.admit(bridge=self.bridge.replace('u32','i32'))
    def test_pointer_bridge_rejected(self):
        with self.assertRaises(RuntimeError):self.admit(bridge=self.bridge.replace('b_x: u32','b_x: *const u32'))
    def test_report_pointer_rejected(self):
        r=copy.deepcopy(self.report);r['functions'][0]['params'][0]['pointer']=True
        with self.assertRaises(RuntimeError):self.admit(report=r)
    def test_wrong_calling_convention_rejected(self):
        with self.assertRaises(RuntimeError):self.admit(bridge=self.bridge.replace('extern "C"','extern "system"'))
    def test_wrong_data_model_rejected(self):
        r=copy.deepcopy(self.report);r['build']['configurations'][0]['model']['pointer_bits']=32
        with self.assertRaises(RuntimeError):self.admit(report=r)
    def test_bridge_generated_mismatch_rejected(self):
        with self.assertRaises(RuntimeError):self.admit(generated=self.bridge+'// different\n')
    def test_duplicate_inode_bundle_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=root/'bundle';bundle.mkdir();(bundle/'bridge.rs').write_text('data')
            os.link(bundle/'bridge.rs',bundle/'generated.rs')
            with self.assertRaises(RuntimeError):native.inspect_bundle(bundle)
    def test_leftover_stage_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=root/'bundle';bundle.mkdir();(bundle/'bridge.rs').write_text('data')
            (root/'.hepta-c-project-unexpected').mkdir()
            with self.assertRaises(RuntimeError):native.inspect_bundle(bundle)


class ScientificAndWorkflowTests(unittest.TestCase):
    def test_new_native_worker_first_production_denial_aborts_all_later_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'tools').mkdir();(root/'tools/c_typedef_port_controls.json').write_text('{"files_sha256":{}}')
            out=root/'evidence';out.mkdir();denials=[];runs=[]
            def observed_tool(argv,*args,**kwargs):
                runs.append(argv)
                return 'bound\n' if argv[-1]=='HEAD' else 'clang 19.1.7 gcc 14.2.0 rustc 1.90.0\n'
            def denied(*args,**kwargs):denials.append(args);raise PermissionError('synthetic compiler execution denial')
            def migration(*args,**kwargs):return subprocess.run(['denied-compiler'])
            with patch.object(native,'ROOT',root),patch.object(native,'OUT',out),\
                 patch.object(native.owner,'source_hashes',return_value={'fixed':'source'}),\
                 patch.object(native.owner,'run',side_effect=observed_tool),\
                 patch.object(native.shutil,'which',return_value=sys.executable),\
                 patch.dict(os.environ,{'RUSTC':sys.executable,'HEPTA_QUALIFICATION_HEAD_SHA':'bound'}),\
                 patch('hepta.c_migrate.migrate_c_project',side_effect=migration),\
                 patch.object(subprocess,'run',side_effect=denied):
                with self.assertRaises(native.owner.WorkerAbort):native.worker()
            self.assertEqual(len(denials),1);self.assertEqual(len(runs),4)
            report=json.loads((out/'report.json').read_text());self.assertFalse(report['ok'])
            self.assertEqual(report['cases'],[])
    def test_original_scientific_functions_and_cases_unchanged(self):
        expected=SCIENTIFIC_AST_HASHES
        for relative,items in expected.items():
            tree=ast.parse((native.ROOT/relative).read_text())
            indexed={node.name:node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
            for node in tree.body:
                if isinstance(node,ast.Assign):
                    for target in node.targets:
                        if isinstance(target,ast.Name):indexed[target.id]=node
            for name,sha in items.items():
                self.assertEqual(hashlib.sha256(ast.dump(indexed[name],include_attributes=False).encode()).hexdigest(),sha)
    def test_workflow_success_only_chain_and_fixed_budgets(self):
        text=(native.ROOT/'.github/workflows/hepta-active-typedef-qualification.yml').read_text()
        for item in ('id: publisher-profile','id: formal-receipt-controls','id: six-case-oracle','id: typed-oracle','timeout-minutes: 45',
                     'timeout-minutes: 90','timeout-minutes: 10','timeout-minutes: 12','timeout-minutes: 5',
                     "steps.publisher-profile.outcome == 'success'", "steps.six-case-oracle.outcome == 'success'",
                     "steps.typed-oracle.outcome == 'success'", "steps.formal-receipt-controls.outcome == 'success'"):
            self.assertIn(item,text)
        self.assertNotIn('workflow_dispatch',text)


SCIENTIFIC_AST_HASHES = {'tools/probe_c_typedef_alignment.py': {'worker': '7ab23cdeac6344444732f46e34b922f2edd5d27b02be6f0f859301c48e5246ac', 'gate': 'ddb467c5399d84df816d8ed66fa7dcd19059070f74e7e58277351d40dd096a7e', 'layout': '664988884d2b0108bd7ee8a8a64ce38f986e29164c995ec4997a1f0e7f77d420', 'packet_layout_binding': '512f3977317a828faa3c30f7d175c95f9a1842f0c11459ae7688d0787c755e7a', 'execution_guard': '243e4498d7b3289f87a0961504f7921f3306a00346de44f365d7151d1b9767eb'}, 'tools/probe_c_record_typedef_attributes.py': {'CASES': 'e9d9f81ddd0e8044b75121c842bfc32cba192cdca72ac298d30c7bebf3a61d41', 'worker': 'c1e2a4ec83b9436da1fa0dd70c3107bac5eb3a4cca339cffdf11608e6ee7d6e5', 'gate': '55465a8ee300916720d1ab793a244e301d5f6b194343a6769c002eea75a4ca11', 'fixture': '10877f4771aa79533f1a8bfa27349ac287df772f56b64c9dd05e48a199e8ab0f', 'observe_ast': '956966ae234d55b9fcaf51ddf7d12cf66cbce81b55f4d846fd4aed55aff67b7b', 'ordinary_layout': '5b21795e58b36b28e4ae1a0d15accd93753c343d69f5b18a3d694da29795a588'}}

if __name__=='__main__':unittest.main()
