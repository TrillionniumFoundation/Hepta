"""Compiler-free probe-policy controls, not native qualification."""
import copy
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import probe_c_record_typedef_attributes as typed
from tools import qualify_c_typedef_port as release


class TypedefProbePolicyTests(unittest.TestCase):
    def positive(self):
        return [{'compiler':c,'optimization':o,'original':[16,8,0,8],'generated':[16,8,0,8]}
                for c in ('clang','gcc') for o in ('0','2')]

    def test_positive_exact_layout_denominator(self):
        self.assertTrue(typed.gate({'negative':False},{'ok':True,'diagnostics':[]},True,self.positive()))
        self.assertFalse(typed.gate({'negative':False},{'ok':True,'diagnostics':[]},True,self.positive()[:-1]))

    def test_positive_mismatched_layout_rejected(self):
        rows=self.positive();rows[2]['generated'][0]=32
        self.assertFalse(typed.gate({'negative':False},{'ok':True,'diagnostics':[]},True,rows))

    def test_positive_duplicate_or_unbounded_measurement_rejected(self):
        for rows in (self.positive()[:3]+self.positive()[:1],self.positive()):
            if rows[-1]['compiler']=='gcc':rows[0]['original']=rows[0]['generated']=[True,8,0,8]
            self.assertFalse(typed.gate({'negative':False},{'ok':True,'diagnostics':[]},True,rows))

    def test_negative_requires_attribute_and_no_bundle_or_execution(self):
        good={'ok':False,'diagnostics':[{'code':'E_C_ATTRIBUTE'}]}
        self.assertTrue(typed.gate({'negative':True},good,False,[]))
        for report,bundle,layouts in [(good,True,[]),(good,False,self.positive()),
            ({'ok':True,'diagnostics':[{'code':'E_C_ATTRIBUTE'}]},False,[]),
            ({'ok':False,'diagnostics':[{'code':'E_C_TYPE'}]},False,[])]:
            self.assertFalse(typed.gate({'negative':True},report,bundle,layouts))

    def test_cases_are_unique_and_have_explicit_scope(self):
        self.assertEqual(len(typed.CASES),13)
        self.assertEqual(len({x['name'] for x in typed.CASES}),13)
        self.assertEqual(sum(x['negative'] for x in typed.CASES),8)
        self.assertEqual(sum(not x['negative'] for x in typed.CASES),5)

    def test_all_fixtures_are_local_data_and_real_compiler_databases(self):
        with patch('subprocess.Popen',side_effect=AssertionError('No native process')) as forbidden:
            for case in typed.CASES:
                with self.subTest(case=case['name']),tempfile.TemporaryDirectory() as temp:
                    root=Path(temp);units,contract=typed.fixture(root,case)
                    entries=json.loads((root/'compile_commands.json').read_text())
                    self.assertEqual(len(units),len(entries))
                    self.assertEqual(contract['schema'],'hepta.c-record-views.v1')
                    for unit,entry in zip(units,entries):
                        self.assertTrue(unit['source'].is_file())
                        self.assertEqual(entry['arguments'][0],'clang')
                        self.assertIn('-std=c11',entry['arguments'])
                        if unit['variant'].get('system'):self.assertIn('-isystem',entry['arguments'])
            self.assertEqual(forbidden.call_count,0)

    def test_ast_requires_actual_decl_attribute_not_just_name(self):
        ast={'kind':'TranslationUnitDecl','inner':[{'kind':'TypedefDecl','name':'Ptr','type':{'qualType':'int *'}}]}
        with self.assertRaises(RuntimeError):typed.observe_ast(ast,{'attribute':'Ptr'})
        ast['inner'][0]['inner']=[{'kind':'AlignedAttr'}]
        self.assertEqual(typed.observe_ast(ast,{'attribute':'Ptr'})['attributed_typedefs'],['Ptr'])

    def test_ast_pointer_spelling_shape_control(self):
        ast={'kind':'TranslationUnitDecl','inner':[{'kind':'RecordDecl','name':'State','inner':[
            {'kind':'FieldDecl','name':'data','type':{'qualType':'Ptr','desugaredQualType':'int *'}}]}]}
        typed.observe_ast(ast,{'raw':'Ptr','desugared_pointer':True})
        ast['inner'][0]['inner'][0]['type']['qualType']='int *'
        with self.assertRaises(RuntimeError):typed.observe_ast(ast,{'raw':'Ptr','desugared_pointer':True})

    def valid_release(self):
        names=['gate'+str(i) for i in range(36)]
        report={'status':'passed','snapshot_unchanged':True,'gates':[{'name':n,'status':'passed','exit_code':0} for n in names]}
        report['gates'][0].update(test_count=1000,skipped=0)
        return report,names

    def test_release_requires_every_active_gate(self):
        r,names=self.valid_release();release.validate_report(r,names)
        for bad in [r['gates'][:-1],r['gates'][::-1],r['gates']+[r['gates'][0]]]:
            x=copy.deepcopy(r);x['gates']=bad
            with self.assertRaises(RuntimeError):release.validate_report(x,names)

    def test_release_refuses_skips_or_boolean_counts(self):
        for field,value in [('skipped',1),('skipped',False),('test_count',True),('test_count',0)]:
            r,names=self.valid_release();r['gates'][0][field]=value
            with self.assertRaises(RuntimeError):release.validate_report(r,names)

    def test_release_refuses_source_change_failure_or_boolean_exit(self):
        r,names=self.valid_release()
        cases=[dict(r,status='failed'),dict(r,snapshot_unchanged=False)]
        x=copy.deepcopy(r);x['gates'][1]['exit_code']=False;cases.append(x)
        for case in cases:
            with self.assertRaises(RuntimeError):release.validate_report(case,names)


    def test_execution_guard_preserves_success_and_aborts_denial(self):
        calls=[]
        marker=object()
        def allowed(*args,**kwargs):
            calls.append((args,kwargs));return marker
        self.assertIs(typed.owner.execution_guard(allowed,'clang',cwd='here'),marker)
        self.assertEqual(calls,[(('clang',),{'cwd':'here'})])
        denial=PermissionError('synthetic execution denial')
        with patch('subprocess.run',side_effect=denial) as denied:
            with self.assertRaises(typed.owner.WorkerAbort) as caught:
                typed.owner.execution_guard(denied,['clang'])
        self.assertIs(caught.exception.__cause__,denial)
        self.assertEqual(denied.call_count,1)

    def _assert_worker_stops_after_execution_denial(self,module):
        # Exercise the actual production error-normalization path while all
        # subprocess execution is mocked/forbidden. No compiler or namespace runs.
        import hepta.c_migration_project as migration
        import hepta.c_project as project
        import subprocess
        owner=typed.owner
        attempts=[]
        def denied_run(*args,**kwargs):
            attempts.append(list(args[0]))
            raise PermissionError('synthetic execution denial')
        def capture(*args,**kwargs):
            return project.invoke(['clang','synthetic-denied-operation'],Path.cwd())
        def recorded(*args,**kwargs):
            tag=args[2]
            if tag=='head':return 'synthetic-head'
            if tag=='actual-ast':return json.dumps({'kind':'TranslationUnitDecl','inner':[{'kind':'TypedefDecl','name':'Wide','inner':[{'kind':'AlignedAttr'}]}]})
            return {'clang':'clang version 19.1.7','gcc':'gcc 14.2.0','rustc':'rustc 1.90.0'}.get(tag,'{}')
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)
            with patch('subprocess.Popen',side_effect=AssertionError('Native execution forbidden')) as forbidden, \
                    patch.object(module,'OUT',output),patch.object(owner,'source_hashes',return_value=dict(typed.EXPECTED)), \
                    patch.object(owner,'run',side_effect=recorded),patch.object(typed,'observe_ast',return_value={}), \
                    patch.object(typed.shutil,'which',return_value=sys.executable), \
                    patch.object(migration,'capture_project',side_effect=capture), \
                    patch.object(subprocess,'run',side_effect=denied_run), \
                    patch.dict(os.environ,{'HEPTA_QUALIFICATION_HEAD_SHA':'synthetic-head','RUSTC':sys.executable}):
                with self.assertRaises(owner.WorkerAbort):module.worker()
            self.assertEqual(forbidden.call_count,0)
            self.assertEqual(len(attempts),1)
            report=json.loads((output/'report.json').read_text())
            self.assertFalse(report['ok'])
            self.assertEqual(len(report['cases']),1)
            first=output/report['cases'][0]['name']
            retained=json.loads((first/('migration-native-commands.json' if module is typed else 'migration-invocations.json')).read_text())
            self.assertEqual(len(retained),1)
            self.assertTrue(retained[0]['execution_denied'])
            self.assertIn('synthetic execution denial',retained[0]['error'])
            self.assertFalse((first/'bundle').exists())

    def test_typed_worker_stops_after_first_execution_denial(self):
        self._assert_worker_stops_after_execution_denial(typed)

    def test_six_case_worker_stops_after_first_execution_denial(self):
        self._assert_worker_stops_after_execution_denial(typed.owner)

    def test_unused_collision_requires_attributed_and_ordinary_tus(self):
        spec=next(v for v in typed.CASES if v['name']=='two-unit-unused-attribute')
        with tempfile.TemporaryDirectory() as temporary:
            units,_=typed.fixture(Path(temporary),spec)
        self.assertEqual(len(units),2)
        declaration={'kind':'TypedefDecl','name':'Ptr','type':{'qualType':'int *'},'inner':[{'kind':'AlignedAttr'}]}
        ast={'kind':'TranslationUnitDecl','inner':[declaration]}
        typed.observe_ast(ast,units[0]['variant'])
        for attributes in ([],[{'kind':'DeprecatedAttr'}]):
            missing=copy.deepcopy(ast);missing['inner'][0]['inner']=attributes
            with self.assertRaises(RuntimeError):typed.observe_ast(missing,units[0]['variant'])
        ordinary={'kind':'TranslationUnitDecl','inner':[
            {'kind':'TypedefDecl','name':'Ptr','type':{'qualType':'int *'}},
            {'kind':'RecordDecl','name':'State','inner':[{'kind':'FieldDecl','name':'data','type':{'qualType':'Ptr','desugaredQualType':'int *'}}]}]}
        typed.observe_ast(ordinary,units[1]['variant'])
        for bad in ({'kind':'TranslationUnitDecl','inner':ordinary['inner'][1:]},copy.deepcopy(ordinary)):
            if len(bad['inner'])==2:bad['inner'][0]['inner']=[{'kind':'AlignedAttr'}]
            with self.assertRaises(RuntimeError):typed.observe_ast(bad,units[1]['variant'])



if __name__=='__main__':unittest.main()
