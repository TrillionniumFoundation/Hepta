"""Actual bounded harness preparation controls; zero project test bodies."""
from __future__ import annotations
import ast
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent
INPUTS=ROOT/'harness/inputs'
sys.path.insert(0,str(INPUTS))
import joint_source as joint
import run_requests_development as r2
from source_custody import files,metadata,digest

UNION=ROOT.parent/'v82-requests-front-integration-r1/source'
BASE=ROOT.parent/'v81-service-requests-development-r2/source'

class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet=joint.load_union(INPUTS)
        cls.before=json.loads((BASE.parent/'FINAL-SOURCE-MANIFEST.json').read_bytes())

    def test_actual_whole_candidate_and_before_bytes_match_exact_packet(self):
        prepared,expected=joint.validate_union(self.packet,self.before)
        self.assertEqual(len(prepared),32)
        self.assertEqual({n:r2.compact(v) for n,v in files(BASE).items()},self.before)
        self.assertEqual({n:r2.compact(v) for n,v in files(UNION).items()},expected)
        self.assertEqual(joint.tree_identity(expected),joint.UNION_TREE)

    def test_late_old_source_drift_refused_before_any_publication(self):
        before=copy.deepcopy(self.before)
        before['hepta/hia_agent_service.py']['sha256']='0'*64
        with self.assertRaises(ValueError):joint.validate_union(self.packet,before)

    def test_changed_after_bytes_or_mode_refused(self):
        for field,value in (('text','incorrect source'),('mode','100755')):
            mutated=copy.deepcopy(self.packet)
            row=mutated['files']['hepta/hia_program.py']
            if field=='text':row[field]=value
            else:row['after'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                joint.validate_union(mutated,self.before)

    def test_escape_and_undeclared_added_source_refused(self):
        mutated=copy.deepcopy(self.packet)
        mutated['files']['../escape.py']=mutated['files'].pop('hepta/hia_program.py')
        with self.assertRaises(ValueError):joint.validate_union(mutated,self.before)
        mutated=copy.deepcopy(self.packet)
        mutated['all_source_metadata']['unexpected.py']=joint.row_for(b'')
        with self.assertRaises(ValueError):joint.validate_union(mutated,self.before)

    def test_all_original_driver_and_test_bytes_preserved(self):
        original=ROOT.parent/'v81-service-requests-development-r2/ci-r2/harness'
        listing=json.loads((INPUTS/'R2-ORIGINAL-FILES.json').read_bytes())
        for name,row in listing.items():
            actual=ROOT/'harness'/name
            if name in ('README.md','.github/workflows/hia-service-requests-v81.yml'):
                actual=INPUTS/'original-r2'/name
            self.assertEqual(r2.compact(metadata(actual)),row,name)
            self.assertEqual(actual.read_bytes(),(original/name).read_bytes(),name)
        front=ROOT.parent/'v81-core-assembly-front-development-r4/cpython-ci-r2/inputs'
        for path in (INPUTS/'front-original').iterdir():
            self.assertEqual(path.read_bytes(),(front/path.name).read_bytes(),path.name)

    def test_complete_901_order_and_original_893_prefix_load_without_body(self):
        names,generators=joint.workflow_inventory(UNION)
        self.assertEqual((len(names),len(generators)),(175,93))
        sys.path.insert(0,str(UNION))
        try:
            loader=unittest.TestLoader()
            suite=loader.loadTestsFromNames(names)
            from run_controls import flatten
            ids=[test.id() for test in flatten(suite)]
        finally:
            sys.path.remove(str(UNION))
        saved=json.loads((INPUTS/'expected-source-901.json').read_bytes())
        self.assertFalse(loader.errors)
        self.assertEqual(ids,saved['full_ordered_ids'])
        self.assertEqual(ids[:893],saved['old_ordered_ids'])
        self.assertEqual(ids[893:],saved['new_ordered_ids'])
        self.assertEqual(len(ids),len(set(ids)))

    def test_real_failure_and_timeout_do_not_block_later_original_supervisor(self):
        with tempfile.TemporaryDirectory(prefix='joint-harness-') as name:
            work=Path(name)
            source=work/'fixture-source';source.mkdir()
            (source/'data').write_bytes(b'actual supervisor fixture')
            (work/'snapshots').mkdir()
            report={'commands':[]}
            import os
            self.assertFalse(r2.run_group(source,INPUTS,work,report,'failed',
                ['-c','raise SystemExit(7)'],os.environ.copy(),limit=2))
            self.assertFalse(r2.run_group(source,INPUTS,work,report,'timed-out',
                ['-c','import time; time.sleep(10)'],os.environ.copy(),limit=0.03))
            self.assertTrue(r2.run_group(source,INPUTS,work,report,'later',
                ['-c','print("later original supervisor executed")'],os.environ.copy(),limit=2))
            self.assertEqual([x['label'] for x in report['commands']],['failed','timed-out','later'])
            self.assertTrue(report['commands'][1]['timed_out'])
            self.assertTrue(all(row['cleanup']['complete'] for row in report['commands']))
            (ROOT/'PREPARATION-SUPERVISOR-RAW.json').write_text(json.dumps({
                'commands':report['commands'],
                'files':{p.relative_to(work).as_posix():p.read_text() for p in work.rglob('*') if p.is_file()}},
                sort_keys=True,indent=2)+'\n')

    def test_source901_adds_only_exact_order_assertion_to_original_runner(self):
        original=(INPUTS/'run_controls.py').read_text()
        current=(INPUTS/'run_source901.py').read_text()
        current=current.replace("    parser.add_argument('--expected-ids',type=Path,required=True)\n",'',1)
        block="""        frozen=json.loads(args.expected_ids.read_bytes())
        if (ids!=frozen['full_ordered_ids'] or len(ids)!=901 or ids[:893]!=frozen['old_ordered_ids']
                or ids[893:]!=frozen['new_ordered_ids']):
            raise AssertionError('complete original 893 plus 8 ordered source IDs differ')
"""
        self.assertEqual(current.count(block),1)
        current=current.replace(block,'',1)
        self.assertEqual(current,original)
        self.assertEqual(ast.dump(ast.parse(current)),ast.dump(ast.parse(original)))

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(PreparationTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    ok=result.testsRun==8 and not any((result.failures,result.errors,result.skipped,
        result.expectedFailures,result.unexpectedSuccesses))
    (ROOT/'PREPARATION-RESULT.json').write_text(json.dumps({'schema':'hia.joint.harness.preparation.v82.r3',
        'status':'PASS' if ok else 'FAIL','python':sys.version,'tests_run':result.testsRun,
        'failures':[(t.id(),x) for t,x in result.failures],'errors':[(t.id(),x) for t,x in result.errors],
        'skips':result.skipped,'expected_failures':[(t.id(),x) for t,x in result.expectedFailures],
        'unexpected_successes':[t.id() for t in result.unexpectedSuccesses],
        'project_test_bodies_executed':0,'actual_native_entries':0,'current_cold':False},sort_keys=True,indent=2)+'\n')
    raise SystemExit(0 if ok else 1)
