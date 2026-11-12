"""Original fourteen custody controls plus five launch-identity controls."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
spec=importlib.util.spec_from_file_location('original_custody_controls',BASE/'test_custody_controls.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
custody,runner=base.custody,base.runner


class LaunchControls(unittest.TestCase):
    setUp=base.CustodyControls.setUp

    def probe(self,mode):
        directory=self.root/'probe'
        command=[sys.executable,'-I','-S','-B',str(ROOT/'probe_launch_identity.py'),
                 '--module-root',str(BASE/'source'),'--mode',mode,'--output',str(directory)]
        actual=subprocess.run(command,capture_output=True,timeout=8)
        (self.root/'probe.stdout').write_bytes(actual.stdout);(self.root/'probe.stderr').write_bytes(actual.stderr)
        self.assertEqual(actual.returncode,0,actual.stderr)
        value=json.loads((directory/'PROBE.json').read_bytes())
        self.assertIsNone(runner.live_identity(value['producer_RUN']['runner']))
        return directory,value

    def assert_refused(self,mode):
        directory,value=self.probe(mode);record=value['producer_RUN'];row=record['calls'][0]
        self.assertFalse(record['known_direct_children_reaped'])
        self.assertFalse(custody.direct_child_custody_closed(row))
        quiet=runner.quiescence(directory/'records')
        self.assertFalse(quiet['ready_for_fixture_read']);self.assertEqual(quiet['not_observed_reaped'],[0])
        output=self.root/'archive'
        self.assertEqual(runner.archive_evidence(directory/'records',output),1)
        self.assertFalse((output/'publication-originals.tar.gz').exists())
        self.assertEqual(json.loads((output/'ARCHIVE.json').read_bytes())['status'],'HOLD')
        return value,row

    def test_real_child_identity_exception_is_unknown_even_after_control_cleanup(self):
        value,row=self.assert_refused('raise')
        self.assertIsNotNone(value['control_observed_os_identity'])
        self.assertIsNone(value['actual_child_returncode_before_finish'])
        self.assertTrue(row['launch_attempted']);self.assertTrue(row['launch_completed'])
        self.assertEqual(row['launched_pid'],value['actual_child_pid']);self.assertIsNone(row['process'])
        self.assertFalse(row['direct_child_reaped_observed']);self.assertTrue(row['pid_identity_error'])
        self.assertTrue(value['control_cleanup_identity_absent'])

    def test_real_child_missing_identity_after_normal_return_remains_hold(self):
        value,row=self.assert_refused('none')
        self.assertEqual(value['result']['returncode'],0)
        self.assertTrue(row['launch_completed']);self.assertTrue(row['direct_child_reaped_observed'])
        self.assertEqual(row['returncode'],0);self.assertIsNone(row['process'])

    def test_real_constructor_error_does_not_prove_no_launch(self):
        value,row=self.assert_refused('constructor-error')
        self.assertTrue(row['launch_attempted']);self.assertFalse(row['launch_completed'])
        self.assertIn('FileNotFoundError',value['exception'])

    def test_real_known_identity_and_reap_admits_complete_archive(self):
        directory,value=self.probe('normal');record=value['producer_RUN'];row=record['calls'][0]
        self.assertTrue(record['known_direct_children_reaped']);self.assertTrue(custody.direct_child_custody_closed(row))
        self.assertEqual(row['launched_pid'],row['process']['pid'])
        self.assertTrue(runner.quiescence(directory/'records')['ready_for_fixture_read'])
        self.assertEqual(runner.archive_evidence(directory/'records',self.root/'archive'),0)

    def test_actual_normal_record_rejects_missing_flags_boolean_pid_and_mismatches(self):
        _,value=self.probe('normal');original=value['producer_RUN']['calls'][0]
        samples=[]
        for name in ('launch_attempted','launch_completed','launched_pid','pid_identity_error'):
            row=copy.deepcopy(original);del row[name];samples.append(row)
        for name,value in [('launched_pid',True),('launch_completed',1),('direct_child_reaped_observed',1),
                           ('returncode',False),('process',None),('pid_identity_error','unknown')]:
            row=copy.deepcopy(original);row[name]=value;samples.append(row)
        row=copy.deepcopy(original);row['launched_pid']+=1;samples.append(row)
        for row in samples:
            with self.subTest(row=row):self.assertFalse(custody.direct_child_custody_closed(row))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    args.output.mkdir(mode=0o700);os.environ['HIA_CUSTODY_CONTROL_RETAIN']=str(args.output)
    loader=unittest.TestLoader();suite=unittest.TestSuite([loader.loadTestsFromTestCase(base.CustodyControls),loader.loadTestsFromTestCase(LaunchControls)])
    def flat(s):
        for t in s:
            if isinstance(t,unittest.TestSuite):yield from flat(t)
            else:yield t
    ids=[t.id() for t in flat(suite)];executed=[]
    class Result(unittest.TextTestResult):
        def startTest(self,test):executed.append(test.id());super().startTest(test)
    with (args.output/'unittest.log').open('x') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
    value={'loaded_ids':ids,'executed_ids':executed,'tests_run':result.testsRun,'loader_errors':loader.errors,
           'actual_product_tests_executed':False,'original_custody_controls':14,'new_controls':5,
           'status':'PASS' if result.wasSuccessful() and ids==executed and result.testsRun==19 and not loader.errors else 'HOLD'}
    for key in ('failures','errors','skipped','expectedFailures'):value[key]=[[t.id(),detail] for t,detail in getattr(result,key)]
    value['unexpectedSuccesses']=[t.id() for t in result.unexpectedSuccesses]
    custody.write_json(args.output/'REPORT.json',value)
    print(json.dumps({'status':value['status'],'tests_run':value['tests_run']}))
    return 0 if value['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
