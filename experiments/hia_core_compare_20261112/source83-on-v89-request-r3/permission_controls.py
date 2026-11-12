"""Four isolated controller controls. No project code or child process is run."""
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import traceback
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'control'))
spec = importlib.util.spec_from_file_location('permission_child', HERE / 'control/child.py')
child = importlib.util.module_from_spec(spec)
spec.loader.exec_module(child)
POLICY = json.loads((HERE / 'REQUEST.json').read_bytes())
SOURCE = Path(POLICY['source_root'])


class PermissionControls(unittest.TestCase):
    def make(self, output):
        denied = []
        current = {'id': child.NEGATIVE_PROCESS_POLICY['target_test_id']}
        def forbidden(*args, **kwargs):
            denied.append('forbidden')
            raise AssertionError('forbidden permission')
        guard = child.NegativeAdmissions(POLICY, SOURCE, output, lambda: current['id'], forbidden)
        return guard, denied, current

    def arguments(self, cwd, case):
        (cwd / 'cold.json').write_bytes(b'{}')
        return [guard_value for guard_value in (
            [sys.executable, '-I', '-S', '-B',
             str(SOURCE / 'tools/qualify_hia_store_page_ci.py'), 'component',
             '--owner', case['owner'], '--cold-report', str(cwd / 'cold.json'),
             '--output', str(cwd / 'report.json'), '--evidence-dir', str(cwd / 'evidence')],
            {'cwd': cwd, 'env': dict(child.NEGATIVE_PROCESS_POLICY['environment']),
             'capture_output': True, 'timeout': 10})]

    def environment(self, case):
        env = dict(child.NEGATIVE_PROCESS_POLICY['environment'])
        if case['development']:
            env[child.NEGATIVE_PROCESS_POLICY['prefixes'][case['owner']] + '_DEVELOPMENT_MANIFEST'] = '/old/development'
        return env

    def fake(self, guard, observed_calls, *, error=None, second_popen=False):
        def popen(command, *, cwd, env, stdout, stderr):
            observed_calls.append((command, cwd, env, stdout, stderr))
            return types.SimpleNamespace(pid=40000+len(observed_calls), returncode=1,
                stdout=types.SimpleNamespace(closed=True), stderr=types.SimpleNamespace(closed=True))
        guard.original_popen = popen
        def run(command, **keywords):
            self.assertEqual(set(keywords), {'cwd','env','capture_output','timeout'})
            self.assertIs(keywords['capture_output'], True)
            self.assertEqual(keywords['timeout'], 10)
            process = guard.popen(command, cwd=keywords['cwd'], env=keywords['env'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if second_popen:
                with self.assertRaises(AssertionError):
                    guard.popen(command, cwd=keywords['cwd'], env=keywords['env'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if error is not None:
                raise error
            case = child.NEGATIVE_PROCESS_POLICY['cases'][len(guard.rows)-1]
            stderr = b'development selection' if case['development'] else b'nested_report'
            value = subprocess.CompletedProcess(command, process.returncode, b'', stderr)
            guard.last_synthetic_completed = value
            return value
        guard.original_run = run

    def test_four_original_shapes_delegate_once_and_preserve_completed_value(self):
        with tempfile.TemporaryDirectory() as output:
            guard, denied, current = self.make(Path(output)); calls=[]
            self.fake(guard, calls)
            for case in child.NEGATIVE_PROCESS_POLICY['cases']:
                with tempfile.TemporaryDirectory() as temporary:
                    cwd=Path(temporary); args, kwargs=self.arguments(cwd, case)
                    kwargs['env']=self.environment(case)
                    value=guard.run(args, **kwargs)
                    self.assertIs(value, guard.last_synthetic_completed)
                    self.assertEqual(value.args, args)
                    self.assertFalse((cwd/'report.json').exists())
                    self.assertFalse((cwd/'evidence').exists())
            guard.complete()
            self.assertEqual(len(calls), 4); self.assertEqual(denied, [])
            self.assertEqual([r['case'] for r in guard.rows], child.NEGATIVE_PROCESS_POLICY['cases'])
            self.assertEqual(len(list(Path(output).iterdir())), 20)
            for row in guard.rows:
                self.assertEqual(row['status'], 'NEGATIVE_ADMISSION_RETURNED_AND_CLOSED')
                self.assertEqual(json.loads(Path(row['receipt_original']['path']).read_bytes()),
                                 {k:v for k,v in row.items() if k!='receipt_original'})
            with tempfile.TemporaryDirectory() as temporary:
                args, kwargs=self.arguments(Path(temporary), child.NEGATIVE_PROCESS_POLICY['cases'][0])
                with self.assertRaises(AssertionError): guard.run(args, **kwargs)
            self.assertEqual(len(calls), 4)

    def test_bad_command_environment_timeout_and_input_are_rejected_before_launch(self):
        changes=('test','python','flags','script','owner','env','timeout','capture','extra-key',
                 'input','input-symlink','extra-file','directory-mode')
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as output, tempfile.TemporaryDirectory() as temporary:
                guard, denied, current=self.make(Path(output)); calls=[]
                self.fake(guard,calls)
                cwd=Path(temporary); args,kwargs=self.arguments(cwd,child.NEGATIVE_PROCESS_POLICY['cases'][0])
                if change=='test': current['id']='tests.other.test'
                elif change=='python': args[0]='/other/python'
                elif change=='flags': args[1]='-c'
                elif change=='script': args[4]=str(SOURCE/'tools/qualify_hia_selfhost.py')
                elif change=='owner': args[7]='page'
                elif change=='env': kwargs['env']['LD_PRELOAD']='/unwanted'
                elif change=='timeout': kwargs['timeout']=11
                elif change=='capture': kwargs['capture_output']=False
                elif change=='extra-key': kwargs['shell']=True
                elif change=='input': (cwd/'cold.json').write_bytes(b'[]')
                elif change=='input-symlink':
                    (cwd/'cold.json').unlink(); (Path(output)/'outside.json').write_bytes(b'{}')
                    (cwd/'cold.json').symlink_to(Path(output)/'outside.json')
                elif change=='extra-file': (cwd/'unwanted').write_bytes(b'x')
                elif change=='directory-mode': cwd.chmod(0o755)
                with self.assertRaises((AssertionError,OSError,ValueError)): guard.run(args,**kwargs)
                self.assertEqual(calls,[])
                self.assertEqual(guard.rows,[])

    def test_popen_requires_current_one_use_run_permission_and_reentry_cannot_pass(self):
        with tempfile.TemporaryDirectory() as output, tempfile.TemporaryDirectory() as temporary:
            guard,denied,current=self.make(Path(output));calls=[]
            self.fake(guard,calls,second_popen=True)
            cwd=Path(temporary);args,kwargs=self.arguments(cwd,child.NEGATIVE_PROCESS_POLICY['cases'][0])
            with self.assertRaises(AssertionError):
                guard.popen(args,cwd=cwd,env=kwargs['env'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            guard.run(args,**kwargs)
            self.assertEqual(len(calls),1)
            self.assertGreaterEqual(len(denied),2)
            with self.assertRaises(ValueError): guard.complete()

    def test_timeout_and_baseexception_are_not_replaced_by_recording_failures(self):
        for original in (subprocess.TimeoutExpired(['original'],10,output=b'partial-out',stderr=b'partial-err'),
                         KeyboardInterrupt('original-base-exception')):
            with self.subTest(error=type(original).__name__), tempfile.TemporaryDirectory() as output, tempfile.TemporaryDirectory() as temporary:
                guard,denied,current=self.make(Path(output));calls=[]
                self.fake(guard,calls,error=original)
                cwd=Path(temporary);args,kwargs=self.arguments(cwd,child.NEGATIVE_PROCESS_POLICY['cases'][0])
                real_save=child.save
                def fail_terminal(path,value):
                    if str(path).endswith('.receipt.json'): raise OSError('synthetic terminal-write failure')
                    return real_save(path,value)
                with patch.object(child,'save',fail_terminal):
                    try: guard.run(args,**kwargs)
                    except BaseException as observed: self.assertIs(observed,original)
                    else: self.fail('original exception was swallowed')
                self.assertEqual(len(calls),1)
                self.assertEqual(guard.rows[0]['status'],'HOLD')
                self.assertTrue(guard.rows[0]['original_process_context_closed'])
                self.assertFalse(guard.rows[0]['original_run_returned'])
                self.assertTrue(guard.rows[0]['preservation_errors'])
                if isinstance(original,subprocess.TimeoutExpired):
                    self.assertEqual(Path(guard.rows[0]['stdout_partial']['path']).read_bytes(),b'partial-out')
                    self.assertEqual(Path(guard.rows[0]['stderr_partial']['path']).read_bytes(),b'partial-err')
                with self.assertRaises(ValueError): guard.complete()


def main():
    output=Path(sys.argv[1]); output.mkdir(mode=0o700)
    loader=unittest.TestLoader();suite=loader.loadTestsFromTestCase(PermissionControls)
    expected=[test.id() for test in suite];executed=[]
    report={'schema':'hepta.source83-r3-permission-control-report.v1','status':'HOLD',
            'scope':'SYNTHETIC_CONTROLLER_ONLY_NO_REAL_PYTHON_CHILD_OR_PROJECT_IMPORT',
            'expected_ids':expected,'loaded_ids':expected,'executed_ids':executed,
            'loader_errors':list(loader.errors),'real_subprocess_attempts':[]}
    def blocked(*args,**kwargs):
        report['real_subprocess_attempts'].append('blocked')
        raise AssertionError('controller controls cannot launch any real process/native image')
    class Result(unittest.TextTestResult):
        def startTest(self,test): executed.append(test.id());super().startTest(test)
    with ExitStack() as stack:
        stack.enter_context(patch.object(subprocess,'Popen',blocked))
        stack.enter_context(patch.object(subprocess,'run',blocked))
        for name in ('CDLL','PyDLL','CFUNCTYPE','PYFUNCTYPE'):
            stack.enter_context(patch.object(ctypes,name,blocked))
        stream=stack.enter_context((output/'unittest.log').open('x'))
        result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
    report['tests_run']=result.testsRun
    for key in ('errors','failures','skipped','expectedFailures','unexpectedSuccesses'):
        report[key]=[(x[0].id(),x[1]) if isinstance(x,tuple) else x.id() for x in getattr(result,key)]
    report['project_modules_loaded']=[name for name in sys.modules if name=='hepta' or name.startswith('hepta.') or name=='tools' or name.startswith('tools.')]
    if result.wasSuccessful() and expected==executed and len(expected)==4 and not any(report[k] for k in
        ('loader_errors','errors','failures','skipped','expectedFailures','unexpectedSuccesses','real_subprocess_attempts','project_modules_loaded')):
        report['status']='SYNTHETIC_CONTROLLER_CONTROLS_PASS'
    (output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':report['status'],'tests_run':report['tests_run']}))
    return 0 if report['status']=='SYNTHETIC_CONTROLLER_CONTROLS_PASS' else 1

if __name__=='__main__': raise SystemExit(main())

