"""Frozen twenty tiny source/IO checks, never a receiver or original program."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parent.parent

class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.actual_ids=[]; self.success_ids=[]
    @staticmethod
    def name(test): return type(test).__name__+'.'+test._testMethodName
    def startTest(self, test): self.actual_ids.append(self.name(test));super().startTest(test)
    def addSuccess(self, test): self.success_ids.append(self.name(test));super().addSuccess(test)

def create(path, value):
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    if Path(path).read_bytes()!=raw:raise RuntimeError('control report readback differs')

def main():
    request=json.loads((ROOT/'CONTROL-REQUEST.json').read_bytes());output=Path(request['output'])
    if len(sys.argv)!=1 or os.path.lexists(output):raise RuntimeError('fresh fixed source-control output required')
    output.mkdir(mode=0o700);(output/'tmp').mkdir(mode=0o700);tempfile.tempdir=str(output/'tmp')
    report={'schema':'hia.v92.three-view-twenty-source-controls.v1','status':'HOLD',
            'expected_ids':request['expected_ids'],'loaded_ids':[],'actual_ids':[],'success_ids':[],
            'tests_run':0,'failures':[],'errors':[],'skipped':[],'expected_failures':[],
            'unexpected_successes':[],'denied_effects':[],'network_bytes':0,'product_execution':False,
            'receiver_executed':False,'private_proxy_capture_performed':False}
    def pins():
        rows={}
        for name,expected in request['inputs'].items():
            raw=(ROOT/name).read_bytes();row={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
            if row!=expected:raise RuntimeError('frozen source-control pin differs')
            rows[name]=row
        return rows
    began=time.monotonic()
    try:
        before=pins();report['inputs_before']=before
        def audit(event,args):
            if event in {'subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec',
                         'socket.__new__','socket.connect','socket.bind','ctypes.dlopen'}:
                report['denied_effects'].append({'event':event});raise RuntimeError('source-only external effect denied')
        sys.addaudithook(audit)
        spec=importlib.util.spec_from_file_location('v92_view_source_checks',ROOT/'controls/check_view.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        declared=['StoredContainerControls.'+name for name in module.StoredContainerControls.__dict__ if name.startswith('test_')]
        if declared!=request['expected_ids'] or len(declared)!=20:raise RuntimeError('complete finite source IDs differ')
        suite=unittest.TestSuite(module.StoredContainerControls(x.split('.')[1]) for x in declared)
        report['loaded_ids']=[Result.name(test) for test in suite]
        result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun,actual_ids=result.actual_ids,success_ids=result.success_ids,
            failures=[{'id':Result.name(t),'traceback':s} for t,s in result.failures],
            errors=[{'id':Result.name(t),'traceback':s} for t,s in result.errors],
            skipped=[{'id':Result.name(t),'reason':s} for t,s in result.skipped],
            expected_failures=[{'id':Result.name(t),'traceback':s} for t,s in result.expectedFailures],
            unexpected_successes=[Result.name(t) for t in result.unexpectedSuccesses])
        after=pins();report['inputs_after']=after
        if (before!=after or report['expected_ids']!=report['loaded_ids'] or report['loaded_ids']!=report['actual_ids']
            or report['actual_ids']!=report['success_ids'] or result.testsRun!=20
            or any(report[k] for k in ('failures','errors','skipped','expected_failures','unexpected_successes','denied_effects'))):
            raise RuntimeError('complete twenty source/IO controls failed')
        report['status']='TWENTY_SOURCE_IO_CONTROLS_PASS_ONLY'
    except BaseException as error:
        report['status']='HOLD';report['exception']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
    report['elapsed_seconds']=time.monotonic()-began;create(output/'REPORT.json',report)
    print(json.dumps({'status':report['status'],'tests_run':report['tests_run'],'network_bytes':0}))
    return 0 if report['status']=='TWENTY_SOURCE_IO_CONTROLS_PASS_ONLY' and 'exception' not in report else 1

if __name__=='__main__':raise SystemExit(main())
