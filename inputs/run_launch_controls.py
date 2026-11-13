"""Strict explicit groups; unavailable ptrace remains a separate failed gate."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import unittest

ROOT=Path(__file__).parent/'source'
sys.path.insert(0,str(ROOT))
BASE=Path(__file__).parent

def flatten(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite):yield from flatten(item)
        else:yield item

def pins():
    result={}
    for p in ROOT.rglob('*'):
        if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts:
            raw=p.read_bytes();result[p.relative_to(ROOT).as_posix()]={
                'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'mode':p.stat().st_mode&0o777}
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--group',choices=('local-observations','required-ptrace'),required=True)
    a=p.parse_args();a.output.mkdir(mode=0o700)
    from tests import test_hia_release_launch as m
    loader=unittest.defaultTestLoader
    all_ids=[case.id() for case in flatten(loader.loadTestsFromModule(m))]
    trace='test_actual_trace_seals_readback_single_exec_and_descriptor_cleanup'
    pending=[value for value in all_ids if '.ReleaseLaunchSyscallFaultTests.' in value or value.endswith('.'+trace)]
    ids=pending if a.group=='required-ptrace' else [value for value in all_ids if value not in pending]
    assert len(ids)==(5 if a.group=='required-ptrace' else 21),(len(ids),ids)
    assert len(set(ids))==len(ids)
    suite=loader.loadTestsFromNames(ids);loaded=[case.id() for case in flatten(suite)]
    assert loaded==ids
    before=pins();executed=[]
    class Result(unittest.TextTestResult):
        def startTest(self,test):executed.append(test.id());super().startTest(test)
    started=time.monotonic_ns()
    result=unittest.TextTestRunner(stream=sys.stderr,verbosity=2,resultclass=Result).run(suite)
    after=pins()
    anomalies={'failures':[(t.id(),raw) for t,raw in result.failures],
               'errors':[(t.id(),raw) for t,raw in result.errors],
               'skipped':[(t.id(),reason) for t,reason in result.skipped],
               'expected_failures':[(t.id(),raw) for t,raw in result.expectedFailures],
               'unexpected_successes':[t.id() for t in result.unexpectedSuccesses]}
    passed=not any(anomalies.values()) and result.testsRun==len(ids) and executed==ids and before==after
    report={'schema':'hia.release-launch.development-controls.v1','group':a.group,
            'status':'PASS' if passed else 'FAIL','python':sys.version,
            'wall_ns':time.monotonic_ns()-started,'loaded_ids':loaded,'executed_ids':executed,
            'tests_run':result.testsRun,'anomalies':anomalies,
            'source_before':before,'source_after':after,'source_unchanged':before==after,
            'required_ptrace_ids':pending,'entire_gate_complete':False,
            'matching_cold':False,'whole_native':False}
    (a.output/'REPORT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:report[k] for k in ('group','status','tests_run','source_unchanged','whole_native')},sort_keys=True))
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
