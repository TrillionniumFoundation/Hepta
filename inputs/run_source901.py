"""Run a complete explicitly named unittest group and preserve ordered events."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import traceback
import unittest

def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expected',type=int)
    parser.add_argument('--expected-ids',type=Path,required=True)
    parser.add_argument('names',nargs='+')
    args=parser.parse_args()
    args.source=args.source.resolve(strict=True)
    args.output.mkdir(mode=0o700)
    sys.path.insert(0,str(args.source))
    report={'schema':'hia.evaluation.actual-unittest.v1','status':'FAIL',
            'python':sys.version,'selectors':args.names,'executed_ids':[],'events':[]}
    started=time.monotonic_ns()
    try:
        loader=unittest.TestLoader()
        suite=loader.loadTestsFromNames(args.names)
        ids=[test.id() for test in flatten(suite)]
        report['loaded_ids']=ids
        report['loader_errors']=list(loader.errors)
        frozen=json.loads(args.expected_ids.read_bytes())
        if (ids!=frozen['full_ordered_ids'] or len(ids)!=901 or ids[:893]!=frozen['old_ordered_ids']
                or ids[893:]!=frozen['new_ordered_ids']):
            raise AssertionError('complete original 893 plus 8 ordered source IDs differ')
        if not ids or loader.errors or len(ids)!=len(set(ids)):
            raise AssertionError('empty, duplicate, or failed original unittest discovery')
        if args.expected is not None and len(ids)!=args.expected:
            raise AssertionError('explicit original unittest denominator differs')
        for selector in args.names:
            module='.'.join(selector.split('.')[:2])
            path=Path(sys.modules[module].__file__).resolve()
            expected=args.source/(module.replace('.','/')+'.py')
            if path!=expected:raise AssertionError('test imported outside frozen source: '+module)
        class Result(unittest.TextTestResult):
            def startTest(self,test):
                report['executed_ids'].append(test.id())
                report['events'].append(['start',test.id(),time.monotonic_ns()])
                super().startTest(test)
            def stopTest(self,test):
                report['events'].append(['stop',test.id(),time.monotonic_ns()])
                super().stopTest(test)
        result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun,
            failures=[(test.id(),trace) for test,trace in result.failures],
            errors=[(test.id(),trace) for test,trace in result.errors],
            skips=[(test.id(),why) for test,why in result.skipped],
            expected_failures=[(test.id(),trace) for test,trace in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        ok=(type(result.testsRun) is int and result.testsRun==len(ids)
            and report['executed_ids']==ids and not any(report[key] for key in
                ('failures','errors','skips','expected_failures','unexpected_successes')))
        report['status']='PASS' if ok else 'FAIL'
    except BaseException:
        report['exception']=traceback.format_exc()
    finally:
        report['elapsed_ns']=time.monotonic_ns()-started
        raw=(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
        (args.output/'REPORT.json').write_bytes(raw)
        print(json.dumps({'status':report['status'],'loaded':len(report.get('loaded_ids',())),
                          'executed':len(report['executed_ids']),'report_sha256':sha256(raw).hexdigest()}),flush=True)
    return int(report['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
