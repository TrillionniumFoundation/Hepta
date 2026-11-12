from pathlib import Path
import argparse, json, sys, time, traceback, unittest

class Observed(unittest.TextTestResult):
    def __init__(self, *a, **k): super().__init__(*a, **k); self.executed=[]
    def startTest(self, test): self.executed.append(test.id()); super().startTest(test)

def leaves(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite): yield from leaves(test)
        else: yield test

def main():
    p=argparse.ArgumentParser(); p.add_argument('--source',type=Path,required=True); p.add_argument('--output',type=Path,required=True); a=p.parse_args()
    sys.path.insert(0,str(a.source.resolve()))
    report={'scope':'BYTE_WHOLE_EMIT_INTEGRATION_DEVELOPMENT_ONLY','status':'HOLD','current_source_cold':False,'whole_qualified':False}; start=time.monotonic()
    try:
        loader=unittest.TestLoader(); suite=loader.loadTestsFromName('tests.test_hia_native_byte_abi_integration.NativeByteABIIntegrationTests')
        ids=[t.id() for t in leaves(suite)]; report.update(loaded=ids,loader_errors=loader.errors)
        if loader.errors or len(ids)!=4 or len(set(ids))!=4: raise ValueError('exact4 integration controls required')
        r=unittest.TextTestRunner(verbosity=2,resultclass=Observed).run(suite)
        report.update(testsRun=r.testsRun,executed=r.executed,failures=[(t.id(),s) for t,s in r.failures],errors=[(t.id(),s) for t,s in r.errors],skipped=[(t.id(),s) for t,s in r.skipped],expectedFailures=[(t.id(),s) for t,s in r.expectedFailures],unexpectedSuccesses=[t.id() for t in r.unexpectedSuccesses])
        if r.testsRun!=4 or r.executed!=ids or any(report[k] for k in ('failures','errors','skipped','expectedFailures','unexpectedSuccesses')): raise ValueError('complete integration conjunction failed')
        report['status']='PASS'
    except BaseException as e:report['failure']={'type':type(e).__name__,'text':str(e),'traceback':traceback.format_exc()}
    finally:
        report['elapsed_seconds']=time.monotonic()-start;a.output.write_text(json.dumps(report,indent=2)+'\n')
    return int(report['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
