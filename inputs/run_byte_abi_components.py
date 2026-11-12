"""Run the exact four Byte ABI classes, preserving every original anomaly."""
from pathlib import Path
import argparse,json,sys,time,traceback,unittest

def leaves(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite): yield from leaves(item)
        else: yield item

class Observed(unittest.TextTestResult):
    def __init__(self,*a,**k):super().__init__(*a,**k);self.executed=[]
    def startTest(self,test):self.executed.append(test.id());super().startTest(test)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',required=True,type=Path);parser.add_argument('--output',required=True,type=Path);a=parser.parse_args()
    sys.path.insert(0,str(a.source.resolve()))
    names=['tests.test_hia_native_byte_abi_native.'+n for n in ('NativeByteABISourceTests','NativeByteABINativeTests','NativeByteABIVMTests','NativeByteABIInstalledTests')]
    report={'scope':'EXACT_BYTE_R4_COMPONENT_DEVELOPMENT_ONLY','classes':names,'status':'HOLD','cold':False,'full_qualified':False};started=time.monotonic();failure=None
    try:
        loader=unittest.TestLoader();suite=loader.loadTestsFromNames(names);ids=[t.id() for t in leaves(suite)]
        report.update(loaded=ids,loader_errors=loader.errors)
        if loader.errors or len(ids)!=25 or len(set(ids))!=25:raise ValueError('exact 25 unique Byte ABI component tests required')
        result=unittest.TextTestRunner(verbosity=2,resultclass=Observed).run(suite)
        report.update(testsRun=result.testsRun,executed=result.executed,failures=[(t.id(),s) for t,s in result.failures],errors=[(t.id(),s) for t,s in result.errors],skipped=[(t.id(),s) for t,s in result.skipped],expectedFailures=[(t.id(),s) for t,s in result.expectedFailures],unexpectedSuccesses=[t.id() for t in result.unexpectedSuccesses])
        if result.testsRun!=25 or result.executed!=ids or any(report[k] for k in ('failures','errors','skipped','expectedFailures','unexpectedSuccesses')):raise ValueError('Byte ABI full component conjunction failed')
        report['status']='PASS'
    except BaseException as e:failure=e;report['failure']={'type':type(e).__name__,'text':str(e),'traceback':traceback.format_exc()}
    finally:
        report['elapsed_seconds']=time.monotonic()-started;a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    return int(failure is not None)
if __name__=='__main__':raise SystemExit(main())
