"""New documentation-path and compile-original custody regression controls only."""
from pathlib import Path
import json,sys,unittest
ROOT=Path('/workspace/scratch/e26ed3e2edcf/combined-ci-fixes-r3')
OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
expected=json.loads((OUT/'EXPECTED-IDS.json').read_bytes())
loader=unittest.TestLoader()
suite=loader.loadTestsFromNames(expected)
def ids(test):
 if isinstance(test,unittest.TestSuite):return [name for child in test for name in ids(child)]
 return [test.id()]
loaded=ids(suite);executed=[]
class Result(unittest.TextTestResult):
 def startTest(self,test):
  executed.append(test.id());super().startTest(test)
result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
anomalies={name:len(getattr(result,name)) for name in ('errors','failures','skipped','expectedFailures','unexpectedSuccesses')}
passed=(len(expected)==3 and expected==loaded==executed and result.testsRun==3 and not loader.errors and not any(anomalies.values()))
report={'schema':'hia.combined-ci-regression-source-controls.v1','status':'PASS' if passed else 'FAIL','expected_ids':expected,'loaded_ids':loaded,'executed_ids':executed,'tests_run':result.testsRun,'anomaly_counts':anomalies,'loader_errors':loader.errors,'runtime':sys.version,'scope':'Three new source controls only; inert transports exercise all106 real names cases without native execution; no contract/cold/retained qualification.'}
with (OUT/'RESULT.json').open('x') as stream:json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if passed else 1)
