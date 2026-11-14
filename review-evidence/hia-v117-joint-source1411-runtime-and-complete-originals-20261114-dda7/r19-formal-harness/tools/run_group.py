from pathlib import Path
import hashlib,json,os,sys,time,traceback,unittest
from bounded_support import ROOT, SOURCE, snapshot
sys.path.insert(0,str(SOURCE))
label,group=sys.argv[1:3];OUT=ROOT/'evidence'/label;OUT.mkdir(exist_ok=False)
def save(name,value):(OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
before=snapshot();save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
report={'schema':'hia-cli-discovery-portable-development-group.v1','scope':'FORMAL_ACTUAL314_BOUNDED_DEVELOPMENT_NOT_COLD','python':sys.version,'status':'FAIL','group':group,'started_ids':[],'stopped_ids':[]}
try:
 from tools import qualify_hia_cli_discovery_bundle as qualifier
 if group=='source':
  names=('tests.test_hia_cli_discovery_routing_native.CliDiscoveryRoutingSourceTests',);expected=10
 elif group=='native':
  names=qualifier.NATIVE_IDS;expected=9
  os.environ[qualifier.DEVELOPMENT]=str(Path(sys.argv[3]).resolve(strict=True));os.environ[qualifier.EVIDENCE]=str(OUT/'controls');(OUT/'controls').mkdir()
 elif group=='original43':
  names=('tests.test_hia_cli_native','tests.test_hia_cli_continuation_native');expected=43
  os.environ[qualifier.OLD_DEVELOPMENT]=str(Path(sys.argv[3]).resolve(strict=True));os.environ[qualifier.OLD_EVIDENCE]=str(OUT/'controls')
  packaging=Path(sys.executable).resolve(strict=True)
  os.environ['HEPTA_HIA_TEST_PACKAGING_PYTHON']=str(packaging)
  report['declared_packaging_interpreter']=str(packaging)
  report['packaging_scope']='Actual CPython3.14.4 is used for packaging, original test bodies and installed children'
 else:raise ValueError('unknown fixed group')
 loader=unittest.TestLoader();suite=loader.loadTestsFromNames(names);ids=[test.id() for test in qualifier._flatten(suite)]
 report.update(loaded_ids=ids,loaded=suite.countTestCases(),loader_errors=loader.errors)
 fixed=json.loads((ROOT/'FORMAL-EXPECTED-IDS.json').read_bytes())['bounded_groups'][group]
 assert ids==fixed
 assert len(ids)==len(set(ids))==expected and not loader.errors
 if group=='original43':assert ids==list(qualifier.groups()['original_cli'])
 class Result(unittest.TextTestResult):
  def startTest(self,test):report['started_ids'].append(test.id());super().startTest(test)
  def stopTest(self,test):report['stopped_ids'].append(test.id());super().stopTest(test)
 result=unittest.TextTestRunner(stream=sys.stderr,verbosity=2,resultclass=Result).run(suite)
 report.update(tests_run=result.testsRun,failures=[(t.id(),e) for t,e in result.failures],errors=[(t.id(),e) for t,e in result.errors],skipped=[(t.id(),e) for t,e in result.skipped],expected_failures=[(t.id(),e) for t,e in result.expectedFailures],unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
 assert report['loaded']==report['tests_run']==expected and ids==report['started_ids']==report['stopped_ids']
 assert not any(report[key] for key in qualifier.ANOMALIES)
 report['status']='PASS'
except BaseException:report['traceback']=traceback.format_exc()
finally:
 after=snapshot();save('SOURCE-AFTER.json',after);report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
 if before!=after:report['status']='FAIL'
 save('REPORT.json',report)
print(json.dumps({key:report.get(key) for key in ('status','loaded','tests_run','source_unchanged','wall_ns','traceback')}))
raise SystemExit(0 if report['status']=='PASS' else 1)
