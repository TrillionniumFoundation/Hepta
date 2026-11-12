from __future__ import annotations
import hashlib,json,os,subprocess,sys,time,traceback,unittest
from pathlib import Path

ROOT=Path('/workspace/scratch/hia-bounded-product-v80-20261112-r2/checkout')
OUT=Path(__file__).parent
sys.path.insert(0,str(ROOT))

def write(path,value):
    with path.open('x') as stream:
        json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')

def source():
    from tools.hia_selfhost_contract import file_digests,CONTRACT_PATH
    return {**file_digests(ROOT),CONTRACT_PATH:hashlib.sha256((ROOT/CONTRACT_PATH).read_bytes()).hexdigest()}

def flatten(suite):
    for test in suite:
        if isinstance(test,unittest.TestSuite):yield from flatten(test)
        else:yield test

class Observed(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.ids=[]
    def startTest(self,test):
        self.ids.append(test.id());super().startTest(test)

report={'schema':'hepta.hia.bounded-read-v80-source-verification.v1','status':'HOLD','steps':[],'native_executed':False,'new_component_tests_executed':False,'errors':[]}
try:
    report['source_before']=source()
    commands=[['tools/generate_hia_bounded_read.py','--check'],['tools/generate_hia_selfhost_contract.py'],['tests/test_hia_selfhost_language_coverage.py','--generate-inventory'],['tools/generate_hia_selfhost_contract.py'],['tools/generate_hia_selfhost_contract.py','--check']]
    for index,argv in enumerate(commands):
        stdout=OUT/('%02d.stdout.log'%index);stderr=OUT/('%02d.stderr.log'%index)
        command=[sys.executable,'-B',*argv];started=time.monotonic_ns()
        with stdout.open('xb') as out,stderr.open('xb') as err:
            run=subprocess.run(command,cwd=ROOT,env=os.environ.copy(),stdout=out,stderr=err,timeout=120)
        row={'command':command,'returncode':run.returncode,'wall_ns':time.monotonic_ns()-started,'stdout':{'bytes':stdout.stat().st_size,'sha256':hashlib.sha256(stdout.read_bytes()).hexdigest()},'stderr':{'bytes':stderr.stat().st_size,'sha256':hashlib.sha256(stderr.read_bytes()).hexdigest()}}
        report['steps'].append(row)
        if run.returncode:raise RuntimeError('source command failed at '+str(index))
    loader=unittest.TestLoader()
    suite=loader.loadTestsFromNames(['tests.test_hia_bounded_read_source.BoundedReadSourceTests','tests.test_hia_selfhost_contract.SelfhostContractTests'])
    loaded=[test.id() for test in flatten(suite)]
    report['loaded_ids']=loaded;report['loader_errors']=list(loader.errors)
    if loader.errors or len(loaded)!=13:raise RuntimeError('source test denominator differs')
    with (OUT/'source-tests.log').open('x') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Observed).run(suite)
    report['executed_ids']=result.ids;report['testsRun']=result.testsRun
    report['anomalies']={'failures':[(t.id(),d) for t,d in result.failures],'errors':[(t.id(),d) for t,d in result.errors],'skips':[(t.id(),d) for t,d in result.skipped],'expected_failures':[(t.id(),d) for t,d in result.expectedFailures],'unexpected_successes':[t.id() for t in result.unexpectedSuccesses]}
    if result.ids!=loaded or result.testsRun!=13 or any(report['anomalies'].values()):raise RuntimeError('source checks failed')
    report['status']='SOURCE_VERIFICATION_PASS_NOT_NATIVE_QUALIFICATION'
except BaseException as error:
    report['errors'].append({'type':type(error).__name__,'text':str(error),'traceback':traceback.format_exc()})
finally:
    try:
        report['source_after']=source()
        changes=sorted(name for name in set(report.get('source_before',{}))|set(report['source_after']) if report.get('source_before',{}).get(name)!=report['source_after'].get(name))
        report['derived_changes']=changes
        if set(changes)-{'docs/HIA_SELFHOST_CORE_SUPPORT.json','docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'}:
            report['status']='HOLD';report['errors'].append({'text':'unexpected source changes'})
    except BaseException as error:
        report['status']='HOLD';report['errors'].append({'phase':'final_source','type':type(error).__name__,'text':str(error)})
    write(OUT/'report.json',report)
print(json.dumps({'status':report['status'],'steps':len(report['steps']),'tests':report.get('testsRun'),'errors':report['errors']}))
raise SystemExit(0 if report['status']=='SOURCE_VERIFICATION_PASS_NOT_NATIVE_QUALIFICATION' else 1)
