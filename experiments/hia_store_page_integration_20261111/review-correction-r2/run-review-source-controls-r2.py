"""Only the thirteen controls needed for the preserved review correction."""
from pathlib import Path
from hashlib import sha256
import json, os, stat, subprocess, sys, time, traceback, unittest, zipfile

root = Path(__file__).resolve().parent
source = root / 'source'; os.chdir(source); sys.path.insert(0, str(source))
from tools.hia_selfhost_contract import file_digests, CONTRACT_PATH
out = root / 'source-controls-review-r2' / 'inner'; out.mkdir(mode=0o700)
def save(name, value):
    (out / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
def snapshot():
    return {name: {'size': (source / name).stat().st_size,
                   'mode': stat.S_IMODE((source / name).stat().st_mode),
                   'sha256': sha256((source / name).read_bytes()).hexdigest()}
            for name in sorted(set(file_digests(source)) | {CONTRACT_PATH})}
started = time.monotonic(); before = snapshot(); save('source-before.json', before)
review = json.loads((root / 'REVIEW-CORRECTION-PREEXECUTION.json').read_bytes())
with zipfile.ZipFile(out / 'executed-review-delta.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
    for record in review['delta']:
        raw = (source / record['path']).read_bytes()
        assert sha256(raw).hexdigest() == record['sha256']
        item = zipfile.ZipInfo(record['path']); item.create_system=3
        item.external_attr = (stat.S_IFREG | 0o644) << 16; item.compress_type=zipfile.ZIP_DEFLATED
        archive.writestr(item, raw)
with zipfile.ZipFile(out / 'executed-review-delta.zip') as archive:
    assert set(archive.namelist()) == {v['path'] for v in review['delta']}
    for record in review['delta']:
        assert sha256(archive.read(record['path'])).hexdigest() == record['sha256']
groups = ('tests.test_hia_store_page_gates', 'tests.test_hia_selfhost_contract.SelfhostContractTests')
report = {'schema':'hia.store-page-review-source-controls.v1','status':'HOLD',
          'scope':'SOURCE_ONLY_NOT_COLD_OR_NATIVE_OR_FULL','source_commit':'a3ebd11545d48dedbed8dbdb0d2c01f39bd7e564',
          'source_tree':'9d71f032a2301c56c21abe8c2c38e306b450eafb','groups':groups,
          'loaded_ids':[], 'executed_ids':[], 'loader_errors':[], 'python':sys.version,
          'python_executable':sys.executable,'generators_rerun':0,'previous_55_generators_source':'683e91b700129ebdc6ea0b0431a49cc98612aa13',
          'previous_50_methods_relabelled':False,'HIA_or_owner_source_changed':False,
          'declared_source_pins_including_contract':len(before)}
for name in ('failures','errors','skipped','expectedFailures','unexpectedSuccesses'): report[name]=[]
try:
    argv=[sys.executable,'-B','tools/generate_hia_selfhost_contract.py','--check']
    process=subprocess.run(argv,cwd=source,capture_output=True,check=False)
    (out/'contract.stdout').write_bytes(process.stdout);(out/'contract.stderr').write_bytes(process.stderr)
    report['contract_check']={'argv':argv,'returncode':process.returncode}
    assert process.returncode==0
    loader=unittest.TestLoader();suite=loader.loadTestsFromNames(groups)
    def ids(item):
        if isinstance(item,unittest.TestSuite):return [n for child in item for n in ids(child)]
        return [item.id()]
    report['loaded_ids']=ids(suite);report['loader_errors']=list(loader.errors)
    class Result(unittest.TextTestResult):
        def startTest(self,test):
            report['executed_ids'].append(test.id());super().startTest(test)
    with (out/'unittest.log').open('x') as log:
        result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Result).run(suite)
    report['tests_run']=result.testsRun
    for name in ('failures','errors','skipped','expectedFailures','unexpectedSuccesses'):
        report[name]=[([v[0].id(),v[1]] if isinstance(v,tuple) else v.id()) for v in getattr(result,name)]
    report['strict_pass']=(len(report['loaded_ids'])==len(set(report['loaded_ids']))==13
        and report['loaded_ids']==report['executed_ids'] and result.testsRun==13
        and result.wasSuccessful() and not loader.errors and all(not report[k] for k in
            ('failures','errors','skipped','expectedFailures','unexpectedSuccesses')))
except BaseException:
    report['error']=traceback.format_exc();report['strict_pass']=False
finally:
    after=snapshot();save('source-after.json',after);report['source_preserved']=before==after
    report['status']='PASS' if report.get('strict_pass') and report['source_preserved'] else 'HOLD'
    report['seconds']=time.monotonic()-started;save('report.json',report)
print(json.dumps({k:report.get(k) for k in ('status','tests_run','seconds','source_preserved','error')}),flush=True)
raise SystemExit(0 if report['status']=='PASS' else 1)
