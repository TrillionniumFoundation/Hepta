from __future__ import annotations
import hashlib, importlib.util, io, json, pathlib, tempfile, urllib.error
from unittest import mock
ROOT=pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work')
SOURCE=ROOT/'experiments/hia_agent_assembly_recovery_20261030/run_recovery.py'
source_bytes=SOURCE.read_bytes()
spec=importlib.util.spec_from_file_location('credential_reviewed_recovery',SOURCE)
module=importlib.util.module_from_spec(spec)
exec(compile(source_bytes,str(SOURCE),'exec'),module.__dict__)
marker='HEPTA_FAKE_CREDENTIAL_SENTINEL_FOR_PURE_TEST_ONLY'
rows=[]
with mock.patch.dict(module.os.environ,{'HEPTA_RECOVERY_GITHUB_TOKEN':marker,'GITHUB_TOKEN':marker,'GH_TOKEN':marker,'ACTIONS_RUNTIME_TOKEN':marker,'SAMPLE_PASSWORD':marker,'SAMPLE_SECRET':marker,'PATH':'/usr/bin','LLAMA_ARG_REPACK':'1'},clear=True):
    child=module.child_environment()
rows.append({'name':'child_env_omits_ci_credentials','passed':marker not in json.dumps(child) and child.get('LLAMA_ARG_REPACK')=='0' and child.get('PATH')=='/usr/bin','retained_keys':sorted(child)})
class Response:
    def __init__(self,data): self.stream=io.BytesIO(data);self.headers={'Content-Length':str(len(data))}
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def read(self,size=-1): return self.stream.read(size)
    def geturl(self): return 'https://fake.invalid/object?signed='+marker
for mode in ('success','http_failure'):
    captured={}
    def urlopen(request,timeout):
        captured['has_required_auth']=request.get_header('Authorization')=='Bearer '+marker
        if mode=='http_failure': raise urllib.error.HTTPError(request.full_url,403,'Forbidden',{},io.BytesIO(b'bounded error body'))
        return Response(b'{"id":100,"head_sha":"fixed"}')
    with tempfile.TemporaryDirectory(prefix='hepta-pure-credential-') as folder:
        failure=None
        with mock.patch.object(module.urllib.request,'urlopen',side_effect=urlopen):
            try: module.github_json('https://api.github.com/repos/fake/repo/actions/runs/100',marker,pathlib.Path(folder),'current')
            except BaseException as error: failure=type(error).__name__
        files={path.name:path.read_bytes() for path in pathlib.Path(folder).rglob('*') if path.is_file()}
        rows.append({'name':'api_'+mode+'_does_not_log_request_credentials','passed':captured.get('has_required_auth') is True and bool(files) and all(marker.encode() not in data and b'Bearer ' not in data and b'Authorization' not in data for data in files.values()) and (failure=='HTTPError' if mode=='http_failure' else failure is None),'raw_names':sorted(files),'observed_error_type':failure})
with tempfile.TemporaryDirectory(prefix='hepta-pure-download-credential-') as folder:
    base=pathlib.Path(folder);evidence=base/'evidence';cache=base/'cache';evidence.mkdir();cache.mkdir();payload=b'four'
    opener=mock.Mock();opener.open.return_value=Response(payload)
    item={'id':'fake','filename':'fixed.bin','url':'https://fake.invalid/fixed/revision/fixed.bin','bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
    with mock.patch.object(module.urllib.request,'build_opener',return_value=opener): module.download_fixed(evidence,cache,item)
    files={path.name:path.read_bytes() for path in evidence.rglob('*') if path.is_file()}
    rows.append({'name':'download_receipt_uses_original_url_not_redirect_signed_url','passed':bool(files) and all(marker.encode() not in data for data in files.values()),'raw_names':sorted(files)})
registration=json.loads((ROOT/'experiments/hia_agent_assembly_v4_20261030/REGISTRATION.json').read_bytes())
reviewed=[]
for name,want in registration['sources'].items():
    data=(ROOT/name).read_bytes();actual=hashlib.sha256(data).hexdigest()
    reviewed.append({'path':name,'sha256':actual,'matches_original_registration':actual==want})
report={'schema':'hepta.independent.pure-recovery-credential-review.v1','source':{'path':str(SOURCE.relative_to(ROOT)),'sha256':hashlib.sha256(source_bytes).hexdigest()},'source_unchanged':SOURCE.read_bytes()==source_bytes,'registered_sources':reviewed,'source_count':len(reviewed),'all_registered_sources_match':all(row['matches_original_registration'] for row in reviewed),'cases':rows,'count':len(rows),'passed':sum(row['passed'] for row in rows),'real_tokens_used':0,'real_network_requests':0,'model_completions':0,'native_executions':0,'static_findings':['The original 31-source runtime condition records only LLAMA_ARG_REPACK from /proc/PID/environ; no full environment dump was found.','Current API metadata records response bytes and original API URL, not request Authorization headers.','Downloaded object receipts record fixed original URL; returned redirect URL is not inspected or recorded.'],'pending':['Final workflow must disable checkout persisted credentials and upload only evidence/publication directories.'],'limitations':['Mock credential separation does not establish arbitrary-code or host isolation.','Actual future artifact contents still require inspection; this is source and pure mock evidence.']}
path=pathlib.Path('/tmp/hepta-recovery-credential-review-01.json')
with path.open('x') as stream:json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
print(json.dumps({'path':str(path),'count':report['count'],'passed':report['passed'],'source_sha256':report['source']['sha256'],'source_unchanged':report['source_unchanged'],'all_registered_sources_match':report['all_registered_sources_match']}))
