"""Installed worker uses selected file capture and exact installation identity."""
from __future__ import annotations
import base64,csv,io,json,os,shutil,sys,zipfile
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from tests.hia_store_file_capture_controls import run_process,clean_environment,write
from tests.hia_store_file_capture_oracle import canonical
WORKER=r'''import importlib.abc,json,sys
from pathlib import Path
installed=sys.argv.pop(1);sys.path.insert(0,installed)
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed capture imported tools')
sys.meta_path.insert(0,NoTools())
from hepta import hia_agent_store as store
from hepta import hia_agent_service as service
from hepta import hia_store_file_capture_native as native
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':0,'request':0};active=False
def forbidden(*args,**kwargs):raise AssertionError('selected capture entered retained body')
store._STABLE_READ_REFERENCE=forbidden;store._CAPTURE_PATH_REFERENCE=forbidden
initialize=native.NativeStoreFileCapture.__init__
def image_initialize(image,*args,**kwargs):
    initialize(image,*args,**kwargs);entry=image._entry
    def observed(*values):
        code=entry(*values);counts['request' if active else 'startup']+=1;return code
    image._entry=observed
native.NativeStoreFileCapture.__init__=image_initialize
reference_call=service.HIAAgentService._reference_call
def request(self,*args,**kwargs):
    global active
    active=True
    try:return reference_call(self,*args,**kwargs)
    finally:active=False
service.HIAAgentService._reference_call=request
try:code=main()
finally:sys.stderr.write('CAPTURE_COUNTS='+json.dumps(counts,sort_keys=True)+'\n')
raise SystemExit(code)
'''
def counts(stderr):
    lines=[x[len(b'CAPTURE_COUNTS='):] for x in stderr.splitlines() if x.startswith(b'CAPTURE_COUNTS=')]
    if len(lines)!=1:raise ValueError('worker lacks exact capture count record')
    return json.loads(lines[0])

def run(manifest,output):
    from hepta import hia_agent_service as api
    from hepta import hia_store_file_capture_native as native
    from hepta.hia_native_helpers import ABI,SCHEMA,TARGET,native_helpers_scope
    from tests.test_hia_agent_installed_resources import RESOURCES,SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    output=Path(output);output.mkdir(mode=0o700)
    staging=output/'source';staging.mkdir()
    shutil.copytree(ROOT/'hepta',staging/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES,*SDIST_SUPPORT_FILES,'setup.py','pyproject.toml','MANIFEST.in'):
        target=staging/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
    environment=clean_environment();environment['PYTHONDONTWRITEBYTECODE']= '1'
    commands=[]
    def command(label,arguments,*,body=None,expected=0):
        out,err,receipt=run_process(output,label,arguments,env=environment,body=body,expected=expected,timeout=60)
        commands.append(receipt);return out,err
    from tests.hia_distribution_fixture import installed_wheel_path, ordinary_wheel
    command('wheel',['-m','pip','wheel','--no-deps','--no-build-isolation','--no-index','--wheel-dir',output/'wheels',ordinary_wheel(staging)])
    wheel,=(output/'wheels').glob('*.whl');installed=output/'installed'
    command('install',['-m','pip','install','--no-deps','--no-index','--no-compile','--target',installed,wheel])
    files={}
    with zipfile.ZipFile(wheel) as archive:
        record_name,=[name for name in archive.namelist() if name.endswith('.dist-info/RECORD')]
        wheel_record=archive.read(record_name)
        for name,digest,size in csv.reader(io.StringIO(wheel_record.decode())):
            raw=archive.read(name)
            if digest and (digest!='sha256='+base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode() or size!=str(len(raw))):
                raise ValueError('wheel RECORD differs from member')
            if name!=record_name:
                if installed_wheel_path(installed, name).read_bytes()!=raw:raise ValueError('installed member differs: '+name)
                files[name]=sha256(raw).hexdigest()
    source=installed/'hepta/_data/examples/hia_bootstrap/store_file_capture.hepta'
    if source.read_bytes()!=native.SOURCE.read_bytes():raise ValueError('installed source differs')
    original_manifest=Path(manifest).read_bytes();bundle=output/'bundle.json'
    write(bundle,{'schema':SCHEMA,'target':TARGET,'abi':ABI,'helpers':[{'selector':native.SELECTOR,
        'manifest_path':str(Path(manifest).absolute()),'manifest_sha256':sha256(original_manifest).hexdigest()}]})
    bundle_pin=sha256(bundle.read_bytes()).hexdigest()
    script=output/'worker.py';script.write_text(WORKER)
    raw,err=command('identity',[script,installed,'--installation-manifest','--native-helpers-manifest',bundle,
                                 '--expected-native-helpers-sha256',bundle_pin])
    identity=json.loads(raw)
    if set(identity)!={'worker_sha256','backend_sha256','catalog_sha256','native_helpers_sha256'}:
        raise ValueError('installed identity fields differ')
    if identity['native_helpers_sha256']!=bundle_pin or any(type(v)is not str or len(v)!=64 or set(v)-set('0123456789abcdef') for v in identity.values()):
        raise ValueError('installed identity is not exact')
    if counts(err)!={'startup':0,'request':0}:raise ValueError('identity query executed provider')

    case=AgentToolCase('runTest');saved_environment=dict(os.environ)
    try:
        os.environ.clear();os.environ.update(environment)
        with native_helpers_scope(str(bundle),bundle_pin):case.setUp()
        target=case.files_root/'installed-capture.bin';target.write_bytes(b'actual installed capture\x00\n')
        arguments=case.session.arguments(context=False,artifact_profile=case.session.profiles['artifact'],
            source={'kind':'path','path':str(target),'expected_sha256':sha256(target.read_bytes()).hexdigest(),'max_bytes':4096})
        request={'schema':'hia-agent-worker-request-v1','tool':'hia_artifact','arguments':arguments,
                 'profile_sha256':'a'*64,'catalog_sha256':case.service.catalog_sha256}
        request['request_sha256']=api.digest(request);case.service.close()
        def worker(label,*,expected=0):
            return command(label,[script,installed,'--state-root',case.state_root,'--artifact-root',case.files_root,
                '--request-json-stdin','--native-helpers-manifest',bundle,'--expected-native-helpers-sha256',bundle_pin,
                '--expected-worker-sha256',identity['worker_sha256'],'--expected-backend-sha256',identity['backend_sha256'],
                '--expected-catalog-sha256',identity['catalog_sha256']],body=canonical(request),expected=expected)
        first_raw,first_err=worker('normal');first=json.loads(first_raw)
        if first['response']['status']!='completed' or counts(first_err)['request']<=0:
            raise AssertionError('installed worker did not execute selected capture')
        ref=first['response']['result']['artifact']
        if ref['sha256']!=sha256(target.read_bytes()).hexdigest() or (case.state_root/'artifacts'/ref['sha256']).read_bytes()!=target.read_bytes():
            raise AssertionError('installed retained bytes differ')
        replay_raw,replay_err=worker('replay');replay=json.loads(replay_raw)
        if replay['response']!=first['response'] or counts(replay_err)['request']!=0:
            raise AssertionError('original replay executed capture again')
        original_source=source.read_bytes();extra=installed/'hepta/capture_unlisted_control.py'
        try:
            try:
                source.write_bytes(original_source+b'\n');raw,err=worker('source-plus-LF',expected=2)
                if raw or counts(err)['request']:raise AssertionError('changed source reached request')
            finally:source.write_bytes(original_source)
            try:
                extra.write_text('UNLISTED_CAPTURE_INPUT = True\n');raw,err=worker('extra-module',expected=2)
                if raw or counts(err)['request']:raise AssertionError('extra module bypassed identity')
            finally:extra.unlink(missing_ok=True)
        finally:source.write_bytes(original_source)
        observations={'normal':first,'normal_counts':counts(first_err),'replay':replay,'replay_counts':counts(replay_err)}
    finally:
        try:
            if hasattr(case,'temporary'):case.tearDown()
        finally:os.environ.clear();os.environ.update(saved_environment)
    if Path(manifest).read_bytes()!=original_manifest:raise ValueError('manifest changed')
    for name,digest in files.items():
        if sha256(installed_wheel_path(installed, name).read_bytes()).hexdigest()!=digest:raise ValueError('installed member not restored: '+name)
    report={'schema':'hepta.hia.store-file-capture-installed-worker.v1','wheel':str(wheel),
        'wheel_sha256':sha256(wheel.read_bytes()).hexdigest(),'installed':str(installed),
        'wheel_files_checked_against_installed':files,'wheel_RECORD_sha256':sha256(wheel_record).hexdigest(),
        'installed_RECORD_sha256':sha256((installed/record_name).read_bytes()).hexdigest(),
        'identity':identity,'bundle_sha256':bundle_pin,'commands':commands,'observations':observations,
        'runtime_authoring_imports_forbidden':True,'every_request_has_all_three_expected_identity_flags':True,
        'whole_native_stack_qualified':False,'unknown_descriptor_case_covered_elsewhere':True}
    write(output/'installed.json',report);return report
