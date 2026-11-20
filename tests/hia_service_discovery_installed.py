"""Installed worker uses selected service discovery and exact installation identity."""
from __future__ import annotations
import base64,csv,io,json,os,shutil,sys,zipfile
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from tests.hia_service_discovery_controls import run_process,clean_environment,write
from tests.hia_service_discovery_oracle import canonical
WORKER=r'''import importlib.abc,json,sys,ctypes,struct
from pathlib import Path
installed=sys.argv.pop(1);sys.path.insert(0,installed)
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed discovery imported tools')
sys.meta_path.insert(0,NoTools())
from hepta import hia_agent_store as store
from hepta import hia_agent_service as service
from hepta import hia_service_discovery_native as native
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':{'1':0,'2':0},'request':{'1':0,'2':0}};active=False
def forbidden(*args,**kwargs):raise AssertionError('selected discovery entered retained body')
service._SERVICE_DISCOVERY_DESCRIBE_REFERENCE=forbidden
service._SERVICE_DISCOVERY_EXAMPLES_REFERENCE=forbidden
service.HIAAgentService._hia_describe_reference=forbidden
service.HIAAgentService._examples_reference=staticmethod(forbidden)
initialize=native.NativeServiceDiscovery.__init__
def image_initialize(image,*args,**kwargs):
    initialize(image,*args,**kwargs);entry=image._entry
    def observed(*values):
        request=struct.unpack('<16Q',ctypes.string_at(values[0],values[1]))
        code=entry(*values)
        counts['request' if active else 'startup'][str(request[5])]+=1
        return code
    image._entry=observed
native.NativeServiceDiscovery.__init__=image_initialize
reference_call=service.HIAAgentService._reference_call
def request(self,*args,**kwargs):
    global active
    active=True
    try:return reference_call(self,*args,**kwargs)
    finally:active=False
service.HIAAgentService._reference_call=request
try:code=main()
finally:sys.stderr.write('DISCOVERY_COUNTS='+json.dumps(counts,sort_keys=True)+'\n')
raise SystemExit(code)
'''
def counts(stderr):
    lines=[x[len(b'DISCOVERY_COUNTS='):] for x in stderr.splitlines() if x.startswith(b'DISCOVERY_COUNTS=')]
    if len(lines)!=1:raise ValueError('worker lacks exact discovery count record')
    return json.loads(lines[0])

def run(manifest,store_manifest,output):
    from hepta import hia_agent_service as api
    from hepta import hia_service_discovery_native as native
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
    command('wheel',['-m','pip','wheel','--no-deps','--no-build-isolation','--no-index','--wheel-dir',output/'wheels',staging])
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
                if (installed/name).read_bytes()!=raw:raise ValueError('installed member differs: '+name)
                files[name]=sha256(raw).hexdigest()
    source=installed/'hepta/_data/examples/hia_bootstrap/service_discovery.hepta'
    if source.read_bytes()!=native.SOURCE.read_bytes():raise ValueError('installed source differs')
    from hepta import hia_store_artifact_profile_native as store_native
    original_manifest=Path(manifest).read_bytes();store_manifest_raw=Path(store_manifest).read_bytes()
    bundle=output/'bundle.json'
    write(bundle,{'schema':SCHEMA,'target':TARGET,'abi':ABI,'helpers':[
        {'selector':native.SELECTOR,'manifest_path':str(Path(manifest).absolute()),
         'manifest_sha256':sha256(original_manifest).hexdigest()},
        {'selector':store_native.SELECTOR,'manifest_path':str(Path(store_manifest).absolute()),
         'manifest_sha256':sha256(store_manifest_raw).hexdigest()}]})
    bundle_pin=sha256(bundle.read_bytes()).hexdigest()
    script=output/'worker.py';script.write_text(WORKER)
    raw,err=command('identity',[script,installed,'--installation-manifest','--native-helpers-manifest',bundle,
                                 '--expected-native-helpers-sha256',bundle_pin])
    identity=json.loads(raw)
    if set(identity)!={'worker_sha256','backend_sha256','catalog_sha256','native_helpers_sha256'}:
        raise ValueError('installed identity fields differ')
    if identity['native_helpers_sha256']!=bundle_pin or any(type(v)is not str or len(v)!=64 or set(v)-set('0123456789abcdef') for v in identity.values()):
        raise ValueError('installed identity is not exact')
    if counts(err)!={'startup':{'1':0,'2':0},'request':{'1':0,'2':0}}:
        raise ValueError('identity query executed provider')

    case=AgentToolCase('runTest');saved_environment=dict(os.environ)
    try:
        os.environ.clear();os.environ.update(environment)
        with native_helpers_scope(str(bundle),bundle_pin):case.setUp()
        case.service.close()
        def request_for(section):
            request={'schema':'hia-agent-worker-request-v1','tool':'hia_describe',
                     'arguments':{'section':section},'profile_sha256':'a'*64,
                     'catalog_sha256':case.service.catalog_sha256}
            request['request_sha256']=api.digest(request)
            return request
        def worker(label,section='manifest',*,expected=0):
            return command(label,[script,installed,'--state-root',case.state_root,'--artifact-root',case.files_root,
                '--request-json-stdin','--native-helpers-manifest',bundle,'--expected-native-helpers-sha256',bundle_pin,
                '--expected-worker-sha256',identity['worker_sha256'],'--expected-backend-sha256',identity['backend_sha256'],
                '--expected-catalog-sha256',identity['catalog_sha256']],body=canonical(request_for(section)),expected=expected)
        observations=[]
        for section in ('manifest','language','backend','examples','diagnostics','plans'):
            raw,err=worker('normal-'+section,section);result=json.loads(raw);observed=counts(err)
            if (result['response']['status']!='completed' or observed['request']['1']<=0
                    or observed['startup']['2']<=0 or observed['request']['2']!=0):
                raise AssertionError('worker did not execute both actual discovery paths')
            if result['response']['result']['next_cursor'] is not None:
                raise AssertionError('bounded discovery cursor changed')
            observations.append({'section':section,'result':result,'counts':observed})
        # This read-only catalog schema has no request_key. An identical repeat
        # must run the original discovery policy again; it is not cached replay.
        repeat_raw,repeat_err=worker('repeat-manifest');repeat=json.loads(repeat_raw);repeat_counts=counts(repeat_err)
        if (repeat['response']!=observations[0]['result']['response']
                or repeat_counts['request']['1']<=0 or repeat_counts['startup']['2']<=0):
            raise AssertionError('read-only repeat did not preserve original execution semantics')
        original_source=source.read_bytes();extra=installed/'hepta/discovery_unlisted_control.py'
        try:
            try:
                source.write_bytes(original_source+b'\n');raw,err=worker('source-plus-LF',expected=2)
                if raw or any(counts(err)['request'].values()):raise AssertionError('changed source reached request')
            finally:source.write_bytes(original_source)
            try:
                extra.write_text('UNLISTED_DISCOVERY_INPUT = True\n');raw,err=worker('extra-module',expected=2)
                if raw or any(counts(err)['request'].values()):raise AssertionError('extra module bypassed identity')
            finally:extra.unlink(missing_ok=True)
        finally:source.write_bytes(original_source)
        observations={'sections':observations,'repeat':repeat,'repeat_counts':repeat_counts,'read_only_repeat_not_request_journal_replay':True}
    finally:
        try:
            if hasattr(case,'temporary'):case.tearDown()
        finally:os.environ.clear();os.environ.update(saved_environment)
    if Path(manifest).read_bytes()!=original_manifest or Path(store_manifest).read_bytes()!=store_manifest_raw:raise ValueError('manifest changed')
    for name,digest in files.items():
        if sha256((installed/name).read_bytes()).hexdigest()!=digest:raise ValueError('installed member not restored: '+name)
    report={'schema':'hepta.hia.service-discovery-installed-worker.v1','wheel':str(wheel),
        'wheel_sha256':sha256(wheel.read_bytes()).hexdigest(),'installed':str(installed),
        'wheel_files_checked_against_installed':files,'wheel_RECORD_sha256':sha256(wheel_record).hexdigest(),
        'installed_RECORD_sha256':sha256((installed/record_name).read_bytes()).hexdigest(),
        'identity':identity,'bundle_sha256':bundle_pin,'commands':commands,'observations':observations,
        'runtime_authoring_imports_forbidden':True,'every_request_has_all_three_expected_identity_flags':True,
        'whole_native_stack_qualified':False,'resource_and_cross_owner_faults_covered_in_native_control_group':True}
    write(output/'installed.json',report);return report
