"""Installed worker uses selected service verification and exact installation identity."""
from __future__ import annotations
import base64,csv,io,json,os,shutil,sys,zipfile
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from tests.hia_service_verification_controls import run_process,clean_environment,write
from tests.hia_service_verification_oracle import canonical
from tests.hia_worker_installed_journal import JournalSnapshots

WORKER=r'''import importlib.abc,json,sys,ctypes,struct
from pathlib import Path
installed=sys.argv.pop(1);behavior=sys.argv.pop(1);sys.path.insert(0,installed)
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed verification imported tools')
sys.meta_path.insert(0,NoTools())
from hepta import hia_agent_service as service
from hepta import hia_service_verification_native as native
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':{},'request':{}};active=False;fired=[]
def forbidden(*args,**kwargs):raise AssertionError('selected verification entered retained whole method')
names=('_behavior_equivalence','_subject','_hia_verify','_verification','_replay_verification',
       '_native_refinement_binding','_independent_native_refinement','_check_native_refinement_evidence','_required_claims')
for number,name in enumerate(names,1):
    setattr(service,'_SERVICE_VERIFICATION_REFERENCE_'+str(number),forbidden)
    setattr(service.HIAAgentService,name+'_reference',staticmethod(forbidden) if number==6 else forbidden)
initialize=native.NativeServiceVerification.__init__
def image_initialize(image,*args,**kwargs):
    initialize(image,*args,**kwargs);entry=image._entry
    def observed(*values):
        request=struct.unpack('<16Q',ctypes.string_at(values[0],values[1]))
        code=entry(*values)
        lane=counts['request' if active else 'startup'];key=str(request[5]);lane[key]=lane.get(key,0)+1
        if (active and behavior=='lost-receipt' and not fired
                and request[1]==native.SUCCEEDED and request[3]==native.PORT['verify_receipt']):
            fired.append(True);raise ValueError('actual verification receipt ACK withheld')
        return code
    image._entry=observed
native.NativeServiceVerification.__init__=image_initialize
reference_call=service.HIAAgentService._reference_call
def request(self,*args,**kwargs):
    global active
    active=True
    try:return reference_call(self,*args,**kwargs)
    finally:active=False
service.HIAAgentService._reference_call=request
try:code=main()
finally:sys.stderr.write('VERIFICATION_COUNTS='+json.dumps({'counts':counts,'lost':fired},sort_keys=True)+'\n')
raise SystemExit(code)
'''

def counts(stderr):
    rows=[line[len(b'VERIFICATION_COUNTS='):] for line in stderr.splitlines() if line.startswith(b'VERIFICATION_COUNTS=')]
    if len(rows)!=1:raise ValueError('worker lacks its exact verification entry record')
    return json.loads(rows[0])

def run(manifest,store_manifest,output):
    from hepta import hia_agent_service as api,hia_service_verification_native as native
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta.hia_native_helpers import ABI,SCHEMA,TARGET,native_helpers_scope
    from tests.test_hia_agent_installed_resources import RESOURCES,SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tools.hia_agent_native_qualification import add_program
    import sqlite3
    output=Path(output);output.mkdir(mode=0o700)
    staging=output/'source';staging.mkdir()
    shutil.copytree(ROOT/'hepta',staging/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES,*SDIST_SUPPORT_FILES,'setup.py','pyproject.toml','MANIFEST.in'):
        target=staging/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
    environment=clean_environment();environment['PYTHONDONTWRITEBYTECODE']='1'
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
    source=installed/'hepta/_data/examples/hia_bootstrap/service_verification.hepta'
    if source.read_bytes()!=native.SOURCE.read_bytes():raise ValueError('installed source differs')
    original_manifest=Path(manifest).read_bytes();store_manifest_raw=Path(store_manifest).read_bytes()
    bundle=output/'bundle.json'
    write(bundle,{'schema':SCHEMA,'target':TARGET,'abi':ABI,'helpers':[
        {'selector':native.SELECTOR,'manifest_path':str(Path(manifest).absolute()),
         'manifest_sha256':sha256(original_manifest).hexdigest()},
        {'selector':store_native.SELECTOR,'manifest_path':str(Path(store_manifest).absolute()),
         'manifest_sha256':sha256(store_manifest_raw).hexdigest()}]})
    bundle_pin=sha256(bundle.read_bytes()).hexdigest()
    script=output/'worker.py';script.write_text(WORKER)
    raw,err=command('identity',[script,installed,'normal','--installation-manifest',
        '--native-helpers-manifest',bundle,'--expected-native-helpers-sha256',bundle_pin])
    identity=json.loads(raw)
    if set(identity)!={'worker_sha256','backend_sha256','catalog_sha256','native_helpers_sha256'}:
        raise ValueError('installed identity fields differ')
    if identity['native_helpers_sha256']!=bundle_pin:raise ValueError('installed helper identity differs')
    if counts(err)!={'counts':{'startup':{},'request':{}},'lost':[]}:raise ValueError('identity query executed verification')
    case=AgentToolCase('runTest');saved_environment=dict(os.environ);ready=False
    try:
        os.environ.clear();os.environ.update(environment)
        with native_helpers_scope(str(bundle),bundle_pin):
            case.setUp();ready=True
            case.session.freeze({'schema':'hepta.hia.agent.workload.v1',
                'cases':[{'function':'transform','arguments':[0]}],'warmup_iterations':0,'repetitions':1})
            candidate=case.session.import_program(add_program())
        def arguments(label):
            return case.session.arguments(request_key='installed-verification/'+label,candidate=candidate,
                base_program=None,validation_profile=case.session.profiles['validation'],
                subject={'kind':'core'},claims=['core_admission'])
        normal_arguments=arguments('normal');lost_arguments=arguments('lost')
        database=case.service.store.db.execute('PRAGMA database_list').fetchone()[2]
        case.service.close()
        journal=JournalSnapshots(output,database,
            ('normal','completed-replay','lost-receipt','unknown-replay',),api.digest,commands)
        def state(request):
            return journal.capture(request)
        def worker(label,arguments,*,behavior='normal',expected=0):
            request={'schema':'hia-agent-worker-request-v1','tool':'hia_verify','arguments':arguments,
                     'profile_sha256':'a'*64,'catalog_sha256':case.service.catalog_sha256}
            request['request_sha256']=api.digest(request)
            return command(label,[script,installed,behavior,'--state-root',case.state_root,'--artifact-root',case.files_root,
                '--request-json-stdin','--native-helpers-manifest',bundle,'--expected-native-helpers-sha256',bundle_pin,
                '--expected-worker-sha256',identity['worker_sha256'],'--expected-backend-sha256',identity['backend_sha256'],
                '--expected-catalog-sha256',identity['catalog_sha256']],body=canonical(request),expected=expected)
        raw,err=worker('normal',normal_arguments);normal=json.loads(raw);normal_counts=counts(err)
        assert normal['response']['status']=='completed' and normal_counts['counts']['request'].get('3',0)>0
        normal_state=state(normal_arguments)
        raw,err=worker('completed-replay',normal_arguments);replay=json.loads(raw);replay_counts=counts(err)
        assert replay['response']==normal['response']
        assert replay_counts['counts']['request'].get('3',0)==0 and replay_counts['counts']['request'].get('5',0)>0
        replay_state=state(normal_arguments)
        assert replay_state==normal_state
        raw,err=worker('lost-receipt',lost_arguments,behavior='lost-receipt',expected=2)
        lost_counts=counts(err);lost_state=state(lost_arguments)
        assert not raw and lost_counts['lost']==[True] and lost_counts['counts']['request'].get('3',0)>0
        assert lost_state['request']==('running',)
        raw,err=worker('unknown-replay',lost_arguments);unknown=json.loads(raw);unknown_counts=counts(err)
        unknown_state=state(lost_arguments)
        assert unknown['response']['error']['code']=='E_HIA_REQUEST_UNKNOWN'
        assert unknown_counts['counts']['request'].get('3',0)==0
        assert unknown_state['request']==lost_state['request'] and unknown_state['artifacts']==lost_state['artifacts']
        assert unknown_state['costs']==lost_state['costs']+1
        original_source=source.read_bytes()
        try:
            source.write_bytes(original_source+b'\n')
            raw,err=worker('source-drift',normal_arguments,expected=2)
            assert not raw and counts(err)['counts']['request']=={}
        finally:source.write_bytes(original_source)
        observations={'normal':normal,'normal_counts':normal_counts,'normal_state':normal_state,
            'replay':replay,'replay_counts':replay_counts,'replay_state':replay_state,
            'lost_counts':lost_counts,'lost_state':lost_state,
            'unknown':unknown,'unknown_counts':unknown_counts,'unknown_state':unknown_state}
    finally:
        try:
            if ready:case.tearDown()
        finally:os.environ.clear();os.environ.update(saved_environment)
    assert Path(manifest).read_bytes()==original_manifest and Path(store_manifest).read_bytes()==store_manifest_raw
    for name,digest in files.items():
        if sha256((installed/name).read_bytes()).hexdigest()!=digest:raise ValueError('installed member not restored: '+name)
    report={'schema':'hepta.hia.service-verification-installed-worker.v1','wheel':str(wheel),
        'wheel_sha256':sha256(wheel.read_bytes()).hexdigest(),'installed':str(installed),
        'wheel_files_checked_against_installed':files,'wheel_RECORD_sha256':sha256(wheel_record).hexdigest(),
        'installed_RECORD_sha256':sha256((installed/record_name).read_bytes()).hexdigest(),
        'identity':identity,'bundle_sha256':bundle_pin,'commands':commands,'observations':observations,
        'database_capture':journal.finish(),
        'runtime_authoring_imports_forbidden':True,'every_request_has_all_three_expected_identity_flags':True,
        'whole_native_stack_qualified':False}
    write(output/'installed.json',report);return report
