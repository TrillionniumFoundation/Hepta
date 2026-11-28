"""New explicit v2 worker terminal controls; original v1 installed gate stays intact.

The complete original verification workload is retained and augmented by two
actual lost-receipt swallow/replacement requests. All child budgets remain60s.
This helper is separately frozen; it never edits an original test/helper.
"""
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
from hepta import hia_agent_worker as worker_module,hia_agent_store as store_module
from hepta.hia_worker_report_native import NativeWorkerReport,WorkerSession
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':{},'request':{}};active=False;fired=[]
terminal={'close_attempts':0,'close_body_entries':0,'native_worker_entries':0,'diagnostics':[],'regions':[]}
foreign_observe=WorkerSession._observe
def region_observed(session):
    call_region,close_region=struct.unpack_from('<2Q',session.workspace,120)
    opcode,sequence=struct.unpack_from('<2Q',session.workspace,8)
    assert call_region in (0,1) and close_region in (0,1) and not (call_region and close_region)
    result=foreign_observe(session)
    if call_region or close_region:
        magic,returned_sequence,returned_opcode,error=struct.unpack_from('<4Q',session.packet,0)
        assert (returned_sequence,returned_opcode)==(sequence,opcode)
        terminal['regions'].append([opcode,call_region,close_region,error])
    return result
WorkerSession._observe=region_observed
primary_error=cleanup_error=withheld_error=None
report_run=NativeWorkerReport.run
def report_observed(owner,*args,**kwargs):
    entry=owner.policy._entry
    def entered(*values):
        result=entry(*values);terminal['native_worker_entries']+=1;return result
    owner.policy._entry=entered
    try:return report_run(owner,*args,**kwargs)
    finally:owner.policy._entry=entry
NativeWorkerReport.run=report_observed
def hosted_worker_forbidden(*args,**kwargs):raise AssertionError('v2 entered complete hosted worker policy')
worker_module._reference_run=hosted_worker_forbidden
public_call=service.HIAAgentService.call
def called(self,*args,**kwargs):
    global primary_error
    try:return public_call(self,*args,**kwargs)
    except BaseException as error:
        primary_error=error;raise
service.HIAAgentService.call=called
public_close=service.HIAAgentService.close
def closed(self,*args,**kwargs):
    global cleanup_error
    terminal['close_attempts']+=1
    try:return public_close(self,*args,**kwargs)
    except BaseException as error:
        cleanup_error=error;raise
service.HIAAgentService.close=closed
close_body=store_module._NATIVE_STORE_CLOSE_REFERENCE
def body_entered(self,*args,**kwargs):
    terminal['close_body_entries']+=1
    return close_body(self,*args,**kwargs)
store_module._NATIVE_STORE_CLOSE_REFERENCE=body_entered
original_diagnostic=worker_module._unknown_request_exit
def diagnostic(observation,error):
    terminal['diagnostics'].append({'primary_same':observation.primary_error is primary_error,
        'cleanup_same':observation.cleanup_error is cleanup_error,
        'actual_origin_error_same':observation.origin.error is withheld_error,
        'origin_lost':observation.origin.loss is not None,
        'primary_type':None if primary_error is None else type(primary_error).__name__,
        'cleanup_type':None if cleanup_error is None else type(cleanup_error).__name__})
    return original_diagnostic(observation,error)
worker_module._unknown_request_exit=diagnostic
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
        global withheld_error
        request=struct.unpack('<16Q',ctypes.string_at(values[0],values[1]))
        code=entry(*values)
        lane=counts['request' if active else 'startup'];key=str(request[5]);lane[key]=lane.get(key,0)+1
        if (active and behavior in ('lost-receipt','lost-swallowed','lost-replaced') and not fired
                and request[1]==native.SUCCEEDED and request[3]==native.PORT['verify_receipt']):
            fired.append(True);withheld_error=ValueError('actual verification receipt ACK withheld');raise withheld_error
        return code
    image._entry=observed
native.NativeServiceVerification.__init__=image_initialize
reference_call=service.HIAAgentService._reference_call
def request(self,*args,**kwargs):
    global active
    active=True
    try:return reference_call(self,*args,**kwargs)
    except BaseException:
        if fired and behavior=='lost-swallowed':return {'status':'completed','result':{'unconfirmed':True}}
        if fired and behavior=='lost-replaced':raise RuntimeError('replacement after actual verification loss')
        raise
    finally:active=False
service.HIAAgentService._reference_call=request
try:code=main()
finally:
    sys.stderr.write('VERIFICATION_COUNTS='+json.dumps({'counts':counts,'lost':fired},sort_keys=True)+'\n')
    sys.stderr.write('WORKER_UNKNOWN_COUNTS='+json.dumps(terminal,sort_keys=True)+'\n')
raise SystemExit(code)
'''

def counts(stderr):
    rows=[line[len(b'VERIFICATION_COUNTS='):] for line in stderr.splitlines() if line.startswith(b'VERIFICATION_COUNTS=')]
    if len(rows)!=1:raise ValueError('worker lacks its exact verification entry record')
    return json.loads(rows[0])

def terminal_counts(stderr):
    prefix=b'WORKER_UNKNOWN_COUNTS='
    rows=[line[len(prefix):] for line in stderr.splitlines() if line.startswith(prefix)]
    if len(rows)!=1:raise ValueError('worker terminal custody evidence missing')
    return json.loads(rows[0])


def run(manifest,store_manifest,report_manifest,request_manifest,output):
    from hepta import hia_agent_service as api,hia_service_verification_native as native
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta.hia_native_helpers import ABI,SCHEMA,TARGET,native_helpers_scope
    from tools.build_hia_worker_report import bind_worker_bundle
    REQUEST_SELECTOR='HEPTA_HIA_WORKER_REQUEST_MANIFEST'
    from tests.test_hia_agent_installed_resources import RESOURCES,SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tools.hia_agent_native_qualification import add_program
    import sqlite3
    from tools.hia_worker_installed_workload_source import capture_workload_source, verify_workload_source
    workload_source = capture_workload_source(ROOT)
    original_helper=ROOT/'tests/hia_service_verification_installed.py'
    original_helper_raw=workload_source['physical']
    if sha256(workload_source['original']).hexdigest()!='0f95cc59fe2a66bcc2fbcfa8dc253266e763bbc8ca7c873d5bdf956fd04bdda6':
        raise ValueError('original installed workload changed')
    extra_inputs={str(Path(p).resolve(strict=True)):Path(p).read_bytes() for p in (report_manifest,request_manifest)}
    output=Path(output);output.mkdir(mode=0o700)
    staging=output/'source';staging.mkdir()
    shutil.copytree(ROOT/'hepta',staging/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES,*SDIST_SUPPORT_FILES,'setup.py','pyproject.toml','MANIFEST.in'):
        target=staging/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
    environment=clean_environment();environment['PYTHONDONTWRITEBYTECODE']='1'
    commands=[]
    request_inputs={}
    def command(label,arguments,*,body=None,expected=0):
        if body is not None:
            with (output/(label+'.stdin.bin')).open('xb') as stream:stream.write(body)
            request_inputs[label]={'bytes':len(body),'sha256':sha256(body).hexdigest()}
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
    source=installed/'hepta/_data/examples/hia_bootstrap/service_verification.hepta'
    if source.read_bytes()!=native.SOURCE.read_bytes():raise ValueError('installed source differs')
    original_manifest=Path(manifest).read_bytes();store_manifest_raw=Path(store_manifest).read_bytes()
    base_bundle=output/'helpers-v1.json'
    write(base_bundle,{'schema':SCHEMA,'target':TARGET,'abi':ABI,'helpers':[
        {'selector':native.SELECTOR,'manifest_path':str(Path(manifest).absolute()),
         'manifest_sha256':sha256(original_manifest).hexdigest()},
        {'selector':store_native.SELECTOR,'manifest_path':str(Path(store_manifest).absolute()),
         'manifest_sha256':sha256(store_manifest_raw).hexdigest()},
        {'selector':REQUEST_SELECTOR,'manifest_path':str(Path(request_manifest).resolve(strict=True)),
         'manifest_sha256':sha256(extra_inputs[str(Path(request_manifest).resolve(strict=True))]).hexdigest()}]})
    bundle,bound_pin=bind_worker_bundle(output/'bundle.json',base_bundle,Path(report_manifest))
    bundle_pin=sha256(bundle.read_bytes()).hexdigest()
    if bundle_pin!=bound_pin:raise ValueError('actual v2 bundle bytes changed after admission')
    script=output/'worker.py';script.write_text(WORKER)
    raw,err=command('identity',[script,installed,'normal','--installation-manifest',
        '--native-helpers-manifest',bundle,'--expected-native-helpers-sha256',bundle_pin])
    identity=json.loads(raw)
    if set(identity)!={'worker_sha256','backend_sha256','catalog_sha256','native_helpers_sha256'}:
        raise ValueError('installed identity fields differ')
    if identity['native_helpers_sha256']!=bundle_pin:raise ValueError('installed helper identity differs')
    if counts(err)!={'counts':{'startup':{},'request':{}},'lost':[]}:raise ValueError('identity query executed verification')
    identity_terminal=terminal_counts(err)
    assert identity_terminal['native_worker_entries']>0 and identity_terminal['close_attempts']==0
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
            ('normal','completed-replay','lost-receipt','unknown-replay','lost-swallowed','lost-replaced',),api.digest,commands)
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
        normal_terminal=terminal_counts(err)
        assert normal_terminal['native_worker_entries']>0
        assert (normal_terminal['close_attempts'],normal_terminal['close_body_entries'])==(1,1)
        assert normal_terminal['diagnostics']==[]
        assert normal['response']['status']=='completed' and normal_counts['counts']['request'].get('3',0)>0
        normal_state=state(normal_arguments)
        raw,err=worker('completed-replay',normal_arguments);replay=json.loads(raw);replay_counts=counts(err)
        assert replay['response']==normal['response']
        assert replay_counts['counts']['request'].get('3',0)==0 and replay_counts['counts']['request'].get('5',0)>0
        replay_state=state(normal_arguments)
        assert replay_state==normal_state
        raw,err=worker('lost-receipt',lost_arguments,behavior='lost-receipt',expected=2)
        lost_counts=counts(err);lost_state=state(lost_arguments)
        lost_terminal=terminal_counts(err)
        assert lost_terminal['native_worker_entries']>0
        assert (lost_terminal['close_attempts'],lost_terminal['close_body_entries'])==(1,0)
        assert len(lost_terminal['diagnostics'])==1
        assert [9,1,0,1] in lost_terminal['regions'] and [8,0,1,1] in lost_terminal['regions']
        assert all(lost_terminal['diagnostics'][0][key] for key in
            ('primary_same','cleanup_same','actual_origin_error_same','origin_lost'))
        assert b'REQUEST_PRIMARY_EXCEPTION' in err and b'REQUEST_CLEANUP_EXCEPTION' in err
        assert not raw and lost_counts['lost']==[True] and lost_counts['counts']['request'].get('3',0)>0
        assert lost_state['request']==('running',)
        raw,err=worker('unknown-replay',lost_arguments);unknown=json.loads(raw);unknown_counts=counts(err)
        unknown_state=state(lost_arguments)
        assert unknown['response']['error']['code']=='E_HIA_REQUEST_UNKNOWN'
        assert unknown_counts['counts']['request'].get('3',0)==0
        assert unknown_state['request']==lost_state['request'] and unknown_state['artifacts']==lost_state['artifacts']
        assert unknown_state['costs']==lost_state['costs']+1
        extra_losses=[]
        for mode in ('lost-swallowed','lost-replaced'):
            args=arguments(mode)
            raw,err=worker(mode,args,behavior=mode,expected=2)
            actual=terminal_counts(err);actual_state=state(args);actual_counts=counts(err)
            assert raw==b'' and actual_counts['lost']==[True]
            assert actual_counts['counts']['request'].get('3',0)>0
            assert actual['native_worker_entries']>0
            assert (actual['close_attempts'],actual['close_body_entries'])==(1,0)
            assert actual_state['request']==('running',)
            assert len(actual['diagnostics'])==1
            assert [9,1,0,1] in actual['regions'] and [8,0,1,1] in actual['regions']
            assert all(actual['diagnostics'][0][key] for key in
                ('primary_same','cleanup_same','actual_origin_error_same','origin_lost'))
            extra_losses.append({'mode':mode,'terminal':actual,'state':actual_state,'counts':actual_counts})
        original_source=source.read_bytes()
        try:
            source.write_bytes(original_source+b'\n')
            raw,err=worker('source-drift',normal_arguments,expected=2)
            assert not raw and counts(err)['counts']['request']=={}
        finally:source.write_bytes(original_source)
        observations={'normal':normal,'normal_counts':normal_counts,'normal_state':normal_state,
            'replay':replay,'replay_counts':replay_counts,'replay_state':replay_state,
            'lost_counts':lost_counts,'lost_state':lost_state,
            'unknown':unknown,'unknown_counts':unknown_counts,'unknown_state':unknown_state,
            'identity_terminal':identity_terminal,'normal_terminal':normal_terminal,
            'lost_terminal':lost_terminal,'additional_actual_losses':extra_losses}
    finally:
        try:
            if ready:case.tearDown()
        finally:os.environ.clear();os.environ.update(saved_environment)
    assert Path(manifest).read_bytes()==original_manifest and Path(store_manifest).read_bytes()==store_manifest_raw
    for name,digest in files.items():
        if sha256(installed_wheel_path(installed, name).read_bytes()).hexdigest()!=digest:raise ValueError('installed member not restored: '+name)
    if original_helper.read_bytes()!=original_helper_raw:raise ValueError('original installed helper changed')
    verify_workload_source(workload_source)
    for name,raw in extra_inputs.items():
        if Path(name).read_bytes()!=raw:raise ValueError('additional current bundle input changed')
    report={'schema':'hepta.hia.worker-unknown-installed-v2.v1','wheel':str(wheel),
        'wheel_sha256':sha256(wheel.read_bytes()).hexdigest(),'installed':str(installed),
        'wheel_files_checked_against_installed':files,'wheel_RECORD_sha256':sha256(wheel_record).hexdigest(),
        'installed_RECORD_sha256':sha256((installed/record_name).read_bytes()).hexdigest(),
        'identity':identity,'bundle_sha256':bundle_pin,'commands':commands,'observations':observations,
        'database_capture':journal.finish(),
        'runtime_authoring_imports_forbidden':True,'every_request_has_all_three_expected_identity_flags':True,
        'whole_native_stack_qualified':False,
        'original_workload_sha256':sha256(workload_source['original']).hexdigest(),
        'original_workload_source_relation':workload_source['proof'],
        'explicit_worker_profile':'v2','hosted_worker_policy_poisoned':True,
        'additional_manifests':{name:sha256(raw).hexdigest() for name,raw in extra_inputs.items()},
        'request_inputs':request_inputs}
    write(output/'installed.json',report);return report
