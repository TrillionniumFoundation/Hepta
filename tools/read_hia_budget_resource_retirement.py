"""Read Budget B raw custody evidence without importing product or test bodies."""
from __future__ import annotations
import argparse
import ast
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as s
from tools import read_hia_service_bootstrap as r

IMAGE_ORDER=('bootstrap','store','transaction','context','candidate','ledger','operations')
SELECTORS={
    'bootstrap':'HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST',
    'store':'HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST',
    'transaction':'HEPTA_HIA_STORE_TRANSACTION_MANIFEST',
    'context':'HEPTA_HIA_SERVICE_CONTEXT_MANIFEST',
    'candidate':'HEPTA_HIA_CANDIDATE_BUDGET_MANIFEST',
    'ledger':'HEPTA_HIA_SLOT_LEDGER_MANIFEST',
    'operations':'HEPTA_HIA_SLOT_OPERATIONS_MANIFEST',
}
METHODS=(
 'test_01_actual_construction_ack_admission_cleanup_and_repeated_close',
 'test_02_actual_close_return_ordinary_error_and_child_loss_identity',
 'test_03_actual_nested_series_parent_receipts_and_preparation_returns',
 'test_04_actual_unknown_reinitialize_Context_thread_and_fork',
)
PREFIX='tests.test_hia_budget_resource_retirement.BudgetResourceRetirementNativeTests.'
CASE_IDS=(
 'constructor-confirmed','constructor-ACK-loss','constructor-late-FINALIZE-loss',
 'constructor-open-refusal','constructor-admission-cleanup','close-confirmed-repeat',
 'close-ACK-loss','ordinary-error-confirmed','child-loss-swallowed','child-loss-replaced',
 'standalone-opted-child-loss','healthy-other-budget','series-confirmed',
 'series-inner-confirmed-outer-loss','series-child-loss-swallowed',
 'series-already-closed-outer-loss','preparation-finalizer-child-loss',
 'return-identity-error-outer-loss','unknown-reinitialize-refused',
 'unknown-new-Context-close','unknown-thread-close','unknown-fork-close',
)


def truth(value,message):
    if value is not True:raise ValueError(message)


def source_ids(captured):
    declared=r.literal_assignment(ROOT/'tests/hia_budget_resource_retirement_controls.py','CASE_IDS',captured)
    r.equal(declared,CASE_IDS,'full resource case domain changed')
    raw=r.captured_bytes(ROOT/'tests/test_hia_budget_resource_retirement.py',None,captured)
    tree=ast.parse(raw)
    cls,=[node for node in tree.body if isinstance(node,ast.ClassDef)
          and node.name=='BudgetResourceRetirementNativeTests']
    methods=tuple(node.name for node in cls.body if isinstance(node,ast.FunctionDef)
                  and node.name.startswith('test_'))
    r.equal(methods,METHODS,'complete Native4 source method inventory differs')
    return methods


def authority(root,captured,*,require_cold):
    root=Path(root).resolve()
    value=r.capture(root/'authority.json',None,captured)
    if value['schema']!='hepta.hia.budget-resource-authority.v1':
        raise ValueError('wrong seven-image authority')
    source=s.source_snapshot()
    for key in ('source_before','source_after'):
        r.equal(value[key],source,'current exact component source differs')
    if value['whole_native_stack_qualified'] is not False:
        raise ValueError('component build cannot qualify whole stack')
    construction,declared,images=r.construction(root/'images',value['construction'],captured,
                                               source,require_cold=require_cold)
    r.equal(str(Path(value['construction_path']).resolve()),str(root/'images/construction.json'),'construction path differs')
    for key in ('scope','compiler','compiler_path','cold_report','cold_report_path'):
        r.equal(value[key],construction[key],'six-image construction authority differs: '+key)
    declarations=r.capture(root/'manifest-list.json',value['manifest_list'],captured)
    r.equal(str(Path(value['manifest_list_path']).resolve()),str(root/'manifest-list.json'),'seven-image path differs')
    if set(declarations)!=set(IMAGE_ORDER):raise ValueError('seven-image scope differs')
    r.equal({key:declarations[key] for key in declared},declared,'six original images were substituted')
    path=Path(declarations['operations'])
    r.equal(str(path.resolve()),str(root/'slot-operations-image/manifest.json'),'Slot image is not from this attempt')
    manifest=r.capture(path,None,captured)
    r.equal(manifest['schema'],'hepta.hia.slot-operations.v1','wrong complete Slot schema')
    if Path(manifest['image_path']).name!=manifest['image_path']:
        raise ValueError('Slot image leaves its owned directory')
    raw_source=r.captured_bytes(ROOT/'examples/hia_bootstrap/slot_operations.hepta',None,captured)
    raw_image=r.captured_bytes(path.parent/manifest['image_path'],None,captured)
    r.equal(manifest['source_sha256'],s.bytes_pin(raw_source)['sha256'],'Slot HIA source differs')
    r.equal(manifest['image_sha256'],s.bytes_pin(raw_image)['sha256'],'Slot image differs')
    r.equal(manifest['compiler_sha256'],value['compiler']['sha256'],'seventh compiler differs')
    manifest_raw=next(raw for file,raw in reversed(captured) if file==path)
    images['operations']={'manifest':s.bytes_pin(manifest_raw),'image':s.bytes_pin(raw_image)}
    r.equal(value['images'],images,'seven current source/image pins differ')
    build_path=root/'slot-operations-image/build.json'
    r.equal(str(Path(value['operations_build_path']).resolve()),str(build_path),'Slot build path differs')
    build=r.capture(build_path,value['operations_build'],captured)
    r.equal(build['manifest'],manifest,'Slot build manifest differs')
    cold=None if value['cold_report'] is None else r.capture(
        value['cold_report_path'],value['cold_report'],captured)
    r.equal(build['cold_report_sha256'],None if cold is None else value['cold_report']['sha256'],
            'seventh cold report differs')
    r.equal(build['scope'],'DEVELOPMENT_COMPONENT' if cold is None
            else 'MATCHING_SOURCE_COLD_COMPONENT','Slot build mode differs')
    r.equal(build['source_manifest'],None if cold is None else cold['source_manifest'],
            'seventh full source differs')
    inputs=r.literal_assignment(ROOT/'tools/build_hia_slot_operations.py','INPUTS',captured)
    if set(inputs)!=set(build['component_inputs']):raise ValueError('Slot builder INPUTS incomplete')
    for name in inputs:
        raw=r.captured_bytes(ROOT/name,None,captured)
        r.equal(s.bytes_pin(raw)['sha256'],build['component_inputs'][name],'Slot component input differs')
        if cold is not None:
            r.equal(cold['source_manifest'].get(name),build['component_inputs'][name],
                    'Slot input absent from same current cold')
    compiler=r.captured_bytes(value['compiler_path'],value['compiler'],captured)
    r.verify_pack(path,manifest,build,compiler,raw_source,raw_image,captured)
    bundle=r.capture(root/'bundle.json',value['bundle'],captured)
    r.equal(str(Path(value['bundle_path']).resolve()),str(root/'bundle.json'),'actual bundle path differs')
    for key in ('schema','abi','target'):
        r.equal(bundle[key],r.literal_assignment(ROOT/'hepta/hia_native_helpers.py',
                 key.upper(),captured),'administrator scope declaration differs')
    r.equal(bundle['helpers'],[
        {'selector':SELECTORS[key],'manifest_path':str(Path(declarations[key]).resolve()),
         'manifest_sha256':images[key]['manifest']['sha256']}
        for key in IMAGE_ORDER],'actual seven-image bundle was expanded or substituted')
    r.unchanged(captured)
    return value,s.bytes_pin(next(raw for file,raw in captured if file==root/'authority.json')),source,images


def packets(entries):
    if type(entries) is not list or not entries:raise ValueError('no actual native packet observation')
    for row in entries:
        owner=row['owner']
        if owner not in ('bootstrap','candidate','operations'):raise ValueError('undeclared packet owner')
        truth(row['actual_entry_returned'],'entry did not really return before control intervention')
        request=bytes.fromhex(row['request']);output=bytes.fromhex(row['output']);state=bytes.fromhex(row['state'])
        for field,raw in (('request_bytes',request),('output_bytes',output),('state_bytes',state)):
            r.integer(row[field],len(raw))
        r.integer(row['event']);r.integer(row['code'])
        if owner=='candidate':
            r.integer(len(output),272);r.integer(len(state),384)
            if not 96<=len(request)<=288 or not 80<=row['code']<=272:
                raise ValueError('actual candidate packet extent differs')
        else:
            r.integer(len(request),128);r.integer(len(output),96);r.integer(len(state),192)
            r.integer(row['code'],96)
            r.integer(row['port']);r.integer(row['mode'])
            r.integer(row['port'],struct.unpack_from('<Q',request,24)[0])
            r.integer(row['mode'],struct.unpack_from('<Q',request,40)[0])
        r.integer(row['event'],struct.unpack_from('<Q',request,8)[0])
    return len(entries)

def control(root,name,method,authority_pin,source,images,captured):
    report,result,start=r.owned_child(root,name,'tests/hia_budget_resource_retirement_controls.py',
                                     180,captured)
    r.equal(report['schema'],'hepta.hia.budget-resource-control.v1','control schema differs')
    r.equal(report['status'],'PASS_CONTROL_ONLY','control did not complete')
    r.equal(report['case'],name,'wrong resource control case')
    r.equal(report['authority'],authority_pin,'control used a different actual authority')
    for field in ('source_before','source_after'):
        r.equal(report[field],source,'control source identity changed')
    for field in ('images_before','images_after'):
        r.equal(report[field],images,'control image identity changed')
    truth(report['validated'],'control predicates did not finish')
    for field in ('manual_resource_registration','loss_fields_written','parent_check_bypassed',
                  'whole_native_stack_qualified'):
        if report[field] is not False:raise ValueError('resource control changed authority: '+field)
    truth(report['unknown_resources_not_manually_closed'],'unknown resource was forcibly closed')
    packets(report['entries'])
    if name not in ('constructor-open-refusal','constructor-admission-cleanup'):
        connections=report['connections']
        if not connections:raise ValueError('real distinct Budget connection evidence is missing')
        for row in connections:
            truth(row['distinct'],'Budget was represented by the Store connection')
            for key in ('budget','connection','Store_connection'):r.integer(row[key])
            if row['connection']==row['Store_connection']:
                raise ValueError('Budget B was not physically distinct')
    else:
        truth(report['constructor_error_identity'],'ordinary constructor error identity changed')
        expected=int(name=='constructor-admission-cleanup')
        r.integer(report['opened_connections'],expected)
        r.integer(report['original_admission_cleanup_closed'],expected)
    refs=report.get('close_refusals',[])
    required=name not in ('constructor-confirmed','constructor-open-refusal',
        'constructor-admission-cleanup','close-confirmed-repeat','ordinary-error-confirmed',
        'series-confirmed')
    if required and not refs:raise ValueError('actual unknown Budget public close refusal missing')
    for row in refs:
        already=name in ('close-ACK-loss','series-already-closed-outer-loss')
        if row['closed_before'] is not already or row['closed_after'] is not already:
            raise ValueError('refused close changed original closed state')
        if row['actual_connection_open'] is not (not already):
            raise ValueError('refused close changed the physical connection')
        r.equal(row['error']['type'],'NativeDeliveryUnknown','unknown public close class differs')
    if name=='close-confirmed-repeat':
        truth(report['healthy_repeat_same_closed_connection'],'healthy repeated close differs')
    if name=='ordinary-error-confirmed':
        truth(report['ordinary_error_identity_preserved'],'ordinary error was replaced')
    if name=='healthy-other-budget':
        truth(report['different_B_close_confirmed'],'unrelated healthy B did not really close')
    if name.startswith('series-') or name=='return-identity-error-outer-loss':
        r.equal(report['series_callbacks'],{'outer':1,'inner':1},'actual nested series providers incomplete')
        truth(report['child_finalization_does_not_confirm_parent'],'child ACK discharged parent')
    if name=='preparation-finalizer-child-loss':
        if report['preparation_original_B_SQL_started'] is not False:
            raise ValueError('new Budget SQL began after preparation loss')
        truth(report['actual_child_inherited_live_B_resource_scope'],'actual child B association missing')
        r.equal(report['finalizer_errors'],[],'finalizer hid a control failure')
        r.equal(report['finalizer_returns'],[True],'actual finalizer loss callback did not return')
    if name=='return-identity-error-outer-loss':
        truth(report['return_identity_query_failed_after_body'],'actual body-return fact was not tested')
    if name=='unknown-reinitialize-refused':
        truth(report['no_SQL_or_rebinding_on_reinitialize'],'same-object loss was laundered')
    if name=='unknown-new-Context-close':
        truth(report['fresh_Context_close_refused'],'fresh Context lost retirement identity')
    if name=='unknown-thread-close':
        r.integer(len(report['thread']),1)
        truth(report['thread'][0]['unknown'],'thread close did not reject actual loss')
        r.equal(report['thread'][0]['error']['type'],'NativeDeliveryUnknown','thread failure class differs')
    if name=='unknown-fork-close':
        fork=report['fork'];r.integer(fork['pid'])
        truth(fork['reaped'],'actual fork was not reaped')
        if fork['timed_out'] is not False:raise ValueError('fork exceeded its ten-second control')
        r.equal(fork['result']['code'],'E_HIA_BUDGET_NATIVE_CUSTODY','original PID guard changed')
        if fork['result']['closed'] is not False:raise ValueError('inherited close touched SQLite')
    row=r.capture(Path(root)/(name+'.record.json'),None,captured)
    r.equal(row['case'],name,'case terminal identity differs')
    if row['started'] is not True or row['stopped'] is not True:
        raise ValueError('case start/stop incomplete')
    r.equal(row['status'],'PASS_CONTROL_ONLY','case was not successful')
    r.equal(row['command'],result,'case original owned command differs')
    raw=next(raw for file,raw in reversed(captured) if file==Path(root)/name/'report.json')
    r.equal(row['inner_report'],s.bytes_pin(raw),'case used unbound inner bytes')
    r.equal(method,row,'method aggregation does not bind its confirmed child')
    planned=r.capture(Path(root)/(name+'.planned.json'),None,captured)
    r.equal(planned,{'test_id':PREFIX+Path(root).name,'case':name,'started':True},
            'original declared case start differs')
    command=start['command']
    if command.count('--case')!=1 or command[command.index('--case')+1]!=name:
        raise ValueError('actual child command does not select this case')
    for flag,value in (('--authority',str(Path(root).parent/'authority.json')),
                       ('--output',str(Path(root)/name)),
                       ('--authority-sha256',authority_pin['sha256']),
                       ('--authority-bytes',str(authority_pin['bytes']))):
        if command.count(flag)!=1 or command[command.index(flag)+1]!=value:
            raise ValueError('actual child argv omitted exact authority')
    return report

def installed(root,source,images,authority_value,authority_pin,captured):
    parent=Path(root)/'installed-method'
    method=r.capture(parent/'method.json',None,captured)
    r.equal(method['schema'],'hepta.hia.budget-resource-installed-method.v1','installed method schema differs')
    r.equal(method['status'],'PASS_INSTALLED_METHOD_ONLY','installed Native method is incomplete')
    r.equal(method['test_id'],PREFIX+METHODS[-1],'installed method changed its complete suite position')
    r.equal(method['authority'],authority_pin,'installed method authority differs')
    report,result,start=r.owned_child(parent,'installed','tests/hia_budget_resource_retirement_installed.py',
                                      1800,captured,fixed={'report':method['inner_report']})
    r.equal(method['command'],result,'installed method aggregate command differs')
    r.equal(report['schema'],'hepta.hia.budget-resource-installed.v2','wrong installed report')
    r.equal(report['status'],'PASS_INSTALLED_ONLY','actual installed scope did not finish')
    r.equal(report['authority'],authority_pin,'installed source/build authority differs')
    for field in ('source_before','source_after'):r.equal(report[field],source,'installed source changed')
    for field in ('images_before','images_after'):r.equal(report[field],images,'installed images changed')
    r.equal(report['manifest_list'],authority_value['manifest_list'],'installed manifest list differs')
    r.equal(report['bundle'],authority_value['bundle'],'installed bundle differs')
    for key in ('whole_native_stack_qualified','manual_resource_registration','loss_fields_written'):
        if report[key] is not False:raise ValueError('installed resource authority is overstated')
    truth(report['all_repeated_worker_expected_flags'],'installed repeated worker identity flags missing')
    truth(report['actual_budget_connection_and_public_close'],'installed B was not actually checked')
    directory=parent/'installed'
    commands=r.capture(directory/'commands.json',report['commands'],captured)
    observations=r.capture(directory/'observations.json',report['observations'],captured)
    modes=('normal','lost_parent_init_ACK','lost_child_commit_ACK')
    labels=('wheel','install','identity','worker-first','worker-replay',
            'worker-manifest-first','worker-manifest-replay',
            *('consumer-'+mode for mode in modes),'worker-budget-source-LF')
    if set(commands)!=set(labels) or set(observations)!=set(labels):
        raise ValueError('complete installed commands are missing or duplicated')
    package=r.zip_installation(directory,report['installation'],captured)
    identity_raw=r.captured_bytes(directory/'identity/stdout.log',report['worker_identity']['raw'],captured)
    identity=s.parse(identity_raw)
    r.equal(identity,report['worker_identity']['value'],'actual worker parsed identity changed')
    r.equal(identity['native_helpers_sha256'],authority_value['bundle']['sha256'],'worker bundle digest differs')
    identity_readback=r.installed_worker_identity(package,identity,captured)
    for name in ('hepta/hia_budget_resource_custody.py',
                 'hepta/_data/examples/hia_bootstrap/candidate_budget.hepta'):
        original=name.removeprefix('hepta/_data/')
        left=r.captured_bytes(package/name,None,captured)
        right=r.captured_bytes(ROOT/original,None,captured)
        if left!=right:raise ValueError('installed Budget source is not current exact source')
    for producer,variable,filename in (
        ('tests/hia_service_bootstrap_installed.py','WORKER','worker.py'),
        ('tests/hia_budget_resource_retirement_installed.py','CONSUMER','consumer.py')):
        expected=r.literal_assignment(ROOT/producer,variable,captured).encode()
        if r.captured_bytes(directory/filename,None,captured)!=expected:
            raise ValueError('installed subprocess literal is not its fixed producer')
    flags={'--expected-worker-sha256':identity['worker_sha256'],
           '--expected-backend-sha256':identity['backend_sha256'],
           '--expected-catalog-sha256':identity['catalog_sha256']}
    for label in labels:
        actual=r.capture(directory/label/'result.json',None,captured)
        r.equal(actual,commands[label],'installed command terminal aggregation changed')
        spec=r.capture(directory/label/'command.json',None,captured)
        r.equal(spec,actual['command'],'installed original command differs')
        r.integer(spec['timeout_seconds'],60);r.integer(spec['cleanup_seconds'],5)
        r.integer(spec['pid']);r.integer(spec['pgid'],spec['pid'])
        r.integer(actual['pid'],spec['pid'])
        r.integer(actual['exit_code'],2 if label=='worker-budget-source-LF' else 0)
        if (actual['timed_out'] is not False or actual['interruption'] is not None
                or actual['owned_cleanup']['reaped'] is not True
                or actual['owned_cleanup']['after']!=[]
                or actual['owned_cleanup']['signals']!=[]):
            raise ValueError('installed owned command did not terminate naturally')
        for name in ('stdout','stderr'):
            raw=r.captured_bytes(directory/label/(name+'.log'),actual[name],captured)
            r.equal(observations[label][name],s.bytes_pin(raw),'installed complete raw log differs')
        argv=spec['argv']
        r.equal(argv[:3],[report['executable'],'-I','-B'],'installed isolated prefix changed')
        if label.startswith('worker-') or label=='identity':
            r.equal(argv[3:5],[str(directory/'worker.py'),str(package)],'actual worker path differs')
            if label!='identity':
                for flag,value in flags.items():
                    if argv.count(flag)!=1 or argv[argv.index(flag)+1]!=value:
                        raise ValueError('actual worker expected identity was missing or changed')
            if (argv.count('--expected-native-helpers-sha256')!=1 or
                    argv[argv.index('--expected-native-helpers-sha256')+1]!=authority_value['bundle']['sha256']):
                raise ValueError('installed worker did not bind the actual bundle')
        if label.startswith('consumer-'):
            mode=label.removeprefix('consumer-')
            r.equal(argv[3:8],[str(directory/'consumer.py'),str(package),mode,
                    authority_value['bundle_path'],authority_value['bundle']['sha256']],
                    'actual installed consumer mode/bundle changed')
            raw=r.captured_bytes(directory/label/'stdout.log',observations[label]['stdout'],captured)
            value=s.parse(raw)
            r.equal(value,observations[label]['response'],'actual installed consumer raw differs')
            r.equal(value['status'],'PASS_INSTALLED_CONTROL_ONLY','installed consumer failed')
            r.equal(value['mode'],mode,'installed consumer mode differs')
            for key in ('actual_distinct_budget_connection','budget_selected','open_before_close'):
                truth(value[key],'actual installed B observation missing: '+key)
            for key in ('manual_registration','loss_fields_written','whole_native_stack_qualified'):
                if value[key] is not False:raise ValueError('installed B authority was fabricated')
            packets(value['entries'])
            if mode=='normal':
                truth(value['public_close_completed'],'installed public close failed')
                truth(value['repeated_close_completed'],'installed healthy repeat failed')
                if value['actual_connection_open_after'] is not False:
                    raise ValueError('installed normal close did not close SQLite')
                r.integer(value['lost_records'],0);r.integer(value['resources'],0)
            else:
                for key in ('public_close_refused','actual_connection_open_after',
                            'loss_contains_actual_fault','unknown_resource_not_manually_closed'):
                    truth(value[key],'installed actual lost B outcome missing: '+key)
                if r.integer(value['lost_records'])<1:raise ValueError('installed actual loss not retained')
            if mode!='lost_parent_init_ACK':
                r.integer(value['commit_SQL_count'],1);r.integer(value['actual_original_attempts'],1)
                if value['SQL'].count('COMMIT')!=1:
                    raise ValueError('actual installed COMMIT was missing or repeated')
    requests=r.read_installed_describe_requests(directory,report['worker_requests'],commands,
        observations,identity,package,authority_value['bundle_path'],
        authority_value['bundle']['sha256'],captured)
    r.unchanged(captured)
    return {'commands':len(labels),'actual_B_consumers':list(modes),
            'full_wheel_RECORD_and_expected_worker_flags':True,'request_controls':requests,**identity_readback}

def read(evidence,report_pin,*,allow_development=False):
    evidence=Path(evidence).resolve();captured=[]
    outer=r.capture(evidence/'report.json',report_pin,captured)
    r.equal(outer['schema'],'hepta.hia.budget-resource-owned-suite.v1','wrong complete owned suite')
    r.equal(outer['status'],'PASS_COMPLETE_SUITE','outer suite incomplete')
    r.equal(outer['suite'],'native','wrong declared suite')
    if outer['whole_native_stack_qualified'] is not False:
        raise ValueError('component suite overstates whole-stack qualification')
    source_ids(captured)
    suite,result,start=r.owned_child(evidence,'suite','tests/hia_budget_resource_retirement_suite.py',
        1800,captured,fixed={'start':outer['outer_start'],'result':outer['outer_result'],
                           'report':outer['suite_report']},stderr_empty=False)
    r.equal(suite['schema'],'hepta.hia.budget-resource-suite.v1','suite observer source differs')
    r.equal(suite['status'],'PASS_COMPLETE_SUITE','complete Native4 did not pass')
    r.equal(suite['suite'],'native','suite selector differs')
    r.integer(suite['new_outer_budget_seconds'],1800)
    if suite['whole_native_stack_qualified'] is not False:
        raise ValueError('Native4 is being treated as whole stack')
    ids=[PREFIX+name for name in METHODS]
    for key in ('planned','starts','stops'):r.equal(suite[key],ids,'complete ordered Native4 '+key+' differs')
    r.equal(suite['method_statuses'],{name:'success' for name in ids},'method terminal status differs')
    r.integer(suite['run'],4)
    for key in ('failures','errors','skips','expected_failures','unexpected_successes'):
        r.integer(suite[key],0)
    events_raw=r.captured_bytes(evidence/'suite/events.jsonl',suite['events'],captured)
    if not events_raw.endswith(b'\n'):raise ValueError('method events are not a complete JSONL stream')
    events=[s.parse(line) for line in events_raw.splitlines()]
    expected_events=[]
    for name in ids:
        expected_events.extend(({'event':'start','id':name},
                                {'event':'stop','id':name,'status':'success'}))
    r.equal(events,expected_events,'complete real Native4 event stream differs')
    r.equal(outer['command'],start['command'],'outer original suite argv differs')
    expected_command=[suite['executable'],'-I','-B',
        str(ROOT/'tests/hia_budget_resource_retirement_suite.py'),'--suite','native',
        '--output',str(evidence/'suite')]
    r.equal(start['command'],expected_command,'original full Native4 command was filtered')
    component=Path(suite['component_evidence']).resolve()
    if not component.is_relative_to(evidence/'component'):
        raise ValueError('component evidence is outside this owned suite')
    r.equal(str(component),outer['component_evidence'],'outer component evidence differs')
    value,pin,source,images=authority(component,captured,require_cold=not allow_development)
    r.equal(suite['component_authority'],{'path':str(component/'authority.json'),'pin':pin},
            'suite actual construction authority changed')
    for item in (outer,suite):
        for key in ('source_before','source_after'):
            r.equal(item[key],source,'complete suite source identity differs')
    parent=r.capture(component/'parent.json',None,captured)
    for key in ('pid','pgid','argv','runtime','cwd','executable'):
        r.equal(parent[key],suite[key],'component parent does not match actual suite: '+key)
    r.equal(parent['evidence_variable'],'HEPTA_HIA_BUDGET_RESOURCE_EVIDENCE','component evidence channel differs')
    groups=(CASE_IDS[:6],CASE_IDS[6:12],CASE_IDS[12:18],CASE_IDS[18:])
    count=0
    for method,names in zip(METHODS,groups):
        directory=component/method
        report=r.capture(directory/'method.json',None,captured)
        r.equal(report['schema'],'hepta.hia.budget-resource-method.v1','wrong full method report')
        r.equal(report['status'],'PASS_METHOD_ONLY','resource method did not finish all subcases')
        r.equal(report['test_id'],PREFIX+method,'method report identity differs')
        r.equal(report['authority'],pin,'method construction authority differs')
        r.equal(report['planned'],list(names),'complete subcase order changed')
        for key in ('pid','pgid','argv','runtime','cwd','executable'):
            r.equal(report[key],suite[key],'method parent differs: '+key)
        for key in ('source_before','source_after'):r.equal(report[key],source,'method source differs')
        r.integer(len(report['cases']),len(names))
        for name,row in zip(names,report['cases']):
            control(directory,name,row,pin,source,images,captured);count+=1
    r.integer(count,22)
    installation=installed(component,source,images,value,pin,captured)
    r.unchanged(captured)
    return {'schema':'hepta.hia.budget-resource-readback.v1','status':'PASS_READBACK_ONLY',
            'scope':value['scope'],'full_method_ids':ids,'resource_cases':list(CASE_IDS),
            'cases':count,'installed':installation,'seven_current_images':images,
            'source':source,'authority':pin,'matching_current_cold':value['scope']=='MATCHING_SOURCE_COLD',
            'development_only':value['scope']=='DEVELOPMENT_ONLY',
            'original_Bootstrap232_qualification_established_here':False,
            'old_complete_budget_modules_established_here':False,
            'whole_native_stack_qualified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--report-bytes',type=int,required=True)
    parser.add_argument('--report-sha256',required=True)
    parser.add_argument('--allow-development',action='store_true')
    args=parser.parse_args()
    result=read(args.evidence,{'bytes':args.report_bytes,'sha256':args.report_sha256},
                allow_development=args.allow_development)
    s.write_json(args.output,result)
    return 0


if __name__=='__main__':raise SystemExit(main())
