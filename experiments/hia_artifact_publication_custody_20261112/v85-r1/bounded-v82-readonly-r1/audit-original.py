"""Independent bytes-only reader of the already completed v82 CI artifact."""
from pathlib import Path
from hashlib import sha256
import ast, io, json, stat, subprocess, tarfile, time, zipfile

ROOT=Path(__file__).parent
OUTPUT=ROOT/'bounded-v82-readonly-r1'
ZIP=Path('/tmp/hia-v82-custody-43191120147-r2/artifact-13932321157.original.zip')
EXPECTED_ZIP='bcf5d0a4585bfc418afc67af9f0bccef1d4ba637db9f589e33380f147b82da7f'
BASE='35ff5374bc2f913e5139c49e1cea0acaf37ffc3c'
before=ZIP.stat();start=time.monotonic_ns();OUTPUT.mkdir(mode=0o700)
checks=[];unavailable=[];pin_count=0
def check(name, condition, **detail):
    checks.append({'name':name,'passed':bool(condition),**detail})
def digest(raw):return sha256(raw).hexdigest()
def source_raw(name):return subprocess.check_output(['git','show',BASE+':'+name],cwd=ROOT/'source')
def pin(row, name):
    global pin_count
    path=row['path']
    if path.startswith('/home/runner/work/_temp/'):
        member=path.removeprefix('/home/runner/work/_temp/')
    elif path.startswith('/home/runner/work/Hepta/Hepta/'):
        member='hia-cold.cold/source/'+path.removeprefix('/home/runner/work/Hepta/Hepta/')
    else:
        unavailable.append({'label':name,'path':path,'reason':'external runtime path not supplied by original ZIP'});return None
    if member not in all_names:
        unavailable.append({'label':name,'path':path,'reason':'original ZIP member absent'});return None
    raw=z.read(member);pin_count+=1
    check(name,len(raw)==row['bytes'] and digest(raw)==row['sha256'],member=member,sha256=digest(raw),bytes=len(raw))
    return raw
def pins(value, name):
    if isinstance(value,dict):
        if {'path','bytes','sha256'}<=value.keys() and type(value['path']) is str:pin(value,name)
        for k,v in value.items():pins(v,name+'/'+k)
    elif isinstance(value,list):
        for i,v in enumerate(value):pins(v,name+'/'+str(i))
def case_ids(name):
    data=source_raw('tools/hia_bounded_read_checks/'+name+'.py');tree=ast.parse(data)
    target='CASES' if name=='reject_cases' else 'EXPECTED_IDS'
    node=next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==target for t in n.targets))
    values=ast.literal_eval(node)
    return [v[0] for v in values] if name=='reject_cases' else list(values)

raw_zip_sha=sha256()
with ZIP.open('rb') as stream:
    while block:=stream.read(1<<20):raw_zip_sha.update(block)
check('original whole ZIP external seal',ZIP.stat().st_size==68009561 and raw_zip_sha.hexdigest()==EXPECTED_ZIP)
with zipfile.ZipFile(ZIP) as z:
    all_names=set(z.namelist());prefix='hia-bounded-read/';members=[];raws={}
    for info in z.infolist():
        if info.filename.startswith(prefix):
            raw=z.read(info);raws[info.filename]=raw
            members.append({'path':info.filename,'bytes':len(raw),'sha256':digest(raw),'crc32':info.CRC,
                            'external_attr':info.external_attr,'date_time':info.date_time,'compress_type':info.compress_type})
    j=lambda p:json.loads(raws[prefix+p])
    cold=json.loads(z.read('hia-cold.json'));main=j('work/report.json');accept=j('acceptance.json');orig=j('work/original-eight/report.json')
    check('149 retained bounded members read in full with CRC',len(members)==149 and sum(r['bytes'] for r in members)==35941302)
    check('actual main finite scope',main['schema']=='hepta.hia.bounded-read-finite-validation.v1' and main['status']=='FINITE_BOUNDED_READ_VALIDATION_PASS' and main['errors']==[] and
          main['finite_component_cases']==55 and main['original_methods']==8 and main['original_CLI_children']==7 and
          main['outer_seconds']==180 and main['cleanup_seconds']==3 and main['original_CLI_child_timeout_seconds']==20 and
          main['all_input_equivalence_proved'] is False and main['cold_qualification'] is False and main['production_activated'] is False)
    check('acceptance retains finite-only scope',accept['status']=='FINITE_BOUNDED_READ_VALIDATION_PASS' and accept['product_full_qualification'] is False and accept['errors']==[])
    pin(accept['report'],'acceptance report byte binding')
    check('main source before and after exact',main['source_before']==main['source_after']==cold['source_manifest'])
    for name,value in main['source_before'].items():
        raw=source_raw(name);check('canonical35ff source/'+name,digest(raw)==value,bytes=len(raw),sha256=digest(raw))
        member='hia-cold.cold/source/'+name
        check('cold exported source/'+name,member in all_names and z.read(member)==raw)
    compiler=z.read('hia-cold.cold/qualification.evidence/B3.image.bin');image=raws[prefix+'work/build/bounded-read.image.bin'];text=raws[prefix+'work/build/bounded-read.input.bin'];output=raws[prefix+'work/build/bounded-read.output.bin']
    expected_compiler={'bytes':len(compiler),'sha256':digest(compiler)}
    check('compiler originals and report before-after',main['compiler_before']==main['compiler_after']==expected_compiler and len(compiler)==670467 and digest(compiler)=='9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892')
    check('bundle before-after',main['bundle_before']==main['bundle_after'])
    pins(main['bundle_before'],'bundle')
    manifest=j('work/build/manifest.json');receipt=j('work/build/bounded-read.receipt.json');child=json.loads(raws[prefix+'work/build/bounded-read.stdout.log']);request=j('work/build/bounded-read.request.json');build=j('work/build/build.json')
    check('manifest actual values',manifest==main['bundle_before']['value'] and manifest['compiler_sha256']==digest(compiler) and manifest['image_sha256']==digest(image) and manifest['source_sha256']==digest(text))
    check('compiled HIA exactly frozen source',text==source_raw('examples/hia_bootstrap/bounded_read.hiaasm') and len(text)==59728)
    added={'case','input_sha256','input_bytes','artifact_sha256','format','runner_sha256','wall_elapsed_ns','produced_image','produced_bytes','produced_sha256'}
    check('child stdout to complete compiler receipt',{k:v for k,v in receipt.items() if k not in added}==child)
    check('compiler source image full-output and prefix bytes',child['status']=='returned' and child['abi_status']==0 and child['source_unchanged'] is True and child['forbidden_compiler_modules_loaded']==[] and
          child['image_sha256']==digest(compiler) and child['source_sha256']==digest(text) and child['output_sha256']==digest(output) and len(output)==1<<20 and image==output[:child['core_u32']] and receipt['produced_bytes']==len(image) and receipt['produced_sha256']==digest(image))
    check('unchanged compiler CPU/capacity',child['limits']=={'address_bytes':256<<20,'core_dumpable':False,'cpu_seconds':10,'output_capacity':1<<20,'stack_bytes':8<<20,'workspace_bytes':1<<20})
    pin(main['build']['record'],'actual build record')
    check('matching-source cold build',main['build']['scope']=='MATCHING_SOURCE_COLD_BUILD' and build['source_manifest']==cold['source_manifest'] and build['compiler_sha256']==digest(compiler))
    groups={'reject':12,'lifetime':24,'permission':10,'filesystem':9,'original-eight':8}
    check('complete five groups',[row['name'] for row in main['groups']]==list(groups))
    native_identity={'image_sha256':digest(image),'source_sha256':digest(text)}
    for group in main['groups']:
        name=group['name'];report=j('work/'+name+'/report.json');expected=case_ids('original_eight' if name=='original-eight' else name+'_cases')
        pin(group['report'],'group report/'+name);check('exact embedded group/'+name,group['result']==report)
        check('full exact IDs/'+name,report['expected_ids']==report['loaded_ids']==report['executed_ids']==expected and len(expected)==groups[name] and report['errors']==[] and not any(report['anomalies'].values()))
        pins(group['originals'],'group originals/'+name)
        if name!='original-eight':
            check('all case originals/'+name,len(report['cases'])==groups[name] and [c['id'] for c in report['cases']]==expected)
            for case in report['cases']:
                row=case.get('record',case.get('original'));raw=pin(row,'case raw/'+name+'/'+case['id']);body=json.loads(raw)
                check('case successful/'+name+'/'+case['id'],case['status']=='PASS' and body['status']=='PASS' and body['id']==case['id'])
                if 'reference' in body:check('complete reference/native outcomes/'+name+'/'+case['id'],body['reference']==body['native'])
                if name=='permission':
                    absent={'after_entry_transition_counter_fault','after_actual_entry_exception_fault','before_foreign_effect_attempt_counter_fault','foreign_exception_finish_is_single_use'}
                    check('actual native permission and no repeat/'+case['id'],body['actual_native_entry_returns']>=1 and body['terminal_permission_sealed'] is True and body['Path_callback_count']==(0 if case['id'] in absent else 1))
        for field in ('native_before','native_after','image_identity_before','image_identity_after'):
            if field in report:check('actual native identity/'+name+'/'+field,report[field]==native_identity)
    steps=[*main['processes'],*accept['processes']]
    check('seven original owners',len(steps)==7)
    owner_rows=[]
    for step in steps:
        raw=pin(step['receipt'],'owner/'+step['label']);actual=json.loads(raw);reqraw=pin(step['request'],'owner request/'+step['label']);req=json.loads(reqraw);cleanup=actual['cleanup']
        check('actual complete returned owner/'+step['label'],step['owner_returned']==dict(actual,supervisor_returncode=0,receipt_sha256=digest(raw)) and actual['request_sha256']==digest(reqraw))
        check('natural original owner/'+step['label'],actual['status']=='OWNED_PROCESS_COMPLETED' and actual['returncode']==0 and actual['subreaper_enabled'] is True and actual['timed_out'] is False and actual['exit_observed_before_deadline'] is True and actual['event_overflow'] is False and actual.get('owner_error') is None and actual['interrupted_signals']==[] and cleanup['complete'] is True and cleanup['leader_reaped'] is True and cleanup['observed_echild'] is True and cleanup['deadline_exceeded'] is False and cleanup['remaining_direct_children']==[] and cleanup['errors']==[] and all(e['kind'] in {'qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'} for e in actual['events']))
        check('original request and budgets/'+step['label'],req['command']==step['command'] and req['cwd']==step['cwd'] and req['qualification_seconds']==actual['qualification_seconds']==step['qualification_seconds'] and req['cleanup_seconds']==actual['cleanup_seconds']==step['cleanup_seconds']==3)
        pins(step['original_files'],'owner originals/'+step['label']);owner_rows.append({'label':step['label'],'seconds':actual['qualification_seconds'],'raw_sha256':digest(raw),'events':actual['events']})
    check('original parent raw unchanged',j('work/original-eight/parent-original.json')==orig['parent'])
    check('7 CLI actual raw children',len(orig['children'])==7 and orig['original_CLI_timeout_seconds']==20 and orig['testsRun']==8 and orig['loader_errors']==[])
    observations=[orig['parent']];policy=j('work/original-eight/child-policy.json');policy_raw=raws[prefix+'work/original-eight/child-policy.json']
    for row in orig['children']:
        raw=pin(row['record'],'CLI child original');check('CLI complete child record embedded',json.loads(raw)==row['result']);observations.append(row['result'])
    reads=[]
    for record in observations:
        check('actual caller identity/selector/old owner',record['native_before']==record['native_after']==native_identity and record['bundle_before']==record['bundle_after'] and record['retained_owner_calls']==[] and record['policy_sha256']==digest(policy_raw) and record['original_CLI_timeout_seconds_unchanged']==20)
        pins(record['bundle_before'],'caller bundle');reads.extend(record['read_calls'])
        for row in record['read_calls']:check('actual native read call/transition increased',row['native_calls_after']==row['native_calls_before']+1 and row['native_transitions_after']>row['native_transitions_before'])
    check('12 actual public read attempts and 11 normal returns',len(reads)==orig['actual_native_read_attempts']==12 and sum(r['outcome']=='returned' for r in reads)==orig['actual_native_read_returns']==11)
    # Save every actually uploaded bounded byte, independently of all reports.
    with tarfile.open(OUTPUT/'bounded-originals.tar.gz','w:gz',format=tarfile.PAX_FORMAT,compresslevel=1) as tar:
        for row in members:
            info=tarfile.TarInfo(row['path']);info.mode=0o600;info.size=row['bytes'];tar.addfile(info,io.BytesIO(raws[row['path']]))
    with tarfile.open(OUTPUT/'bounded-originals.tar.gz','r:gz') as tar:
        readback=[(m.name,digest(tar.extractfile(m).read())) for m in tar]
    check('all 149 retained bytes independently archived',readback==[(r['path'],r['sha256']) for r in members])

after=ZIP.stat();check('original ZIP identity stable',(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
report={'schema':'hia.v82.bounded-original-readonly-audit.v1','status':'READONLY_RETAINED_FINITE_EVIDENCE_PASS' if all(c['passed'] for c in checks) else 'HOLD',
        'run_id':43191120147,'actual_head':'afea182f1e15525d974303b9667a1949bd1292f0','canonical_product_base':BASE,'artifact_id':13932321157,'artifact_sha256':EXPECTED_ZIP,
        'checks':checks,'check_count':len(checks),'failed_checks':[c for c in checks if not c['passed']],'raw_members':members,'pin_joins':pin_count,'unavailable_paths':unavailable,
        'owners':owner_rows,'finite_counts':[12,24,10,9,8],'actual_CLI_children':7,'actual_public_read_attempts':12,'actual_public_read_returns':11,
        'actual_python':main['python'],'native_image_sha256':digest(image),'compiler_sha256':digest(compiler),
        'product_executed_by_auditor':False,'original_CI_failure_reclassified':False,'all_input_equivalence_proved':False,'whole_native_delivery_qualified':False,
        'limits':['Full original ZIP and all149 uploaded bounded members were read; omitted live special-node fixture metadata cannot be reconstructed from upload.','Seven original CLI input temporary files are not separately retained; their exact argv/source binding and actual native read records are retained.','Raw remote inode/UID/mtime identity claims are historical report observations, not a new physical reopening of that CI host.'],
        'elapsed_ns':time.monotonic_ns()-start}
(OUTPUT/'AUDIT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'checks':len(checks),'failures':report['failed_checks'],'members':len(members),'pin_joins':pin_count,'unavailable_paths':len(unavailable)}))
