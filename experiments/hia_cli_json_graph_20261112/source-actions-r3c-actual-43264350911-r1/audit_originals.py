"""Read-only audit of the one completed Source4 artifact. No product imports."""
from __future__ import annotations
import base64, hashlib, io, json, os, pathlib, stat, tarfile, time, traceback, zipfile

BASE = pathlib.Path(__file__).parent
REMOTE = '/home/runner/work/_temp/hia-cli-json-four-source-r3c-actions-r1'
PUBLIC = REMOTE + '-public'
A = 'f26b68a95ae257f59d9807dcccc950797442ab79'
B = 'a1715cbc26b71f9226e1d3c60582e5063e40bb07'
SOURCE = '62ac5111cd6316c7815e9c6f7d80f77e083decb7'
POLICY_SHA = '8e66871a71e0ecdb8cca704133d96ec604156aa17d94b5c81f204be3d06950a6'
ZIP_SHA = '73971a4a092757767c037d65c9e7646c4e9d8efb52c7c647efc1d0c00b970731'
AUDIT = {'schema':'hia.cli-json.source4-complete-originals-readonly-audit.v1',
         'status':'HOLD','checks':[], 'errors':[], 'product_reexecuted':False,
         'native_executed':False,'original_cli_methods_executed':0,'trace_cases_executed':0,
         'compiler_line_gate_measured':False,
         'scope':'Exact original source-only run43264350911; no r4a or product qualification'}
def need(condition, name, detail=None):
    AUDIT['checks'].append({'name':name,'pass':bool(condition),**({'detail':detail} if detail is not None else {})})
    if not condition: raise ValueError(name)
def digest(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def unique(rows):
    result={}
    for key,value in rows:
        if key in result: raise ValueError('duplicate original JSON key: '+key)
        result[key]=value
    return result
def parse(raw): return json.loads(raw,object_pairs_hook=unique)
def wire(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def check_record(raw,record,label):
    d=digest(raw)
    need(all(record.get(k)==v for k,v in d.items() if k in record),label+' full byte/hash/Git record')
    need(record.get('bytes')==len(raw) and record.get('sha256')==d['sha256'],label+' byte+SHA fields required')
    if 'identity' in record:
        x=record['identity']
        need(len(x)==9 and all(type(v)is int for v in x) and stat.S_ISREG(x[2]) and x[5]==1 and x[6]==len(raw),label+' original regular single-link identity')
    return d
def safe_name(name):
    p=pathlib.PurePosixPath(name)
    return name and not name.startswith('/') and '\\' not in name and '\0' not in name and all(x not in ('','..','.') for x in name.split('/')) and p.as_posix()==name
def save_new(path, raw):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with path.open('xb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    need(path.read_bytes()==raw,'saved exact original '+str(path.relative_to(BASE)))
def metadata_projection(row):return {k:v for k,v in row.items() if k!='git_blob'}
def measure(doc, size, limits):
    rows=[]
    for f in doc['functions']:
        names={x['name'] for x in f['params']}
        params=len(f['params']);args=results=ops=0
        for block in f['blocks']:
            names.update(x['name'] for x in block['params'])
            params=max(params,len(block['params']))
            for op in block['ops']:
                names.update(x['name'] for x in op['out'])
                ops+=1;args=max(args,len(op['args']));results=max(results,len(op['out']))
            term=block['term']
            if term['op']=='jump':args=max(args,len(term['args']))
            elif term['op']=='branch':args=max(args,len(term['then']['args']),len(term['else']['args']))
            elif term['op']=='ret':args=max(args,len(term['values']))
        rows.append({'name':f['name'],'blocks':len(f['blocks']),'operations':ops,'ssa_names':len(names),
                     'parameters':params,'arguments':args,'instruction_results':results,'function_results':len(f['returns'])})
    actual={'source_bytes':size,'functions':len(rows),'blocks_per_function':max(r['blocks'] for r in rows),
            'blocks_total':sum(r['blocks'] for r in rows),'parameters_or_arguments':max(max(r['parameters'],r['arguments']) for r in rows),
            'ssa_names_per_function':max(r['ssa_names'] for r in rows),'instruction_results':max(r['instruction_results'] for r in rows),
            'function_results':max(r['function_results'] for r in rows),'instructions':sum(r['operations'] for r in rows)}
    return {'actual':actual,'limits':limits,'functions':rows,'within_limits':all(actual[k]<=limits[k] for k in actual)}
def main():
    started=time.monotonic_ns()
    zip_path=BASE/'ARTIFACT.original.zip';before=zip_path.stat();zip_raw=zip_path.read_bytes()
    need(len(zip_raw)==1498067 and digest(zip_raw)['sha256']==ZIP_SHA,'official complete artifact external seal')
    outer={};outer_rows=[]
    with zipfile.ZipFile(io.BytesIO(zip_raw)) as z:
        infos=z.infolist()
        need(len(infos)==18 and len({x.filename for x in infos})==18,'18 unique complete outer members')
        for x in infos:
            need(safe_name(x.filename) and not x.is_dir() and stat.S_ISREG(x.external_attr>>16),'safe regular outer member '+x.filename)
            need(x.file_size<=16<<20 and not x.flag_bits&1,'unencrypted bounded outer member '+x.filename)
            raw=z.read(x)
            need(len(raw)==x.file_size,'outer complete CRC/size '+x.filename)
            outer[x.filename]=raw;outer_rows.append({'name':x.filename,'crc32':x.CRC,'mode':x.external_attr>>16,**digest(raw)})
    need(sum(len(v) for v in outer.values())<16<<20,'complete outer raw bounded')
    for name,raw in outer.items():save_new(BASE/'outer'/name,raw)
    final=parse(outer['FINAL.json']);custody=parse(outer['CUSTODY.json'])
    setup=parse(outer['SETUP.original.json']);run=parse(outer['RUN.original.json'])
    small=parse(outer['SMALL.json']);framing=parse(outer['FRAMING.json'])
    policy_raw=(BASE/'POLICY.expected.json').read_bytes();policy=parse(policy_raw)
    need(digest(policy_raw)['sha256']==POLICY_SHA,'external frozen policy SHA')
    need(final['source_commit']==SOURCE and final['control_commit']==A and final['source_tree']==policy['source_tree'] and final['policy_sha256']==POLICY_SHA,'final source and actual authority identities')
    need(final['owned_children_closed'] is True and final['errors']==[] and final['status']=='REMOTE_FOUR_SOURCE_COMPONENTS_PASS_NOT_NATIVE','final exact source-only success')
    need(final['native_executed'] is False and final['original_cli_methods_executed']==final['trace_cases_executed']==0 and final['compiler_line_gate_measured'] is False,'final no native/callers/traces/line-gate claim')
    need(custody['status']=='CLOSED_AVAILABLE_ORIGINAL_BYTES_RETAINED' and custody['errors']==[] and custody['owned_children_closed'] is True and custody['typed_without_bytes']=={},'whole closed custody has no refusal/error')
    check_record(outer['CUSTODY.json'],final['custody'],'final custody')
    check_record(outer['SETUP.original.json'],final['setup'],'final setup')
    check_record(outer['SMALL.json'],final['small_selection'],'final small selection')
    check_record(outer['originals.tar'],custody['archive'],'whole typed tar')
    need(custody['archive_limit']==256<<20 and custody['raw_total_limit']==192<<20 and custody['file_bytes_limit']==32<<20,'unchanged custody budgets')
    owned={};tar_rows=[]
    with tarfile.open(fileobj=io.BytesIO(outer['originals.tar']),mode='r:') as t:
        members=t.getmembers()
        need(len(members)==197 and len({x.name for x in members})==197,'197 unique typed tar regular members')
        for x in members:
            need(x.isreg() and safe_name(x.name) and x.name.startswith('owned/') and not x.linkname and not x.pax_headers,'tar regular no-link canonical name '+x.name)
            raw=t.extractfile(x).read();name=x.name[len('owned/'):]
            need(len(raw)==x.size and x.size<=32<<20,'tar whole member '+name)
            check_record(raw,custody['captured'][name],'captured '+name)
            need(custody['namespace'][name]['kind']=='regular' and custody['namespace'][name]['identity']==custody['captured'][name]['identity'],'namespace exact captured identity '+name)
            owned[name]=raw;tar_rows.append({'name':x.name,'mode':x.mode,'uid':x.uid,'gid':x.gid,**digest(raw)})
    need(set(owned)==set(custody['captured']),'complete tar/captured set equality')
    need(sum(len(r)for r in owned.values())==custody['raw_bytes']==11896687,'complete captured raw count')
    need(set(custody['missing'])=={'actual/error.txt',*(f'actual/{x}.error.txt' for x in ('text','sort','note','cgraph'))},'only five unproduced error originals missing')
    need(set(custody['expected_paths'])==set(owned)|set(custody['missing']),'all fixed original paths accounted')
    need({k for k,v in custody['namespace'].items() if v['kind']=='regular'}==set(owned),'physical namespace has no uncaptured regulars')
    need(all(v['kind']in('regular','directory')for v in custody['namespace'].values()),'no unretained special member')
    for name,raw in owned.items():save_new(BASE/'retained'/name,raw)
    need(owned['SETUP.json']==outer['SETUP.original.json'] and owned['RUN.json']==outer['RUN.original.json'],'parent originals exact copies')
    need(owned['authority/POLICY.json']==policy_raw and owned['authority/controller.py']==(BASE/'controller.expected.py').read_bytes(),'physical authority is frozen A2')
    need(set(policy['source_pins'])==set(setup['source']) and len(setup['source'])==160,'160 fixed source names')
    need(set(k[7:]for k in owned if k.startswith('source/'))==set(policy['source_pins']),'entire actual source namespace')
    before_source=parse(owned['actual/source.before.json']);after_source=parse(owned['actual/source.after.json'])
    need(before_source==after_source and len(before_source)==160,'all 160 original source identities stable')
    need(sum(row['bytes']for row in setup['source'].values())==2498584==policy['source_bytes'],'actual complete source bytes')
    for name,pin in policy['source_pins'].items():
        raw=owned['source/'+name];check_record(raw,pin,'frozen source '+name)
        check_record(raw,setup['source'][name],'setup source '+name)
        need(setup['source'][name]['path']==REMOTE+'/source/'+name and before_source[name]==metadata_projection(setup['source'][name]),'before/after/setup identity '+name)
        need(custody['captured']['source/'+name]==setup['source'][name],'final source identity '+name)
    for name,pin in policy['original_controls'].items():
        check_record(owned['control/'+name],pin,'unchanged original control '+name)
        need(setup['controls'][name]==custody['captured']['control/'+name],'setup/final original control '+name)
    configuration=parse(owned['control/CONFIG.json'])
    for key in ('components','limits','original_cli_ids','trace_plan_ids','source_pins'):
        need(configuration[key]==policy[key],'configuration unchanged '+key)
    need(configuration['source_root']==REMOTE+'/source' and configuration['native_executed'] is False and configuration['trace_execution_requested'] is False and configuration['caller_execution_requested'] is False,'source-only relocated config flags')
    need(setup['status']=='FOUR_COMPONENT_SOURCE_REQUEST_READY_NOT_EXECUTED' and setup['errors']==[] and setup['control_commit']==A and setup['source_commit']==SOURCE,'actual setup/source')
    event=setup['event']
    need(event=={'GITHUB_SHA':B,'GITHUB_REF':'refs/heads/'+policy['trigger_branch'],'GITHUB_EVENT_NAME':'create','GITHUB_RUN_ID':'43264350911','GITHUB_RUN_ATTEMPT':'1','RUNNER_OS':'Linux','RUNNER_ARCH':'X64'},'actual run/create/attempt/context')
    runtime=setup['runtime']
    need(runtime['version_info']==[3,14,4,'final',0] and runtime['implementation']=='cpython' and runtime['machine']=='x86_64' and runtime['platform']=='linux' and runtime['pointer_bytes']==8,'actual Python3.14.4 profile')
    need(runtime['stdlib_or_entire_OS_closure_claimed'] is False,'runtime scope accurate')
    for key in ('executable','shared_library'):
        row=runtime[key];need(stat.S_ISREG(row['identity'][2]) and row['identity'][5]==1 and row['identity'][6]==row['bytes'] and not row['identity'][2]&0o022,'recorded immutable runtime '+key)
    need(runtime['shared_library_mapping']['path']==runtime['shared_library']['path'] and runtime['shared_library_mapping']['same_actual_device_inode_checked'] is True and runtime['shared_library_mapping']['segments'],'actual mapping receipt bound')
    request=parse(owned['guardian/REQUEST.json']);guard=parse(owned['guardian/guardian.json']);life=guard['lifecycle'];cleanup=life['cleanup']
    expected={r['path']:r['sha256'] for group in ('source','controls','authority') for r in setup[group].values()}
    expected[setup['configuration']['path']]=setup['configuration']['sha256']
    for key in ('executable','shared_library'):expected[runtime[key]['path']]=runtime[key]['sha256']
    python=runtime['executable']['path']
    command=[python,'-I','-S','-B',REMOTE+'/control/source_authoring_worker.py',REMOTE+'/control/CONFIG.json',REMOTE+'/actual']
    need(request=={'schema':'hia-external-guardian-request.v1','controller_seconds':180,'command':command,'cwd':REMOTE+'/source','source_identities':expected},'complete actual guardian request equality')
    check_record(owned['guardian/REQUEST.json'],setup['request'],'actual request seal')
    need(guard['schema']=='hepta.hia.external-qualification-guardian.v1' and guard['command']==command and guard['cwd']==request['cwd'] and guard['external_controller_seconds']==180,'guardian command and original deadline')
    need(guard['source_identities_before']==guard['source_identities_after']==expected and guard['input_identity_preserved'] is True,'168 exact input/runtime SHA identities stable')
    need(len(expected)==168,'actual all-input denominator')
    for path,sha in expected.items():
        if path.startswith(REMOTE+'/'):need(digest(owned[path[len(REMOTE)+1:]])['sha256']==sha,'complete actual input bytes '+path[len(REMOTE)+1:])
    need(guard['lifecycle_implementation_sha256']=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2','original lifecycle implementation')
    need(guard['status']=='EXTERNAL_OWNED_PROCESS_COMPLETED' and guard['qualification'] is None and guard['whole_native_delivery_qualified'] is False,'guardian source-only terminal')
    need(life['qualification_seconds']==180 and life['cleanup_seconds']==3 and life['status']=='OWNED_PROCESS_COMPLETED' and life['returncode']==0 and life['qualification_started'] is True and life['subreaper_enabled'] is True,'original180/3 natural owner')
    need(life['timed_out'] is False and life['exit_observed_before_deadline'] is True and life['event_overflow'] is False and life['interrupted_signals']==[] and life.get('owner_error') is None,'no timeout/overflow/interrupt/owner error')
    need(cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True and cleanup['remaining_direct_children']==[] and cleanup['errors']==[] and cleanup['deadline_exceeded'] is False,'actual kernel ECHILD complete cleanup')
    events=life['events']
    need([e['kind']for e in events]==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'],'exact four natural events/no kill')
    owner_elapsed=events[2]['monotonic_ns']-events[0]['monotonic_ns']
    need(0<=owner_elapsed<180_000_000_000 and events[2]['si_status']==0 and events[3]['returncode']==0,'actual owner elapsed and natural exit')
    need(run['returned'] is True and run['returncode']==0 and run['launch_attempted'] is True and run['errors']==[] and run['command']==setup['guardian_command'] and run['cwd']==REMOTE+'/source' and run['environment']==setup['environment'] and run['request']==setup['request'],'complete launcher receipt')
    need(set(guard['logs'])=={REMOTE+'/guardian/child.stdout.log',REMOTE+'/guardian/child.stderr.log'},'two exact original child logs')
    for path,sha in guard['logs'].items():need(digest(owned[path[len(REMOTE)+1:]])['sha256']==sha,'actual child log '+path)
    report=parse(owned['actual/REPORT.json']);accept=final['source_acceptance']
    need(report['schema']=='hia.cli-json.source-authoring.r3.v1' and report['status']=='FOUR_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN' and report['errors']==[],'actual worker complete source result')
    need(report['native_executed'] is False and report['product_callers_executed'] is False and report['counts_are_plan_only'] is True,'actual worker source-only scope')
    need(report['original_cli_ids']==policy['original_cli_ids'] and len(report['original_cli_ids'])==17 and report['trace_plan_ids']==policy['trace_plan_ids'] and len(report['trace_plan_ids'])==46,'unchanged17/46 plan only')
    need(report['configuration']==metadata_projection(setup['configuration']),'worker actual config pin')
    for key,relative in [('source_before','actual/source.before.json'),('source_after','actual/source.after.json')]:
        check_record(owned[relative],report[key],'worker '+key);need(report[key]==metadata_projection(custody['captured'][relative]),'whole original '+key+' identity')
    need([[x['name'],x['module']]for x in report['components']]==policy['components'],'all four components exact order')
    need(set(m for _,m in policy['components']).issubset(report['actual_repository_modules']) and all(v in policy['source_pins']for v in report['actual_repository_modules'].values()),'actual imported repository source closure')
    metrics=[]
    suffix={'authoring_source':'.authoring.py.txt','document':'.document.json','assembly':'.hiaasm','verified_document':'.verified.json','caps':'.caps.json'}
    for row,accepted in zip(report['components'],accept['components']):
        label=row['name']
        need(row['status']=='SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE' and row['error'] is None,'actual source component '+label)
        for key,ext in suffix.items():
            relative='actual/'+label+ext;check_record(owned[relative],row[key],label+' '+key)
            need(row[key]==metadata_projection(custody['captured'][relative]) and accepted['records'][key]==custody['captured'][relative],label+' original producer/acceptance identity '+key)
        doc=parse(owned['actual/'+label+'.document.json']);verified=parse(owned['actual/'+label+'.verified.json'])
        need(doc==verified,label+' complete actual Core roundtrip document equality')
        caps=parse(owned['actual/'+label+'.caps.json']);recomputed=measure(verified,len(owned['actual/'+label+'.hiaasm']),policy['limits'])
        need(caps==recomputed and caps['within_limits'] is True and len(caps['actual'])==9,label+' all nine exact measured caps')
        need(accepted['actual_caps']==caps['actual'] and accepted['elapsed_ns']==row['elapsed_ns'] and accepted['name']==label and accepted['module']==row['module'],label+' final component projection')
        metrics.append({'name':label,'assembly':digest(owned['actual/'+label+'.hiaasm']),'actual':caps['actual'],'elapsed_ns':row['elapsed_ns'],
                        'line_count_diagnostic_only':len(owned['actual/'+label+'.hiaasm'].splitlines())})
    need(accept['status']=='FOUR_SOURCE_COMPONENTS_ACCEPTED_NOT_NATIVE' and accept['source_files']==160 and accept['source_bytes']==2498584 and accept['worker_elapsed_ns']==report['elapsed_ns'] and accept['owner_elapsed_ns']==owner_elapsed,'final accepted actual result binding')
    check_record(owned['actual/REPORT.json'],accept['report'],'final worker original')
    check_record(owned['guardian/guardian.json'],final['guardian'],'final guardian original')
    check_record(owned['RUN.json'],accept['run'],'final launcher original')
    decoded=parse((BASE/'SMALL-DECODED.json').read_bytes())
    stream=base64.b64decode(decoded['protocol']['base64'],validate=True)
    need(stream==outer['small.frames.txt'] and len(stream)<=1<<20,'actual strict small stream matches artifact')
    need(digest(outer['FRAMING.json'])['sha256']==decoded['end']['framing_sha256'],'END original framing SHA')
    need(framing['selected_files']==len(decoded['originals'])==13 and framing['selected_raw_bytes']==sum(r['bytes']for r in decoded['originals'])==522744,'complete13 file bounded channel denominator')
    need(small['whole_files_only'] is True and small['failure_originals_prioritized'] is False and small['complete_originals_are_in_artifact_not_all_stdout'] is True,'success small order/omission scope accurate')
    for row in small['rows']:
        if row['status']=='CAPTURED':
            name=row['record']['path'][len(PUBLIC)+1:];check_record(outer[name],row['record'],'actual selected original '+name)
            need(row['source'] in owned and owned[row['source']]==outer[name],'small actual body matches full tar '+name)
    for row in decoded['originals']:
        raw=base64.b64decode(row['base64'],validate=True);check_record(raw,row,'V8 strict decoded original')
    need(digest((BASE/'JOB.original.log').read_bytes())['sha256']==decoded['log']['sha256'],'full actual job log exact byte seal')
    after=zip_path.stat()
    need(all(getattr(after,k)==getattr(before,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')) and zip_path.read_bytes()==zip_raw,'original artifact identity and bytes stable after complete read')
    AUDIT.update(status='READONLY_FULL_ORIGINALS_AND_FOUR_SOURCE_COMPONENTS_PASS_NOT_NATIVE',
                 artifact={'id':13964912684,**digest(zip_raw)},outer_members=outer_rows,tar_members=tar_rows,
                 source_files=160,source_bytes=2498584,all_input_identities=168,components=metrics,
                 worker_elapsed_ns=report['elapsed_ns'],owner_elapsed_ns=owner_elapsed,
                 actual_runtime_receipt=runtime,runtime_binary_bodies_transported=False,
                 scope_limits=['All four original source generation/Core roundtrip/nine structural caps only.',
                               '16384 line gate was not part of the executed request; line counts are diagnostics.',
                               'No product, C compilation, native, original17 or trace46 execution.',
                               'Runtime executable/library hashes are original remote observations, not locally transported binary bodies.'],
                 elapsed_ns=time.monotonic_ns()-started)
try:main()
except BaseException as error:
    AUDIT['errors'].append({'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()})
finally:
    AUDIT['checks_count']=len(AUDIT['checks'])
    AUDIT['failed_checks']=[x for x in AUDIT['checks']if not x['pass']]
    with (BASE/'AUDIT.json').open('xb') as f:f.write(wire(AUDIT))
    print(json.dumps({k:AUDIT[k]for k in ('status','checks_count','errors')}))
if AUDIT['errors']:raise SystemExit(1)

