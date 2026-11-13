"""Independent read-only custody audit. No product imports, execution or download."""
from pathlib import Path, PurePosixPath
import hashlib,json,os,re,sys,zipfile,zlib,time
ROOT=Path("/home/qq/hia-rewrite-20261113-e26e-r1/pc-ci-a2-small-14022456964-r1")
CONTROL=Path("/home/qq/hia-rewrite-20261113-e26e-r1/pc-ci-a2-diagnostics-only-r1")
sys.path.insert(0,str(ROOT/'control')); import source_common as c
os.umask(0o077)
CHECKS=0
def ck(value,message):
    global CHECKS
    CHECKS+=1
    if not value: raise RuntimeError(message)
def j(raw):return c.decode(raw)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return c.read_regular(path)[0]
def samefile(row,raw,label):ck(type(row['bytes']) is int and len(raw)==row['bytes'] and sha(raw)==row['sha256'],label)
qraw=read(ROOT/'REQUEST.json');ck(sha(qraw)=="b8bd9c4c56a31503b231c4890b9fd41d0ff51ef201cc69e88652efdf18dac826",'fixed local request')
q=j(qraw);q['worker_command']=[sha(qraw) if x=='<REQUEST-SHA256>' else x for x in q['worker_command_template']]
actual=Path(q['output_root'])
wrapper=j(read(actual/'owner-wrapper.json'))
local_owner,local_request,natural=c.bind_closed(q,wrapper,actual/'process-owner.json')
ck(natural,'local owner natural zero before child access')
report_raw=read(actual/'REPORT.json');ck(sha(report_raw)=="24b686ba5cd1c0180f651918edff7e976a28bc84471f2508f8c6caa568624831",'fixed complete local report')
report=j(report_raw)
ck(report['request_sha256']==sha(qraw) and report['artifact']==q['artifact'] and report['download_attempts']==1 and report['exception'] is None and report['status']=='WHOLE_OFFICIAL_ARTIFACT_READBACK_COMPLETE_NOT_PRODUCT_PASS','single whole local reception')
small=read(actual/'ARTIFACT.original.zip');samefile(q['artifact'],small,'provider complete original ZIP')
members=report['members']; selected=report['selected'];byname={x['name']:x for x in selected}
ck(len(byname)==len(selected)==len(members),'complete small selection unique')
retained={}
with zipfile.ZipFile(actual/'ARTIFACT.original.zip') as z:
    infos=z.infolist();ck(len(infos)==len(members),'all small central entries')
    for i,(info,row) in enumerate(zip(infos,members)):
        ck(row['index']==i and row['name']==info.filename and row['bytes']==info.file_size and row['compressed_bytes']==info.compress_size and row['compress_type']==info.compress_type and row['crc32']==info.CRC,'small central identity')
        raw=z.read(info);samefile(row,raw,'complete small body')
        ck(zlib.crc32(raw)&0xffffffff==info.CRC and row['full_body_read_and_crc_verified'] is True and not info.is_dir(),'whole small CRC')
        chosen=byname[info.filename];got=c.read_regular(chosen['file'],chosen['pin'])[0]
        ck(got==raw,'retained original full bytes')
        retained[info.filename]=raw
ck(sum(len(x) for x in retained.values())==report['expanded_bytes']==report['selected_bytes'],'complete small expanded total')
def data(name):return j(retained[name])
policy_raw=read(CONTROL/'policy.json')
ck(sha(policy_raw)=="0cbed326589fbf1fd640cedcef64c5465a7ba7e2e03279c90f6802279557b4ea",'frozen policy')
policy=j(policy_raw);context=data('controls/context.json');guard=data('controls/guard--guardian.json');grequest=data('controls/guard--request.json')
ck(context['run_id']==43394928015 and context['run_attempt']==1 and context['event']=='create' and context['actual_control_checkout']=='1fbeb3f2706e7521f4b234c7ccabbbcad7009767' and context['actual_workflow_commit']=='744512bdb82a5f700e8fe50e2c01637c161bb99d','current recovery execution context')
ck(context['policy_sha256']==sha(policy_raw) and context['original_product_commit']==policy['source']['head'] and context['original_product_tree']==policy['source']['tree'] and context['qualification_executed'] is False,'current original source context')
for name,row in policy['control_files'].items():
    ck(context['control_sources']['/home/runner/work/Hepta/Hepta/control/'+policy['control_prefix']+'/'+name]==row['sha256'],'canonical remote source')
ck(guard['command']==grequest['command'] and guard['cwd']==grequest['cwd']==context['root'] and guard['external_controller_seconds']==grequest['controller_seconds']==900,'bound remote request')
ck(guard['source_identities_before']==guard['source_identities_after']==grequest['source_identities'] and guard['input_identity_preserved'] is True,'bound remote complete source')
ck(grequest['source_identities'][context['root']+'/context.json']==sha(retained['controls/context.json']),'raw context binding')
life=guard['lifecycle'];cl=life['cleanup']
ck(life['qualification_seconds']==900 and life['cleanup_seconds']==3 and guard['lifecycle_implementation_sha256']==policy['control_files']['process_owner_impl.py']['sha256'],'remote original900/3')
ck(life['subreaper_enabled'] is True and cl['complete'] is True and cl['observed_echild'] is True and cl['leader_reaped'] is True and cl['remaining_direct_children']==[] and cl['errors']==[] and cl['deadline_exceeded'] is False,'remote ECHILD before original diagnostics')
ck(life['returncode']==0 and life['timed_out'] is False and life['exit_observed_before_deadline'] is True and life['event_overflow'] is False and life['interrupted_signals']==[] and guard['status']=='EXTERNAL_OWNED_PROCESS_COMPLETED','remote natural success')
setup=data('controls/setup.json');worker=data('controls/recovery-terminal.json');final=data('FINAL.json');capture=data('SMALL-READBACK.json')
ck(worker==data('controls/recovery.json'),'terminal worker complete raw duplicate')
ck(setup['context']==context and setup['command']==guard['command'] and setup['source_identities']==grequest['source_identities'],'actual setup binding')
ck(setup['guardian_config_sha256']==sha(retained['controls/guard--request.json']),'actual setup request SHA')
ck(worker['status']=='SEALED_DIAGNOSTICS_PENDING_NATURAL_GUARDIAN' and worker['artifact']==policy['artifact'] and worker['source']==policy['source'] and worker['policy_sha256']==sha(policy_raw),'actual worker fixed original')
ck(type(worker['elapsed_ns']) is int and 0<=worker['elapsed_ns']<=720000000000,'original720 transfer budget')
ck(worker['qualification_executed'] is False and worker['project_code_executed'] is False and worker['old_runs_replayed'] is False and worker['partition_files_created'] is False,'transport scope')
ck(len(worker['API_attempts'])==2 and len(worker['GET_attempts'])==1,'original remote API/GET population')
get=worker['GET_attempts'][0]
ck(get['artifact_id']==policy['artifact']['id'] and get['attempt']==1 and get['retries']==0 and get['redirects']==0 and get['bytes']==policy['artifact']['bytes'] and get['sha256']==policy['artifact']['sha256'],'original remote exact single GET')
official=data('controls/api--artifact-14021690212.metadata.original.json')
ck(official['id']==policy['artifact']['id'] and official['size_in_bytes']==policy['artifact']['bytes'] and official['digest']=='sha256:'+policy['artifact']['sha256'] and official['workflow_run']['id']==policy['artifact']['run_id'] and official['workflow_run']['head_sha']==policy['artifact']['checkout_commit'],'actual remote official input')
ck(final['status']=='ALL_AVAILABLE_STEP42_ORIGINALS_VERIFIED_NOT_QUALIFICATION' and final['errors']==[] and final['missing_originals']==[] and final['context']==context and final['artifact']==policy['artifact'],'current remote final')
ck(final['closed_echild'] is True and final['complete_local_diagnostic_readback'] is True and final['complete_original_ZIP_member_read_verified'] is True and final['source_inputs_preserved'] is True and final['partition_files_created'] is False and final['new_product_execution'] is False,'remote custody scope')
ck(final['diagnostic_capture']==capture and capture['complete'] is True and capture['errors']==[],'capture raw receipt binding')
idx=data('originals/INDEX.json')
samefile(worker['diagnostics'],retained['originals/INDEX.json'],'worker INDEX full body')
ck(idx['artifact']==policy['artifact'] and idx['status']=='AVAILABLE_STEP42_ORIGINALS_PRESERVED_NOT_QUALIFICATION' and idx['all_members_fully_read'] is True and idx['complete_selection_of_available_originals'] is True and idx['errors']==[],'current original INDEX')
dr=retained['originals/DIRECTORY.jsonl'];ir=retained['originals/FULL-INVENTORY.jsonl']
samefile(idx['directory'],dr,'complete directory body');samefile(idx['inventory'],ir,'complete inventory body')
ck(dr.endswith(b'\n') and ir.endswith(b'\n'),'complete metadata newline')
directory=[j(x) for x in dr.splitlines()];inventory=[j(x) for x in ir.splitlines()]
ck(type(idx['members']) is int and len(directory)==len(inventory)==idx['members'],'current observed original count')
names=[]
for i,(d,v) in enumerate(zip(directory,inventory)):
    ck(type(d['index']) is int and type(v['index']) is int and d['index']==v['index']==i,'complete ordered original row')
    ck(type(v['bytes']) is int and v['bytes']>=0 and type(v['crc32']) is int and type(v['directory']) is bool and v['body_fully_read'] is True and re.fullmatch('[0-9a-f]{64}',v['sha256']) is not None,'typed complete original body record')
    ck(all(d[k]==v[k] for k in ('name','bytes','crc32')),'original central/body identity')
    name=v['name'];normalized=name[:-1] if v['directory'] and name.endswith('/') else name
    ck(type(name) is str and 0<len(name.encode())<=4096 and '\\' not in name and '\0' not in name and not any(ord(x)<32 or ord(x)==127 for x in name) and not PurePosixPath(normalized).is_absolute() and all(x not in ('','.','..') for x in normalized.split('/')) and str(PurePosixPath(normalized))==normalized,'canonical original name')
    names.append(name)
ck(len(names)==len(set(names)) and sum(x['bytes'] for x in inventory)==idx['expanded_bytes'],'original uniqueness/complete expanded total')
top=('hia-core-unpack-callers-admission.json','hia-core-unpack-gates.json','hia-cold.json')
chosen=[x for x in inventory if not x['directory'] and (x['name'] in top or (x['name'].startswith('hia-core-unpack-evidence/') and x['name'].endswith(('.json','.jsonl','.log'))))]
ck(len(chosen)==len(idx['selected']) and sum(x['bytes'] for x in chosen)==idx['selected_bytes'],'current selector complete population')
originals={};mapping=[]
for row,entry in zip(chosen,idx['selected']):
    ck(all(entry[k]==v for k,v in row.items()) and entry['retained_name']=='member-%05d.bin'%row['index'] and entry['truncated'] is False,'original selection exact mapping')
    smallname='originals/'+entry['retained_name'];raw=retained[smallname]
    samefile(entry,raw,'original actual complete SHA');samefile(entry['actual'],raw,'original pre-relocation bytes')
    ck(zlib.crc32(raw)&0xffffffff==row['crc32'],'original actual complete CRC')
    originals[row['name']]=raw
    mapping.append({'name':row['name'],'small_name':smallname,'local':byname[smallname]['file'],'bytes':len(raw),'sha256':sha(raw),'crc32':row['crc32']})
expected=('hia-core-unpack-callers-admission.json','hia-core-unpack-evidence/callers-owner/process-owner.json','hia-core-unpack-evidence/callers-owner/run-result.json','hia-core-unpack-evidence/callers-owner/stdout.log','hia-core-unpack-evidence/callers-owner/stderr.log','hia-core-unpack-evidence/callers/integer-report.json','hia-core-unpack-evidence/callers/numeric/numeric-report.json','hia-core-unpack-evidence/callers/numeric/callers/report.json','hia-core-unpack-evidence/callers/numeric/callers/progress.jsonl','hia-core-unpack-evidence/callers/numeric/callers/progress.receipt.json','hia-core-unpack-evidence/callers/numeric/callers/core-callers/report.json','hia-core-unpack-evidence/callers/numeric/callers/core-callers/component-fixture/installed-control/report.json')
missing=[n for n in expected if n not in names]
ck(idx['missing_expected']==missing and idx['expected_originals_all_present']==(not missing),'all12 expected explicit missing')
ck(set(n for n in retained if n.startswith('originals/'))=={'originals/'+x['retained_name'] for x in idx['selected']}|{'originals/INDEX.json','originals/DIRECTORY.jsonl','originals/FULL-INVENTORY.jsonl'},'all originals namespace exactly')
ck(capture['selected_count']==len(chosen) and capture['selected_bytes']==idx['selected_bytes'] and capture['complete_members']==len(inventory) and capture['missing_expected']==missing,'capture population actual joins')
for f in capture['files']:
    raw=retained['originals/'+f['name']]
    samefile(f['original'],raw,'capture original record');samefile(f['retained'],raw,'capture retained record')
    ck(f['accepted_complete_original'] is True and f['partial_not_promoted'] is False,'capture completeness meaning')
ck(len(capture['files'])==len(chosen)+3,'capture 3 full metadata')
for f in final['small_controls']:
    raw=retained['controls/'+f['name'].replace('/','--')]
    samefile(f['original'],raw,'remote control original');samefile(f['retained'],raw,'remote control retained')
def orig(n):return j(originals[n])
pref='hia-core-unpack-evidence/callers-owner/'
inner=orig(pref+'process-owner.json');innerreq=orig(pref+'process-owner.json.request.json');run=orig(pref+'run-result.json');returned=run['returned_owner']
ck(returned['receipt_sha256']==sha(originals[pref+'process-owner.json']) and returned['request_sha256']==sha(originals[pref+'process-owner.json.request.json']) and all(returned[k]==v for k,v in inner.items()),'original owner/wrapper full byte binding')
ck(innerreq['deadline_ns']-innerreq['started_ns']==180000000000 and innerreq['qualification_seconds']==inner['qualification_seconds']==180 and innerreq['cleanup_seconds']==inner['cleanup_seconds']==3,'product original180/3')
ck(inner['request_sha256']==sha(originals[pref+'process-owner.json.request.json']) and inner['implementation_sha256']==innerreq['implementation_sha256']=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2','original process identity')
ck(innerreq['command']==run['command'] and innerreq['cwd']==run['cwd'] and inner['subreaper_enabled'] is True and inner['cleanup']['complete'] is True and inner['cleanup']['observed_echild'] is True and inner['cleanup']['leader_reaped'] is True and inner['cleanup']['remaining_direct_children']==[] and inner['cleanup']['errors']==[] and inner['cleanup']['deadline_exceeded'] is False,'original caller bound cleanup')
expected_source_raw=read(CONTROL/'reference/CURRENT-COLD-SOURCE-MANIFEST.json')
ck(sha(expected_source_raw)=='5cc4a57f0ad86794bf2926807c09c9e7ad38fc83affbe7be54e3f90d1df9335d','fixed expected source export')
expected_source=j(expected_source_raw)
ck(run['source_before']==run['source_after']==expected_source and run['source_preserved'] is True and len(expected_source)==892,'original all892 current source identities')
ck(run['runtime_before']==run['runtime_after'] and run['runtime_before']['version']==[3,14,4] and run['cold_inputs_preserved'] is True,'original runtime/cold preserved')
samefile(run['cold_inputs'][0],originals['hia-cold.json'],'original current cold report')
ck(inner['status']=='QUALIFICATION_TIMEOUT' and inner['timed_out'] is True and inner['returncode']==-9 and inner['exit_observed_before_deadline'] is False and any(x['kind']=='owned_child_sigkill' for x in inner['events']),'actual original timeout evidence')
progress_raw=originals['hia-core-unpack-evidence/callers/numeric/callers/progress.jsonl']
ck(progress_raw.endswith(b'\n'),'complete available progress rows')
events=[j(x) for x in progress_raw.splitlines()]
ck(all(type(x['sequence']) is int and x['sequence']==i for i,x in enumerate(events)),'progress contiguous sequences')
ck(all(a['monotonic_ns']<=b['monotonic_ns'] and a['native_returns']<=b['native_returns'] for a,b in zip(events,events[1:])),'progress monotonic observations')
fixtures=[];stack=[];tests=[];open_test=None
for e in events:
    if e['event']=='fixture_begin':stack.append(e)
    elif e['event']=='fixture_end':
        wanted=(e['group'],e['subject'],e['detail']['kind'])
        matches=[i for i,x in enumerate(stack) if (x['group'],x['subject'],x['detail']['kind'])==wanted]
        ck(bool(matches),'observed fixture end has begin');b=stack.pop(matches[-1])
        fixtures.append({'group':b['group'],'subject':b['subject'],'kind':b['detail']['kind'],'seconds':(e['monotonic_ns']-b['monotonic_ns'])/1e9,'native_returns':e['native_returns']-b['native_returns'],'outcome':e['detail']['outcome']})
    elif e['event']=='test_start':ck(open_test is None,'no overlapping test');open_test=e
    elif e['event']=='test_stop':
        ck(open_test is not None and open_test['subject']==e['subject'],'observed stop has actual start')
        tests.append({'group':e['group'],'subject':e['subject'],'seconds':(e['monotonic_ns']-open_test['monotonic_ns'])/1e9,'native_returns':e['native_returns']-open_test['native_returns']});open_test=None
logs={}
for g,basename in (('component','component'),('original-machine','original-machine'),('original-core','original-core')):
    name='hia-core-unpack-evidence/callers/numeric/callers/core-callers/'+basename+'.unittest.log'
    raw=originals[name];lines=raw.decode().splitlines();oks=[x for x in lines if x.endswith(' ... ok')]
    ck(len(oks)==len([x for x in tests if x['group']==g]),'available successful test text/stop population')
    logs[g]={'name':name,'bytes':len(raw),'sha256':sha(raw),'observed_ok_lines':len(oks),'summary':lines[-5:]}
compiler=[]
for name,raw in originals.items():
    if name.endswith('.receipt.json'):
        x=j(raw);compiler.append({'name':name,'bytes':len(raw),'sha256':sha(raw),'receipt':x})
out=ROOT/'audit';out.mkdir(mode=0o700)
map_pin=c.save_json(out/'ORIGINAL-MAP.json',mapping)
compiler_pin=c.save_json(out/'COMPILER-RECEIPTS.json',compiler)
phase={'groups':[x for x in events if x['event'] in ('group_begin','group_end')],'class_setups':sorted([x for x in fixtures if x['kind']=='class_setup'],key=lambda x:-x['seconds']),'open_fixtures':stack,'open_test':open_test,'test_counts':{g:sum(x['group']==g for x in tests) for g in logs},'top_tests':sorted(tests,key=lambda x:-x['seconds'])[:20],'last_progress':events[-1],'last_available_phase_before_owner_deadline_seconds':(innerreq['deadline_ns']-events[-1]['monotonic_ns'])/1e9,'progress_does_not_grant_PASS':True}
phase_pin=c.save_json(out/'PHASE-ANALYSIS.json',phase)
summary={'schema':'hia.pc-attempt2.actual-diagnostics-independent-readback.v1','status':'FULL_CUSTODY_READBACK_PASS_OF_ACTUAL_PRODUCT_TIMEOUT','checks':CHECKS,'small_artifact':q['artifact'],'small_members':len(members),'small_expanded_bytes':report['expanded_bytes'],'original_artifact':policy['artifact'],'original_members':len(inventory),'original_expanded_bytes':idx['expanded_bytes'],'selected_originals':len(chosen),'selected_original_bytes':idx['selected_bytes'],'metadata_files':3,'missing_original_reports':missing,'local_owner':{'natural_zero':natural,'implementation':q['owner_implementation']['sha256'],'seconds':180,'cleanup_seconds':3,'ECHILD':True},'remote_owner':{'natural_zero':True,'seconds':900,'cleanup_seconds':3,'worker_ns':worker['elapsed_ns'],'ECHILD':True},'original_owner':inner,'original_source_count':len(expected_source),'original_source_equal':True,'logs':logs,'phase_analysis':phase_pin,'original_map':map_pin,'compiler_receipts':compiler_pin,'actual_product_PASS':False,'old_failures_or_UNKNOWN_reclassified':False,'new_network_or_product_execution':False}
summary_pin=c.save_json(out/'READBACK.json',summary)
print(json.dumps({'status':summary['status'],'checks':CHECKS,'readback':summary_pin,'original_members':len(inventory),'selected':len(chosen),'test_counts':phase['test_counts'],'last_progress':events[-1],'compiler_receipts':len(compiler),'phase':phase_pin},sort_keys=True))
