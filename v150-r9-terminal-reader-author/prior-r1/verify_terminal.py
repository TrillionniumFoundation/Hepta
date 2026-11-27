"""Independent complete data readback. No project import or product execution."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import stat
import time
import traceback

AUTHOR = Path('/tmp/hia-r8-r9-controls-author-r1-dda7')
PRODUCT = Path('/hia-r8-r9-controls-20261114-dda7')
OUTER = Path('/tmp/hia-r9-controls-outer-r1-dda7')
ADMISSION = Path('/tmp/hia-r9-controls-fresh-admission-r1-dda7')
MAPPING = Path('/tmp/hia-u32-r8-r4-admission-author-r1-dda7/EXPECTED-MAPPING.json')
ROOT_AUTHOR = Path('/tmp/hia-progress-v149-20261114-dda7')
CUSTODY = Path('/tmp/hia-r9-controls-complete-custody-r1-dda7')
PREVIOUS = Path('/dev/shm/hia-u32-r8-controls-r4-dda7')
PREVIOUS_READER = Path('/tmp/hia-u32-r8-r4-terminal-readback-r1-dda7')
KEYS = ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
TREE = '4c62be4ed66ff107fa6f88c6131313a354868bd9'
NAMES = ('source','output','workspace')
STARTED = ('public-R5-refusal','native162','semantic-edge-vm','semantic-remaining-vm')
SKIPPED = ('kernel130','observer-build','pipeline7','tail2')
VM_STEPS = (4028084,2974291,7746379,192888,275860,10000001)
PREVIOUS_VM_STEPS = (4426100,3267145,8506363,216015,302985,10000001)
READS = {}
INODES = {}
LEDGER = None

def need(value, message):
    if not value: raise AssertionError(message)

def seven(s): return [getattr(s,k) for k in KEYS]

def pin(b, mode=None):
    r={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
       'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if mode is not None: r.update(mode=mode,git_mode='100755' if mode&0o111 else '100644')
    return r

def canonical(value): return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def dump(p,value):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f: f.write(canonical(value))

def full(p, expected=None, wanted_stat=None, contents=False):
    p=Path(p)
    need(p.is_absolute() and '..' not in p.parts,'unsafe absolute input')
    parents=[]
    for parent in reversed(p.parents):
        s=parent.lstat();need(stat.S_ISDIR(s.st_mode),'parent is not a directory')
        parents.append((parent,(s.st_dev,s.st_ino,s.st_mode)))
    s=p.lstat();before=seven(s)
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'input is not a single-link regular file: '+str(p))
    if wanted_stat is not None: need(before==wanted_stat,'frozen stat differs: '+str(p))
    key=str(p);inode=(s.st_dev,s.st_ino)
    need(INODES.get(inode,key)==key,'aliased input inode');INODES[inode]=key
    fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(s.st_size).encode()+b'\0');count=0;pieces=[]
    try:
        need(seven(os.fstat(fd))==before,'opened file differs')
        while True:
            b=os.read(fd,1048576)
            if not b: break
            count+=len(b);need(count<=s.st_size,'file grew');sha.update(b);git.update(b)
            if contents: pieces.append(b)
        need(count==s.st_size,'truncated file')
        need(seven(os.fstat(fd))==before==seven(p.lstat()),'file changed during full read')
    finally: os.close(fd)
    for parent,wanted in parents:
        now=parent.lstat();need((now.st_dev,now.st_ino,now.st_mode)==wanted,'parent binding changed')
    mode=stat.S_IMODE(s.st_mode)
    identity={'bytes':count,'sha256':sha.hexdigest(),'git_blob':git.hexdigest(),
              'mode':mode,'git_mode':'100755' if mode&0o111 else '100644'}
    if expected is not None:
        need(set(expected)<=set(identity) and all(identity[k]==v for k,v in expected.items()),'identity differs: '+key)
    row={'path':key,'identity':identity,'seven_stats':before}
    if key in READS: need(READS[key]==row,'file changed between reader stages: '+key)
    else:
        READS[key]=row
        if LEDGER is not None:
            LEDGER.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');LEDGER.flush()
    return b''.join(pieces) if contents else row

def read(p,expected=None): return full(p,expected=expected,contents=True)

def j(p,git=None):
    raw=read(p)
    if git is not None: need(pin(raw)['git_blob']==git,'JSON authority differs: '+str(p))
    return json.loads(raw)

def tree_state(root):
    root=Path(root);need(stat.S_ISDIR(root.lstat().st_mode),'tree root is not a directory')
    files={};directories={}
    for here,dirs,names in os.walk(root,followlinks=False):
        dirs.sort();names.sort();here=Path(here);s=here.lstat()
        need(stat.S_ISDIR(s.st_mode),'directory link/special')
        directories[here.relative_to(root).as_posix()]={'mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s)}
        for name in dirs: need(stat.S_ISDIR((here/name).lstat().st_mode),'directory symlink')
        for name in names:
            p=here/name;s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'file link/special')
            files[p.relative_to(root).as_posix()]=seven(s)
    return {'files':files,'directories':directories}

def git_tree(files):
    root={}
    for path,row in files.items():
        parts=Path(path).parts;d=root
        for name in parts[:-1]: d=d.setdefault(name,{})
        need(parts[-1] not in d,'duplicate Git path');d[parts[-1]]=(row['git_mode'],row['git_blob'])
    def finish(d):
        entries=[]
        for name,v in d.items():
            entries.append((name+'/' if isinstance(v,dict) else name,
                            '40000' if isinstance(v,dict) else v[0],name,
                            finish(v) if isinstance(v,dict) else v[1]))
        b=b''.join(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)
                   for _,mode,name,sha in sorted(entries,key=lambda x:x[0].encode()))
        return hashlib.sha1(b'tree '+str(len(b)).encode()+b'\0'+b).hexdigest()
    return finish(root)

def native_frames(folder,initial,stored,image,old):
    qraw=read(folder/'request.json');q=json.loads(qraw)
    child=j(folder/'CHILD-REPORT.json');obs=j(folder/'OBSERVATION.json')
    need(q['schema']=='hia.linux-stdio.native-request.v1' and q['mode']=='ordinary','native request differs')
    need(q['image']==str(image) and q['image_sha256']==READS[str(image)]['identity']['sha256'],'native image differs')
    need(q['report']==str(folder/'CHILD-REPORT.json') and child==obs['child'],'child report binding differs')
    need(child['schema']=='hia.linux-stdio.native-observation.v1' and child['status']=='returned','native did not return')
    need(child['request_sha256']==pin(qraw)['sha256'] and child['image_sha256']==q['image_sha256'],'request/image pin differs')
    need(child['limits']=={'address_bytes':268435456,'core_dumpable':False,'cpu_seconds':10,
         'source_output_workspace_bytes':1048576,'stack_bytes':8388608,'wall_seconds':20},'native limits differ')
    need(child['forbidden_modules_loaded']==[] and child['matched_cold'] is False and child['whole'] is False,'native scope differs')
    need(obs['returncode']==0 and obs['timed_out'] is False and obs['timeout_seconds']==20 and
         obs['cleanup_seconds']==3 and obs['stdin_consumed']==0 and obs['canaries']==[True]*3,'native terminal differs')
    for n in ('stdin','stdout','stderr'): need(read(folder/(n+'.bin'))==b'','unexpected native IO')
    need(obs['stdout_hex']==obs['stderr_hex']=='','native IO observation differs')
    need(stored['request']==str(folder/'request.json') and stored['request_identity']==pin(qraw) and
         stored['observation_present'] is True and stored['complete_six_logical_buffers'] is True,'frame binding differs')
    need(len(q['buffers'])==len(stored['buffers'])==3,'native frame count differs')
    guard=b'\xd3'*64
    for label,value,item,frame in zip(NAMES,initial,q['buffers'],stored['buffers'],strict=True):
        p=folder/(label+'.shared');physical=read(p);after=physical[64:-64]
        need(item['path']==str(p) and item['extent']==len(value) and item['bytes']==len(value)+128 and
             item['sha256']==pin(guard+value+guard)['sha256'],'actual native preimage differs')
        need(len(physical)==item['bytes'] and physical[:64]==physical[-64:]==guard,'native physical extent/canary differs')
        need(after==bytes.fromhex(obs[label+'_hex']),'actual native shared bytes and hex differ')
        before=PRODUCT/'initial-buffers'/pin(value)['sha256']
        need(frame['name']==label and frame['guard_ends']==[True,True] and
             frame['before']=={'path':str(before),**pin(value)} and read(before)==value,'native before buffer differs')
        need(frame['after']=={'path':str(p),'offset':64,'extent':len(value),**pin(after)} and
             frame['physical']==pin(physical,stat.S_IMODE(p.lstat().st_mode)),'native complete after pin differs')
    checks={'terminal':obs['returncode']==0 and not obs['timed_out'],
        'same_return':child['result_u64']==old['child']['result_u64'],
        'same_complete_source':obs['source_hex']==old['source_hex']==initial[0].hex(),
        'same_complete_output':obs['output_hex']==old['output_hex']==initial[1].hex(),
        'same_complete_workspace':obs['workspace_hex']==old['workspace_hex'],
        'canaries':obs['canaries']==old['canaries']==[True]*3,'no_IO':obs['stdout_hex']==obs['stderr_hex']=='',
        'no_project_modules':child['forbidden_modules_loaded']==[]}
    need(all(checks.values()),'actual Native differs from complete original oracle')
    return obs,checks

def vm_frames(folder,name,initial,row,reused):
    need(row['name']==name and row['exact_current_R8_edge_reused'] is reused and row['complete_six_buffers'] is True,
         'semantic VM frame declaration differs')
    need(set(row['frames'])=={n+'.'+t for n in NAMES for t in ('before','after')},'VM six-buffer pathset differs')
    after=[]
    for label,value in zip(NAMES,initial,strict=True):
        before=PRODUCT/'VM-buffer-pool'/pin(value)['sha256']
        need(row['frames'][label+'.before']=={'path':str(before),**pin(value)} and read(before)==value,'VM initial bytes differ')
        p=folder/(label+'.bin');raw=read(p)
        need(len(raw)==len(value) and row['frames'][label+'.after']==
             {'path':str(p),**pin(raw,stat.S_IMODE(p.lstat().st_mode))},'actual VM after bytes differ')
        after.append(raw)
    return after

def verify(output):
    plan=j(AUTHOR/'EXECUTION-PLAN.json','125dc522389049145d6f63166b39ed9754993327')
    mapping=j(MAPPING,'7b3e66803be1c566f87ab7abfaac67d3a4db1a50')
    top=j(PRODUCT/'RESULT.json','e71435798df5407edcb472bd8b80aedcffa20876')
    admission=j(ADMISSION/'RESULT.json','ab25ae2113554b444c38f09e23ca36bd75d5eb57')
    need(admission['status']=='PASS_FULL_FRESH_R9_EIGHT_GROUP_ADMISSION_ONLY' and
         admission['full_original_domain_files']==6777 and admission['full_original_domain_bytes']==948620735 and
         admission['free_bytes_at_admission']>=3221225472 and admission['new_controls']==67 and
         admission['all962_full_roles'] is True and admission['old948_roles_exact'] is True,
         'actual R9 fresh admission differs')
    sealed=j(CUSTODY/'MANIFEST.json','2849d18a18a46d01e8150738fcd173101361255e')
    need(sealed['file_count']==2213 and sealed['logical_bytes']==1122457162,'sealed R9 denominator differs')
    for logical,wanted in sealed['files'].items():
        if logical.startswith(('root_author/','r9_author/')):
            full(wanted['source_path'],{**wanted['identity'],'mode':wanted['mode']},wanted['seven_stats'])
    original_plan=j(Path('/tmp/hia-u32-r8-post-reset-r4-dda7/EXECUTION-PLAN.json'),
                    '2374488181b268a9ea557832302025c135e63f36')
    need(len(original_plan['fixed_inputs'])==948 and len(plan['fixed_inputs'])==962 and
         all(plan['fixed_inputs'][name]==row for name,row in original_plan['fixed_inputs'].items()),
         'original 948 role bindings differ')
    new_roles=plan['R9_explicit_successor']['actual_candidate_roles']
    need(set(new_roles)==set(plan['fixed_inputs'])-set(original_plan['fixed_inputs']) and len(new_roles)==14,
         'explicit R9 14-role additions differ')
    frozen_roles=j(ADMISSION/'ALL-962-FULL-ROLES.json','2e9a901ca157392f1a764f677a2f856bd52245c7')
    need(frozen_roles['reference_count']==len(frozen_roles['roles'])==962 and
         set(frozen_roles['roles'])==set(plan['fixed_inputs']),'actual admission role set differs')
    original_fresh=j(ADMISSION/'FULL-FRESH-6777.json','8e7671a3b37465c66e63af409f50578d2dc75fd6')
    need(original_fresh=={'groups':mapping['groups'],'extra_authorities':mapping['extra_authorities'],
         'files':6777,'bytes':948620735},'actual original-domain admission map differs')
    material=dict(plan);authorization=material.pop('authorization_pin')
    need(pin(canonical(material))['sha256']==authorization and plan['minimum_free_bytes']==3221225472,
         'execution plan authority/floor differs')
    need(plan['source']['tree']==TREE and [p['name'] for p in plan['phases']]==list(STARTED+SKIPPED),'original source/phases differ')
    need(top['status']=='FAIL' and [r['phase'] for r in top['rows']]==list(STARTED) and
         [r['pass'] for r in top['rows']]==[True,True,True,False] and top['not_started']==list(SKIPPED),'actual fail-stop differs')
    for k in ('automatic_retry','public_R5_profile_qualified','ordinary_compiler_admission','new_current_cold','whole_native'):
        need(top[k] is False,'unexpected scope claim '+k)
    for phase in plan['phases'][4:]: need(not (PRODUCT/phase['out']).exists(),'unstarted phase output exists')
    input_rows={};input_trees={}
    for group in mapping['groups']:
        root=Path(group['root']);state=tree_state(root);input_trees[group['name']]=state
        need(set(state['files'])==set(group['files']) and state['directories']==group['directories'],
             'frozen input pathset/directory differs: '+group['name'])
        for name,wanted in group['files'].items():
            need(state['files'][name]==wanted['seven_stats'],'input stat drift')
            input_rows[str(root/name)]=full(root/name,wanted['identity'],wanted['seven_stats'])
    for row in mapping['extra_authorities']:
        need(row['path'] not in input_rows,'extra authority duplicated')
        input_rows[row['path']]=full(row['path'],row['identity'],row['seven_stats'])
    need(len(input_rows)==6777 and sum(r['identity']['bytes'] for r in input_rows.values())==948620735,
         'post-run fresh complete-input denominator differs')
    source_group=next(g for g in mapping['groups'] if g['name']=='source')
    source_files={n:input_rows[str(Path(source_group['root'])/n)]['identity'] for n in source_group['files']}
    need(len(source_files)==3180 and git_tree(source_files)==TREE,'actual source Git tree differs')
    original_input_count=len(input_rows)
    original_input_bytes=sum(r['identity']['bytes'] for r in input_rows.values())
    need(set(admission['controls'])==set(plan['controls']) and len(plan['controls'])==67,
         'all R9 control admission names differ')
    for name,wanted in plan['controls'].items():
        observed=admission['controls'][name]
        need(observed['identity']==wanted,'R9 control admission identity differs')
        path=str(AUTHOR/name)
        need(path not in input_rows,'new control aliases original input path')
        input_rows[path]=full(path,wanted,observed['seven_stats'])
    for name,wanted in new_roles.items():
        observed=admission['new_candidate_roles'][name]
        need(observed=={'identity':wanted['identity'],'seven_stats':wanted['seven_stats']} and
             {k:v for k,v in plan['fixed_inputs'][name].items() if k!='phases'}==
             {'path':wanted['path'],'identity':wanted['identity']},'R9 candidate role admission differs')
        need(wanted['path'] not in input_rows,'R9 role aliases original/control path')
        input_rows[wanted['path']]=full(wanted['path'],wanted['identity'],wanted['seven_stats'])
    need(len(input_rows)==6777+67+14,'post-run original plus R9 extension denominator differs')
    role_readback={}
    for name,wanted in plan['fixed_inputs'].items():
        observed=frozen_roles['roles'][name]
        actual=full(wanted['path'],wanted['identity'],observed['seven_stats'])
        need(actual==input_rows[wanted['path']] and actual['identity']==observed['identity'],
             'full actual role differs from pre-run admission')
        role_readback[name]={'path':wanted['path'],'identity':actual['identity'],'seven_stats':actual['seven_stats'],
                             'phases':wanted['phases']}
    need(sum(row['identity']['bytes'] for row in role_readback.values())==frozen_roles['reference_bytes']==724909501,
         'all 962 full role-reference bytes differ')
    dump(output/'ALL-962-ROLE-READBACK.json',role_readback)
    prefix=plan['R9_explicit_successor']['prefix_plan']
    prefix_plan=json.loads(full(prefix['path'],prefix['identity'],prefix['seven_stats'],contents=True))
    prefix_root=Path(prefix['path']).parent;prefix_readback={}
    prefix_expected={name:row for name,row in prefix_plan['fixed_controls'].items()}
    for name,identity in prefix_plan['author_files'].items():
        need('author:'+name not in prefix_expected,'prefix authority name collision')
        prefix_expected['author:'+name]={'path':str(prefix_root/name),'identity':identity}
    need(set(prefix_expected)==set(admission['prefix_controls']) and len(prefix_expected)==43,
         'all prefix-admission authority names differ')
    for name,wanted in prefix_expected.items():
        observed=admission['prefix_controls'][name]
        need(observed['identity']==wanted['identity'],'prefix authority identity differs')
        prefix_readback[name]=full(wanted['path'],wanted['identity'],observed['seven_stats'])
    dump(output/'PREFIX-AUTHORITY-READBACK.json',prefix_readback)
    for label in ('plan','launch'):
        observed=admission[label]
        full(observed['path'],observed['identity'],observed['seven_stats'])
    dump(output/'INPUT-READBACK.json',input_rows)
    roots=[('product',PRODUCT),('outer',OUTER),('fresh_admission',ADMISSION)]
    raw_trees={};raw_inventory={}
    for label,root in roots:
        state=tree_state(root);raw_trees[label]=state
        sealed_label={'product':'r9_actual','outer':'r9_outer','fresh_admission':'fresh_admission'}[label]
        wanted_paths={n[len(sealed_label)+1:] for n in sealed['files'] if n.startswith(sealed_label+'/')}
        need(set(state['files'])==wanted_paths,'complete actual raw pathset differs from sealed original')
        for name,wanted in state['files'].items():
            frozen_row=sealed['files'][sealed_label+'/'+name]
            need(frozen_row['source_path']==str(root/name) and wanted==frozen_row['seven_stats'],
                 'sealed actual raw path/stat differs')
            raw_inventory[label+'/'+name]=full(root/name,
                {**frozen_row['identity'],'mode':frozen_row['mode']},wanted)
    product_rows={n:r for n,r in raw_inventory.items() if n.startswith(('product/','outer/'))}
    need(len(product_rows)==2105 and sum(r['identity']['bytes'] for r in product_rows.values())==1110456844,
         'complete actual product/outer original denominator differs')
    dump(output/'FULL-RAW-INVENTORY.json',raw_inventory);dump(output/'DIRECTORIES-BEFORE.json',raw_trees)
    outer=j(OUTER/'RESULT.json');intent=j(OUTER/'INTENT.json')
    need(outer['status']=='FAIL' and outer['returncode']==1 and outer['timeout'] is False and
         outer['ECHILD'] is True and outer['process_group_absent'] is True and
         outer['direct_restored_interpreter_invocations']==outer['maximum_attempts']==1,'outer terminal differs')
    launch=j(AUTHOR/'PRODUCT-LAUNCH.json','acd6c350f3eec17941292d92da1989390e1b24aa')
    correction=j(ROOT_AUTHOR/'R9-CONTROLS-ROOT-LAUNCHER-R1-FAILURE-RETAINED.json',
                 'c72d69134afefc2d8c43d85c9bb032f7bc45a27c')
    first=read(ROOT_AUTHOR/'launch_r9_controls_r1.py');second=read(ROOT_AUTHOR/'launch_r9_controls_r2.py')
    old_literal=correction['before_literal'].encode();new_literal=correction['after_literal'].encode()
    need(pin(first)==correction['before'] and pin(second)==correction['after'] and
         first.count(old_literal)==second.count(new_literal)==1 and
         first.replace(old_literal,new_literal)==second and second.replace(new_literal,old_literal)==first,
         'actual Root launcher one-literal whole inverse differs')
    first_return=j(ROOT_AUTHOR/'R9-CONTROLS-EXEC.json','df85fd758536fc23f57a906bb227984ebfd51138')
    need(pin(read(ROOT_AUTHOR/'R9-CONTROLS-EXEC.json'))==correction['failure_exec_receipt'] and
         first_return['exit_code']==1 and 'AssertionError' in first_return['output'] and
         correction['prior_product_child_launches']==correction['original_eight_group_attempts_so_far']==0 and
         correction['prior_outer_directory_absent'] is True and correction['prior_product_directory_absent'] is True,
         'original zero-child launcher failure record differs')
    started=j(ROOT_AUTHOR/'R9-CONTROLS-R2-EXEC.json','6decad95ad59fce058d38564864c2c58d83fe184')
    returned=j(ROOT_AUTHOR/'R9-CONTROLS-R2-RETURN.json','483d8855ff9863be324504386826f1418317b295')
    need(started['session_id']==79468 and returned['exit_code']==1 and json.loads(returned['output'])==outer,
         'actual tool execution/terminal does not bind outer')
    need(intent['admission']==pin(read(ADMISSION/'RESULT.json')) and
         intent['argv']==launch['argv'] and intent['cwd']==launch['cwd']==plan['source']['path'] and
         intent['outer_watchdog_seconds']==launch['outer_seconds']==1800 and
         launch['outer_cleanup_seconds']==3 and launch['each_product_owner_seconds']==180 and
         launch['each_cleanup_seconds']==3 and launch['no_stage_retries'] is True and
         launch['outer_root']==str(OUTER) and launch['output']==str(PRODUCT) and
         launch['plan']==admission['plan'] and intent['launch_seven_stats']==admission['launch']['seven_stats'] and
         launch['argv'][-2:]==['--plan-sha256',authorization],
         'Root actual R9 launch/admission/request binding differs')
    need(intent['launch']==pin(read(AUTHOR/'PRODUCT-LAUNCH.json')) and intent['original_owner_seconds']==180
         and intent['cleanup_seconds']==3 and intent['maximum_attempts']==1,'actual launch differs')
    for label in ('stdout','stderr'): need(pin(read(OUTER/(label+'.bin')))==outer[label],'outer stream pin differs')
    frozen=j(AUTHOR/'FROZEN-3180-SOURCE.json');need(frozen==source_files,'frozen/current source differ')
    parent_before=j(PRODUCT/'PARENT-FULL-SOURCE-BEFORE.json')
    need(parent_before==j(PRODUCT/'PARENT-FULL-SOURCE-AFTER.json'),'parent source captures differ')
    snapshots=[parent_before];reports={};frames={}
    for index,(phase,summary) in enumerate(zip(plan['phases'][:4],top['rows'],strict=True)):
        folder=PRODUCT/phase['out'];owner=j(folder/'OWNER-RETURNED.json');rc=0 if index<3 else 1
        need(owner==summary['owner'] and owner['returncode']==owner['supervisor_returncode']==rc and
             owner['status']==('OWNED_PROCESS_COMPLETED' if rc==0 else 'QUALIFICATION_FAILED'),'owner terminal differs')
        need(owner['qualification_seconds']==180 and owner['cleanup_seconds']==3 and owner['timed_out'] is False and
             owner['exit_observed_before_deadline'] is True and owner['cleanup']['complete'] is True and
             owner['cleanup']['observed_echild'] is True and owner['cleanup']['remaining_direct_children']==[] and
             owner['event_overflow'] is False,'owner budget or complete cleanup differs')
        need(pin(read(folder/'OWNER.json.request.json'))['sha256']==owner['request_sha256'] and
             pin(read(folder/'OWNER.json'))['sha256']==owner['receipt_sha256'],'actual owner request/receipt differs')
        so=j(folder/'OUTER.json');need(so['owner']==so['terminal']==owner and so['status']==('PASS' if rc==0 else 'FAIL'),
                                   'stage outer differs')
        wrapper=j(folder/'WRAPPER-RESULT.json')
        need(wrapper['original_returncode']==rc and wrapper['errors']==[] and wrapper['original_child_restored'] is True
             and wrapper['ordinary_SOURCE_rebound'] is False and wrapper['public_R5_pin_changed'] is False,
             'actual wrapper/custody differs')
        before=j(folder/'FULL-SOURCE-BEFORE.json');need(before==j(folder/'FULL-SOURCE-AFTER.json'),'stage source capture differs')
        snapshots.append(before)
        binding=j(folder/'BINDINGS-BEFORE.json');need(binding==j(folder/'BINDINGS-AFTER.json'),'stage binding differs')
        names={n for n,r in plan['fixed_inputs'].items() if '*' in r['phases'] or phase['name'] in r['phases']}
        need(set(binding['controls'])==set(plan['controls']) and set(binding['inputs'])==names and
             set(binding['runtime'])=={'executable','library'},'stage binding pathset differs')
        for n,row in binding['controls'].items():
            cur=input_rows[str(AUTHOR/n)]
            need(row['identity']==plan['controls'][n]==cur['identity'] and row['stat']==dict(zip(KEYS,cur['seven_stats'])),
                 'current control bytes/state differ')
        for n,row in binding['inputs'].items():
            wanted=plan['fixed_inputs'][n];cur=input_rows[wanted['path']]
            need(row['fixed_identity']==wanted['identity'] and row['identity']==cur['identity'] and
                 row['stat']==dict(zip(KEYS,cur['seven_stats'])),'current fixed input bytes/state differ')
        for n,row in binding['runtime'].items():
            cur=input_rows[plan['runtime'][n]['path']]
            need(row['identity']==plan['runtime'][n]['identity']==cur['identity'] and
                 row['stat']==dict(zip(KEYS,cur['seven_stats'])),'current runtime bytes/state differ')
        raw=read(folder/'REPORT.json');reports[phase['name']]=json.loads(raw)
        if index<3: need(summary['report_identity']==pin(raw),'parent report identity differs')
        frames[phase['name']]=j(folder/'SIX-BUFFER-READBACK.json');f=frames[phase['name']]
        need(f['stage']==phase['name'] and f['calls']==len(f['rows'])==phase['standalone_native_calls'] and
             f['no_additional_product_execution'] is True,'standalone Native frame count differs')
        if index>0:
            old_inventory=j(folder/'SOURCE-BEFORE.json')
            need(old_inventory==j(folder/'SOURCE-AFTER.json') and old_inventory==
                 {n:{k:r[k] for k in ('bytes','sha256','mode','git_blob')} for n,r in source_files.items()},
                 'original script source inventory differs')
    for snapshot in snapshots:
        need(snapshot['tree']==TREE and snapshot['files']==frozen and len(snapshot['inode_states'])==3180,'source snapshot differs')
        for n,s in snapshot['inode_states'].items():
            need(s==dict(zip(KEYS,input_rows[str(Path(source_group['root'])/n)]['seven_stats'])),'source current stat differs')
    refusal=reports['public-R5-refusal']
    need(refusal['status']=='EXPECTED_PUBLIC_R5_REFUSAL' and refusal['provider_calls']==0 and
         refusal['VM_execution_reached'] is False and refusal['public_profile_pass'] is False,'public refusal differs')
    native_root=PRODUCT/plan['phases'][1]['out'];image=PRODUCT/'semantic/evidence/compact-build-r1/checker.image.bin'
    full(image,plan['fixed_inputs']['R9-image']['identity'])
    report=reports['native162']
    need(report['status']=='PASS' and report['count']==report['actual_native_entries']==162 and report['failures']==[] and
         report['each_native_wall_seconds']==20 and [r['group']+'/'+r['name'] for r in report['rows']]==plan['original_native162_order'],
         'Native162 original ordered rows differ')
    frame_map={r['request']:r for r in frames['native162']['rows']};need(len(frame_map)==162,'duplicate Native requests')
    for row in report['rows']:
        name=row['group']+'/'+row['name'];folder=native_root/name
        initial=(read(folder/'INPUT.hepta'),read(folder.parent/'OUTPUT-PREIMAGE.bin'),read(folder.parent/'WORKSPACE-PREIMAGE.bin'))
        original_inputs=sorted({x['path'] for x in plan['fixed_inputs'].values() if x['path'].endswith('/compact/evidence/'+name+'/INPUT.hepta')})
        need(len(original_inputs)==1 and read(original_inputs[0])==initial[0],'actual Native source differs from original input')
        original_reports=sorted({x['path'] for x in plan['fixed_inputs'].values()
                                 if x['path'].endswith('/compact/evidence/'+row['group']+'/REPORT.json')})
        need(len(original_reports)==1 and pin(read(original_reports[0]))['sha256']==row['prior_report_sha256'],
             'original group report binding differs')
        old_raw=read(plan['original_observation_paths'][name]);old=json.loads(old_raw)
        obs,checks=native_frames(folder/'native',initial,frame_map[str(folder/'native/request.json')],image,old)
        need(row==j(folder/'RESULT.json') and row['checks']==checks and row['pass'] is True and
             row['input_sha256']==pin(initial[0])['sha256'] and row['prior_observation_sha256']==pin(old_raw)['sha256'] and
             row['return']==obs['child']['result_u64'],'Native actual row differs')
    requests=[r['path'] for n,r in raw_inventory.items() if n.startswith('product/') and Path(r['path']).name=='request.json'
              and Path(r['path']).parent.name=='native']
    need(len(requests)==163 and all(j(p)['schema']=='hia.linux-stdio.native-request.v1' for p in requests),
         'complete actual Native request count differs')
    edge=PRODUCT/plan['phases'][2]['out'];edge_initial=tuple(read(plan['fixed_inputs'][n]['path'])
                for n in ('edge-source','edge-output','edge-workspace'))
    old=j(plan['original_observation_paths']['compact-semantic-r1/edge-256-reversed-origin'])
    edge_native,_=native_frames(edge/'native',edge_initial,frames['semantic-edge-vm']['rows'][0],image,old)
    ef=j(edge/'VM-SIX-BUFFER-READBACK.json')
    need(ef['calls_or_logical_rows']==len(ef['rows'])==1 and ef['VM_reruns']==0 and ef['required_complete'] is True,'edge VM count differs')
    edge_buffers=vm_frames(edge,'edge-256-reversed-origin',edge_initial,ef['rows'][0],False)
    edge_vm=j(edge/'VM-REPORT.json');er=reports['semantic-edge-vm']
    need(edge_vm['status']=='returned' and edge_vm['steps']==7746379 and edge_vm['values']==[0] and er['status']=='PASS' and
         er['VM_steps']==edge_vm['steps'] and er['new_native_executions']==1 and er['VM_step_limit']==10000000,'edge VM differs')
    need(all(b==bytes.fromhex(edge_native[n+'_hex']) for n,b in zip(NAMES,edge_buffers,strict=True)),'edge full Native/VM differs')
    need(sum(r['exclusive_steps'] for r in j(edge/'STEP-COUNTS.json'))==edge_vm['steps']==er['exclusive_step_sum'],'edge step accounting differs')
    remaining=PRODUCT/plan['phases'][3]['out'];r=reports['semantic-remaining-vm']
    need(r['status']=='FAIL' and r['count']==6 and r['new_VM_calls']==5 and r['reused_VM_calls']==1 and
         r['failures']==['root-v8-cross-target-loans'] and r['VM_steps_per_case']==10000000 and
         r['VM_buffer_limit']==1048576 and r['new_native_executions']==0,'six VM terminal differs')
    need([[x['group'],x['name']] for x in r['rows']]==plan['original_semantic_six_order'],'six VM original order differs')
    vf=j(remaining/'VM-SIX-BUFFER-READBACK.json')
    need(vf['calls_or_logical_rows']==len(vf['rows'])==6 and vf['VM_reruns']==0 and vf['required_complete'] is False,'VM frame scope differs')
    previous_proof=j(PREVIOUS_READER/'RESULT.json','4b8c87f5f98161f0dc92530a9ee73947ab0633ba')
    previous_inventory=json.loads(read(PREVIOUS_READER/'FULL-RAW-INVENTORY.json',previous_proof['raw_inventory']))
    def previous_raw(path):
        path=Path(path)
        key='product/'+path.relative_to(PREVIOUS).as_posix()
        need(key in previous_inventory,'previous raw member missing from actual Root readback')
        old=previous_inventory[key]
        need(old['path']==str(path),'previous raw path binding differs')
        return full(path,old['identity'],old['seven_stats'],contents=True)
    previous_folder=PREVIOUS/plan['phases'][3]['out']
    previous_report=json.loads(previous_raw(previous_folder/'REPORT.json'))
    need(pin(previous_raw(previous_folder/'REPORT.json'))['git_blob']=='868d44d6e34fce5e02bcf0339c3aeb3039f6a508' and
         previous_report['status']=='FAIL' and previous_report['count']==6 and
         previous_report['failures']==['root-v8-cross-target-loans'] and
         [[x['group'],x['name']] for x in previous_report['rows']]==plan['original_semantic_six_order'],
         'actual R4 six-case report differs')
    previous_frames=json.loads(previous_raw(previous_folder/'VM-SIX-BUFFER-READBACK.json'))
    need(previous_frames['calls_or_logical_rows']==len(previous_frames['rows'])==6 and
         previous_frames['VM_reruns']==0 and previous_frames['required_complete'] is False,
         'actual R4 six-frame report differs')
    predecessor_comparison=[];vm_rows=[]
    for index,(row,frame) in enumerate(zip(r['rows'],vf['rows'],strict=True)):
        name=row['name'];folder=remaining/name;prior=native_root/row['group']/name
        initial=(read(prior/'INPUT.hepta'),read(prior.parent/'OUTPUT-PREIMAGE.bin'),read(prior.parent/'WORKSPACE-PREIMAGE.bin'))
        actual=j(prior/'native/OBSERVATION.json');reused=name=='edge-256-reversed-origin'
        previous_frame=previous_frames['rows'][index];previous_row=previous_report['rows'][index]
        need(previous_frame['name']==previous_row['name']==name and previous_frame['complete_six_buffers'] is True and
             previous_frame['exact_current_R8_edge_reused'] is reused,'R4/R9 case identity differs')
        before_pins=[]
        for label,value in zip(NAMES,initial,strict=True):
            old_before=previous_frame['frames'][label+'.before']
            old_bytes=previous_raw(old_before['path'])
            need(old_before=={'path':old_before['path'],**pin(old_bytes)} and old_bytes==value,
                 'R4/R9 complete actual VM initial buffer differs')
            before_pins.append({'name':label,**pin(value)})
        old_vm=json.loads(previous_raw(previous_folder/name/'VM-REPORT.json'))
        old_result=json.loads(previous_raw(previous_folder/name/'RESULT.json'))
        need(old_result==previous_row and old_vm['steps']==previous_row['VM_steps']==PREVIOUS_VM_STEPS[index],
             'R4 actual VM steps/result differ')
        predecessor_comparison.append({'name':name,'same_complete_initial_buffers':True,'initial_buffers':before_pins,
            'R4_steps':old_vm['steps'],'R9_steps':VM_STEPS[index],'difference_R9_minus_R4':VM_STEPS[index]-old_vm['steps'],
            'R4_status':old_vm['status'],'R4_phase':previous_row['phase_word'],'R4_error':previous_row['semantic_error_word'],
            'R9_phase':row['phase_word'],'R9_error':row['semantic_error_word'],
            'not_a_general_fuel_monotonicity_or_performance_claim':True})
        buffers=vm_frames(folder,name,initial,frame,reused);vm=j(folder/'VM-REPORT.json')
        need(row==j(folder/'RESULT.json') and row['VM_steps']==vm['steps']==VM_STEPS[index] and
             row['values']==vm['values'] and row['reused_exact_VM'] is reused,'actual per-VM row differs')
        checks={'VM_returned':vm['status']=='returned','same_return':vm['values']==[actual['child']['result_u64']],
                'same_complete_source':buffers[0].hex()==actual['source_hex']==initial[0].hex(),
                'same_complete_output':buffers[1].hex()==actual['output_hex']==initial[1].hex(),
                'same_complete_workspace':buffers[2].hex()==actual['workspace_hex'],
                'spare_tail_unchanged':buffers[2][1047040:]==initial[2][1047040:],'original_fuel':vm['steps']<=10000000}
        need(row['checks']==checks and row['pass']==all(checks.values()) and
             row['phase_word']==int.from_bytes(buffers[2][48:56],'little') and
             row['semantic_error_word']==int.from_bytes(buffers[2][40:48],'little'),'actual VM full-frame checks differ')
        if reused:
            reuse=j(folder/'REUSED-VM-RECEIPT.json')
            need(reuse['path']==str(edge) and reuse['raw_VM_report_sha256']==pin(read(edge/'VM-REPORT.json'))['sha256'] and
                 reuse['outer_sha256']==pin(read(edge/'OUTER.json'))['sha256'] and read(folder/'VM-REPORT.json')==read(edge/'VM-REPORT.json') and
                 buffers==edge_buffers and not (folder/'RAW-VM-STATE.json').exists(),'current edge reuse binding differs')
        else:
            state=j(folder/'RAW-VM-STATE.json');need(state['status']==vm['status'] and state['steps']==vm['steps'] and
                  state['values']==vm['values'],'actual VM state differs')
            if name=='root-v8-cross-target-loans':
                exception=read(folder/'EXCEPTION.txt').decode()
                need(vm['status']=='budget_exceeded' and vm['error']['code']=='steps' and state['error']['type']=='HIAProgramBudgetExceeded'
                     and 'E_HIA_BUDGET_STEPS: finite step limit reached' in exception and row['phase_word']==1 and row['semantic_error_word']==0,
                     'actual original fuel failure differs')
            else:
                need(vm['status']=='returned' and state['error'] is None and not (folder/'EXCEPTION.txt').exists(),'unexpected VM failure')
        vm_rows.append({'name':name,'steps':vm['steps'],'status':vm['status'],'current_edge_reused':reused,'checks':checks})
    need(sum(row['pass'] for row in r['rows'])==5,'actual six-VM pass denominator differs')
    dump(output/'R4-R9-ACTUAL-VM-INPUT-COMPARISON.json',predecessor_comparison)

    for path,row in READS.items(): need(seven(Path(path).lstat())==row['seven_stats'],'final current stat differs: '+path)
    for group in mapping['groups']: need(tree_state(group['root'])==input_trees[group['name']],'input pathset changed while reading')
    for label,root in roots: need(tree_state(root)==raw_trees[label],'actual raw tree changed while reading')
    return {'schema':'hepta.r8.r9.independent-terminal-readback.v1','status':'PASS_READBACK_OF_ACTUAL_R9_VM_FUEL_FAILURE',
        'qualification':'FAIL','groups_started':4,'groups_passed':3,'failed_group':'semantic-remaining-vm','not_started':list(SKIPPED),
        'Native162_passed':162,'edge_native_passed':1,'actual_new_Native_calls':163,'Native_six_logical_frames':978,
        'Native_physical_canary_spans':489,'actual_VM_calls':6,'semantic_logical_cases':6,'VM_PASS':5,'VM_FAIL':1,
        'reused_current_edge_rows':1,'VM_six_buffer_records':7,'VM_frame_references':42,'VM_limit':10000000,
        'failure':'root-v8-cross-target-loans','failure_steps':10000001,'VM_rows':vm_rows,
        'aggregate_groups_started':0,'compile_calls':0,'pack_calls':0,'public_R5_refusal_provider_calls':0,'wrapper_errors':[],
        'source_tree':TREE,'source_files':3180,'full_source_snapshots_verified':10,
        'post_run_original_domain_files':original_input_count,'post_run_original_domain_bytes':original_input_bytes,
        'post_run_input_full_fresh_files':len(input_rows),
        'post_run_input_full_fresh_bytes':sum(x['identity']['bytes'] for x in input_rows.values()),
        'all_fixed_role_references':len(role_readback),'fixed_role_reference_bytes':frozen_roles['reference_bytes'],
        'fresh_prefix_authorities':len(prefix_readback),'R4_R9_actual_VM_comparison':predecessor_comparison,
        'input_source_runtime_author_and_R3_failure_unchanged':True,'actual_product_outer_files':len(product_rows),
        'actual_product_outer_bytes':1110456844,'raw_with_admission_files':len(raw_inventory),
        'raw_with_admission_bytes':sum(x['identity']['bytes'] for x in raw_inventory.values()),
        'raw_inventory':pin(read(output/'FULL-RAW-INVENTORY.json')),'input_readback':pin(read(output/'INPUT-READBACK.json')),
        'owner_count':4,'owner_seconds':180,'cleanup_seconds':3,'all_owner_ECHILD':True,'outer_ECHILD':True,
        'original_failure_preserved':True,'additional_product_execution':False,'ordinary_admission':False,
        'new_current_cold':False,'public_profile_qualification':False,'whole_native':False,'automatic_retry':False}

def main(output):
    global LEDGER
    output.mkdir(mode=0o700,exist_ok=False);start=time.monotonic_ns()
    dump(output/'INTENT.json',{'schema':'hepta.r8.r9.terminal-reader.intent.v1','root':str(PRODUCT),'outer':str(OUTER),
         'product_executions':0,'project_imports':0,'CI':0,'expected_qualification':'FAIL','no_retry':True,
         'all_actual_raw_preserved':True,'full_fresh_prior_inputs':6777})
    with (output/'READ-LEDGER.jsonl').open('x',encoding='utf-8') as ledger:
        LEDGER=ledger
        try:
            result=verify(output);result['elapsed_ns']=time.monotonic_ns()-start
            dump(output/'RESULT.json',result)
            print(json.dumps({'status':result['status'],'qualification':'FAIL','result':pin((output/'RESULT.json').read_bytes())},sort_keys=True))
            return 0
        except BaseException:
            dump(output/'READER-FAILURE.json',{'status':'FAIL_READER','qualification':'ORIGINAL_R9_FAIL_UNCHANGED',
                 'traceback':traceback.format_exc(),'full_unique_reads_so_far':len(READS),'products':0,'partial_preserved':True})
            raise
        finally: LEDGER=None

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('/tmp/hia-r9-controls-terminal-readback-r1-dda7'))
    a=p.parse_args();need(a.out.is_absolute() and not a.out.exists(),'new absolute reader output required')
    raise SystemExit(main(a.out))
