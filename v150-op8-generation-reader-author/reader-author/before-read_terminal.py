"""Independent full-byte generation terminal reader. No project imports."""
from __future__ import annotations
import argparse,ast,hashlib,json,os,stat,time
from pathlib import Path

SCOPE=Path('/workspace/hia-patch-terminal-quarantine-execution-r1-dda7')
AUTHOR=Path('/workspace/hia-patch-terminal-quarantine-generation-author-r1-dda7')
OUTER=Path('/workspace/hia-patch-terminal-quarantine-generation-outer-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
GENERATED=('examples/hia_bootstrap/patch_result.hepta','hepta/hia_patch_result_ports.py','hepta/hia_patch_result_data.py')
READS=0;BYTES=0;SEEN={}

def require(v,m):
    if not v:raise AssertionError(m)

def seven(s):return {k:getattr(s,k)for k in FIELDS}

def pin(b,mode=None):
    r={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if mode is not None:r['mode']=mode
    return r

def pairs(rows):
    d={}
    for k,v in rows:
        require(type(k)is str and k not in d,'duplicate JSON key');d[k]=v
    return d

def decode(b):return json.loads(b,object_pairs_hook=pairs)

def read(path,expected=None,expected_stat=None):
    global READS,BYTES
    p=Path(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);before=seven(s)
        require(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and before==seven(p.lstat()),'unique regular held/named input required')
        parts=[];left=s.st_size+1
        while left:
            b=os.read(fd,min(1048576,left))
            if not b:break
            parts.append(b);left-=len(b)
        b=b''.join(parts);require(len(b)==s.st_size and before==seven(os.fstat(fd))==seven(p.lstat()),'input changed around fresh full read')
    finally:os.close(fd)
    mode='100755'if s.st_mode&0o111 else'100644';actual=pin(b,mode)
    if expected is not None:require({k:actual[k]for k in expected}==expected,'complete content/mode pin differs: '+str(p))
    if expected_stat is not None:require(before==expected_stat,'seven-stat authority differs: '+str(p))
    if str(p)in SEEN:require(SEEN[str(p)]['stat']==before,'repeated fresh input identity changed')
    SEEN[str(p)]={'path':str(p),'pin':actual,'stat':before};READS+=1;BYTES+=len(b)
    return b

def fixed(r):return read(r['path'],r['pin'],r['stat'])

def metadata(root):
    root=Path(root);out={'.':seven(root.lstat())};require(stat.S_ISDIR(out['.']['st_mode']),'ordinary root required')
    def walk(p,prefix):
        for e in sorted(os.scandir(p),key=lambda x:x.name):
            s=e.stat(follow_symlinks=False);name=prefix+e.name
            require(stat.S_ISDIR(s.st_mode)or(stat.S_ISREG(s.st_mode)and s.st_nlink==1),'unknown/multilink member')
            out[name]=seven(s)
            if stat.S_ISDIR(s.st_mode):walk(e.path,name+'/')
    walk(root,'');return out

def tree(flat):
    root={}
    for name,r in flat.items():
        n=root;p=name.split('/')
        for part in p[:-1]:n=n.setdefault(part,{})
        n[p[-1]]=(r['mode'],r['git_blob'])
    def digest(n):
        chunks=[]
        for name,v in sorted(n.items(),key=lambda x:(x[0]+('/'if isinstance(x[1],dict)else'')).encode()):
            mode,key=('40000',digest(v))if isinstance(v,dict)else v
            chunks.append(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(key))
        b=b''.join(chunks);return hashlib.sha1(b'tree '+str(len(b)).encode()+b'\0'+b).hexdigest()
    return digest(root)

def complete_source(root,flat,state,count,tree_key=None):
    require(len(flat)==count and metadata(root)==state,'complete source identity differs before read')
    require({n for n,s in state.items()if stat.S_ISREG(s['st_mode'])}==set(flat),'complete source file set differs')
    inodes=set()
    for n,r in flat.items():
        read(Path(root)/n,r,state[n]);key=(state[n]['st_dev'],state[n]['st_ino'])
        require(key not in inodes,'source inode alias');inodes.add(key)
    require(metadata(root)==state,'complete source identity differs after read')
    if tree_key is not None:require(tree(flat)==tree_key,'Git source tree differs')
    return inodes

def directories(rows):
    for r in rows:
        s=Path(r['path']).lstat();require(stat.S_ISDIR(s.st_mode),'directory path changed type')
        require({'path':r['path'],'dev':s.st_dev,'ino':s.st_ino,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid}==r,'ancestor authority changed')

def inputs(plan):
    for r in plan['controls'].values():fixed(r)
    for r in plan['provenance'].values():fixed(r)
    for r in plan['expected_runtime'].values():fixed(r)
    fixed(plan['compiler']);fixed(plan['foundation']);fixed(plan['projected_source_map'])
    directories(plan['parent_ancestors']);directories(plan['author_ancestors'])
    base=plan['base_source'];flat=decode(fixed(base['map']));state=decode(fixed(base['state']))
    base_inodes=complete_source(base['root'],flat,state,3210,base['tree'])
    protected=plan['protected_source'];original=decode(fixed(protected['map']));state=decode(fixed(protected['state']))
    other={n:{'bytes':r['identity']['bytes'],'mode':r['identity']['git_mode'],'sha256':r['identity']['sha256'],
        'git_blob':r['identity']['git_blob']}for n,r in original.items()}
    complete_source(protected['root'],other,state,3180)
    value=decode(fixed(plan['runtime_map']));root=Path(value['root']);before=metadata(root)
    require(len(value['files'])==2496 and {n for n,s in before.items()if stat.S_ISREG(s['st_mode'])}=={r['path']for r in value['files']}
        and {n for n,s in before.items()if stat.S_ISDIR(s['st_mode'])}=={'.',*value['new_directories']},'full runtime set differs')
    for r in value['files']:
        s=dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),r['new_file_seven_stat']))
        require(stat.S_IMODE(s['st_mode'])==r['mode'],'runtime POSIX mode differs')
        read(root/r['path'],{**r['pin'],'mode':'100755'if r['mode']&0o111 else'100644'},s)
    require(metadata(root)==before,'runtime changed after full read')
    return base_inodes

def publish(path,value):
    b=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
    with os.fdopen(fd,'wb')as f:f.write(b)
    require(Path(path).read_bytes()==b,'reader evidence write failed')

def stages(plan,bound,result):
    attempt=Path(plan['attempt']);env=decode(read(attempt/'ENVIRONMENT.json'))
    expected_env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(attempt),'TMPDIR':str(attempt/'tmp'),
        'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0',
        'LD_LIBRARY_PATH':bound['runtime']['library_directory']}
    require(env==expected_env and decode(read(attempt/'RUNTIME.json'))==bound['runtime'],'actual runtime/environment differs')
    labels=['generate-1','generate-2','check'];require([s['label']for s in result['stages']]==labels,'three original stage order differs')
    source_map=decode(fixed(bound['source_map']));output_sets=[]
    for i,label in enumerate(labels):
        directory=attempt/('%02d-'%(i+1)+label)
        stage=decode(read(directory/'STAGE.json'));child=decode(read(directory/'RESULT.json'))
        request_raw=read(directory/'REQUEST.json');request=decode(request_raw);command=decode(read(directory/'COMMAND.json'))
        require(stage==result['stages'][i] and stage['status']==child['status']=='PASS','actual stage/child differs')
        require(not any('error'in k for k in stage) and not child['terminal_guard_errors'],'stage guard failed')
        require(request['limits']==plan['limits'] and request['stage']==label and decode(fixed(request['plan']))==bound,'actual request binding differs')
        outputs=child['outputs'];require(outputs==stage['outputs'],'parent/child output descriptors differ')
        target=attempt/'02-generate-2'/'outputs'if label=='check'else directory/'outputs'
        paths={'assembly':str(target/'patch_result.hepta'),'ports':str(target/'hia_patch_result_ports.py'),
            'identity':str(target/'hia_patch_result_data.py')}
        argv=[str(Path(bound['source'])/plan['generator_relative']),'--output',paths['assembly'],
            '--ports',paths['ports'],'--identity',paths['identity']]+(['--check']if label=='check'else[])
        require(request['outputs']==paths and request['generator_argv']==child['generator_argv']==argv,'original generator argv changed')
        expected_command=[bound['runtime']['launch_executable'],'-I','-B',plan['controls']['run_generation_child.py']['path'],
            '--request',str(directory/'REQUEST.json'),'--request-sha256',hashlib.sha256(request_raw).hexdigest()]
        require(command['command']==expected_command and command['cwd']==bound['source']
            and command['environment']==command['supervisor_environment']==env
            and command['qualification_seconds']==180 and command['cleanup_seconds']==3,'exact command/limits differ')
        owner_raw=read(directory/'OWNER.json');owner=decode(owner_raw);returned=decode(read(directory/'OWNER-RETURNED.json'))
        require(returned==stage['owner_returned'] and set(returned)==set(owner)|{'receipt_sha256','supervisor_returncode'}
            and {k:returned[k]for k in owner}==owner and returned['receipt_sha256']==hashlib.sha256(owner_raw).hexdigest()
            and returned['supervisor_returncode']==0,'raw/returned owner relation differs')
        owner_request_raw=read(directory/'OWNER.json.request.json');owner_request=decode(owner_request_raw)
        require(owner_request['command']==expected_command and owner_request['cwd']==bound['source']and owner_request['env']==env
            and owner_request['qualification_seconds']==owner['qualification_seconds']==180
            and owner_request['cleanup_seconds']==owner['cleanup_seconds']==3
            and owner_request['deadline_ns']-owner_request['started_ns']==180000000000
            and owner_request['implementation_sha256']==owner['implementation_sha256']==source_map['tools/hia_selfhost_process_owner.py']['sha256']
            and owner['request_sha256']==hashlib.sha256(owner_request_raw).hexdigest(),'original owner source/request/deadline differs')
        c=owner['cleanup'];require(owner['status']=='OWNED_PROCESS_COMPLETED'and owner['returncode']==0
            and owner['timed_out']is False and owner['exit_observed_before_deadline']is True
            and not owner.get('owner_error')and not owner.get('event_overflow')and c['complete']is True
            and c['observed_echild']is True and c['leader_reaped']is True and not c.get('errors')
            and not c.get('remaining')and not c.get('remaining_pids')and c['remaining_direct_children']==[]
            and not c.get('deadline_exceeded'),'actual owner failed or cleanup incomplete')
        require(child['request_pin']==pin(request_raw,'100644') and child['generator_returned']is True
            and child['generator_invocation_started']is True and child['actual_generator_calls']==1
            and child['source_before']==child['source_after'] and child['tests_run']==child['native_calls']==child['vm_calls']==child['compilations']==0,
            'actual child result scope/guards differ')
        full={k:fixed(v)for k,v in outputs.items()};output_sets.append(full)
        require(all(outputs[k]['path']==paths[k]for k in paths),'actual output location differs')
        require(metadata(target)==child['output_metadata_after'],'actual generated output stats differ')
        printed=ast.literal_eval(read(directory/'stdout.raw').decode())
        require(read(directory/'stderr.raw')==b'' and printed['source_sha256']==hashlib.sha256(full['assembly']).hexdigest()
            and printed['ports_sha256']==hashlib.sha256(full['ports']).hexdigest()
            and printed['compatibility_sha256']==hashlib.sha256(full['identity']).hexdigest(),'original stdout identity differs')
        if label=='check':require(request['check_outputs']==outputs==result['stages'][1]['outputs'],'check modified second triple')
        else:require(request['check_outputs']is None,'generation unexpectedly used check inputs')
    require(output_sets[0]==output_sets[1]==output_sets[2],'actual triples differ byte-for-byte')
    return output_sets[1]

def verify(output):
    started=time.monotonic_ns()
    require(output==Path('/workspace/hia-patch-terminal-quarantine-generation-terminal-actual-r1-dda7')
            and not os.path.lexists(output),'fixed new independent reader output required')
    output.mkdir(mode=0o700)
    result={'status':'FAIL','product_execution':0,'project_imports':0,'whole':False,'started_ns':started}
    try:
        plan=decode(read(AUTHOR/'GENERATION-PLAN-R2.json',{'bytes':30794,'git_blob':'35114c9be6fdebe0392e28e26762284017022e4c',
            'sha256':'ec6a9c62c9e94139826b81af17c5a010c8ad39213f82b7529a47c32a62eb8450'}))
        launch=decode(read(AUTHOR/'GENERATION-LAUNCH-R2.json'))
        actual_raw=read(SCOPE/'generation-attempt-r1/RESULT.json',{'bytes':32379,'git_blob':'ba0bb71338e1cbb91d8cbf280898dd518ada8f6a',
            'sha256':'7dda441a400a9da7fd4c586452e15571f7494955a182f3490b5eb7140c7e4c43'})
        actual=decode(actual_raw);bound=decode(read(SCOPE/'BOUND-GENERATION-PLAN.json'))
        require(actual['status']=='PASS_GENERATION_ONLY_TWO_RUNS_AND_ORIGINAL_CHECK'
            and actual['copy_rows']==3211 and actual['actual_owner_launch_attempts']==3
            and actual['tests_run']==actual['compilations']==actual['native_calls']==actual['vm_calls']==0
            and actual['immutable_before']==actual['immutable_after'],'actual generation terminal differs')
        require('source_copy_performed'not in bound and 'project_imports'not in bound,'author-only markers leaked into actual bound plan')
        require(bound['runtime']==plan['previous_runtime_context'],'actual runtime context changed')
        scope_before=metadata(SCOPE);outer_before=metadata(OUTER)
        base_inodes=inputs(plan);directories(bound['scope_ancestors'])
        material=decode(fixed(actual['materialization']))
        require(material['source_copy']is True and material['hardlinks']==0 and material['source_files']==3211
            and material['products_executed']==0 and decode(fixed(material['plan']))==bound,'actual materialization result differs')
        origins=decode(fixed(plan['origin_rows']));copies=decode(fixed(material['copies']))
        copy_lines=[decode(line)for line in read(SCOPE/'COPY-ROWS.jsonl').splitlines()]
        pre=decode(fixed(bound['source_map']));prestate=decode(fixed(bound['source_state']))
        require(copies==copy_lines and len(copies)==len(origins)==3211
            and [r['relative']for r in copies]==[r['relative']for r in origins]==sorted(pre),'complete actual copy journal differs')
        born=set()
        for origin,row in zip(origins,copies):
            n=row['relative'];require(row['origin']==origin['descriptor'],'source origin changed')
            fixed(row['origin']);created=row['created']
            require(created['pin']==pre[n] and created['stat']==prestate[n]
                and created['path']==str(Path(bound['source'])/n),'copied before-generation identity differs')
            inode=(created['stat']['st_dev'],created['stat']['st_ino'])
            require(inode not in base_inodes|born,'source copy aliases original or another path');born.add(inode)
        final=actual['final_source'];final_map=decode(fixed(final['map']));final_state=decode(fixed(final['state']))
        require(final['tree']=='aa2608ca25c3a9736a62d549c3130b98893542ff'
            and final['changed_bytes']==['hepta/hia_patch_result_data.py'],'final actual delta differs')
        complete_source(final['source'],final_map,final_state,3211,final['tree'])
        parent_dirs={str(Path(n).parent)for n in GENERATED}
        for n,s in prestate.items():
            if n in GENERATED:continue
            if n in parent_dirs:require(all(s[k]==final_state[n][k]for k in ('st_dev','st_ino','st_mode','st_nlink')),'output parent authority changed')
            else:require(s==final_state[n],'unrelated source seven stats changed')
        full=stages(plan,bound,actual)
        for n,k in zip(GENERATED,('assembly','ports','identity')):
            require(read(Path(final['source'])/n,final_map[n],final_state[n])==full[k],'installed complete output differs')
        intent=decode(read(Path(plan['attempt'])/'INSTALL-INTENT.json'))
        journal=[decode(line)for line in read(Path(plan['attempt'])/'INSTALL-JOURNAL.jsonl').splitlines()]
        require([r['relative']for r in intent['rows']]==[r['relative']for r in journal]==list(GENERATED),'three install rows differ')
        for before,after in zip(intent['rows'],journal):
            n=after['relative'];require(before['previous']==after['previous'] and before['output']==after['generated'], 'install provenance differs')
            require(before['previous']['stat']==prestate[n] and before['previous']['pin']==pre[n],'original private output differs')
            fixed(after['installed']);require(after['installed']['stat']==final_state[n],'installed current stat differs')
            require((before['staged']['stat']['st_dev'],before['staged']['stat']['st_ino'])not in born
                and all(before['staged']['stat'][k]==after['installed']['stat'][k]for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_nlink')),
                'staged new inode was not actually installed')
        data={n.targets[0].id:ast.literal_eval(n.value)for n in ast.parse(full['identity']).body if isinstance(n,ast.Assign)}
        hosts={n:hashlib.sha256(read(Path(final['source'])/'hepta'/n)).hexdigest()for n in plan['host_source_files']}
        require(data['SOURCE_BYTES']==len(full['assembly']) and data['SOURCE_SHA256']==hashlib.sha256(full['assembly']).hexdigest()
            and list(data['HOST_SOURCE_SHA256'])==plan['host_source_files']and data['HOST_SOURCE_SHA256']==hosts,'generated13 host binding differs')
        outer=decode(read(OUTER/'RESULT.json'));outer_intent=decode(read(OUTER/'INTENT.json'))
        require(outer_intent['argv']==launch['exact_clean_env_argv']and outer_intent['cwd']==launch['cwd']
            and outer_intent['outer_watchdog_seconds']==1800 and outer_intent['cleanup_seconds']==3
            and outer['returncode']==0 and outer['timeout']is False and outer['ECHILD']is True
            and outer['process_group_absent']is True and outer['adopted']==[],'outer actual terminal differs')
        read(OUTER/'stdout.bin',outer['stdout']);read(OUTER/'stderr.bin',outer['stderr'])
        raw_inventory=[]
        for root,state in ((SCOPE,scope_before),(OUTER,outer_before)):
            for name,s in state.items():
                if stat.S_ISREG(s['st_mode'])and not(root==SCOPE and name.startswith('source/')):
                    p=root/name;read(p,expected_stat=s);raw_inventory.append(SEEN[str(p)])
        require(metadata(SCOPE)==scope_before and metadata(OUTER)==outer_before,'actual evidence pathset/stats changed')
        inputs(plan);complete_source(final['source'],final_map,final_state,3211,final['tree'])
        for p,row in SEEN.items():require(seven(Path(p).lstat())==row['stat'],'terminal input identity changed')
        publish(output/'RAW-INVENTORY.json',raw_inventory);publish(output/'READ-INPUTS.json',list(SEEN.values()))
        result.update(status='PASS_COMPLETE_GENERATION_TERMINAL_READBACK',source_files=3211,source_tree=final['tree'],
            actual_owners=3,raw_files=len(raw_inventory),raw_bytes=sum(r['pin']['bytes']for r in raw_inventory),
            generated_triples_full_bytes_equal=True,original_check_output_stats_equal=True,actual_new_installations=3,
            only_generated_data_bytes_changed=True,all13hosts_current=True,protected_R3=3210,protected_R8=3180,
            runtime_files=2496,all_current_pathsets_and_seven_stats_equal=True,compile_execution=0,
            Native_execution=0,VM_execution=0,tests=0,original_Native11_still_failed=True)
    except BaseException:
        import traceback
        result['error']=traceback.format_exc()
    finally:
        result.update(finished_ns=time.monotonic_ns(),fresh_reads=READS,read_bytes=BYTES,unique_paths=len(SEEN))
        publish(output/'RESULT.json',result)
    return 0 if result['status']=='PASS_COMPLETE_GENERATION_TERMINAL_READBACK'else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args()
    raise SystemExit(verify(Path(a.output)))

