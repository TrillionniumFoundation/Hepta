"""Independent stdlib-only preparation readback; never imports project code or starts a process."""
from __future__ import annotations
import argparse,ast,hashlib,json,os,stat,time
from pathlib import Path

AUTHOR=Path('/workspace/hia-patch-terminal-quarantine-preparation-reader-r1-dda7')
SCOPE=Path('/workspace/hia-patch-terminal-quarantine-qualification-r2-dda7')
OUTER=Path('/workspace/hia-patch-terminal-quarantine-preparation-outer-r2-dda7')
OUTPUT=Path('/workspace/hia-patch-terminal-quarantine-preparation-readback-actual-r1-dda7')
TREE='b4f7d4862d6b391781808d603547ce3a504ffc83'
EXTERNAL_RELATIVE='tests/test_hia_patch_result_quarantine_native.py'
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
LIMITS={'cleanup_seconds':3,'compile_seconds':20,'native_capacity':1048576,
    'owner_seconds':180,'vm_call_depth':128,'vm_heap':8388608,'vm_steps':10000000}
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

def publish(path,value):
    b=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
    with os.fdopen(fd,'wb')as f:f.write(b)
    require(Path(path).read_bytes()==b,'reader evidence write failed')

def source_authority(value, count):
    flat=decode(fixed(value['map']));state=decode(fixed(value['state']))
    require(value['files']==count,'original source count changed')
    inodes=complete_source(value['root'],flat,state,count,value['tree'])
    summary={'files':count,'all_bytes_read':True,'map':value['map']['pin'],
        'state':value['state']['pin'],'tree':value['tree']}
    return flat,state,inodes,summary

def runtime_authority(plan):
    value=decode(fixed(plan['runtime_map']));root=Path(value['root']);before=metadata(root)
    rows=value['files'];names=[row['path']for row in rows]
    require(len(rows)==len(set(names))==2496
        and {n for n,s in before.items()if stat.S_ISREG(s['st_mode'])}==set(names)
        and {n for n,s in before.items()if stat.S_ISDIR(s['st_mode'])}=={'.',*value['new_directories']},
        'complete runtime file/directory sets differ')
    inodes=set()
    for row in rows:
        s=dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),row['new_file_seven_stat']))
        require(stat.S_IMODE(s['st_mode'])==row['mode'],'full runtime POSIX mode differs')
        read(root/row['path'],{**row['pin'],'mode':'100755'if row['mode']&0o111 else'100644'},s)
        inode=(s['st_dev'],s['st_ino']);require(inode not in inodes,'runtime alias');inodes.add(inode)
    require(metadata(root)==before,'runtime complete pathset/seven stats changed')
    for role,row in plan['expected_runtime'].items():
        fixed(row);context=plan['runtime'][role];s=row['stat'];p=row['pin']
        require(context=={'path':row['path'],'bytes':p['bytes'],'sha256':p['sha256'],
            'mode':stat.S_IMODE(s['st_mode']),'device':s['st_dev'],'inode':s['st_ino'],
            'mtime_ns':s['st_mtime_ns'],'ctime_ns':s['st_ctime_ns']},'actual runtime context binding differs')
    require(plan['runtime']['version']==[3,14,4]
        and plan['runtime']['launch_executable']==plan['expected_runtime']['executable']['path']
        and plan['runtime']['library_directory']==str(Path(plan['expected_runtime']['library']['path']).parent),
        'fixed actual runtime launch differs')
    return {'files':2496,'all_bytes_read':True,'map':plan['runtime_map']['pin']},before,inodes

def generation_authority(plan):
    value=decode(fixed(plan['generation_evidence']))
    require(value['schema']=='hepta.hia.patch-terminal.generation-evidence.v1'
        and value['product_execution']==0 and len(value['files'])==59,'complete original generation evidence required')
    wanted=[]
    for root in value['roots']:
        current=metadata(root['path'])
        current={n:s for n,s in current.items()if not any(n==e or n.startswith(e+'/')for e in root['exclude'])}
        require(current==root['state'],'generation complete evidence pathset/stat differs')
        wanted.extend(str(Path(root['path'])/n)for n,s in current.items()if stat.S_ISREG(s['st_mode']))
    actual=[row['path']for row in value['files']]
    require(len(actual)==len(set(actual))==59 and set(actual)==set(wanted),'generation raw inventory has omissions or extras')
    for row in value['files']:fixed(row)
    for row in value['directories']:
        require(seven(Path(row['path']).lstat())==row['stat']and stat.S_ISDIR(row['stat']['st_mode']),
            'original generation directory changed')
    for root in value['roots']:
        current=metadata(root['path'])
        current={n:s for n,s in current.items()if not any(n==e or n.startswith(e+'/')for e in root['exclude'])}
        require(current==root['state'],'generation evidence changed during full reads')
    result=decode(fixed(plan['generation_result']));terminal=decode(fixed(plan['generation_terminal']))
    require(result['status']=='PASS_GENERATION_ONLY_TWO_RUNS_AND_ORIGINAL_CHECK'
        and terminal['status']=='PASS_COMPLETE_GENERATION_TERMINAL_READBACK'
        and terminal['source_files']==3211 and terminal['actual_owners']==3
        and terminal['source_tree']==plan['mother_source']['tree'],'actual generation predecessor differs')
    return {'actual_generation_files':59,'every_file_fresh_read':True,
        'actual_root_terminal':plan['generation_terminal']['pin']}

def immutable_authority(plan):
    for row in plan['controls'].values():fixed(row)
    for row in plan['provenance'].values():fixed(row)
    fixed(plan['compiler'])
    require(plan['compiler']['pin']=={'bytes':673413,'git_blob':'315c6b5f36a1ec679deb68abdca24bd4d1bef9f8',
        'sha256':'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0','mode':'100644'},
        'fixed ordinary B3 changed')
    directories(plan['scope_ancestors']);directories(plan['author_ancestors'])
    for name in ('origin_rows','projected_source_map','external_test','patch14_before','patch14_after'):
        fixed(plan[name])
    mother,mother_state,mother_inodes,mother_summary=source_authority(plan['mother_source'],3211)
    prior,prior_state,prior_inodes,prior_summary=source_authority(plan['prior_base'],3210)
    value=plan['protected_source'];original=decode(fixed(value['map']));protected_state=decode(fixed(value['state']))
    protected={n:{'bytes':r['identity']['bytes'],'mode':r['identity']['git_mode'],
        'sha256':r['identity']['sha256'],'git_blob':r['identity']['git_blob']}for n,r in original.items()}
    protected_inodes=complete_source(value['root'],protected,protected_state,3180,
        '4c62be4ed66ff107fa6f88c6131313a354868bd9')
    runtime,runtime_state,runtime_inodes=runtime_authority(plan)
    generation=generation_authority(plan)
    summary={'mother3211':mother_summary,'retained_R3_3210':prior_summary,
        'protected_R8':{'files':3180,'all_bytes_read':True,'map':value['map']['pin']},
        'runtime':runtime,'generation':generation}
    return summary,{'mother':(mother,mother_state),'prior':(prior,prior_state),
        'protected':(protected,protected_state),'runtime_state':runtime_state,
        'inodes':mother_inodes|prior_inodes|protected_inodes|runtime_inodes}

def defined_ids(raw,module,cls):
    top=ast.parse(raw);matches=[n for n in top.body if isinstance(n,ast.ClassDef)and n.name==cls]
    require(len(matches)==1,'exact original test class required')
    return [module+'.'+cls+'.'+n.name for n in matches[0].body
        if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')]

def cohorts(plan,flat,state):
    matrix=decode(fixed(plan['controls']['QUALIFICATION-MATRIX.json']))
    cli=decode(fixed(plan['controls']['CONTROL-MATRIX.json']))
    require(matrix['schema']=='hepta.hia.patch-terminal.qualification-matrix.v1'
        and matrix['cohorts']=={'patch_source':11,'patch_native':12,'cli_source':8,'cli_native':12,'vm':12,'new_native':3}
        and matrix['owner_count']==20 and matrix['method_invocations']==58 and matrix['build_count']==8
        and matrix['limits']==LIMITS and matrix['future_test_results']is None
        and matrix['original_cli_matrix_pin']==plan['controls']['CONTROL-MATRIX.json']['pin'],
        'original separate qualification groups/counts/budgets changed')
    labels=['patch-source11','op13-source8','build-report-six','build-inspect','build-patch','patch-native12']
    labels += [r['group']for r in cli['native_groups']]+['patch-quarantine3','patch-vm12']
    groups=matrix['groups']
    require([r['label']for r in groups]==labels and len(groups)==20 and len(set(labels))==20
        and sum(len(r['ids'])for r in groups)==58,'full ordered group selection differs')
    require(groups[1]['ids']==cli['source_ids']and groups[1]['group']=='source8','original Source8 IDs changed')
    for current,old in zip(groups[6:18],cli['native_groups']):
        require(current['group']==old['group']and current['ids']==[old['id']]
            and current['signature_native']is old['signature_native'],'original CLI Native12 selection changed')
    definitions=(('patch-source11','tests/test_hia_patch_result_source.py','PatchResultSourceTests'),
        ('patch-native12','tests/test_hia_patch_result_native.py','PatchResultNativeTests'),
        ('patch-quarantine3',EXTERNAL_RELATIVE,'PatchTerminalQuarantineNativeTests'),
        ('patch-vm12','tests/test_hia_patch_result_vm.py','PatchResultFrameVMTests'))
    for label,relative,cls in definitions:
        raw=fixed(plan['external_test'])if label=='patch-quarantine3'else read(Path(plan['source'])/relative,flat[relative],state[relative])
        expected=next(r['ids']for r in groups if r['label']==label)
        require(defined_ids(raw,relative[:-3].replace('/','.'),cls)==expected,'exact original Patch/new3 IDs differ')
    for relative,cls,ids in (('tests/test_hia_patch_cli_source.py','PatchCliSourceTests',cli['source_ids']),
            ('tests/test_hia_patch_cli_native.py','PatchCliNativeTests',[r['id']for r in cli['native_groups']])):
        raw=read(Path(plan['source'])/relative,flat[relative],state[relative])
        actual=defined_ids(raw,relative[:-3].replace('/','.'),cls)
        require(len(actual)==len(ids)and set(actual)==set(ids),'original CLI test definitions differ')
    return matrix

def actual_copy(plan,context):
    flat=decode(fixed(plan['source_map']));state=decode(fixed(plan['source_state']))
    expected=decode(fixed(plan['projected_source_map']));origins=decode(fixed(plan['origin_rows']))
    mother,mother_state=context['mother'];prior,prior_state=context['prior']
    require(flat==expected and len(flat)==3210 and len(mother)==3211
        and set(flat)==set(mother)-{EXTERNAL_RELATIVE}
        and all(flat[n]==mother[n]for n in flat),'real product view must be exact mother minus external new3')
    external={'path':str(Path(plan['mother_source']['root'])/EXTERNAL_RELATIVE),
        'pin':mother[EXTERNAL_RELATIVE],'stat':mother_state[EXTERNAL_RELATIVE]}
    require(plan['external_test']==external and not os.path.lexists(Path(plan['source'])/EXTERNAL_RELATIVE),
        'new3 must remain complete external controls, not a filtered source scan')
    fixed(external)
    require({n for n in prior if prior[n]!=flat[n]}=={'hepta/hia_patch_result_native.py','hepta/hia_patch_result_data.py'}
        and set(prior)==set(flat),'only the two approved product members may differ from original R3')
    inodes=complete_source(plan['source'],flat,state,3210,TREE)
    require(inodes.isdisjoint(context['inodes']),'product file aliases retained source/runtime')
    dirs={n for n,s in state.items()if stat.S_ISDIR(s['st_mode'])}
    require(dirs=={n for n,s in mother_state.items()if stat.S_ISDIR(s['st_mode'])},'source directory set differs')
    all_original={(s['st_dev'],s['st_ino'])for _,s in mother_state.items()}
    all_new=set()
    for n,s in state.items():
        key=(s['st_dev'],s['st_ino']);require(key not in all_new and key not in all_original,'copied file/directory inode not independent')
        all_new.add(key)
        if n in dirs:require(stat.S_IMODE(s['st_mode'])==stat.S_IMODE(mother_state[n]['st_mode']),'exact inherited source directory mode differs')
    copies=decode(fixed(plan['copies']))
    journal=[decode(line)for line in read(SCOPE/'COPY-JOURNAL.jsonl').splitlines()]
    require(copies==journal and len(copies)==len(origins)==3210
        and [r['relative']for r in copies]==[r['relative']for r in origins]==sorted(flat),'ordered full copy rows/journal differ')
    for origin,row in zip(origins,copies):
        n=row['relative'];source={'path':str(Path(plan['mother_source']['root'])/n),'pin':mother[n],'stat':mother_state[n]}
        created={'path':str(Path(plan['source'])/n),'pin':flat[n],'stat':state[n]}
        require(origin=={'relative':n,'descriptor':source}and row=={'relative':n,'original':source,'copied':created},
            'exact origin/copy authority differs')
        require(fixed(source)==fixed(created),'complete copied bytes differ from current original')
    before=decode(fixed(plan['patch14_before']));after=decode(fixed(plan['patch14_after']))
    require(len(before)==len(after)==14 and set(before)==set(after)
        and {n for n in before if before[n]!=after[n]}=={'hepta/hia_patch_result_native.py','hepta/hia_patch_result_data.py'}
        and all(before[n]==prior[n]and after[n]==flat[n]for n in after),'versioned Patch14 must bind exact original and current product bytes')
    require(decode(fixed(plan['controls']['PATCH14-SOURCE-MAP.json']))==after
        and decode(fixed(plan['controls']['PROJECTED-SOURCE-MAP.json']))==flat,'actual test authority maps differ')
    return flat,state,cohorts(plan,flat,state)

def outer_readback(authority,preparation_launch):
    values={name:fixed(row)for name,row in authority['outer_files'].items()}
    require(set(values)=={'INTENT.json','RESULT.json','SPAWNED.json','stdout.bin','stderr.bin'},'complete actual outer set differs')
    intent=decode(values['INTENT.json']);result=decode(values['RESULT.json']);spawn=decode(values['SPAWNED.json'])
    require(intent['argv']==preparation_launch['argv']and intent['cwd']==preparation_launch['cwd']
        and intent['outer_watchdog_seconds']==preparation_launch['outer_seconds']==180
        and intent['cleanup_seconds']==preparation_launch['cleanup_seconds']==3
        and intent['maximum_attempts']==1 and intent['copy_files']==3210 and intent['mother_files']==3211
        and intent['qualification_authorized']is False
        and intent['compile_calls']==intent['generator_calls']==intent['native_calls']==intent['vm_calls']==intent['tests']==0,
        'exact preparation-only actual invocation differs')
    require(pin(fixed(authority['preparation_launch']))==intent['launch'],'actual original launch pin differs')
    ls=authority['preparation_launch']['stat']
    require(intent['launch_seven_stats']==[ls[k]for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')],
        'actual launched descriptor seven stats differ')
    require(pin(fixed(authority['root_review']))==intent['review'],'actual Root review differs')
    require(result['status']=='PASS_PATCH_SOURCE_VIEW_PREPARATION_PROCESS_ONLY'
        and result['returncode']==0 and result['timeout']is False and result['ECHILD']is True
        and result['process_group_absent']is True and result['adopted']==[]and result['subreaper']is True
        and result['direct_restored_interpreter_invocations']==result['maximum_attempts']==1
        and result['pid']==spawn['pid']==spawn['pgid']and spawn['started_monotonic_ns']>0,
        'actual outer process/cleanup terminal differs')
    require(pin(values['stdout.bin'])==result['stdout']and pin(values['stderr.bin'])==result['stderr']
        and values['stdout.bin']==values['stderr.bin']==b'','outer complete raw streams differ')
    return result

def verify(output,input_path,input_sha):
    started=time.monotonic_ns()
    require(output==OUTPUT and not os.path.lexists(output),'fixed new independent reader output required')
    require(input_path==AUTHOR/'INPUTS.json','fixed reader input plan required')
    output.mkdir(mode=0o700)
    result={'schema':'hepta.hia.patch-terminal.preparation-readback.v1','status':'FAIL',
        'product_execution':0,'project_imports':0,'source_copy':False,'whole_native':False,'started_ns':started}
    try:
        raw=read(input_path);require(hashlib.sha256(raw).hexdigest()==input_sha,'fixed reader input SHA differs')
        authority=decode(raw);fixed(authority['reader']);fixed(authority['previous_reader'])
        require(authority['schema']=='hepta.hia.patch-terminal.preparation-readback-inputs.v1'
            and authority['scope']==str(SCOPE)and authority['outer']==str(OUTER)
            and authority['output']==str(OUTPUT),'exact static reader authority differs')
        for row in authority['root_metadata'].values():fixed(row)
        actual={name:fixed(row)for name,row in authority['scope_files'].items()}
        require(set(actual)=={'BINDING-RESULT.json','BOUND-PLAN.json','COPY-JOURNAL.jsonl','COPY-ROWS.json',
            'PREPARATION-INTENT.json','PRODUCT-LAUNCH.json','RUNTIME.json','SOURCE-MAP.json','SOURCE-STATE.json'},
            'complete actual preparation raw set differs')
        binding=decode(actual['BINDING-RESULT.json']);bound=decode(actual['BOUND-PLAN.json']);launch=decode(actual['PRODUCT-LAUNCH.json'])
        preparation_raw=fixed(authority['preparation_plan']);preparation=decode(preparation_raw)
        preparation_launch=decode(fixed(authority['preparation_launch']))
        require(preparation['schema']==bound['schema']=='hepta.hia.patch-terminal.qualification.v1'
            and preparation['state']=='AUTHORING_ONLY_AWAITING_ROOT_AUTHORIZATION'
            and bound['state']=='BOUND_AWAITING_ROOT_AUTHORIZATION'
            and bound['scope']==str(SCOPE)and bound['source']==str(SCOPE/'source')
            and bound['attempt']==str(SCOPE/'attempt-r1')and bound['source_files']==3210
            and bound['source_tree']==TREE and bound['limits']==LIMITS and bound['storage_floor']==1<<30,
            'actual fixed qualification source/view/budgets differ')
        require(bound['external_test_relative']==EXTERNAL_RELATIVE
            and bound['external_test_module']=='tests.test_hia_patch_result_quarantine_native','external new3 authority differs')
        require(not os.path.lexists(bound['attempt']),'qualification already attempted; preparation readback cannot proceed')
        floor=os.statvfs(SCOPE);free=floor.f_bavail*floor.f_frsize
        require(free>=1<<30,'original actual-output filesystem 1 GiB floor not satisfied')
        require(seven(SCOPE.lstat())==authority['scope_stat']and stat.S_IMODE(SCOPE.lstat().st_mode)==0o700,
            'actual scope identity changed')
        directories(bound['scope_ancestors']);directories(bound['source_ancestors']);directories(bound['author_ancestors'])
        changed={k for k in set(preparation)|set(bound)if preparation.get(k)!=bound.get(k)}
        require(changed=={'state','preparation_plan','source_map','source_state','copies','source_ancestors','scope_ancestors'},
            'actual whole plan has an undeclared change')
        inverse=dict(bound)
        for k in changed:
            if k in preparation:inverse[k]=preparation[k]
            else:del inverse[k]
        require(inverse==preparation,'whole actual bound-plan inverse differs')
        require(bound['preparation_plan']==authority['preparation_plan']
            and bound['source_map']==authority['scope_files']['SOURCE-MAP.json']
            and bound['source_state']==authority['scope_files']['SOURCE-STATE.json']
            and bound['copies']==authority['scope_files']['COPY-ROWS.json'], 'actual bound descriptors differ')
        require(binding['status']=='BOUND_NOT_EXECUTED'and binding['source_copy']is True
            and binding['copied_files']==3210 and binding['hardlinks_created']==0
            and binding['products_executed']==binding['generator_execution']==binding['project_imports']==0
            and binding['mother3211_preserved']is True and binding['old_Source8_not_claimed_on_mother3211']is True
            and binding['qualification_attempt_absent']is True and binding['free_bytes_before']>=1<<30
            and binding['finished_ns']>binding['started_ns']>0 and binding['source_tree']==TREE,
            'actual materialization result differs')
        require(binding['plan']==authority['scope_files']['BOUND-PLAN.json']
            and binding['preparation_plan']==authority['preparation_plan']
            and all(binding[k]==bound[k]for k in ('source_map','source_state','copies')),'actual binding descriptor differs')
        before,context=immutable_authority(bound)
        require(binding['source_before']==binding['source_after']==before,'actual protected before/after summary differs')
        flat,state,matrix=actual_copy(bound,context)
        require(decode(actual['RUNTIME.json'])==bound['runtime']
            ==decode(fixed(bound['provenance']['generation_bound_plan']))['runtime'],'actual runtime provenance changed')
        template=decode(fixed(bound['execution_launch_template']))
        expected_launch=dict(template)
        require(template['plan']is None and template['binding']is None,'future predecessor prefilled')
        expected_launch.update(state='BOUND_AWAITING_ROOT_AUTHORIZATION',binding=authority['scope_files']['BINDING-RESULT.json'],
            plan=authority['scope_files']['BOUND-PLAN.json'])
        expected_launch['argv']=[bound['runtime']['launch_executable'],'-I','-B',bound['controls']['run_qualification.py']['path'],
            '--plan',binding['plan']['path'],'--plan-sha256',binding['plan']['pin']['sha256'],
            '--binding',launch['binding']['path'],'--binding-sha256',launch['binding']['pin']['sha256']]
        require(launch==expected_launch and launch['product_authorization_required']is True
            and launch['owner_count']==20 and launch['method_invocations']==58 and launch['compile_calls']==8
            and launch['owner_seconds']==180 and launch['cleanup_seconds']==3 and launch['maximum_attempts']==1
            and launch['inherit_ambient_environment']is False and launch['cwd']==bound['source'],
            'actual product launch does not follow exact template and actual binding')
        require(launch['environment']=={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':bound['attempt'],
            'TMPDIR':str(Path(bound['attempt'])/'tmp'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC',
            'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','LD_LIBRARY_PATH':bound['runtime']['library_directory']},
            'clean actual product environment differs')
        require(preparation_launch['plan']==authority['preparation_plan']
            and preparation_launch['preparer']==bound['controls']['prepare_qualification.py']
            and preparation_launch['output']==str(SCOPE)and preparation_launch['project_imports']==0
            and preparation_launch['qualification_products']==0,'original preparation launch differs')
        outer=outer_readback(authority,preparation_launch)
        expected_scope={'.':authority['scope_stat'],'source':state['.']}
        expected_scope.update({name:row['stat']for name,row in authority['scope_files'].items()})
        expected_scope.update({'source/'+name:s for name,s in state.items()if name!='.'})
        expected_outer={'.':authority['outer_stat'],**{name:row['stat']for name,row in authority['outer_files'].items()}}
        require(metadata(SCOPE)==expected_scope and metadata(OUTER)==expected_outer,'complete scope/outer pathset/seven stats differ')
        after,final_context=immutable_authority(bound)
        require(after==before and context['runtime_state']==final_context['runtime_state'],'protected complete authorities changed')
        complete_source(bound['source'],flat,state,3210,TREE)
        for row in list(SEEN.values()):read(row['path'],row['pin'],row['stat'])
        require(metadata(SCOPE)==expected_scope and metadata(OUTER)==expected_outer
            and not os.path.lexists(bound['attempt']),'actual preparation evidence changed at terminal')
        for key in ('mother_source','prior_base','protected_source'):
            require(metadata(bound[key]['root'])==decode(fixed(bound[key]['state'])),'protected source final set changed')
        require(metadata(bound['runtime']['base_prefix'])==context['runtime_state'],'runtime final complete set changed')
        for p,row in SEEN.items():require(seven(Path(p).lstat())==row['stat'],'terminal fixed input identity changed')
        directories(bound['scope_ancestors']);directories(bound['source_ancestors']);directories(bound['author_ancestors'])
        floor=os.statvfs(SCOPE);free_after=floor.f_bavail*floor.f_frsize
        require(free_after>=1<<30,'original actual filesystem floor changed below 1 GiB')
        inventory=list(authority['scope_files'].values())+list(authority['outer_files'].values())
        publish(output/'RAW-INVENTORY.json',inventory);publish(output/'READ-INPUTS.json',list(SEEN.values()))
        result.update(status='PASS_COMPLETE_PREPARATION_READBACK',source_files=3210,source_tree=TREE,mother_files=3211,
            retained_R3_files=3210,protected_R8_files=3180,runtime_files=2496,copy_rows=3210,
            independent_file_and_directory_inodes=True,whole_plan_inverse=True,product_launch_matches_actual_binding=True,
            source_directory_modes_match_mother=True,patch14_exact_two_changes=True,original_test_methods=55,new_external_methods=3,
            planned_owner_count=20,planned_compile_calls=8,qualification_attempt_absent=True,
            actual_preparation_returncode=outer['returncode'],outer_cleanup_complete=True,qualification_products_executed=0,
            raw_files=len(inventory),raw_bytes=sum(r['pin']['bytes']for r in inventory),
            free_bytes_before=free,free_bytes_after=free_after,all_current_pathsets_and_seven_stats_equal=True,
            original_Native11_failure_preserved=True,all_frames_retired=False,compile_full_workspace_observed=False)
    except BaseException:
        import traceback
        result['error']=traceback.format_exc()
    finally:
        result.update(finished_ns=time.monotonic_ns(),fresh_reads=READS,read_bytes=BYTES,unique_paths=len(SEEN))
        publish(output/'RESULT.json',result)
    return 0 if result['status']=='PASS_COMPLETE_PREPARATION_READBACK'else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    parser.add_argument('--inputs',required=True);parser.add_argument('--inputs-sha256',required=True)
    args=parser.parse_args()
    raise SystemExit(verify(Path(args.output),Path(args.inputs),args.inputs_sha256))
