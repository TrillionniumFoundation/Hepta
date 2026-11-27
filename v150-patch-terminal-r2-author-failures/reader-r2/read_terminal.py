"""Independent complete actual terminal reader. Only stdlib; no project execution."""
from __future__ import annotations
import argparse,ast,hashlib,json,os,stat,time,re,struct,zlib
from pathlib import Path
AUTHOR=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-reader-r2-dda7')
SCOPE=Path('/workspace/hia-patch-terminal-quarantine-qualification-r2-dda7')
OUTER=Path('/workspace/hia-patch-terminal-quarantine-qualification-outer-r2-dda7')
OUTPUT=Path('/workspace/hia-patch-terminal-quarantine-qualification-terminal-actual-r2-dda7')
TREE='b4f7d4862d6b391781808d603547ce3a504ffc83'
SCHEMA='hepta.hia.patch-terminal.qualification.v1'
SUCCESS='PASS_ALL_SIX_EXPLICIT_COHORTS_AND_EIGHT_DEVELOPMENT_BUILDS'
EXTERNAL_RELATIVE='tests/test_hia_patch_result_quarantine_native.py'
COMPONENTS=('control','format','discovery','routing','parser_context','verified_report','inspect','patch')
VM_KEYS=('apply-start','interface-start','import-claim','import-ack','unpack4-claim','unpack4-ack','generator-start','normal-terminal','exception-terminal','retirement-start','retirement-ack','lost-claim')
FRAME_NAMES=tuple(a+'_'+b for a in('source','output','workspace')for b in('before','after'))
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
LIMITS={'cleanup_seconds':3,'compile_seconds':20,'native_capacity':1048576,'owner_seconds':180,'vm_call_depth':128,'vm_heap':8388608,'vm_steps':10000000}
READS=0;BYTES=0;SEEN={};OBSERVED_READS=[]

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
    # Same JSONEncoder options, ordering, indentation and trailing LF as R1.
    # Count the exact encoding before creation so the Git header is known.
    expected_bytes=0;expected_sha=hashlib.sha256()
    for text in json.JSONEncoder(sort_keys=True,indent=2).iterencode(value):
        chunk=text.encode();expected_bytes+=len(chunk);expected_sha.update(chunk)
    expected_bytes+=1;expected_sha.update(b'\n')
    written_bytes=0;written_sha=hashlib.sha256()
    written_git=hashlib.sha1(b'blob '+str(expected_bytes).encode()+b'\0')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
    with os.fdopen(fd,'wb')as stream:
        for text in json.JSONEncoder(sort_keys=True,indent=2).iterencode(value):
            chunk=text.encode();stream.write(chunk);written_bytes+=len(chunk)
            written_sha.update(chunk);written_git.update(chunk)
        stream.write(b'\n');written_bytes+=1;written_sha.update(b'\n');written_git.update(b'\n')
    require(written_bytes==expected_bytes and written_sha.digest()==expected_sha.digest(),
        'reader JSON encoding changed between exact streamed passes')
    # Independent held/named complete readback; no complete JSON string/bytes copy.
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=seven(os.fstat(fd))
        require(stat.S_ISREG(before['st_mode'])and before['st_nlink']==1
            and before==seven(Path(path).lstat())and before['st_size']==expected_bytes,
            'reader streamed output physical identity differs')
        actual_bytes=0;actual_sha=hashlib.sha256()
        actual_git=hashlib.sha1(b'blob '+str(expected_bytes).encode()+b'\0')
        while True:
            chunk=os.read(fd,1048576)
            if not chunk:break
            actual_bytes+=len(chunk);actual_sha.update(chunk);actual_git.update(chunk)
        require(actual_bytes==written_bytes and actual_sha.digest()==written_sha.digest()
            and actual_git.digest()==written_git.digest()
            and before==seven(os.fstat(fd))==seven(Path(path).lstat()),
            'reader independent streamed full-byte double-hash verification failed')
    finally:os.close(fd)


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


def owner_readback(directory,command,stage,source_map,code):
 req,_,reqraw=jsread(directory/'OWNER.json.request.json','owner-request');raw,_,rawbytes=jsread(directory/'OWNER.json','owner-raw');returned,_,_=jsread(directory/'OWNER-RETURNED.json','owner-returned')
 require(returned=={**raw,'supervisor_returncode':code,'receipt_sha256':hashlib.sha256(rawbytes).hexdigest()}and stage['owner_returned']==returned,'returned owner not exact raw plus two fields')
 require(req['implementation_sha256']==raw['implementation_sha256']==source_map['tools/hia_selfhost_process_owner.py']['sha256']and req['qualification_seconds']==raw['qualification_seconds']==command['qualification_seconds']==180 and req['cleanup_seconds']==raw['cleanup_seconds']==command['cleanup_seconds']==3,'owner implementation/limits differ')
 require(req['deadline_ns']-req['started_ns']==180_000_000_000 and req['command']==command['command']and req['cwd']==command['cwd']and req['env']==command['environment']==command['supervisor_environment'],'owner argv/environment/deadline differs')
 require(req['receipt_path']==str(directory/'OWNER.json')and req['stdout_path']==str(directory/'stdout.raw')and req['stderr_path']==str(directory/'stderr.raw')and raw['request_sha256']==hashlib.sha256(reqraw).hexdigest(),'owner raw request binding differs')
 require(raw['returncode']==code and raw['qualification_started']is True and raw['timed_out']is False and raw['exit_observed_before_deadline']is True and raw['event_overflow']is False and raw['interrupted_signals']==[]and raw['subreaper_enabled']is True and raw['status']==('OWNED_PROCESS_COMPLETED'if code==0 else'QUALIFICATION_FAILED'),'owner actual termination differs')
 c=raw['cleanup'];require(c['attempted']is True and c['complete']is True and c['leader_reaped']is True and c['observed_echild']is True and c['deadline_exceeded']is False and c['errors']==[]and c['remaining_direct_children']==[]and 0<=c['elapsed_ns']<=3_000_000_000,'owner cleanup incomplete')
 starts=[e for e in raw['events']if e['kind']=='qualification_started'];exits=[e for e in raw['events']if e['kind']=='qualification_exit_observed'];reaped=[e for e in raw['events']if e['kind']=='owned_child_reaped'and e['pid']==raw['qualification_pid']]
 require(len(starts)==len(exits)==len(reaped)==1 and starts[0]['pid']==exits[0]['pid']==raw['qualification_pid']and req['started_ns']<=starts[0]['monotonic_ns']<=exits[0]['monotonic_ns']<=req['deadline_ns']and reaped[0]['returncode']==code,'owner actual start/exit/reap differs')
 return {'directory':str(directory),'returncode':code,'status':raw['status'],'observed_ECHILD':True,'deadline_interval_ns':req['deadline_ns']-req['started_ns'],'raw_plus_exact_two_fields':True,'cleanup':c}


def tests_readback(directory,ids,child,status):
 tests,desc,_=jsread(directory/'TESTS.json','actual-original-tests');require(tests['declared_ids']==tests['loaded_ids']==ids and tests['events']==[e for n in ids for e in(['start',n],['stop',n])]and tests['tests_run']==len(ids),'original IDs/events incomplete')
 for k in('loader_errors','skipped','expected_failures','unexpected_successes'):require(tests[k]==[],'test suite incomplete: '+k)
 require(all(s['parent']in ids and s['status']in('PASS','FAIL','ERROR')for s in tests['subtests']),'subtest parent/status differs')
 failures=len(tests['failures']);errors=len(tests['errors']);bad=sum(s['status']!='PASS'for s in tests['subtests']);actual='FAIL'if failures or errors or bad else'PASS';require(tests['status']==status==actual,'original assertions and stage status differ')
 if actual=='PASS':require(child['tests']==tests,'successful full test report differs')
 else:
  require(bool(child.get('traceback')),'failed child lacks real traceback')
  if'tests'in child:require(child['tests']==tests,'failed child changed test report')
 return {'raw':desc,'ids':ids,'events':len(tests['events']),'tests_run':tests['tests_run'],'subtests':tests['subtests'],'failures':tests['failures'],'errors':tests['errors'],'status':actual}


def components_readback(directory,bound,source_map,names):
 envelope,_,_=jsread(directory/'ACTUAL-COMPONENTS.json','actual-components');require(set(envelope)=={'bundle','components'}and set(envelope['components'])==set(names),'actual component set differs');rows=[]
 if envelope['bundle']is not None:observed_fixed(envelope['bundle'],'actual-six-image-bundle')
 for name,desc in envelope['components'].items():
  require(set(desc)=={'image','manifest','source'},'component descriptor differs');image=observed_fixed(desc['image'],'new-image:'+name);manifest=decode(observed_fixed(desc['manifest'],'new-manifest:'+name));source=observed_fixed(desc['source'],'new-compile-source:'+name);relative=bound['component_sources'][name]
  require(desc['source']['path']==str(Path(bound['source'])/relative)and desc['source']['pin']==source_map[relative]and 0<len(image)<=1048576,'component source/image differs')
  ip=Path(desc['image']['path']);base=ip.name.removesuffix('.image.bin');require(ip.parent.is_relative_to(directory),'component outside actual build')
  req,_,_=jsread(ip.parent/(base+'.request.json'),'compile-request');rec,recdesc,_=jsread(ip.parent/(base+'.receipt.json'),'compile-receipt')
  require(req['image']==bound['compiler']['path']and req['image_sha256']==bound['compiler']['pin']['sha256']and req['capacity']==req['workspace_size']==1048576 and req['workspace_fill']==0 and req['format']=='flat-x86-64','compile request/budget differs')
  sp=ip.parent/(base+'.input.bin');op=ip.parent/(base+'.output.bin');require(req['source']==str(sp)and req['output']==str(op),'compile physical path differs');inp,_=observed_read(sp,'compile-input',maximum=len(source));out,_=observed_read(op,'compile-full-output',maximum=1048576)
  require(inp==source and len(out)==1048576 and out[:len(image)]==image,'actual full compile bytes differ')
  require(rec['status']=='returned'and rec['abi_status']==0 and rec['source_unchanged']is True and rec['forbidden_compiler_modules_loaded']==[]and rec['result_u64']==rec['core_u32']==rec['produced_bytes']==len(image)and rec['produced_image']==str(ip)and rec['produced_sha256']==desc['image']['pin']['sha256']and rec['artifact_sha256']==rec['image_sha256']==bound['compiler']['pin']['sha256']and rec['input_bytes']==len(source)and rec['input_sha256']==rec['source_sha256']==req['source_sha256']==hashlib.sha256(source).hexdigest()and rec['output_sha256']==hashlib.sha256(out).hexdigest(),'actual compile receipt identity differs')
  require(rec['limits']=={'address_bytes':268435456,'core_dumpable':False,'cpu_seconds':10,'output_capacity':1048576,'stack_bytes':8388608,'workspace_bytes':1048576}and 0<=rec['native_elapsed_ns']<=rec['wall_elapsed_ns']<=20_000_000_000 and rec['runner_sha256']==source_map['tools/hia_selfhost_child.py']['sha256'],'compile original limits/child differ')
  require(manifest['image_path']==ip.name and manifest['image_sha256']==desc['image']['pin']['sha256']and manifest['source_sha256']==desc['source']['pin']['sha256']and manifest['compiler_sha256']==bound['compiler']['pin']['sha256'],'actual manifest differs')
  for host,sha in manifest.get('host_sources',{}).items():require('/'not in host and source_map['hepta/'+host]['sha256']==sha,'manifest host differs')
  rows.append({'name':name,'component':desc,'compile_receipt':recdesc,'full_compile_input_output_image_equal':True,'full_compile_workspace_observed':False})
 return envelope,rows


def inflate_reference(journal,ref,role,referenced,decoded):
 require(type(ref)is dict and set(ref)in({'file','bytes','sha256','git_blob'},{'file','bytes','sha256','git_blob','mode'})and type(ref['file'])is str and re.fullmatch(r'[0-9a-f]{64}\.zlib',ref['file'])and ref['file']==ref['sha256']+'.zlib'and type(ref['bytes'])is int and ref['bytes']>=0,'invalid full buffer reference')
 if'mode'in ref:require(ref['mode']=='100644','logical buffer mode differs')
 path=journal/'buffers'/ref['file'];compressed,desc=observed_read(path,role+':compressed',maximum=path.lstat().st_size);stream=zlib.decompressobj();raw=stream.decompress(compressed,ref['bytes']+1)
 require(stream.eof and not stream.unused_data and not stream.unconsumed_tail,'buffer zlib incomplete/oversized');actual=physical_pin(raw);require({k:actual[k]for k in('bytes','sha256','git_blob')}=={k:ref[k]for k in('bytes','sha256','git_blob')},'decoded buffer identity differs')
 value={'path':str(path),'compressed':desc,'decoded':actual}
 if str(path)in decoded:require(decoded[str(path)]==value,'repeated physical buffer changed')
 # This map is report bookkeeping only. Every reference above is read anew.
 decoded[str(path)]=value;referenced.add(str(path));return raw


def frames_readback(attempt,images,vm_buffers=None):
 journals=[];referenced=set();decoded={}
 for frames in sorted(attempt.rglob('frames')):
  require(frames.is_dir()and not frames.is_symlink(),'invalid frames directory');journal=frames.parent;entries=sorted(frames.iterdir());require(all(re.fullmatch(r'[0-9]{8}-(BEFORE|AFTER)\.json',p.name)for p in entries),'unknown frame file')
  starts=[p for p in entries if p.name.endswith('-BEFORE.json')];require([int(p.name[:8])for p in starts]==list(range(len(starts))),'frame starts not contiguous');afters={int(p.name[:8])for p in entries if p.name.endswith('-AFTER.json')};require(afters<=set(range(len(starts))),'AFTER without BEFORE')
  rows=[];complete=0;unknown=[];missing=[]
  for i,bp in enumerate(starts):
   before,bdesc,_=jsread(bp,'frame-BEFORE');require(before['index']==i and before['returned']is False and before['image_sha256']in images,'BEFORE/image identity differs');spans={}
   for name in('source_before','output_before','workspace_before'):
    require(name in before,'actual BEFORE lacks an input');spans[name]=inflate_reference(journal,before[name],'BEFORE:'+name,referenced,decoded)
   if i not in afters:missing.append({'index':i,'missing':'AFTER','before':bdesc});continue
   after,adesc,_=jsread(frames/('%08d-AFTER.json'%i),'frame-AFTER');require(after['index']==i and after['image_sha256']==before['image_sha256'],'AFTER/image identity differs')
   for key in('case','command','entry_mode','nonce','runtime_profile','sequence','issued_operation','issued_raw'):
    if key in before:require(after.get(key)==before[key],'AFTER changed input metadata: '+key)
   absent=[]
   for name in FRAME_NAMES:
    if name not in after:absent.append(name);continue
    raw=inflate_reference(journal,after[name],'AFTER:'+name,referenced,decoded)
    if name.endswith('_before'):require(after[name]==before[name]and raw==spans[name],'AFTER input differs from original BEFORE')
    spans[name]=raw
   if absent:missing.append({'index':i,'missing':absent,'after':adesc})
   if after.get('returned')is not True:unknown.append({'index':i,'after':adesc,'returned':after.get('returned')})
   if'source_after'in spans:require(after.get('source_unchanged')==(spans['source_before']==spans['source_after']),'source preservation observation differs')
   if not absent and after.get('returned')is True:complete+=1
   if'complete'in after:require(after['complete']==(not absent),'complete flag differs from available six buffers')
   rows.append(after)
  ip=journal/'INDEX.json';index_desc=None
  if ip.exists():
   idx,index_desc,_=jsread(ip,'journal-INDEX');require(idx['frames']==rows and idx['started_calls']==len(starts)and idx['complete_calls']==len(rows),'INDEX differs from actual frame records')
   if'image_sha256'in idx:require(idx['image_sha256']in images,'INDEX image differs')
   if'all_complete'in idx:require(idx['all_complete']==(not missing),'INDEX completeness differs')
   if'all_source_unchanged'in idx:require(idx['all_source_unchanged']==all(x.get('source_unchanged')is True for x in rows),'INDEX source assertion differs')
  journals.append({'path':str(journal),'actual_started_calls':len(starts),'actual_after_records':len(rows),'actual_full_returned_calls':complete,'index':index_desc,'missing':missing,'unreturned':unknown,'all_frames_retired':False})
 orphans=[]
 for buffers in sorted(attempt.rglob('buffers')):
  if vm_buffers is not None and buffers==vm_buffers:continue
  require(buffers.is_dir()and not buffers.is_symlink(),'invalid buffer directory')
  for path in sorted(buffers.iterdir()):
   require(re.fullmatch(r'[0-9a-f]{64}\.zlib',path.name),'invalid buffer object name')
   if str(path)in referenced:continue
   compressed,desc=observed_read(path,'orphan-buffer-compressed',maximum=path.lstat().st_size);stream=zlib.decompressobj();raw=stream.decompress(compressed);require(stream.eof and not stream.unused_data and not stream.unconsumed_tail,'orphan zlib incomplete');identity=physical_pin(raw);require(identity['sha256']==path.stem,'orphan full bytes differ from filename');orphans.append({'compressed':desc,'decoded':identity,'reference_missing':True})
 return {'journals':journals,'actual_calls':sum(x['actual_started_calls']for x in journals),'actual_full_returned_calls':sum(x['actual_full_returned_calls']for x in journals),'unfinalized_journals':[x['path']for x in journals if x['index']is None],'decoded_physical_objects':list(decoded.values()),'orphan_objects':orphans,'all_frames_retired':False,'every_reference_fresh_read':True,'result_cache_used':False,'VM_execution':0}


def physical_pin(raw,mode='100644'):
    return pin(raw,mode)

def observed_read(path,role,*,expected=None,expected_stat=None,maximum=None):
    path=Path(path)
    require(path.is_absolute()and '..'not in path.parts,'absolute observation path required')
    if maximum is None:maximum=expected['bytes']if expected is not None else 16<<20
    require(0<=path.lstat().st_size<=maximum,'original bounded observation extent differs')
    raw=read(path,expected,expected_stat);row=SEEN[str(path)]
    OBSERVED_READS.append({'role':role,**row})
    return raw,row

def observed_fixed(row,role):
    require(type(row)is dict and set(row)=={'path','pin','stat'},'complete observation descriptor required')
    return observed_read(row['path'],role,expected=row['pin'],expected_stat=row['stat'])[0]

def jsread(path,role,**kwargs):
    raw,row=observed_read(path,role,**kwargs)
    return decode(raw),row,raw

def product_source_summary(bound):
    return {'files':3210,'all_bytes_read':True,'source_map':bound['source_map']['pin'],
        'source_state':bound['source_state']['pin']}

def environment(bound):
    return {'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':bound['attempt'],
        'TMPDIR':str(Path(bound['attempt'])/'tmp'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC',
        'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','LD_LIBRARY_PATH':bound['runtime']['library_directory']}

def cli_context(bound,directory,phase,row,native,bundle,source_map):
    cfg={'schema':'hepta.hia.patch-cli.control-context.v3','phase':phase,'source':bound['source'],
        'controls_output':str(directory/'controls'),
        'adapter_files':{n:source_map[n]for n in ('hepta/hia_cli_inspect_native.py',
            'hepta/hia_inspect_cli_operand.py','hepta/hia_inspect_cli_records.py')},
        'new_production':{n:{k:source_map[n][k]for k in ('bytes','sha256','git_blob')}
            for n in ('hepta/hia_cli_patch_result_native.py','hepta/hia_patch_cli_records.py')},
        'authority_files':{n:{'path':bound['controls'][k]['path'],'pin':bound['controls'][k]['pin'],
            'posix_mode':stat.S_IMODE(bound['controls'][k]['stat']['st_mode'])}for n,k in bound['authority_names'].items()}}
    for name,key in (('retained_support','inspect_cli_control_support.py'),('original_observer','inspect_exec_support.py')):
        r=bound['controls'][key];cfg[name]={'path':r['path'],'pin':r['pin'],'posix_mode':stat.S_IMODE(r['stat']['st_mode'])}
    if phase=='native':
        require(set(native)==set(COMPONENTS)and bundle is not None,'all actual eight components required')
        cfg.update(report_manifest=bundle['path'],inspect_manifest=native['inspect']['manifest']['path'],
            patch_manifest=native['patch']['manifest']['path'],signature_native=row['signature_native'])
    return cfg

def authorities(authority):
    historical=decode(fixed(authority['historical_preparation_inputs']))
    require(historical['scope']==str(SCOPE),'wrong historical preparation authority')
    for row in historical['scope_files'].values():fixed(row)
    for row in historical['outer_files'].values():fixed(row)
    preparation=decode(fixed(historical['preparation_plan']))
    bound=decode(fixed(authority['bound']));binding=decode(fixed(authority['binding']))
    require(authority['bound']==historical['scope_files']['BOUND-PLAN.json']
        and authority['binding']==historical['scope_files']['BINDING-RESULT.json']
        and binding['plan']==authority['bound']and binding['status']=='BOUND_NOT_EXECUTED'
        and binding['products_executed']==0 and binding['copied_files']==3210,'actual original preparation differs')
    changes={k for k in set(bound)|set(preparation)if bound.get(k)!=preparation.get(k)}
    require(changes=={'state','preparation_plan','source_map','source_state','copies','source_ancestors','scope_ancestors'},
        'actual bound-plan change set differs')
    inverse=dict(bound)
    for key in changes:
        if key in preparation:inverse[key]=preparation[key]
        else:del inverse[key]
    require(inverse==preparation,'whole bound-plan inverse differs')
    require(bound['scope']==str(SCOPE)and bound['source']==str(SCOPE/'source')
        and bound['attempt']==str(SCOPE/'attempt-r1')and bound['source_files']==3210 and bound['source_tree']==TREE
        and bound['limits']==LIMITS and bound['storage_floor']==1<<30,'actual scope/source/limits changed')
    # Products add the attempt. The old root seven-stat snapshot is historical.
    for key in ('st_dev','st_ino','st_mode'):
        require(getattr(SCOPE.lstat(),key)==historical['scope_stat'][key],'original scope physical authority changed')
    directories(bound['scope_ancestors']);directories(bound['source_ancestors']);directories(bound['author_ancestors'])
    summary,context=immutable_authority(bound)
    require(binding['source_before']==binding['source_after']==summary,'preparation protected summary differs')
    flat,state,matrix=actual_copy(bound,context)
    proof=decode(fixed(authority['preparation_readback']))
    require(proof['status']=='PASS_COMPLETE_PREPARATION_READBACK'and proof['source_tree']==TREE
        and proof['qualification_products_executed']==0 and proof['source_files']==3210,'independent preparation predecessor differs')
    return bound,binding,flat,state,matrix,summary,context

def stages_readback(authority,bound,parent,matrix,source_map,immutable):
    attempt=Path(bound['attempt']);stages=parent['stages'];expected=matrix['groups']
    require(0<len(stages)<=20 and parent['actual_owner_launch_attempts']==len(stages)
        and [r['label']for r in stages]==[r['label']for r in expected[:len(stages)]],
        'actual owners are not the exact original ordered prefix')
    success=parent['status']==SUCCESS
    require(parent['status']in (SUCCESS,'FAIL'),'unknown product terminal')
    if success:require(len(stages)==20 and all(s['status']=='PASS'for s in stages),'successful product lacks all original owners')
    else:require(all(s['status']=='PASS'for s in stages[:-1])and stages[-1]['status']=='FAIL'
        and parent.get('halted_after_first_failure')is True,'failed product did not stop at first failed owner')
    expected_dirs=['%02d-'%(i+1)+r['label']for i,r in enumerate(expected[:len(stages)])]
    actual_dirs=sorted(p.name for p in attempt.iterdir()if p.is_dir()and re.match(r'^[0-9]{2}-',p.name))
    require(actual_dirs==expected_dirs,'extra/missing original product stage directory')
    env=environment(bound);require(decode(read(attempt/'ENVIRONMENT.json'))==env
        and decode(read(attempt/'RUNTIME.json'))==bound['runtime']
        and decode(read(attempt/'PLAN-USED.json'))==bound,'actual parent environment/runtime/plan differs')
    guard={'immutable':immutable,'candidate3210':product_source_summary(bound)}
    owners=[];tests=[];compiles=[];native={};bundle=None;details=[];predecessor=None
    for ordinal,(declared,stage)in enumerate(zip(expected,stages),1):
        directory=attempt/('%02d-'%ordinal+declared['label']);passed=stage['status']=='PASS'
        rawstage=decode(read(directory/'STAGE.json'));require(rawstage==stage,'parent stage differs from original STAGE')
        require(stage['directory']==str(directory)and stage['kind']==declared['kind']and stage['ids']==declared['ids']
            and stage['finished_ns']>=stage['started_ns']>0,'original stage selection/timing differs')
        request,rdesc,rraw=jsread(directory/'REQUEST.json','guard-wrapper-request')
        inner,idesc,iraw=jsread(directory/'INNER-REQUEST.json','original-inner-request')
        require(request=={'schema':SCHEMA+'.guarded-child-request','plan':authority['bound'],
            'limits':LIMITS,'directory':str(directory),'group':declared['label'],
            'inner_module':{'build':'run_build_child','cli':'run_control_child','patch':'run_patch_child'}[declared['kind']],
            'inner_request':idesc,'product_root_binding':request['product_root_binding']},'exact guard wrapper request differs')
        directories(request['product_root_binding']);require(request['product_root_binding'][-1]['path']==str(attempt),
            'actual stage root authority differs')
        command=decode(read(directory/'COMMAND.json'))
        require(command['command']==[bound['runtime']['launch_executable'],'-I','-B',
            bound['controls']['run_qualification_child.py']['path'],'--request',str(directory/'REQUEST.json'),
            '--request-sha256',rdesc['pin']['sha256']]and command['cwd']==bound['source']
            and command['environment']==command['supervisor_environment']==env and command['free_bytes_before']>=1<<30,
            'actual original wrapper argv/environment/storage differs')
        owned=decode(read(directory/'OWNER.json'));code=owned['returncode']
        if passed:require(code==0,'successful original stage did not complete its owner')
        owners.append(owner_readback(directory,command,stage,source_map,code))
        wrapper=decode(observed_fixed(stage['wrapper_result'],'actual-guard-wrapper-result'))
        child=decode(observed_fixed(stage['actual_child'],'actual-inner-result'))
        require(stage['wrapper_result']['path']==str(directory/'WRAPPER-RESULT.json')
            and stage['actual_child']['path']==str(directory/'RESULT.json')
            and wrapper['request_pin']==physical_pin(rraw)and wrapper['inner_request']==idesc
            and wrapper['nested_owner_launches']==0 and wrapper['source_copy']is False
            and child['request_pin']==physical_pin(iraw),'actual wrapper/inner identity differs')
        if passed:
            require(wrapper['status']==child['status']=='PASS'and wrapper['inner_called']is True
                and wrapper['inner_returncode']==0 and wrapper['full_before']==wrapper['full_after']==guard
                and child['source_before']==child['source_after']==product_source_summary(bound)
                and stage['source_after']==guard and not wrapper.get('terminal_guard_errors')
                and not child.get('terminal_guard_errors')and not stage.get('terminal_errors'),
                'successful original stage lacks complete source/runtime/control guards')
        require(child.get('whole')is False and child.get('current_cold')is False,'child overstates scope')
        kind=declared['kind'];group=declared['group']
        if kind=='build':
            require(inner=={'schema':SCHEMA+'.build-request','plan':authority['bound'],
                'group':declared['label'],'directory':str(directory),'limits':LIMITS},'original build request differs')
            require(child['all_compile_workspaces_observed']is False,'compile workspace claim expanded')
            if passed:
                names=list(COMPONENTS[:6])if group=='build-report-six'else[group.removeprefix('build-')]
                envelope,rows=components_readback(directory,bound,source_map,names)
                require(not set(native)&set(envelope['components']),'same component compiled twice')
                native.update(envelope['components']);compiles.extend(rows)
                if envelope['bundle']is not None:bundle=envelope['bundle']
                build=decode(read(directory/'BUILD.json'));require(child['build']==build,'actual build report differs')
                require(build['matching_current_cold']is False,'development compile claimed current cold')
        elif kind=='cli':
            phase='source'if group=='source8'else'native'
            wanted={'schema':'hepta.hia.patch-cli.bound-child.v3','state':'BOUND_AWAITING_ROOT_AUTHORIZATION',
                'limits':LIMITS,'source':bound['source'],'source_map':bound['source_map'],'source_state':bound['source_state'],
                'controls':bound['controls'],'runtime':bound['runtime'],'phase':phase,'group':group,
                'ids':declared['ids'],'directory':str(directory),
                'context':cli_context(bound,directory,phase,declared,native,bundle,source_map)}
            if phase=='native':wanted.update(native_inputs=native,report_bundle=bundle)
            require(inner==wanted,'complete original CLI request/context differs')
        else:
            wanted={'schema':SCHEMA+'.patch-request','plan':authority['bound'],'limits':LIMITS,
                'group':group,'ids':declared['ids'],'directory':str(directory)}
            cfg={'source':bound['source'],'evidence':str(directory/'component')}
            if group!='patch-source11':
                require(set(native)==set(COMPONENTS),'Patch group lacks eight actual new builds')
                wanted['native_inputs']=native;cfg.update(manifest=native['patch']['manifest']['path'],
                    inspect_manifest=native['inspect']['manifest']['path'])
            if group=='patch-vm12':
                require(predecessor is not None,'VM lacks actual Native12 predecessor')
                wanted['native_predecessor']=predecessor
                catalog=child['catalog'];observed_fixed(catalog,'actual-VM-catalog')
                cfg.update(catalog=catalog['path'],catalog_pin={k:catalog['pin'][k]for k in ('bytes','sha256','git_blob')},
                    image_sha256=native['patch']['image']['pin']['sha256'],
                    hia_source_pin={k:native['patch']['source']['pin'][k]for k in ('bytes','sha256','git_blob')})
            require(inner==wanted,'complete original Patch/new3/VM request differs')
            if passed:require(decode(read(directory/'CONTEXT.json'))==cfg,'actual original Patch context differs')
            if group=='patch-quarantine3'and passed:
                require(child['external_test_loaded']is True and child['external_test_authority']==bound['external_test'],
                    'new three tests did not load exact external authority')
                observed_fixed(child['external_test_authority'],'exact-external-new3')
        if kind!='build':
            if (directory/'TESTS.json').exists():
                test_status=decode(read(directory/'TESTS.json'))['status']
                tests.append(tests_readback(directory,declared['ids'],child,test_status))
                if passed:require(test_status=='PASS','successful stage contains failed original assertions')
            else:require(not passed,'successful original cohort lacks TESTS')
            observed_fixed(stage['frame_readback'],'original-parent-frame-readback')
        for component in inner.get('native_inputs',{}).values():
            for record in component.values():observed_fixed(record,'fresh-stage-native-input')
        if group=='patch-native12'and passed:
            predecessor=parent['actual_native12_predecessor']
            require(predecessor['path']==str(attempt/'native12-predecessor/PREDECESSOR.json'),
                'actual Native12 snapshot outside fixed stage')
            observed_fixed(predecessor,'actual-Native12-predecessor')
        details.append({'directory':str(directory),'label':declared['label'],'kind':kind,'status':stage['status'],
            'ids':declared['ids'],'owner_returncode':code,'request':rdesc,'inner_request':idesc,
            'wrapper':stage['wrapper_result'],'child':stage['actual_child']})
    require(parent['source_after']==guard and parent['free_bytes_before']>=1<<30
        and parent['new_build_calls_required']==8 and parent['cohorts_required']==matrix['cohorts']
        and parent['all_frames_retired']is False and parent['compile_full_workspaces_observed']is False
        and parent['original_R5_witness10']=='FAIL_UNCHANGED_NOT_REQUALIFIED'
        and parent['Source8_scope']=='EXPLICIT_REAL_3210_PRODUCT_VIEW'and parent['mother3211_Source8_claim']is False
        and parent['new_three_scope']=='EXACT_EXTERNAL_ORIGINAL_TEST_MODULE'
        and all(parent[k]is False for k in ('current_cold','default','whole')),'actual parent scope/guard differs')
    if success:
        require(parent['native_inputs']==native and parent['report_bundle']==bundle
            and parent['completed_cohorts']==matrix['cohorts']and parent['actual_test_method_invocations']==58
            and parent['vm12_executed']is True and parent['all_native_frames_replayed']is False
            and parent['original_retained_cli43_rerun']is False and parent['current_source_cold']is False,
            'complete actual qualification result differs')
    return {'owners':owners,'tests':tests,'compiles':compiles,'components':native,'bundle':bundle,
        'stages':details,'not_started':[r['label']for r in expected[len(stages):]],'predecessor':predecessor}

def vm_readback(bound,stages,parent):
    result={'actual_vm_observations':0,'complete_selected_equal':False,'observations':[],
        'all_native_frames_replayed':False,'all_frames_retired':False,'VM_execution':0}
    if not any(r['label']=='patch-vm12'for r in stages['stages']):return result
    stage=next(r for r in stages['stages']if r['label']=='patch-vm12')
    directory=Path(stage['directory']);successful=stage['status']=='PASS'
    predecessor=stages['predecessor'];value=decode(observed_fixed(predecessor,'VM-actual-native-predecessor'))
    native_directory=Path(value['directory']);native_state=decode(observed_fixed(value['state'],'native-predecessor-state'))
    require(native_directory==Path(bound['attempt'])/'06-patch-native12'
        and value['schema']==SCHEMA+'.actual-native-predecessor'
        and value['source_map']==bound['source_map']and value['source_state']==bound['source_state']
        and value['every_original_file_retained']is True and value['all_frames_retired']is False
        and metadata(native_directory)==native_state,'actual Native12 complete snapshot differs')
    native_rows=[]
    for shard in value['shards']:
        raw=observed_fixed(shard,'native-predecessor-shard');require(len(raw)<=4<<20,'original 4 MiB predecessor shard cap differs')
        native_rows.extend(decode(raw))
    ordered=(json.dumps(native_rows,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    require(len(native_rows)==value['files']and physical_pin(ordered)==value['ordered_rows_pin']
        and [r['path']for r in native_rows]==[str(native_directory/n)for n,s in sorted(native_state.items())if stat.S_ISREG(s['st_mode'])],
        'complete ordered Native12 snapshot differs')
    for row in native_rows:
        require(row['stat']==native_state[str(Path(row['path']).relative_to(native_directory))],'snapshot row stat differs')
        observed_fixed(row,'complete-VM-native-predecessor')
    image=stages['components']['patch']['image']['pin']['sha256']
    journals=[];other=[];all_rows=[];inputs=[]
    for descriptor in native_rows:
        path=Path(descriptor['path'])
        if path.name!='INDEX.json':continue
        raw=observed_fixed(descriptor,'actual-predecessor-INDEX');index=decode(raw)
        if index.get('schema')!='hepta.hia.patch-result.full-native-frames.v1':continue
        if index['image_sha256']!=image:
            other.append({'path':str(path),'image_sha256':index['image_sha256']});continue
        require(index['all_complete']is True and index['all_source_unchanged']is True
            and index['entry_restored']is True and index['started_calls']==index['complete_calls']==len(index['frames']),
            'same-image actual Native12 index is incomplete')
        journals.append(str(path.parent));identity=pin(raw);inputs.append({'path':str(path),**identity})
        for frame in index['frames']:
            after=path.parent/'frames'/('%08d-AFTER.json'%frame['index'])
            after_raw=read(after)
            require(decode(after_raw)==frame and frame['returned']is True and frame['complete']is True
                and frame['source_unchanged']is True,'actual native catalog input differs')
            all_rows.append({'journal':str(path),'journal_pin':identity,'after':str(after),
                'after_pin':pin(after_raw),'buffers':str(path.parent/'buffers'),'frame':frame})
    require(journals,'no actual same-image Native12 witnesses')
    catalog=decode(read(directory/'VM-CATALOG.json'))
    # Same original selection predicates, evaluated on freshly read records.
    predicates={
        'apply-start':lambda r:r['command']==0 and r['entry_mode']==2,
        'interface-start':lambda r:r['command']==0 and r['entry_mode']==1,
        'import-claim':lambda r:r['command']==2 and r['issued_operation']==19 and r['result']==4,
        'import-ack':lambda r:r['command']==1 and r['issued_operation']==19,
        'unpack4-claim':lambda r:r['command']==2 and r['issued_operation']==13 and r['issued_raw']==[4]and r['result']==4,
        'unpack4-ack':lambda r:r['command']==1 and r['issued_operation']==13 and r['issued_raw']==[4],
        'generator-start':lambda r:r['command']==0 and r['entry_mode']>2,
        'normal-terminal':lambda r:r['command']==1 and r['result']==0,
        'exception-terminal':lambda r:r['command']==1 and r['result']==3,
        'retirement-start':lambda r:r['command']==4,
        'retirement-ack':lambda r:r['command']==1 and r['result']==5,
        'lost-claim':lambda r:r['case']=='lost-claim'and r['command']==2 and r['result']==4}
    selected={}
    for key in VM_KEYS:
        matches=[row for row in all_rows if predicates[key](row['frame'])]
        require(matches,'missing original actual Native predicate: '+key);selected[key]=matches[0]
    require(catalog=={'schema':'hepta.hia.patch-result.native-vm-catalog.v1','selection_order':list(VM_KEYS),
        'selected':selected,'inputs':inputs,'image_sha256':image,'actual_native_frames':len(all_rows),
        'selected_frames':12,'max_steps':10000000,'heap_bytes':8388608,'call_depth':128,
        'all_native_frames_replayed':False},'entire actual catalog differs from first matching current Native witnesses')
    require(decode(read(directory/'CATALOG-INPUTS.json'))=={'predecessor':predecessor,
        'same_image_journals':journals,'other_image_journals':other,
        'original_make_vm_catalog_called_once':True,'current_native_only':True},'catalog source provenance differs')
    root=directory/'component/vm';require(root.is_dir(),'actual VM observation directory missing')
    found={p.stem:p for p in root.glob('*.json')if p.name!='INDEX.json'}
    require(set(found)<=set(VM_KEYS),'unknown VM observation')
    if successful:require(set(found)==set(VM_KEYS),'original twelve VM records required')
    references=set();decoded={};rows=[];reference_reads=0
    for key in VM_KEYS:
        if key not in found:continue
        row=decode(read(found[key]));chosen=selected[key];native=chosen['frame'];same=True;actual_spans={}
        require(row['key']==key and row['native_frame']==native['index']and row['native_case']==native['case']
            and row['native_result']==native['result'],'actual VM witness identity differs')
        require(decode(read(chosen['after'],chosen['after_pin']))==native,'selected actual AFTER changed before full-byte comparison')
        for side in ('before','after'):
            for name in ('source','output','workspace'):
                actual=inflate_reference(root,row[side][name],'VM:'+key+':'+side+':'+name,references,decoded)
                expected=inflate_reference(Path(chosen['buffers']).parent,native[name+'_'+side],
                    'Native-for-VM:'+key+':'+side+':'+name,references,decoded)
                reference_reads+=2;same=same and actual==expected;actual_spans[name+'_'+side]=actual
        unchanged=actual_spans['source_before']==actual_spans['source_after']
        require(row['source_unchanged']==unchanged and row['exact_native_buffers']==same,
            'VM real six-buffer observation flags differ')
        if row['status']=='PASS':
            require(same and unchanged and type(row['result'])is int and row['result']==native['result']
                and 0<=row['steps']<=10000000,'actual successful VM differs or exceeds original fuel')
        else:require(row['status']=='FAIL'and row.get('traceback'),'failed VM lacks original traceback')
        rows.append(row);result['observations'].append({'key':key,'status':row['status'],'steps':row['steps'],
            'complete_bytes_equal':same,'source_unchanged':unchanged})
    index_path=root/'INDEX.json'
    if index_path.exists():
        index=decode(read(index_path))
        require(index=={'schema':'hepta.hia.patch-result.actual-vm-observations.v1',
            'observations':rows,'max_steps_per_frame':10000000,'all_native_frames_replayed':False},
            'VM final INDEX differs from all actual ordered observations')
    else:require(not successful,'successful VM lacks final INDEX')
    vm_orphans=[]
    for path in sorted((root/'buffers').iterdir()):
        require(re.fullmatch(r'[0-9a-f]{64}\.zlib',path.name),'invalid VM physical buffer member')
        if str(path)in references:continue
        raw=read(path);stream=zlib.decompressobj();full=stream.decompress(raw)
        require(stream.eof and not stream.unused_data and not stream.unconsumed_tail and pin(full)['sha256']==path.stem,
            'unreferenced VM buffer has incomplete/mismatched original bytes')
        vm_orphans.append({'path':str(path),'compressed':SEEN[str(path)],'decoded':pin(full)})
    if successful:require(len(rows)==12 and all(r['status']=='PASS'for r in rows),'original twelve same-frame VM methods not all passed')
    parent_report=decode(read(directory/'VM-READBACK.json'))
    require(parent_report['observations']==[{'key':r['key'],'status':r['status'],'steps':r['steps'],
        'complete_bytes_equal':r['complete_bytes_equal']}for r in result['observations']]
        and parent_report['buffer_reads']==reference_reads and parent_report['all_native_frames_replayed']is False
        and parent_report['all_frames_retired']is False
        and parent_report['complete_selected_equal']==successful,'parent VM report differs from independent complete reads')
    require(metadata(native_directory)==native_state,'complete Native predecessor changed after VM comparison')
    result.update(actual_vm_observations=len(rows),complete_selected_equal=successful,
        original_native_snapshot_files=len(native_rows),original_native_frames=len(all_rows),
        catalog_first_match_predicates_complete=True,buffer_reference_reads=reference_reads,
        physical_buffers=list(decoded.values()),orphan_buffers=vm_orphans)
    return result

def frame_reports_readback(parent,frames):
    reports=[]
    for stage in parent['stages']:
        if stage['kind']=='build':continue
        directory=Path(stage['directory'])
        actual=decode(observed_fixed(stage['frame_readback'],'original-full-frame-parent-report'))
        selected=[j for j in frames['journals']if Path(j['path']).is_relative_to(directory)]
        rows=[];references=0
        for journal in selected:
            missing=[[m['index'],field]for m in journal['missing']if isinstance(m['missing'],list)
                for field in m['missing']]
            started=journal['actual_started_calls'];after=journal['actual_after_records']
            references+=3*started+6*after-len(missing)
            rows.append({'path':journal['path'],'started':started,'after':after,
                'missing_fields':missing,'has_final_index':journal['index']is not None,
                'complete':not journal['missing']and after==started})
        expected={'journals':rows,'complete_calls':sum(r['after']for r in rows),
            'started_calls':sum(r['started']for r in rows),'buffer_reference_reads':references,
            'all_frames_retired':False,'all_observed_frames_complete':all(r['complete']for r in rows)}
        require(actual==expected,'parent full-frame report differs from independent physical reads: '+stage['label'])
        reports.append({'label':stage['label'],**expected})
    return reports

def outer_terminal(authority,bound,parent):
    launch_raw=fixed(authority['product_launch']);launch=decode(launch_raw)
    template=decode(fixed(authority['execution_launch_template']))
    expected=dict(template);expected.update(state='BOUND_AWAITING_ROOT_AUTHORIZATION',
        binding=authority['binding'],plan=authority['bound'])
    expected['argv']=[bound['runtime']['launch_executable'],'-I','-B',
        bound['controls']['run_qualification.py']['path'],'--plan',authority['bound']['path'],
        '--plan-sha256',authority['bound']['pin']['sha256'],'--binding',authority['binding']['path'],
        '--binding-sha256',authority['binding']['pin']['sha256']]
    require(launch==expected and launch['environment']==environment(bound)
        and launch['cwd']==bound['source']and launch['owner_count']==20
        and launch['method_invocations']==58 and launch['compile_calls']==8
        and launch['owner_seconds']==180 and launch['cleanup_seconds']==3
        and launch['maximum_attempts']==1 and launch['inherit_ambient_environment']is False,
        'complete actual product launch differs from frozen template')
    values={n:fixed(r)for n,r in authority['outer_files'].items()}
    require(set(values)=={'INTENT.json','RESULT.json','SPAWNED.json','stdout.bin','stderr.bin'},
        'complete actual outer file set differs')
    intent=decode(values['INTENT.json']);result=decode(values['RESULT.json']);spawn=decode(values['SPAWNED.json'])
    env=launch['environment'];argv=['/usr/bin/env','-i']+[k+'='+v for k,v in env.items()]+launch['argv']
    require(intent['argv']==argv and intent['product_argv']==launch['argv']
        and intent['environment']==env and intent['cwd']==launch['cwd']
        and intent['status']=='ROOT_AUTHORIZED_QUALIFICATION_ONCE'
        and intent['original_owner_seconds']==180 and intent['outer_watchdog_seconds']==1800
        and intent['cleanup_seconds']==3 and intent['maximum_attempts']==1
        and intent['planned_owner_count']==20 and intent['planned_methods']==58
        and intent['planned_compile_calls']==8 and intent['source_files']==3210
        and intent['mother_files']==3211 and intent['new_external_methods']==3
        and intent['fail_stop']is True and intent['old_Native11_failure_retained']is True
        and intent['whole_native']is False and intent['launch']==pin(launch_raw),
        'actual outer exact clean invocation differs')
    s=authority['product_launch']['stat']
    require(intent['launch_seven_stats']==[s[k]for k in('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
        and intent['review']==pin(fixed(authority['preparation_readback']))
        and intent['original_source_review']==pin(fixed(authority['root_preparation_review'])),
        'actual outer predecessor authority differs')
    code=0 if parent['status']==SUCCESS else 1
    require(result['returncode']==code and result['timeout']is False and result['ECHILD']is True
        and result['process_group_absent']is True and result['adopted']==[]and result['subreaper']is True
        and result['direct_restored_interpreter_invocations']==result['maximum_attempts']==1
        and result['pid']==spawn['pid']==spawn['pgid']and spawn['started_monotonic_ns']>0
        and result['elapsed_ns']>=parent['finished_ns']-parent['started_ns']>0
        and result['product_counts_require_original_journals']is True
        and result['requires_actual_original_phase_and_full_frame_readback']is True,
        'actual outer process termination/cleanup differs')
    if code==0:require(result['status']=='PASS_PATCH_QUALIFICATION_PARENT_PROCESS_ONLY','successful outer status differs')
    require(pin(values['stdout.bin'])==result['stdout']and pin(values['stderr.bin'])==result['stderr'],
        'complete actual outer streams differ')
    return result

def verify_terminal(plan_path,expected_sha,output):
    started=time.monotonic_ns()
    require(plan_path==AUTHOR/'READBACK-PLAN.json'and output==OUTPUT and not os.path.lexists(output),
        'fixed independent plan and new output required')
    output.mkdir(mode=0o700)
    report={'schema':'hepta.hia.patch-terminal.independent-terminal-result.v1','status':'FAIL',
        'product_execution':0,'project_imports':0,'binder_execution':0,'source_copy':False,
        'all_frames_retired':False,'full_compile_workspaces_observed':False,'whole_native':False,
        'started_ns':started}
    try:
        raw=read(plan_path);require(hashlib.sha256(raw).hexdigest()==expected_sha,'exact reader plan SHA differs')
        authority=decode(raw)
        require(authority['schema']=='hepta.hia.patch-terminal.independent-terminal-plan.v1'
            and authority['scope']==str(SCOPE)and authority['outer']==str(OUTER)
            and authority['output']==str(OUTPUT)and authority['product_execution']==0,
            'exact current terminal reader authority differs')
        fixed(authority['reader'])
        for row in authority['root_metadata'].values():fixed(row)
        bound,binding,flat,state,matrix,immutable,context=authorities(authority)
        attempt=Path(bound['attempt']);parent=decode(fixed(authority['actual_result']))
        require(authority['actual_result']['path']==str(attempt/'RESULT.json')
            and parent['schema']==SCHEMA+'.qualification-result'
            and parent['plan_pin']==authority['bound']['pin']and parent['binding_pin']==authority['binding']['pin'],
            'actual qualification result identity differs')
        initial_attempt=metadata(attempt);initial_outer=metadata(OUTER);initial_scope=metadata(SCOPE)
        outer=outer_terminal(authority,bound,parent)
        stage_result=stages_readback(authority,bound,parent,matrix,flat,immutable)
        images={r['image']['pin']['sha256']for r in stage_result['components'].values()}
        vm_buffer_root=attempt/'20-patch-vm12/component/vm/buffers'
        frames=frames_readback(attempt,images,vm_buffer_root)
        frame_reports=frame_reports_readback(parent,frames)
        vm=vm_readback(bound,stage_result,parent)
        raw_inventory=[]
        for prefix,root,original in (('attempt',attempt,initial_attempt),('outer',OUTER,initial_outer)):
            for relative,s in sorted(original.items()):
                if not stat.S_ISREG(s['st_mode']):continue
                path=root/relative;read(path,expected_stat=s)
                raw_inventory.append({'logical':prefix+'/'+relative,**SEEN[str(path)]})
            require(metadata(root)==original,'complete actual raw pathset/stat changed during readback')
        historical=decode(fixed(authority['historical_preparation_inputs']))
        expected_top={'source','attempt-r1',*historical['scope_files']}
        require({p.name for p in SCOPE.iterdir()}==expected_top,'unknown/missing scope member')
        for row in historical['scope_files'].values():fixed(row)
        after,final_context=immutable_authority(bound)
        require(after==immutable and final_context['runtime_state']==context['runtime_state'],
            'complete protected source/runtime identities changed')
        complete_source(bound['source'],flat,state,3210,TREE)
        require(metadata(attempt)==initial_attempt and metadata(OUTER)==initial_outer
            and metadata(SCOPE)==initial_scope,'terminal actual evidence changed after final full-source guards')
        directories(bound['scope_ancestors']);directories(bound['source_ancestors']);directories(bound['author_ancestors'])
        for row in SEEN.values():
            require(seven(Path(row['path']).lstat())==row['stat'],'final seven-stat input changed')
        methods=sum(row['tests_run']for row in stage_result['tests'])
        events=sum(row['events']for row in stage_result['tests'])
        if parent['status']==SUCCESS:
            require(len(stage_result['owners'])==20 and len(stage_result['compiles'])==8
                and methods==58 and events==116 and all(t['status']=='PASS'for t in stage_result['tests'])
                and len(stage_result['components'])==8 and vm['actual_vm_observations']==12
                and vm['complete_selected_equal']is True and not stage_result['not_started']
                and all(r['all_observed_frames_complete']for r in frame_reports),
                'successful terminal lacks one of the explicit original/new cohorts or builds')
        inventory={'schema':'hepta.hia.patch-terminal.complete-actual-raw.v1',
            'roots':{'attempt':{'path':str(attempt),'state':initial_attempt},
                'outer':{'path':str(OUTER),'state':initial_outer}},'scope_state':initial_scope,
            'files':raw_inventory,'file_count':len(raw_inventory),
            'logical_bytes':sum(r['pin']['bytes']for r in raw_inventory),
            'all_actual_raw_retained':True,'all_frames_retired':False}
        publish(output/'STAGES.json',stage_result);publish(output/'FRAMES.json',frames)
        publish(output/'PARENT-FRAME-REPORTS.json',frame_reports);publish(output/'VM.json',vm)
        publish(output/'INVENTORY.json',inventory)
        report.update(status='PASS_COMPLETE_QUALIFICATION_TERMINAL_READBACK'if parent['status']==SUCCESS
            else'PASS_FAILURE_EVIDENCE_VERIFIED',product_status=parent['status'],
            original_result=authority['actual_result'],actual_owners=len(stage_result['owners']),
            actual_compiles=len(stage_result['compiles']),actual_test_methods=methods,actual_test_events=events,
            actual_subtests=sum(len(t['subtests'])for t in stage_result['tests']),
            actual_test_failures=sum(len(t['failures'])for t in stage_result['tests']),
            actual_test_errors=sum(len(t['errors'])for t in stage_result['tests']),
            actual_native_calls=frames['actual_calls'],actual_native_full_returned_calls=frames['actual_full_returned_calls'],
            actual_native_after_records=sum(j['actual_after_records']for j in frames['journals']),
            actual_native_journals=len(frames['journals']),native_unfinalized_journals=frames['unfinalized_journals'],
            actual_native_physical_buffer_objects=len(frames['decoded_physical_objects']),
            actual_native_orphan_objects=len(frames['orphan_objects']),
            actual_vm_observations=vm['actual_vm_observations'],vm_complete_selected_equal=vm['complete_selected_equal'],
            all_native_frames_replayed=False,raw_files=len(raw_inventory),raw_bytes=inventory['logical_bytes'],
            source_files=3210,mother_source_files=3211,source_tree=TREE,source_guard=product_source_summary(bound),
            separate_cohorts=matrix['cohorts'],new_tests_external=True,
            original_R5_witness10='FAIL_UNCHANGED_NOT_REQUALIFIED',original_cli43_rerun=False,
            current_cold=False,outer_process_only=outer)
    except BaseException:
        import traceback
        report['traceback']=traceback.format_exc()
    finally:
        report.update(finished_ns=time.monotonic_ns(),fresh_full_reads=READS,fresh_full_bytes=BYTES,
            unique_input_paths=len(SEEN),every_reference_fresh=True,result_cache_used=False)
        publish(output/'READ-INPUTS.json',list(SEEN.values()))
        with (output/'OBSERVATION-READS.jsonl').open('xb')as stream:
            for row in OBSERVED_READS:stream.write((json.dumps(row,sort_keys=True)+'\n').encode())
        publish(output/'RESULT.json',report)
    return 0 if report['status']in('PASS_COMPLETE_QUALIFICATION_TERMINAL_READBACK','PASS_FAILURE_EVIDENCE_VERIFIED')else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--output',required=True);args=parser.parse_args()
    raise SystemExit(verify_terminal(Path(args.plan),args.plan_sha256,Path(args.output)))
