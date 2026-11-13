"""New ai395 finite-native readback. This is not a matching-cold or SQL gate."""
from pathlib import Path
import ast,hashlib,importlib.util,json,os,platform,stat,struct,sys,zlib
import common,matrix
ROOT=Path(__file__).resolve().parent.parent
def read_json(path,maximum=64<<20):
    pin,raw=common.read(path,maximum);return pin,json.loads(raw)
def system_read(path):
    path=Path(path)
    with common.held_parent(path) as (parent,name):
        s=os.stat(name,dir_fd=parent,follow_symlinks=False)
        common.require(stat.S_ISREG(s.st_mode) and s.st_nlink>=1 and s.st_uid==0
            and not s.st_mode&0o022 and s.st_size<=128<<20,'frozen root-owned regular system role')
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            common.require(common.identity(os.fstat(fd))==common.identity(s),'system fd identity')
            sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(s.st_size).encode()+b'\0');count=0
            while True:
                b=os.read(fd,1<<20)
                if not b:break
                count+=len(b);sha.update(b);git.update(b)
                common.require(count<=s.st_size,'system body grew')
            common.require(count==s.st_size and common.identity(os.fstat(fd))==common.identity(s)
                ==common.identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                'system whole read identity changed')
        finally:os.close(fd)
    return {'path':str(path),'bytes':count,'sha256':sha.hexdigest(),'git_blob':git.hexdigest(),'identity':common.identity(s)}
def runtime(request):
    actual=system_read(Path(sys.executable).resolve())
    common.require(actual==request['runtime'] and sys.version==request['python_version']
        and sys.version_info[:3]==(3,14,4) and sys.platform=='linux' and platform.machine()=='x86_64'
        and sys.flags.isolated==1 and sys.flags.no_site==1 and sys.dont_write_bytecode
        and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==request['boot_id'],
        'new ai395 runtime, flags or boot differs')
    return actual
def input_records(request):
    rows=common.input_records(ROOT,request)
    for name,pin in rows.items():
        common.require(pin['identity']==request['inputs'][name]['identity'],'frozen input identity changed: '+name)
    control={str(p.relative_to(ROOT)) for p in (ROOT/'control').iterdir() if p.is_file()}
    common.require(control=={n for n in request['inputs'] if n.startswith('control/')},
        'exact control namespace differs')
    return rows
def source_records(request):
    _,manifest=read_json(ROOT/'SOURCE-BASE.json')
    common.require(manifest['source_commit']==request['source_commit']=='0504beb11c0dae875d8590660c42488b7bc634fb'
        and manifest['source_tree']==request['source_tree']=='596ab07e8813e4811a8dca51800cd51eb397aeb2'
        and manifest['source_root']==str(ROOT/'source-base') and manifest['input_count']==1686
        and manifest['bytes']==40890650 and len(manifest['files'])==1686,'whole 0504 physical input set')
    rows={}
    for item in manifest['files']:
        name=item['path'];common.require(type(name)is str and not name.startswith('/') and '..' not in Path(name).parts,'source relative path')
        pin,_=common.read(ROOT/'source-base'/name)
        common.require(all(pin[k]==item[k] for k in ('bytes','sha256','git_blob','identity'))
            and ('100755' if pin['identity'][2]&0o111 else '100644')==item['mode'],
            'current source exact bytes/mode/identity: '+name)
        common.require(name not in rows,'duplicate source entry');rows[name]=pin
    found=set()
    for base,dirs,names in os.walk(ROOT/'source-base',followlinks=False):
        for d in dirs:common.require(stat.S_ISDIR((Path(base)/d).lstat().st_mode),'source directory link')
        for n in names:
            p=Path(base)/n;common.require(stat.S_ISREG(p.lstat().st_mode),'source special')
            found.add(str(p.relative_to(ROOT/'source-base')))
    common.require(found==set(rows),'source namespace exact')
    return rows
def system_records(request):
    _,doc=read_json(ROOT/request['system_map'])
    common.require(doc['host']=='ai395' and doc['count']==request['system_count']
        and len(doc['files'])==request['system_count'] and doc['bytes']==request['system_bytes'],
        'system complete set denominator')
    rows={}
    for item in doc['files']:
        p=system_read(item['path']);common.require(p==item,'fresh system input mismatch: '+item['path'])
        common.require(p['path'] not in rows,'duplicate system source');rows[p['path']]=p
    for alias,target in doc['aliases'].items():
        common.require(str(Path(alias).resolve(strict=True))==target,'system alias target changed')
    return rows
def current_imports(request):
    source={str(ROOT/'source-base'/r):p for r,p in source_records(request).items()}
    source.update({str(ROOT/n):p for n,p in request['inputs'].items() if n.endswith('.py')})
    rows=[]
    for name,module in sorted(sys.modules.items()):
        if not (name=='hepta' or name.startswith('hepta.') or name=='tools' or name.startswith('tools.')
                or name=='tests' or name.startswith('tests.')):continue
        f=getattr(module,'__file__',None)
        if f is None:
            common.require(name=='tools','unknown project namespace');continue
        p=str(Path(f).resolve())
        common.require(p in source,'project import outside frozen source: '+name)
        observed,_=common.read(p)
        common.require(all(observed[k]==source[p][k] for k in ('bytes','sha256','git_blob')),
                       'project import bytes changed')
        rows.append({'module':name,'source':observed})
    return rows
def loaded_file_maps(request,own):
    _,system=read_json(ROOT/request['system_map'])
    allowed={r['path']:r for r in system['files']}
    allowed.update({str(Path(p).resolve(strict=True)):r for p,r in own.items()})
    raw=Path('/proc/self/maps').read_text()
    rows=[];read_files={}
    for line in raw.splitlines():
        fields=line.split(None,5)
        common.require(len(fields)>=5,'malformed actual maps line')
        if len(fields)<6 or not fields[5].startswith('/'):
            rows.append({'line':line,'file':None});continue
        key=str(Path(fields[5]).resolve(strict=True))
        common.require(key in allowed,'loaded file outside frozen runtime/oracle closure: '+key)
        if key not in read_files:
            p=common.read(key,1<<20)[0] if key in own else system_read(key)
            common.require(all(p[k]==allowed[key][k] for k in ('bytes','sha256','git_blob','identity')),
                           'actual mapped file changed')
            read_files[key]=p
        p=read_files[key];dev=tuple(int(x,16) for x in fields[3].split(':'))
        common.require(dev==(os.major(p['identity'][0]),os.minor(p['identity'][0]))
            and int(fields[4])==p['identity'][1],'mapped device/inode differs')
        rows.append({'line':line,'file':key})
    return {'maps':rows,'files':read_files,'all_file_backed_mappings_joined':True}
def capacity(path,initial=False):
    v=os.statvfs(path);r={'path':str(path),'free_bytes':v.f_bavail*v.f_frsize,
        'free_inodes':v.f_favail,'device':Path(path).stat().st_dev}
    common.require(r['free_bytes']>=(1<<30 if initial else 512<<20) and r['free_inodes']>=4096,
                   'finite-native original capacity/inode gate')
    return r
def command(request,sha):
    q=request['command']
    common.require(q.count('@REQUEST_SHA256@')==1,'exact request hash slot')
    return [sha if v=='@REQUEST_SHA256@' else v for v in q]
def natural_owner(returned,life,parent_request,request,request_sha,life_pin,parent_pin):
    result=dict(returned);rc=result.pop('supervisor_returncode',None);seal=result.pop('receipt_sha256',None)
    common.require(result==life and type(rc)is int and seal==life_pin['sha256']
        and life.get('schema')=='hepta.hia.selfhost-process-owner.v1'
        and life.get('implementation_sha256')==request['inputs']['control/process_owner_impl.py']['sha256']
        and life.get('request_sha256')==parent_pin['sha256']
        and parent_request['implementation_sha256']==life['implementation_sha256']
        and parent_request['command']==command(request,request_sha)
        and parent_request['env']==request['environment'] and parent_request['cwd']==str(ROOT)
        and parent_request['qualification_seconds']==life.get('qualification_seconds')==180
        and parent_request['cleanup_seconds']==life.get('cleanup_seconds')==3
        and parent_request['deadline_ns']-parent_request['started_ns']==180000000000
        and life['parent_pid']==parent_request['parent_pid']
        and parent_request['stdout_path']==str(Path(request['output'])/'stdout.log')
        and parent_request['stderr_path']==str(Path(request['output'])/'stderr.log')
        and parent_request['receipt_path']==str(Path(request['output'])/'lifecycle.json'),
        'whole bound owner request/wrapper/implementation mismatch')
    cleanup=life.get('cleanup',{})
    closed=(life.get('subreaper_enabled') is True and life.get('event_overflow') is False
        and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
        and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children')==[]
        and cleanup.get('errors')==[] and cleanup.get('deadline_exceeded') is False)
    common.require(closed,'owner closure unknown: do not enumerate/read child output')
    events=life.get('events',[])
    natural=(rc==0 and life.get('status')=='OWNED_PROCESS_COMPLETED' and life.get('returncode')==0
        and life.get('timed_out') is False and life.get('exit_observed_before_deadline') is True
        and life.get('owner_error') is None and life.get('interrupted_signals')==[]
        and [e.get('kind') for e in events]==['qualification_started','owned_child_observed',
             'qualification_exit_observed','owned_child_reaped']
        and all(e.get('pid')==life.get('qualification_pid') for e in events))
    return closed,natural
def catalog(output,skip=()):
    output=Path(output);rows=[];total=0
    for base,dirs,names in os.walk(output,followlinks=False):
        for d in dirs:common.require(stat.S_ISDIR((Path(base)/d).lstat().st_mode),'closed special directory')
        for n in sorted(names):
            p=Path(base)/n;name=str(p.relative_to(output))
            if name in skip:continue
            pin,_=common.read(p,64<<20);total+=pin['bytes'];rows.append({'relative_path':name,**pin})
            common.require(total<=384<<20 and len(rows)<=192,'closed full output original quota')
    return {'files':rows,'file_count':len(rows),'bytes':total,'all_bodies_read':True}
def inspect_compiler_inputs():
    _,c=read_json(ROOT/'reference/B3-ORIGINALS-CUSTODY.json')
    names={x['path'] for x in c['members']}
    common.require(len(names)==7 and names=={p.name for p in (ROOT/'compiler-inputs').iterdir()},'seven B3 namespace')
    bodies={};pins={}
    for r in c['members']:
        p,b=common.read(ROOT/'compiler-inputs'/r['path'],2<<20)
        common.require(p['bytes']==r['size'] and p['sha256']==r['sha256'] and p['git_blob']==r['git_blob_sha1']
            and zlib.crc32(b)&0xffffffff==r['zip_crc32'],'B3 original full byte CRC')
        bodies[r['path']]=b;pins[r['path']]=p
    receipt=json.loads(bodies['B3.receipt.json']);req=json.loads(bodies['B3.request.json']);stdout=json.loads(bodies['B3.stdout.log'])
    added={'case','input_sha256','input_bytes','artifact_sha256','format','runner_sha256','wall_elapsed_ns','produced_image','produced_bytes','produced_sha256'}
    common.require(set(receipt)-set(stdout)==added and {k:v for k,v in receipt.items() if k not in added}==stdout,'B3 whole receipt/stdout')
    image=bodies['B3.image.bin'];source=bodies['B3.input.bin'];full=bodies['B3.output.bin']
    common.require(image==full[:len(image)] and len(full)==1<<20 and len(image)==670467
        and receipt['status']=='returned' and receipt['source_unchanged'] is True and receipt['abi_status']==0
        and receipt['forbidden_compiler_modules_loaded']==[] and receipt['produced_bytes']==len(image)
        and receipt['core_u32']==len(image) and receipt['result_u64']==len(image)
        and receipt['output_sha256']==hashlib.sha256(full).hexdigest()
        and req['source_sha256']==receipt['input_sha256']==receipt['source_sha256']==hashlib.sha256(source).hexdigest()
        and req['image_sha256']==receipt['artifact_sha256']==receipt['image_sha256']==receipt['produced_sha256']==hashlib.sha256(image).hexdigest(),
        'historical B3 full original chain')
    return {'pins':pins,'historical_run':43220208164,'current_source_cold':False}
def inspect_new_compile(directory,request):
    directory=Path(directory);label='varint'
    names=[label+s for s in ('.input.bin','.output.bin','.request.json','.receipt.json','.stdout.log','.stderr.log','.image.bin')]
    bodies={};pins={}
    for n in names:pins[n],bodies[n]=common.read(directory/n,2<<20)
    r=json.loads(bodies['varint.receipt.json']);q=json.loads(bodies['varint.request.json']);s=json.loads(bodies['varint.stdout.log'])
    added={'case','input_sha256','input_bytes','artifact_sha256','format','runner_sha256','wall_elapsed_ns','produced_image','produced_bytes','produced_sha256'}
    common.require(set(r)-set(s)==added and {k:v for k,v in r.items() if k not in added}==s,'new compiler stdout complete projection')
    source=common.read(ROOT/'reference/source8-actual/tests/sqlite_varint.hiaasm')[1];image=bodies['varint.image.bin'];output=bodies['varint.output.bin']
    b3=request['inputs']['compiler-inputs/B3.image.bin']['sha256']
    source_sha=hashlib.sha256(source).hexdigest();image_sha=hashlib.sha256(image).hexdigest()
    common.require(bodies['varint.input.bin']==source and image==output[:len(image)]
        and len(output)==1<<20 and 0<len(image)<=1<<20 and q['image']==str(ROOT/'compiler-inputs/B3.image.bin')
        and q['source']==str(directory/'varint.input.bin') and q['output']==str(directory/'varint.output.bin')
        and q['image_sha256']==b3 and q['source_sha256']==source_sha and q['format']=='flat-x86-64'
        and q['capacity']==1<<20 and q['workspace_size']==1<<20 and q['workspace_fill']==0
        and r['status']=='returned' and type(r['abi_status'])is int and r['abi_status']==0
        and type(r['core_u32'])is int and r['core_u32']==len(image)==r['result_u64']==r['produced_bytes']
        and r['produced_image']==str(directory/'varint.image.bin') and r['produced_sha256']==image_sha
        and r['source_unchanged'] is True and r['forbidden_compiler_modules_loaded']==[]
        and r['source_sha256']==r['input_sha256']==source_sha and r['image_sha256']==r['artifact_sha256']==b3
        and r['runner_sha256']==request['original_child_sha256'] and r['input_bytes']==len(source)
        and r['output_sha256']==hashlib.sha256(output).hexdigest() and r['format']=='flat-x86-64'
        and r['limits']=={'cpu_seconds':10,'address_bytes':256<<20,'core_dumpable':False,
            'stack_bytes':8<<20,'output_capacity':1<<20,'workspace_bytes':1<<20}
        and type(r['wall_elapsed_ns'])is int and 0<=r['wall_elapsed_ns']<=20000000000,
        'original 20/10/1MiB compiler full receipt/image join')
    return {'pins':pins,'receipt':r,'image_sha256':image_sha,'image_bytes':len(image)}
def inspect_caps_and_retained():
    _,doc=read_json(ROOT/'reference/source8-actual/tests/CORE.json')
    pin,assembly=common.read(ROOT/'reference/source8-actual/tests/sqlite_varint.hiaasm',1<<20)
    f=doc['functions'];blocks=[b for x in f for b in x['blocks']];ops=sum(len(b['ops']) for b in blocks)
    common.require(len(f)==6<=128 and len(blocks)==54<=1536 and ops==181<=8192
        and len(assembly.decode().split('\n'))==303<=16384,'original HIA total caps')
    ssa=[]
    def walk(v):
        if isinstance(v,dict):
            for k,x in v.items():
                if k in ('args','params') and isinstance(x,list):common.require(len(x)<=16,'16 args')
                walk(x)
        elif isinstance(v,list):
            for x in v:walk(x)
        elif isinstance(v,str) and v.startswith('v') and v[1:].isdigit():ssa.append(int(v[1:]))
    walk(doc);common.require(max(ssa)==128<=2047,'original SSA domain')
    for x in f:
        common.require(len(x['blocks'])<=256 and len(x['returns'])<=3,'original function caps')
        for b in x['blocks']:
            for op in b['ops']:common.require(len(op.get('out',[]))<=3,'original multi-result')
    _,ret=read_json(ROOT/'candidate/reference/RETAINED-CONTROLS.json');total=0
    for r in ret['files']:
        _,b=common.read(ROOT/'source-base'/r['path'])
        common.require(hashlib.sha256(b).hexdigest()==r['sha256'],'retained control original')
        parsed=ast.parse(b);ids=[x.name+'.'+m.name for x in parsed.body if isinstance(x,ast.ClassDef)
            for m in x.body if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and m.name.startswith('test_')]
        common.require(ids==r['test_ids_in_source_order'],'retained IDs unchanged');total+=len(ids)
    common.require(total==59,'old persistence methods retained only')
    return {'assembly':pin,'functions':len(f),'blocks':len(blocks),'operations':ops,
            'ssa_max':max(ssa),'original_source8_methods':8,'source8_reexecuted':False,
            'existing_persistence_methods_preserved_not_executed':total}
def inspect_official_oracles():
    _,up=read_json(ROOT/'candidate/reference/UPSTREAM.json')
    common.require([v['version'] for v in up['versions']]==list(matrix.VERSIONS),'two original C versions')
    rows=[]
    for r in up['versions']:
        p,full=common.read(ROOT/'candidate/reference'/('sqlite-'+r['version'])/'util.c.original')
        q,selected=common.read(ROOT/'candidate/inputs'/r['selected_file'])
        start,end=r['contiguous_byte_range']
        common.require(full[start:end]==selected and p['sha256']==r['full_util_original']['sha256']
            and q['sha256']==r['selected']['sha256'] and r['public_function_denominator']==2
            and r['complete_dependency_functions']==1,'complete official original C algorithms')
        rows.append({'version':r['version'],'full':p,'selected':q,'range':[start,end]})
    return rows
