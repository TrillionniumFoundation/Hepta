"""WAL finite-native readback; shared proven owner, capacity and exact image-map binding."""
from pathlib import Path
import ast,ctypes,hashlib,importlib.util,json,mmap,os,platform,stat,struct,sys,zlib
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
        and manifest['source_root']==str(Path(request['source_root'])) and manifest['input_count']==1686
        and manifest['bytes']==40890650 and len(manifest['files'])==1686,'whole 0504 physical input set')
    rows={}
    for item in manifest['files']:
        name=item['path'];common.require(type(name)is str and not name.startswith('/') and '..' not in Path(name).parts,'source relative path')
        pin,_=common.read(Path(request['source_root'])/name)
        common.require(all(pin[k]==item[k] for k in ('bytes','sha256','git_blob','identity'))
            and ('100755' if pin['identity'][2]&0o111 else '100644')==item['mode'],
            'current source exact bytes/mode/identity: '+name)
        common.require(name not in rows,'duplicate source entry');rows[name]=pin
    found=set()
    for base,dirs,names in os.walk(Path(request['source_root']),followlinks=False):
        for d in dirs:common.require(stat.S_ISDIR((Path(base)/d).lstat().st_mode),'source directory link')
        for n in names:
            p=Path(base)/n;common.require(stat.S_ISREG(p.lstat().st_mode),'source special')
            found.add(str(p.relative_to(Path(request['source_root']))))
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
    source={str(Path(request['source_root'])/r):p for r,p in source_records(request).items()}
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
def loaded_file_maps(request,own,codec,entry,installed_entry,expected_image,evidence):
    """Bind the current image object; a deleted pathname alone grants no admission."""
    _,system=read_json(ROOT/request['system_map'])
    allowed={r['path']:r for r in system['files']}
    allowed.update({str(Path(p).resolve(strict=True)):r for p,r in own.items()})
    image_pin,image=common.read(expected_image['path'],1<<20)
    common.require(all(image_pin[k]==expected_image[k] for k in ('bytes','sha256','git_blob','identity')),
                   'current compiled image changed before mapping observation')
    mapped=codec._mapping
    common.require(type(mapped)is mmap.mmap and not mapped.closed
        and isinstance(entry,ctypes._CFuncPtr) and codec._entry is installed_entry,
        'only the current image mmap, original entry and installed observer may be bound')
    page=os.sysconf('SC_PAGESIZE')
    common.require(type(page)is int and page>0 and page&(page-1)==0 and page==mmap.PAGESIZE,
                   'actual page size')
    size=len(mapped)
    common.require(type(size)is int and 0<size==len(image)<=1<<20
        and codec.image_sha256==image_pin['sha256'],'image mmap length and admitted hash')
    address=ctypes.addressof(ctypes.c_char.from_buffer(mapped))
    entry_address=ctypes.cast(entry,ctypes.c_void_p).value
    common.require(type(address)is int and address>0 and address%page==0
        and type(entry_address)is int and entry_address==address,'original entry equals current mmap start')
    end=address+((size+page-1)//page)*page
    descriptor={'schema':'hia.sqlite.wal.current-image-mapping.v1','mapping_object_id':id(mapped),
        'entry_object_id':id(entry),'observer_object_id':id(installed_entry),'address':address,
        'entry_address':entry_address,'logical_bytes':size,'page_size':page,'mapping_end':end,
        'image':image_pin,'requires_exact_single_segment':True}
    raw=Path('/proc/self/maps').read_bytes()
    common.require(len(raw)<=1<<20,'bounded actual maps')
    evidence=Path(evidence)
    maps_pin=common.create(evidence.with_suffix('.maps.original'),raw,raw=True)
    common.create(evidence.with_suffix('.binding-start.json'),descriptor)
    parsed=[];previous_end=0
    for line in raw.decode('ascii').splitlines():
        f=line.split(None,5)
        common.require(len(f) in (5,6),'malformed actual maps line')
        span=f[0].split('-');dev=f[3].split(':')
        common.require(len(span)==len(dev)==2,'actual maps span/device')
        start,stop=(int(v,16) for v in span);offset=int(f[2],16);device=tuple(int(v,16) for v in dev);inode=int(f[4])
        perms=f[1];name=f[5] if len(f)==6 else ''
        common.require(0<=previous_end<=start<stop<=1<<64 and offset>=0 and inode>=0
            and len(perms)==4 and perms[0] in 'r-' and perms[1] in 'w-'
            and perms[2] in 'x-' and perms[3] in 'ps','whole sorted nonoverlapping map records')
        previous_end=stop
        parsed.append({'line':line,'start':start,'end':stop,'offset':offset,'device':device,
                       'inode':inode,'permissions':perms,'name':name})
    overlaps=[r for r in parsed if r['start']<end and r['end']>address]
    common.require(len(overlaps)==1,'current HIA mapping must have one exact exclusive segment')
    bound=overlaps[0]
    common.require(bound['start']==address and bound['end']==end and bound['offset']==0
        and bound['permissions']=='r-xs','current HIA exact page-rounded shared RX segment')
    common.require((bound['name']=='/dev/zero (deleted)' and bound['inode']>0)
        or (bound['name']=='' and bound['inode']==0 and bound['device']==(0,0)),
        'only the address-bound current HIA anonymous backing representation')
    for row in parsed:
        if row is bound:continue
        common.require(not(bound['inode']>0 and row['inode']==bound['inode'] and row['device']==bound['device']),
                       'current HIA anonymous backing has an additional mapped alias')
    from_object=mapped[:]
    from_address=ctypes.string_at(address,size)
    common.require(type(from_object)is bytes and from_object==from_address==image
        and hashlib.sha256(from_object).hexdigest()==codec.image_sha256==image_pin['sha256'],
        'complete logical image bytes from both mmap object and actual entry address')
    common.require(codec._mapping is mapped and not mapped.closed and len(mapped)==size
        and codec._entry is installed_entry and ctypes.cast(entry,ctypes.c_void_p).value==address,
        'mapping and original entry identity changed during observation')
    rows=[];read_files={};kernel=[]
    for row in parsed:
        if row is bound:
            rows.append({'line':row['line'],'file':None,'role':'current-bound-HIA-image'});continue
        name=row['name']
        if not name.startswith('/'):
            if 'x' in row['permissions']:
                common.require(row['inode']==0 and row['device']==(0,0) and row['offset']==0
                    and ((name=='[vdso]' and row['permissions']=='r-xp')
                         or (name=='[vsyscall]' and row['permissions']=='--xp')),
                    'unbound executable anonymous mapping refused')
                kernel.append(row['line'])
            rows.append({'line':row['line'],'file':None,'role':'kernel-executable' if 'x' in row['permissions'] else 'non-executable-anonymous'})
            continue
        common.require(not name.endswith(' (deleted)'),'unbound deleted mapping refused')
        key=str(Path(name).resolve(strict=True))
        common.require(key in allowed,'loaded file outside frozen runtime/oracle closure: '+key)
        if key not in read_files:
            p=common.read(key,1<<20)[0] if key in own else system_read(key)
            common.require(all(p[k]==allowed[key][k] for k in ('bytes','sha256','git_blob','identity')),
                           'actual mapped file changed')
            read_files[key]=p
        p=read_files[key]
        common.require(row['device']==(os.major(p['identity'][0]),os.minor(p['identity'][0]))
            and row['inode']==p['identity'][1],'mapped device/inode differs')
        rows.append({'line':row['line'],'file':key,'role':'frozen-file'})
    descriptor['actual_segment']=bound
    descriptor['complete_image_sha256']=hashlib.sha256(from_address).hexdigest()
    descriptor['page_rounding_tail_not_hashed_as_image']=end-address-size
    return {'maps':rows,'maps_original':maps_pin,'files':read_files,'image_binding':descriptor,
            'kernel_executable_rows':kernel,'all_file_backed_mappings_joined':True,
            'all_executable_mappings_classified':True}
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
    directory=Path(directory);label='wal'
    names=[label+s for s in ('.input.bin','.output.bin','.request.json','.receipt.json','.stdout.log','.stderr.log','.image.bin')]
    bodies={};pins={}
    for n in names:pins[n],bodies[n]=common.read(directory/n,2<<20)
    r=json.loads(bodies['wal.receipt.json']);q=json.loads(bodies['wal.request.json']);s=json.loads(bodies['wal.stdout.log'])
    added={'case','input_sha256','input_bytes','artifact_sha256','format','runner_sha256','wall_elapsed_ns','produced_image','produced_bytes','produced_sha256'}
    common.require(set(r)-set(s)==added and {k:v for k,v in r.items() if k not in added}==s,'new compiler stdout complete projection')
    source=common.read(Path(request['output'])/'source-generation/sqlite_wal.hiaasm')[1];image=bodies['wal.image.bin'];output=bodies['wal.output.bin']
    b3=request['inputs']['compiler-inputs/B3.image.bin']['sha256']
    source_sha=hashlib.sha256(source).hexdigest();image_sha=hashlib.sha256(image).hexdigest()
    common.require(bodies['wal.input.bin']==source and image==output[:len(image)]
        and len(output)==1<<20 and 0<len(image)<=1<<20 and q['image']==str(ROOT/'compiler-inputs/B3.image.bin')
        and q['source']==str(directory/'wal.input.bin') and q['output']==str(directory/'wal.output.bin')
        and q['image_sha256']==b3 and q['source_sha256']==source_sha and q['format']=='flat-x86-64'
        and q['capacity']==1<<20 and q['workspace_size']==1<<20 and q['workspace_fill']==0
        and r['status']=='returned' and type(r['abi_status'])is int and r['abi_status']==0
        and type(r['core_u32'])is int and r['core_u32']==len(image)==r['result_u64']==r['produced_bytes']
        and r['produced_image']==str(directory/'wal.image.bin') and r['produced_sha256']==image_sha
        and r['source_unchanged'] is True and r['forbidden_compiler_modules_loaded']==[]
        and r['source_sha256']==r['input_sha256']==source_sha and r['image_sha256']==r['artifact_sha256']==b3
        and r['runner_sha256']==request['original_child_sha256'] and r['input_bytes']==len(source)
        and r['output_sha256']==hashlib.sha256(output).hexdigest() and r['format']=='flat-x86-64'
        and r['limits']=={'cpu_seconds':10,'address_bytes':256<<20,'core_dumpable':False,
            'stack_bytes':8<<20,'output_capacity':1<<20,'workspace_bytes':1<<20}
        and type(r['wall_elapsed_ns'])is int and 0<=r['wall_elapsed_ns']<=20000000000,
        'original 20/10/1MiB compiler full receipt/image join')
    return {'pins':pins,'receipt':r,'image_sha256':image_sha,'image_bytes':len(image)}
def inspect_source_generation(request):
    directory=Path(request['output'])/'source-generation'
    gp,g=read_json(directory/'GENERATION.json')
    common.require(g['status']=='SOURCE_GENERATION_ONLY' and g['exception'] is None and g['denied_effects']==[]
        and g['VM_executed'] is False and g['native_executed'] is False and g['roundtrip_equal'] is True
        and g['inputs']['author']==common.read(ROOT/'candidate/inputs/tools/generate_hia_sqlite_wal.py')[0]
        and g['inputs']['test']==common.read(ROOT/'candidate/inputs/tests/test_hia_sqlite_wal_source.py')[0],
        'new same-owner source generation and no old VM actual reconstruction')
    cp,doc=read_json(directory/'CORE.json');pp,program=read_json(directory/'PROGRAM.json')
    ap,assembly=common.read(directory/'sqlite_wal.hiaasm',1<<20)
    common.require(g['outputs']=={'CORE.json':cp,'PROGRAM.json':pp,'sqlite_wal.hiaasm':ap},
                   'actual whole generated documents and assembly')
    funcs=doc['functions'];blocks=[block for f in funcs for block in f['blocks']]
    operations=sum(len(block['ops']) for block in blocks);ssa=[]
    common.require(len(funcs)==6<=128 and len(blocks)<=1536 and operations<=8192
        and len(assembly.decode().split('\n'))<=16384,'original total Core and line limits')
    def walk(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key in ('args','params') and isinstance(item,list):common.require(len(item)<=16,'16 args including edges')
                walk(item)
        elif isinstance(value,list):
            for item in value:walk(item)
        elif isinstance(value,str) and value.startswith('v') and value[1:].isdigit():ssa.append(int(value[1:]))
    walk(doc);common.require(ssa and max(ssa)<=2047,'original SSA domain')
    for f in funcs:
        common.require(len(f['blocks'])<=256 and len(f['returns'])<=3,'original per-function limits')
        for block in f['blocks']:
            for op in block['ops']:common.require(len(op.get('out',[]))<=3,'original result cap')
    testpin,test=common.read(ROOT/'candidate/inputs/tests/test_hia_sqlite_wal_source.py')
    parsed=ast.parse(test)
    classes=[x for x in parsed.body if isinstance(x,ast.ClassDef) and x.name=='SQLiteWalSourceTests']
    common.require(len(classes)==1 and [x.name for x in classes[0].body
        if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)) and x.name.startswith('test_')]==list(matrix.NAMES),
        'original ten source method bodies and order remain physically frozen')
    common.require(g['caps']=={'functions':len(funcs),'blocks':len(blocks),'operations':operations,
        'ssa_max':max(ssa),'lines':len(assembly.decode().split('\n'))},'actual generation counts')
    return {'generation':gp,'assembly':ap,'CORE':cp,'program':pp,'caps':g['caps'],
            'original_methods':10,'new_native_backend':True,'old_VM_actual_reconstructed':False}
def inspect_official_oracles():
    _,up=read_json(ROOT/'candidate/reference/UPSTREAM.json')
    _,native=read_json(ROOT/'NEW-C-ORACLES.json')
    common.require([r['version'] for r in up['sources']]==list(matrix.VERSIONS)
        and [r['version'] for r in native['versions']]==list(matrix.VERSIONS),'two full official C domains')
    rows=[]
    for item,n in zip(up['sources'],native['versions']):
        root=ROOT/'candidate/reference'/('sqlite-'+item['version'])
        p,full=common.read(root/'wal.c.original')
        common.require(p['bytes']==item['whole_source_bytes'] and p['sha256']==item['whole_source_sha256']
            and p['git_blob']==item['whole_source_git_blob'],'whole official wal.c source')
        excerpts=[]
        for e in item['exact_function_excerpts']:
            q,part=common.read(root/e['file'])
            common.require(part==full[e['start_byte']:e['end_byte_exclusive']]+b'\n'
                and q['sha256']==e['sha256'] and q['git_blob']==e['git_blob'] and q['bytes']==e['bytes'],
                'whole original checksum/frame function excerpt')
            excerpts.append(q)
        h=n['header_checks'];hp,hb=common.read(ROOT/h['path'])
        common.require(hb==full[h['start_byte']:h['end_byte_exclusive']]+b'\n'
            and all(hp[k]==h[k] for k in ('bytes','sha256','git_blob')),'complete original header-check block')
        native_files={}
        for name,pin in n['inputs'].items():
            q,body=common.read(ROOT/name)
            common.require(all(q[k]==pin[k] for k in ('bytes','sha256','git_blob')),'finite C transport source')
            native_files[name]=q
        rows.append({'version':item['version'],'full':p,'original_functions':excerpts,
                     'header_checks':hp,'native_inputs':native_files,
                     'C_failed_seed_is_not_HIA_unchanged_output':True})
    return rows
