"""Independent read-only audit of the once-closed ai395 varint R3 experiment.
No project imports, compiler, VM, native call, SQL, network, or process launch.
The producer's original files are read only and never rewritten.
"""
from pathlib import Path
from contextlib import contextmanager
import hashlib,json,os,stat,struct,sys,time,traceback,zlib
ROOT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r3')
OUT=ROOT.parent/'varint-native-r3-actual'
AUDIT=ROOT.parent/'varint-native-r3-independent-audit-r1'
REQUEST_SHA='0f749e45d07d9d6e65c4e54a237d63a1c9b5277c8de8a72f8aac1f35ffa58ee8'
CANARY=bytes(range(64));MASK=(1<<64)-1
MAGIC=int.from_bytes(b'HIASVR01','little')
PROTOCOL,TRUNCATED,CAPACITY=0xfffffffd,0xfffffffe,0xfffffffc
VERSIONS=('3.46.0','3.53.2')
NAMES=('test_01_original_1618_complete_VM_buffers','test_02_all_65536_initialized_two_byte_prefixes',
'test_03_fixed_4096_full_u64_roundtrips','test_04_public_bridge_boundaries_and_nonminimal',
'test_05_public_truncation_and_capacity','test_06_foreign_types_exception_identity_and_canaries',
'test_07_two_original_C_oracles_and_sources','test_08_original_caps_and_source_population')
IDS=['tests.hia_sqlite_varint_native_finite_r2.SQLiteVarintNativeTests.'+n for n in NAMES]
COUNTS=[1618,65536,8192,597,108,3,0,0]
report={'schema':'hia.sqlite.varint.independent-actual-readback.v1','status':'HOLD',
        'owner_closed':False,'checks':0,'errors':[],'producer_files_modified':False,
        'native_or_C_or_VM_execution':False,'source8_reexecuted':False}
def check(ok,why):
    report['checks']+=1
    if not ok:raise RuntimeError(why)
def wire(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def equal(a,b):return wire(a)==wire(b)
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
@contextmanager
def parent_fd(path):
    p=Path(path);check(p.is_absolute() and '..' not in p.parts,'absolute safe path')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in p.parts[1:-1]:
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=new
        yield fd,p.name
    finally:os.close(fd)
def read(path,maximum=64<<20,system=False,keep=True):
    path=Path(path)
    with parent_fd(path) as (parent,name):
        s=os.stat(name,dir_fd=parent,follow_symlinks=False)
        check(stat.S_ISREG(s.st_mode) and 0<=s.st_size<=maximum,'regular bounded file '+str(path))
        check((s.st_nlink>=1 and s.st_uid==0 and not s.st_mode&0o022) if system else s.st_nlink==1,
              'exact regular input role '+str(path))
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            check(ident(os.fstat(fd))==ident(s),'open identity '+str(path))
            sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(s.st_size).encode()+b'\0')
            crc=count=0;chunks=[]
            while True:
                b=os.read(fd,1<<20)
                if not b:break
                count+=len(b);check(count<=s.st_size,'file grew '+str(path))
                sha.update(b);git.update(b);crc=zlib.crc32(b,crc)
                if keep:chunks.append(b)
            check(count==s.st_size and ident(s)==ident(os.fstat(fd))
                  ==ident(os.stat(name,dir_fd=parent,follow_symlinks=False)),'whole file stable '+str(path))
        finally:os.close(fd)
    return {'path':str(path),'bytes':count,'sha256':sha.hexdigest(),'git_blob':git.hexdigest(),
            'crc32':crc&0xffffffff,'identity':ident(s)},b''.join(chunks) if keep else None
def pairs(rows):
    out={}
    for k,v in rows:
        if k in out:raise ValueError('duplicate JSON key '+k)
        out[k]=v
    return out
def parse(raw):
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda v:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def doc(path,maximum=64<<20):
    pin,raw=read(path,maximum);return pin,parse(raw),raw
def pin_matches(p,q):
    return all(equal(p[k],q[k]) for k in ('path','bytes','sha256','git_blob','identity'))
def create(name,data):
    raw=wire(data);path=AUDIT/name
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        v=memoryview(raw)
        while v:
            n=os.write(fd,v);check(n>0,'audit short write');v=v[n:]
        os.fsync(fd)
    finally:os.close(fd)
    return read(path)[0]
def owner(request,request_pin):
    lp,life,_=doc(OUT/'lifecycle.json',4<<20)
    qp,q,_=doc(OUT/'lifecycle.json.request.json',1<<20)
    rp,r,_=doc(OUT/'OWNER-RETURN.json',4<<20)
    rc=r.pop('supervisor_returncode',None);seal=r.pop('receipt_sha256',None)
    check(equal(r,life) and type(rc)is int and seal==lp['sha256'],'wrapper exactly original receipt + two fields')
    command=[REQUEST_SHA if x=='@REQUEST_SHA256@' else x for x in request['command']]
    check(q['command']==command and q['cwd']==str(ROOT) and equal(q['env'],request['environment']),'owner command/cwd/env')
    check(q['qualification_seconds']==life['qualification_seconds']==180
          and q['cleanup_seconds']==life['cleanup_seconds']==3
          and q['deadline_ns']-q['started_ns']==180000000000,'original 180/3')
    check(q['stdout_path']==str(OUT/'stdout.log') and q['stderr_path']==str(OUT/'stderr.log')
          and q['receipt_path']==str(OUT/'lifecycle.json'),'owner output paths')
    check(life['schema']==q['schema']=='hepta.hia.selfhost-process-owner.v1'
          and life['implementation_sha256']==q['implementation_sha256']
          ==request['inputs']['control/process_owner_impl.py']['sha256']
          and life['request_sha256']==qp['sha256'] and life['parent_pid']==q['parent_pid'],'owner full binding')
    c=life['cleanup']
    check(life['subreaper_enabled'] is True and life['event_overflow'] is False
          and c['complete'] is True and c['observed_echild'] is True and c['leader_reaped'] is True
          and c['remaining_direct_children']==[] and c['errors']==[] and c['deadline_exceeded'] is False,
          'kernel ECHILD required before any child output enumeration')
    check(type(life['returncode']) is int and life['returncode']==0 and rc==0
          and life['status']=='OWNED_PROCESS_COMPLETED' and life['timed_out'] is False
          and life['exit_observed_before_deadline'] is True and life.get('owner_error') is None
          and life['interrupted_signals']==[]
          and [e['kind'] for e in life['events']]==['qualification_started','owned_child_observed',
              'qualification_exit_observed','owned_child_reaped']
          and all(e['pid']==life['qualification_pid'] for e in life['events']),
          'original natural closed zero success')
    report['owner_closed']=True
    natural=(rc==0 and life['status']=='OWNED_PROCESS_COMPLETED' and type(life['returncode'])is int
       and life['returncode']==0 and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
       and life.get('owner_error') is None and life['interrupted_signals']==[]
       and [e['kind'] for e in life['events']]==['qualification_started','owned_child_observed',
          'qualification_exit_observed','owned_child_reaped']
       and all(e['pid']==life['qualification_pid'] for e in life['events']))
    report['owner']={'life':lp,'request':qp,'returned':rp,'natural':natural,
                     'status':life['status'],'returncode':life['returncode'],'events':life['events']}
    return natural
def catalog():
    rows=[];dirs=[];total=0
    for base,sub,names in os.walk(OUT,followlinks=False):
        for n in sorted(sub):
            p=Path(base)/n;s=p.lstat();check(stat.S_ISDIR(s.st_mode),'no child directory symlink')
            dirs.append({'path':str(p.relative_to(OUT)),'identity':ident(s)})
        for n in sorted(names):
            p=Path(base)/n;pin,_=read(p,64<<20,keep=False);total+=pin['bytes']
            rows.append({'relative_path':str(p.relative_to(OUT)),**pin})
            check(len(rows)<=192 and total<=384<<20,'unchanged whole output quota')
    return {'files':rows,'directories':dirs,'file_count':len(rows),'bytes':total,'all_bodies_read':True}
def public_pin(p):return {k:p[k] for k in ('path','bytes','sha256','git_blob','identity')}
def fresh_frozen(request):
    frozen={}
    for n,w in request['inputs'].items():
        p,_=read(ROOT/n,keep=False);check(all(equal(p[k],w[k]) for k in ('bytes','sha256','git_blob','identity')),'frozen '+n)
        frozen[n]=public_pin(p)
    check(len(frozen)==94 and {p.name for p in (ROOT/'control').iterdir()}
          =={Path(n).name for n in frozen if n.startswith('control/')},'94 + exact control directory')
    _,manifest,_=doc(ROOT/'SOURCE-BASE.json');source={}
    check(manifest['source_commit']==request['source_commit']=='0504beb11c0dae875d8590660c42488b7bc634fb'
          and manifest['input_count']==len(manifest['files'])==1686,'source original population')
    for w in manifest['files']:
        name=w['path'];check(name not in source,'duplicate source row')
        p,_=read(ROOT/'source-base'/name,keep=False)
        check(all(equal(p[k],w[k]) for k in ('bytes','sha256','git_blob','identity')),'source physical '+name)
        check(('100755' if p['identity'][2]&0o111 else '100644')==w['mode'],'source Git mode '+name)
        source[name]=public_pin(p)
    check(sum(p['bytes'] for p in source.values())==40890650,'source full bytes')
    _,system_doc,_=doc(ROOT/request['system_map']);system={}
    for w in system_doc['files']:
        p,_=read(w['path'],128<<20,system=True,keep=False)
        check(pin_matches(p,w) and p['path'] not in system,'system exact role/body '+w['path'])
        system[p['path']]=public_pin(p)
    check(len(system)==4806 and sum(p['bytes'] for p in system.values())==179325490,'system full bytes')
    for alias,target in system_doc['aliases'].items():
        check(str(Path(alias).resolve(strict=True))==target,'system alias '+alias)
    for stem,current in [('INPUTS',frozen),('SOURCE',source),('SYSTEM',system)]:
        parent_before=doc(OUT/('PARENT-'+stem+'-BEFORE.json'))[1]
        worker_prefix='' if stem=='SYSTEM' else 'WORKER-'
        worker_before=doc(OUT/(worker_prefix+stem+'-BEFORE.json'))[1]
        check(equal(current,parent_before) and equal(current,worker_before),'before snapshots versus independent after-read '+stem)
        for name in ('PARENT-'+stem+'-AFTER.json',worker_prefix+stem+'-AFTER.json'):
            check(equal(doc(OUT/name)[1],current),'complete producer after-snapshot '+name)
    report['producer_after_snapshots']='Parent and worker all three before/after whole maps equal fresh independent reads.'
    report['fresh_inputs']={'frozen_count':len(frozen),'source_count':len(source),'source_bytes':40890650,
       'system_count':len(system),'system_bytes':179325490,'parent_and_worker_before_equal_independent_after':True}
    return frozen,source,system
def compiler_chain(directory,label,historical=False):
    names=[label+s for s in ('.input.bin','.output.bin','.request.json','.receipt.json','.stdout.log','.stderr.log','.image.bin')]
    bodies={};pins={}
    for n in names:pins[n],bodies[n]=read(directory/n,2<<20)
    q=parse(bodies[label+'.request.json']);r=parse(bodies[label+'.receipt.json']);s=parse(bodies[label+'.stdout.log'])
    added={'case','input_sha256','input_bytes','artifact_sha256','format','runner_sha256','wall_elapsed_ns','produced_image','produced_bytes','produced_sha256'}
    check(set(r)-set(s)==added and equal({k:v for k,v in r.items() if k not in added},s),'complete compiler stdout/receipt projection')
    image=bodies[label+'.image.bin'];source=bodies[label+'.input.bin'];full=bodies[label+'.output.bin']
    check(image==full[:len(image)] and len(full)==1<<20 and 0<len(image)<=1<<20
          and r['status']=='returned' and type(r['abi_status'])is int and r['abi_status']==0
          and r['source_unchanged'] is True and r['forbidden_compiler_modules_loaded']==[]
          and type(r['core_u32'])is int and r['core_u32']==r['result_u64']==r['produced_bytes']==len(image)
          and r['output_sha256']==hashlib.sha256(full).hexdigest()
          and r['input_sha256']==r['source_sha256']==q['source_sha256']==hashlib.sha256(source).hexdigest()
          and r['produced_sha256']==hashlib.sha256(image).hexdigest(),'complete compiler output and source')
    if historical:
        _,custody,_=doc(ROOT/'reference/B3-ORIGINALS-CUSTODY.json')
        check(len(custody['members'])==7 and {p.name for p in directory.iterdir()}==set(names),'historical seven originals')
        for w in custody['members']:
            p=pins[w['path']]
            check(p['bytes']==w['size'] and p['sha256']==w['sha256'] and p['git_blob']==w['git_blob_sha1']
                  and p['crc32']==w['zip_crc32'],'historical official CRC/SHA/body')
        check(len(image)==670467 and hashlib.sha256(image).hexdigest()=='9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892','development B3 fixed')
    else:
        assembly=read(ROOT/'reference/source8-actual/tests/sqlite_varint.hiaasm')[1]
        check(source==assembly and q['image']==str(ROOT/'compiler-inputs/B3.image.bin')
              and q['source']==str(directory/(label+'.input.bin')) and q['output']==str(directory/(label+'.output.bin'))
              and q['image_sha256']==r['image_sha256']==r['artifact_sha256']=='9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892'
              and q['capacity']==q['workspace_size']==1<<20 and q['workspace_fill']==0 and q['format']=='flat-x86-64'
              and r['limits']=={'cpu_seconds':10,'address_bytes':256<<20,'core_dumpable':False,'stack_bytes':8<<20,
                               'output_capacity':1<<20,'workspace_bytes':1<<20}
              and type(r['wall_elapsed_ns'])is int and 0<=r['wall_elapsed_ns']<=20000000000,'new original20/10/1MiB compiler')
    return {'files':pins,'image_bytes':len(image),'image_sha256':hashlib.sha256(image).hexdigest(),
            'wall_elapsed_ns':r['wall_elapsed_ns'],'historical_development_only':historical}
def c_compiles(request,system):
    result={}
    import shlex
    for v in VERSIONS:
        root=OUT/('C-'+v);qp,q,_=doc(root/'REQUEST.json');rp,r,_=doc(root/'COMPILE.json')
        adapter=ROOT/'candidate/inputs/tests/fixtures/sqlite_varint'/v/'adapter.c'
        argv=[request['system_binaries']['gcc'],'-std=c11','-O2','-fPIC','-shared','-fno-lto','-fno-common','-g0',
              '-save-temps=obj','-Wl,-Bsymbolic','-Wl,-z,defs','-MD','-MF',str(root/'oracle.d'),
              '-MT',str(root/'oracle.so'),'-Wl,-Map,'+str(root/'oracle.map'),'-o',str(root/'oracle.so'),str(adapter)]
        environment={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC','TMPDIR':str(root/'tmp')}
        check(q['argv']==r['argv']==argv and q['cwd']==r['cwd']==str(root)
              and equal(q['environment'],environment) and equal(r['environment'],environment)
              and pin_matches(qp,r['request']) and r['attempted'] is True and type(r['returncode'])is int and r['returncode']==0
              and r['status']=='C_ORIGINAL_ALGORITHMS_COMPILED_ONLY' and r['timed_out'] is False
              and r['exception'] is None and r['secondary_errors']==[] and 0<=r['elapsed_ns']<=20000000000
              and r['limits']=={'wall_seconds':20,'cpu_seconds':10,'address_bytes':256<<20,'stack_bytes':8<<20,
                                'file_bytes':1<<20,'core_bytes':0},'whole actual C command/receipt '+v)
        check(equal(r['inputs_before'],r['inputs_after']) and equal(r['inputs_before'],q['source_inputs']),'C sources stable')
        image_pin,image=read(root/'oracle.so',1<<20)
        check(pin_matches(image_pin,r['image']) and image[:6]==b'\x7fELF\x02\x01'
              and int.from_bytes(image[16:18],'little')==3 and int.from_bytes(image[18:20],'little')==62,'actual oracle ELF')
        allowed={**system,**q['source_inputs']}
        dp,d=read(root/'oracle.d',1<<20);target,sep,names=d.decode().replace('\\\n','').partition(':')
        check(sep and target.strip()==str(root/'oracle.so'),'actual depfile target')
        deps=[]
        for n in shlex.split(names):
            p=str(Path(n).resolve(strict=True));check(p in allowed,'dep input within frozen closure '+p);deps.append(allowed[p])
        check(deps,'nonempty depfile')
        mp,m=read(root/'oracle.map',1<<20);loads=[]
        for line in m.decode().splitlines():
            if not line.startswith('LOAD '):continue
            p=Path(line[5:].strip()).resolve(strict=True)
            if p.is_relative_to(root):loads.append(read(p,1<<20)[0])
            else:check(str(p) in allowed,'link input frozen '+str(p));loads.append(allowed[str(p)])
        check(loads,'nonempty link map')
        names={p.name for p in root.iterdir() if p.is_file()}
        check(all(any(n.endswith(ext) for n in names) for ext in ('.i','.s','.o')),'complete original preprocessed/asm/object')
        result[v]={'request':qp,'receipt':rp,'image':image_pin,'depfile':dp,'dependencies':deps,'map':mp,'link_inputs':loads}
    return result

def arithmetic(a,b,c):
    status=PROTOCOL;after=b;oracle=None
    if len(c)==16:
        magic,op=struct.unpack('<QQ',c)
        if magic==MAGIC and op==1 and len(a)<=9 and len(b)==8:
            value=0;n=None
            for i,x in enumerate(a):
                if i==8:value=(value<<8)|x;n=9;break
                value=(value<<7)|(x&127)
                if not x&128:n=i+1;break
            if n is None:status=TRUNCATED
            else:
                status=n;after=value.to_bytes(8,'little')
                oracle={'operation':'get','raw_hex':a.hex(),'value':value,'count':n}
        elif magic==MAGIC and op==2 and len(a)==8 and len(b)<=9:
            value=int.from_bytes(a,'little');encoded=independent_encode(value)
            oracle={'operation':'put','value':value,'encoded_hex':encoded.hex(),'count':len(encoded)}
            if len(b)<len(encoded):status=CAPACITY
            else:status=len(encoded);after=encoded+b[len(encoded):]
    return {'status':status,'source_after_hex':a.hex(),'output_after_hex':after.hex(),
            'command_after_hex':c.hex(),'oracle':oracle}
def independent_encode(v):
    if v>>56:
        return bytes([128|((v>>(8+7*(7-i)))&127) for i in range(8)]+[v&255])
    n=max(1,(v.bit_length()+6)//7)
    return bytes([((v>>(7*(n-1-i)))&127)|(128 if i<n-1 else 0) for i in range(n)])
def rows_expected():
    ordinal=0
    def row(method,label,a,b,c):
        nonlocal ordinal
        ordinal+=1
        return {'index':ordinal,'method':IDS[method-1],'label':label,'source_hex':a.hex(),
                'output_hex':b.hex(),'command_hex':c.hex(),'expected':arithmetic(a,b,c)}
    _,vm,_=doc(ROOT/'reference/source8-actual/tests/VM-RAW.json',8<<20)
    check(vm['schema']=='hia.sqlite-varint.source-vm-raw.v1' and len(vm['calls'])==1618,'original 1618 retained vectors')
    for i,x in enumerate(vm['calls'],1):
        a,b,c=[bytes.fromhex(x[k]) for k in ('source_before_hex','output_before_hex','workspace_before_hex')]
        e=arithmetic(a,b,c)
        check(x['actual_returned'] is True and type(x['status'])is int and x['status']==e['status']
              and x['source_after_hex']==e['source_after_hex'] and x['output_after_hex']==e['output_after_hex']
              and x['workspace_after_hex']==e['command_after_hex'],'original VM row independently recomputed')
        yield row(1,'vm-%04d'%i,a,b,c)
    command=lambda op:struct.pack('<QQ',MAGIC,op)
    for prefix in range(65536):
        yield row(2,'prefix-%04x'%prefix,prefix.to_bytes(2,'big')+b'\x80'*6+b'\x55',b'\xa5'*8,command(1))
    state=0x4853494153514c56
    for i in range(4096):
        state=(state+0x9e3779b97f4a7c15)&MASK
        z=state;z=((z^(z>>30))*0xbf58476d1ce4e5b9)&MASK
        z=((z^(z>>27))*0x94d049bb133111eb)&MASK;v=(z^(z>>31))&MASK
        yield row(3,'random-%04d-put'%i,v.to_bytes(8,'little'),b'\xa5'*9,command(2))
        yield row(3,'random-%04d-get'%i,independent_encode(v),b'\xa5'*8,command(1))
    vals={0,1,MASK-1,MASK}
    for bit in range(64):
        vals.update(v for v in ((1<<bit)-1,1<<bit,(1<<bit)+1) if 0<=v<=MASK)
    check(len(vals)==191,'191 complete boundary values')
    for i,v in enumerate(sorted(vals)):
        raw=independent_encode(v)
        yield row(4,'public-%03d-encode'%i,v.to_bytes(8,'little'),b'\xa5'*9,command(2))
        yield row(4,'public-%03d-decode'%i,(raw+b'tail')[:9],b'\xa5'*8,command(1))
        yield row(4,'public-%03d-into'%i,v.to_bytes(8,'little'),b'\xa5'*9,command(2))
    for n in range(2,10):
        for terminal in (0,1,127):
            raw=b'\x80'*(n-1)+bytes([terminal])
            yield row(4,'nonminimal-%d-%d'%(n,terminal),(raw+b'tail')[:9],b'\xa5'*8,command(1))
    for n in range(9):
        for byte in (128,255):
            yield row(5,'truncated-%d-%d'%(n,byte),bytes([byte])*n,b'\xa5'*8,command(1))
    for n in range(1,10):
        v=0 if n==1 else 1<<(7*(n-1))
        for cap in range(10):
            yield row(5,'capacity-%d-%d'%(n,cap),v.to_bytes(8,'little'),b'\xa5'*cap,command(2))
    for kind in ('source','command','tail'):
        yield row(6,'caught-canary-'+kind,(128).to_bytes(8,'little'),b'\xa5'*9,command(2))
def oracle_expected(spec,v):
    o=spec['expected']['oracle']
    if o is None:return {'version':v,'called':False}
    if o['operation']=='get':
        a=bytes.fromhex(o['raw_hex']);a+=b'\x5a'*(9-len(a))+CANARY
        b=b'\xa5'*8+CANARY
        return {'version':v,'called':True,'operation':'get','returned':o['count'],'value':o['value'],
            'input_before_hex':a.hex(),'input_after_hex':a.hex(),'output_before_hex':b.hex(),
            'output_after_hex':(o['value'].to_bytes(8,'little')+CANARY).hex(),'output_alignment_mod8':0}
    raw=bytes.fromhex(o['encoded_hex']);b=b'\xa5'*9+CANARY
    return {'version':v,'called':True,'operation':'put','returned':o['count'],'value':o['value'],
            'output_before_hex':b.hex(),'output_after_hex':(raw+b[len(raw):]).hex()}
def expected_pair(spec):
    before=[bytes.fromhex(spec[k])+CANARY for k in ('source_hex','output_hex','command_hex')]
    after=[bytes.fromhex(spec['expected'][k])+CANARY for k in ('source_after_hex','output_after_hex','command_after_hex')]
    pre={'event':'pre','index':spec['index'],'method':spec['method'],'label':spec['label'],
         'lengths':[len(x)-64 for x in before],'buffers_hex':[x.hex() for x in before]}
    post={'event':'post','index':spec['index'],'actual_returned':True,'status':spec['expected']['status'],
          'buffers_hex':[x.hex() for x in after],'oracles':[oracle_expected(spec,v) for v in VERSIONS]}
    return pre,post
def whole_trace(original_catalog):
    base=OUT/'native/trace';ip,index,_=doc(base/'INDEX.json',1<<20)
    check(index['schema']=='hia.sqlite.varint.full-native-trace.v2' and index['complete'] is True
        and type(index['native_returns'])is int and index['native_returns']==76054
        and index['records']==152108 and index['bytes']==207481528
        and index['chunk_limit']==4<<20 and index['total_limit']==256<<20 and index['record_limit']==3072
        and len(index['parts'])==50,'whole fixed trace denominator and limits')
    _,expected,_=doc(ROOT/'EXPECTED-MATRIX.json')
    _,projection,_=doc(ROOT/'EXPECTED-TRACE.json')
    sequence=iter(rows_expected());spec=None;count={k:0 for k in IDS}
    whole=hashlib.sha256();matrix_hash=hashlib.sha256();size=records=maximum=0;part_pins=[]
    oracle_counts={v:{'get':0,'put':0,'not_called':0} for v in VERSIONS}
    for number,item in enumerate(index['parts']):
        name='part-%04d.jsonl'%number;check(item['path']==name,'ordered unique trace parts')
        p,raw=read(base/name,4<<20)
        check(all(equal(p[k],item[k]) for k in ('bytes','sha256','git_blob')),'entire trace part independent SHA')
        check(pin_matches(p,original_catalog['native/trace/'+name]),'trace versus first complete catalog')
        whole.update(raw);lines=raw.splitlines(keepends=True)
        check(len(lines)==item['records'],'exact per-part record denominator')
        for line in lines:
            check(line.endswith(b'\n') and len(line)<=3072,'whole bounded record')
            x=parse(line);check(wire(x)==line,'no duplicate fields and canonical typed original JSON')
            if records%2==0:
                spec=next(sequence);matrix_hash.update(wire(spec));wanted=expected_pair(spec)[0]
            else:
                wanted=expected_pair(spec)[1];count[spec['method']]+=1
                o=spec['expected']['oracle']
                for v in VERSIONS:oracle_counts[v][o['operation'] if o else 'not_called']+=1
            check(line==wire(wanted),'entire typed PRE/POST/native/C/canary buffers at record '+str(records))
            maximum=max(maximum,len(line));records+=1
        size+=len(raw);part_pins.append(public_pin(p))
    try:next(sequence)
    except StopIteration:pass
    else:raise RuntimeError('missing finite case')
    check(records==152108 and size==207481528 and count==expected['counts']
        and list(count.values())==COUNTS and matrix_hash.hexdigest()==expected['ordered_expected_rows_sha256']
        and all(v=={'get':71045,'put':4943,'not_called':66} for v in oracle_counts.values())
        and whole.hexdigest()==projection['sha256']=='75d0a654b10197b69dd2d9f8bad408b75c5d6469242dbe0117e1246a1b9daff0'
        and maximum==projection['max_record_bytes']==2130,'complete projected trace arithmetic and actual digest')
    check({p.name for p in base.iterdir()}=={'INDEX.json',*('part-%04d.jsonl'%i for i in range(50))},
          'complete trace directory exact namespace')
    return {'index':ip,'parts':part_pins,'bytes':size,'records':records,'native_returns':records//2,'counts':count,
       'oracle_counts':oracle_counts,'expected_rows_sha256':matrix_hash.hexdigest(),'sha256':whole.hexdigest(),
       'max_record_bytes':maximum,'all_pre_post_and_full_C_buffers_read':True,
       'independent_math':'bit-length/bit-mask encoder and shift-accumulate decoder; no imported project, matrix, VM, C or native code'}
def mappings(native,system,compiled):
    results={}
    own={v['image']['path']:public_pin(v['image']) for v in compiled.values()}
    allowed={**system,**own}
    for phase in ('before','after'):
        observed=native['mapped_files_'+phase];bp,binding,_=doc(OUT/'native'/('mapping-'+phase+'.binding-start.json'))
        mp,raw=read(OUT/'native'/('mapping-'+phase+'.maps.original'),1<<20)
        check(pin_matches(mp,observed['maps_original']),'mapping raw physical pin')
        full=observed['image_binding'];extras={'actual_segment','complete_image_sha256','page_rounding_tail_not_hashed_as_image'}
        check(equal({k:v for k,v in full.items() if k not in extras},binding),'mapping start descriptor exact')
        image_pin,image=read(binding['image']['path'],1<<20)
        check(pin_matches(image_pin,binding['image']) and binding['logical_bytes']==len(image)==14508
              and binding['entry_address']==binding['address'] and binding['requires_exact_single_segment'] is True
              and type(binding['page_size'])is int and binding['page_size']>0
              and binding['page_size']&(binding['page_size']-1)==0 and binding['address']%binding['page_size']==0,
              'image/entry/length/page descriptor')
        check(all(type(binding[k])is int and binding[k]>0 for k in
            ('mapping_object_id','entry_object_id','observer_object_id')),'current mapping object identity records')
        end=binding['address']+((len(image)+binding['page_size']-1)//binding['page_size'])*binding['page_size']
        check(end==binding['mapping_end'] and full['page_rounding_tail_not_hashed_as_image']==end-binding['address']-len(image)
              and full['complete_image_sha256']==image_pin['sha256'],'full logical image digest excludes rounded tail')
        parsed=[];previous=0
        for line in raw.decode('ascii').splitlines():
            f=line.split(None,5);check(len(f) in (5,6),'map fields')
            a,b=[int(x,16) for x in f[0].split('-')];dev=[int(x,16) for x in f[3].split(':')]
            row={'line':line,'start':a,'end':b,'permissions':f[1],'offset':int(f[2],16),
                 'device':dev,'inode':int(f[4]),'name':f[5] if len(f)==6 else ''}
            check(0<=previous<=a<b<=1<<64 and len(dev)==2,'complete ordered map')
            previous=b;parsed.append(row)
        matches=[r for r in parsed if r['start']<end and r['end']>binding['address']]
        check(len(matches)==1 and equal(matches[0],full['actual_segment']),'single exact bound raw-map record')
        bound=matches[0]
        check(bound['start']==binding['address'] and bound['end']==end and bound['permissions']=='r-xs'
              and bound['offset']==0 and ((bound['name']=='/dev/zero (deleted)' and bound['inode']>0)
              or (bound['name']=='' and bound['inode']==0 and bound['device']==[0,0])),
              'only same image anonymous backing exact permissions extent')
        roles=[];files={};kernels=[]
        for row in parsed:
            if row is bound:
                roles.append({'line':row['line'],'file':None,'role':'current-bound-HIA-image'});continue
            check(not(bound['inode']>0 and row['inode']==bound['inode'] and row['device']==bound['device']),
                  'no additional bound backing alias')
            name=row['name']
            if not name.startswith('/'):
                if 'x' in row['permissions']:
                    check(row['inode']==0 and row['device']==[0,0] and row['offset']==0
                        and ((name=='[vdso]' and row['permissions']=='r-xp') or
                             (name=='[vsyscall]' and row['permissions']=='--xp')),'only explicit kernel executable maps')
                    kernels.append(row['line'])
                roles.append({'line':row['line'],'file':None,
                    'role':'kernel-executable' if 'x' in row['permissions'] else 'non-executable-anonymous'})
                continue
            check(not name.endswith(' (deleted)'),'no unbound deleted pathname')
            key=str(Path(name).resolve(strict=True));check(key in allowed,'mapped file within fixed closure')
            p=allowed[key];check(row['device']==[os.major(p['identity'][0]),os.minor(p['identity'][0])]
                                and row['inode']==p['identity'][1],'mapped physical device/inode')
            files[key]=p;roles.append({'line':row['line'],'file':key,'role':'frozen-file'})
        check(equal(files,observed['files']) and equal(roles,observed['maps']) and equal(kernels,observed['kernel_executable_rows'])
            and observed['all_file_backed_mappings_joined'] is True and observed['all_executable_mappings_classified'] is True,
            'every original mapping role/file/exec row independently reconstructed')
        results[phase]={'raw':mp,'binding_start':bp,'image_binding':full,'all_map_rows':len(parsed),'file_count':len(files)}
    check(equal(results['before']['image_binding'],results['after']['image_binding']),'same current image binding before/after')
    check(equal(native['mapped_files_before']['files'],native['mapped_files_after']['files']),'same mapped files before/after')
    results['scope']='Exact snapshots and producer whole-image/object checks retained; no claim of continuous VMA immutability between observations.'
    return results
def source16():
    qp,q,_=doc(ROOT/'proof/MAPPING-CONTROL-REQUEST.json',1<<20)
    owner_root=Path(q['owner_root']);actual=Path(q['actual_root'])
    lp,life,_=doc(owner_root/'lifecycle.json');rp,r,_=doc(owner_root/'OWNER-RETURN.json')
    pp,parent,_=doc(owner_root/'lifecycle.json.request.json');r=dict(r)
    rc=r.pop('supervisor_returncode');seal=r.pop('receipt_sha256')
    check(equal(r,life) and rc==life['returncode']==0 and seal==lp['sha256']
          and parent['command']==q['command'] and parent['cwd']==q['cwd']
          and equal(parent['env'],q['environment']) and parent['qualification_seconds']==life['qualification_seconds']==20
          and parent['cleanup_seconds']==life['cleanup_seconds']==3
          and life['request_sha256']==pp['sha256'] and life['implementation_sha256']==q['original_owner']['sha256'],
          'source16 original20/3 request/wrapper/implementation')
    c=life['cleanup']
    check(life['status']=='OWNED_PROCESS_COMPLETED' and life['subreaper_enabled'] is True
        and life['event_overflow'] is False and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
        and life.get('owner_error') is None and life['interrupted_signals']==[] and c['complete'] is True
        and c['observed_echild'] is True and c['leader_reaped'] is True and c['remaining_direct_children']==c['errors']==[]
        and c['deadline_exceeded'] is False and [x['kind'] for x in life['events']]
         ==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'],
        'source16 closed natural before body')
    ap,a,_=doc(actual/'REPORT.json');rootp,root,_=doc(owner_root/'ROOT-READBACK.json')
    check(a['status']=='PURE_MAPPING_CONTROLS_16_PASS_ONLY'
        and a['expected_ids']==a['loaded_ids']==a['actual_ids']==a['success_ids']==q['expected_ids']
        and len(a['rows'])==16 and a['exception'] is None and a['denied_effects']==[]
        and a['native_calls']==a['real_maps_or_native_images_created']==0 and a['source8_reexecuted'] is False
        and all(x['id']==q['expected_ids'][i] and x['status']=='PASS' and x['error'] is None for i,x in enumerate(a['rows']))
        and sum(x['expected_refusal'] is None for x in a['rows'])==2,
        'original16 all2accept14reject no product')
    check(pin_matches(ap,root['report']) and root['status']=='PURE_MAPPING_SOURCE16_PASS_ONLY'
        and equal(root['input_before'],root['input_after']) and root['closed_natural_owner'] is True and root['error'] is None,
        'source16 Root full readback joined')
    for k,p in q['inputs'].items():check(pin_matches(read(p['path'])[0],p),'source16 frozen '+k)
    all_rows=[]
    for base in (owner_root,actual):
        for p in sorted(base.rglob('*')):
            if p.is_dir():continue
            check(p.is_file(),'source16 regular')
            all_rows.append(read(p)[0])
    for name in ('root-varint-r3-mapping-source16-r1.py','root-varint-r3-mapping-source16-r1-HJOB.json'):
        all_rows.append(read(ROOT.parent/name)[0])
    return {'request':qp,'owner':lp,'owner_return':rp,'root_readback':rootp,'report':ap,
        'all_originals':all_rows,'expected_loaded_executed_success':16,'accept':2,'reject':14,'native_calls':0}
def main():
    started=time.monotonic_ns();check(not os.path.lexists(AUDIT),'new audit namespace')
    os.mkdir(AUDIT,0o700)
    try:
        request_pin,request,_=doc(ROOT/'REQUEST.json',1<<20)
        check(request_pin['sha256']==REQUEST_SHA,'canonical native request')
        check(owner(request,request_pin),'natural closed before reading actual')
        cat=catalog();cm={x['relative_path']:x for x in cat['files']}
        report['whole_originals']=create('ORIGINAL-CATALOG.json',cat)
        report['original_files']=cat['file_count'];report['original_bytes']=cat['bytes']
        check(cat['file_count']==114 and cat['bytes']==222911632,'complete actual original physical population')
        fp,final,_=doc(OUT/'FINAL.json');wp,worker,_=doc(OUT/'WORKER.json');np,native,_=doc(OUT/'native/REPORT.json')
        check(final['status']=='FINITE_NATIVE_VARINT_AND_TWO_ORACLES_PASS_ONLY' and final['errors']==[]
            and final['owner_closed'] is True and final['owner_natural'] is True
            and final['source8_reexecuted'] is False and final['SQL_engine_or_durability_qualification'] is False
            and final['matching_cold_qualification'] is False,'producer FINAL finite PASS scope')
        check(worker['status']=='FINITE_NATIVE_WORKER_PASS_ONLY' and worker['exception'] is None
            and worker['secondary_errors']==[] and worker['native_executed'] is True
            and worker['HIA_compile_executed'] is True and worker['C_compiles_executed']==2
            and type(worker['elapsed_ns'])is int and 0<=worker['elapsed_ns']<=180000000000,
            'full worker finite result')
        check(native['status']=='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY'
            and native['exception'] is None and native['secondary_errors']==native['denied_effects']==[]
            and native['expected_ids']==native['loaded_ids']==native['actual_ids']==native['success_ids']==IDS
            and type(native['tests_run'])is int and native['tests_run']==8
            and type(native['native_returns'])is int and native['native_returns']==native['actual_native_starts']==76054
            and all(native[k]==[] for k in ('failures','errors','skipped','expected_failures','unexpected_successes'))
            and all(native[k] is False for k in ('database_opened','network_used','source8_reexecuted','matching_cold_qualification')),
            'all original eight and76054 no denominator reduction')
        check(pin_matches(request_pin,worker['request']) and pin_matches(request_pin,final['request'])
            and pin_matches(np,final['native_report']) and pin_matches(wp,final['worker']),'full report joins')
        frozen,source,system=fresh_frozen(request)
        for k,rows in [('inputs',frozen),('source',source)]:
            check(equal(native[k+'_before'],rows) and equal(native[k+'_after'],rows),'native before/after '+k)
        report['historical_compiler']=compiler_chain(ROOT/'compiler-inputs','B3',True)
        report['new_HIA_compile']=compiler_chain(OUT/'hia-compile','varint')
        check(report['new_HIA_compile']['image_bytes']==14508 and report['new_HIA_compile']['image_sha256']
            =='b5dfd6aeceb5d2ae5db59e2db831a776f432f36dea8be7a1596cc1b4c295e3b5','whole new HIA image')
        report['C_compiles']=c_compiles(request,system)
        check([c['returncode'] for c in worker['commands']]==[0,0,0],'three real child commands all natural zero')
        for i,c in enumerate(worker['commands']):
            check(equal(c['env'],request['environment']) and c['cwd']==str(ROOT),'actual child environment/cwd')
            if i<2:
                qp,q,_=doc(OUT/('C-'+VERSIONS[i])/'REQUEST.json')
                want=[request['runtime']['path'],'-I','-S','-B',str(ROOT/'control/compile_child.py'),qp['path'],qp['sha256']]
                check(c['argv']==want and c['wall_seconds']==20 and 0<=c['elapsed_ns']<=20000000000,'whole C child argv20')
            else:
                check(c['argv']==[request['runtime']['path'],'-I','-S','-B',str(ROOT/'control/native_cases.py'),
                    str(ROOT/'REQUEST.json'),REQUEST_SHA] and c['separate_wall_budget'] is None,'same-owner native command')
        report['trace']=whole_trace(cm)
        check(equal(native['native_counts'],report['trace']['counts']),'actual per method counts')
        for r in (native['full_trace_readback'],worker['full_trace_readback'],final['trace']):
            for key in ('bytes','records','native_returns','counts','oracle_counts','expected_rows_sha256','all_pre_post_and_full_C_buffers_read'):
                check(equal(r[key],report['trace'][key]),'producer trace '+key)
            check(pin_matches(r['index'],report['trace']['index'])
                 and equal(r['parts'],report['trace']['parts']),'whole50 producer part pins')
        behavior=native['bridge_control_observations']
        check(len(behavior)==32 and [r['ordinal'] for r in behavior[:22]]==list(range(1,23))
            and all(r['kind']=='early-refusal' for r in behavior[:22])
            and [r['type'] for r in behavior[22:25]]==['MemoryError','KeyboardInterrupt','SystemExit']
            and all(r['same_object'] is True for r in behavior[22:25])
            and [r['kind'] for r in behavior[25:29]]==['invalid-return']*4
            and [r['buffer'] for r in behavior[29:]]==['source','command','tail']
            and all(r['target_unchanged'] is True for r in behavior[29:]),'all32 public bridge observations')
        report['mapped_image']=mappings(native,system,report['C_compiles'])
        # Validate producer imports using already independently read frozen byte maps.
        allpins={p['path']:p for p in [*frozen.values(),*source.values(),*system.values()]}
        for label,rows in [('worker',worker['imports']),('native',native['imports'])]:
            for row in rows:
                p=row['source'];check(p['path'] in allpins and pin_matches(p,allpins[p['path']]),label+' imported source exact')
        native_modules={r['module'] for r in native['imports']}
        check(native_modules=={'hepta','hepta.hia_json_preflight_native','hepta.hia_sqlite_varint_native'},
              'native dispatch imports only fixed transport/runtime')
        _,up,_=doc(ROOT/'candidate/reference/UPSTREAM.json');oracles=[]
        for item in up['versions']:
            p,full=read(ROOT/'candidate/reference'/('sqlite-'+item['version'])/'util.c.original')
            s,selected=read(ROOT/'candidate/inputs'/item['selected_file']);a,b=item['contiguous_byte_range']
            check(full[a:b]==selected and p['sha256']==item['full_util_original']['sha256']
                and s['sha256']==item['selected']['sha256'],'complete exact upstream C slice')
            oracles.append({'version':item['version'],'full':p,'selected':s,'range':[a,b]})
        report['official_C_originals']=oracles
        cp,closed,_=doc(OUT/'CLOSED-ORIGINAL-CATALOG.json')
        check(pin_matches(cp,final['closed_originals']) and closed['all_bodies_read'] is True,'closed producer catalog pin')
        excluded={'CLOSED-ORIGINAL-CATALOG.json','FINAL.json','PARENT-INPUTS-AFTER.json','PARENT-SOURCE-AFTER.json','PARENT-SYSTEM-AFTER.json'}
        expected={k:v for k,v in cm.items() if k not in excluded};seen=set()
        for row in closed['files']:
            name=row['relative_path'];check(name not in seen and name in expected and pin_matches(row,expected[name]),'full producer catalog row');seen.add(name)
        check(seen==set(expected) and closed['file_count']==len(seen)==109
            and closed['bytes']==sum(v['bytes'] for v in expected.values()),'producer complete observed namespace')
        report['mapping_source16']=source16()
        extras=['root-varint-bound-map-r3-native-r1-'+x for x in ('INTENT.json','OWNER-READBACK.json','HJOB.json')]
        report['root_originals']=[read(ROOT.parent/name)[0] for name in extras]
        report['results']={'final':fp,'worker':wp,'native':np,'methods':8,'native_starts':76054,'native_returns':76054,
            'native_elapsed_ns':native['elapsed_ns'],'worker_elapsed_ns':worker['elapsed_ns'],
            'parent_elapsed_ns':final['elapsed_ns'],'bridge_observations':32}
        check(equal(cat,catalog()),'all114 original files stable after independent reader')
        report['qualification_result']='FINITE_NATIVE_VARINT_AND_TWO_ORACLES_PASS_ONLY'
        report['prior_r2_failure_preserved']='307708ebd56803dad5b52f3986988313a9765429;0methods/0returns'
        report['status']='FINITE_VARINT_R3_WHOLE_ACTUAL_READBACK_PASS'
    except BaseException as e:
        report['status']='READER_HOLD'
        report['errors'].append({'type':type(e).__module__+'.'+type(e).__qualname__,'message':str(e),'traceback':traceback.format_exc()})
    finally:
        report['elapsed_ns']=time.monotonic_ns()-started
        report['scope']='One read-only whole actual audit; no new product, VM, C, native, SQL or matching-cold run. Python transport/allocation/map owners remain.'
        p=create('READBACK.json',report)
        print(json.dumps({'status':report['status'],'checks':report['checks'],'errors':report['errors'],'report':p},sort_keys=True))
    return 0 if report['status']=='FINITE_VARINT_R3_WHOLE_ACTUAL_READBACK_PASS' and not report['errors'] else 1
if __name__=='__main__':raise SystemExit(main())
