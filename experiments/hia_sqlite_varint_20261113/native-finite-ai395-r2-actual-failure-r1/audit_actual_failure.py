"""Independent read-only audit of the once-closed ai395 varint R2 experiment.
No project imports, compiler, VM, native call, SQL, network, or process launch.
The producer's original files are read only and never rewritten.
"""
from pathlib import Path
from contextlib import contextmanager
import hashlib,json,os,stat,struct,sys,time,traceback,zlib
ROOT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r2')
OUT=ROOT.parent/'varint-native-r2-actual'
AUDIT=ROOT.parent/'varint-native-r2-independent-audit-r1'
REQUEST_SHA='240668cfa71442794b24b435282e90e14cddaa6df0f60aaf048395b498f7e9e3'
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
    check(type(life['returncode']) is int and life['returncode']==1 and rc==1
          and life['status']=='QUALIFICATION_FAILED' and life['timed_out'] is False
          and life['exit_observed_before_deadline'] is True and life.get('owner_error') is None
          and life['interrupted_signals']==[]
          and [e['kind'] for e in life['events']]==['qualification_started','owned_child_observed',
              'qualification_exit_observed','owned_child_reaped']
          and all(e['pid']==life['qualification_pid'] for e in life['events']),
          'original natural closed exit-one failure')
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
            check(not os.path.lexists(OUT/name),'failure unexpectedly contains success after-snapshot '+name)
    report['producer_after_snapshots']='Absent after early failure; independent current reads do not replace producer originals.'
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
def main():
    started=time.monotonic_ns()
    check(not os.path.lexists(AUDIT),'new audit-only output required')
    os.mkdir(AUDIT,0o700)
    try:
        request_pin,request,_=doc(ROOT/'REQUEST.json',1<<20)
        check(request_pin['sha256']==REQUEST_SHA,'immutable request')
        natural=owner(request,request_pin)
        original_catalog=catalog()
        report['whole_originals']=create('ORIGINAL-CATALOG.json',original_catalog)
        report['original_files']=original_catalog['file_count'];report['original_bytes']=original_catalog['bytes']
        check(natural is False,'expected original closed qualification failure')
        fp,final,_=doc(OUT/'FINAL.json');wp,worker,_=doc(OUT/'WORKER.json');np,native,_=doc(OUT/'native/REPORT.json')
        check(final['status']==worker['status']==native['status']=='HOLD'
              and final['owner_closed'] is True and final['owner_natural'] is False
              and final['source8_reexecuted'] is False,'all original HOLDs preserved')
        check(native['expected_ids']==IDS and native['started_ids']==native['actual_ids']==native['success_ids']==[]
              and type(native['native_returns'])is int and native['native_returns']==0
              and type(native['actual_native_starts'])is int and native['actual_native_starts']==0
              and native['bridge_control_observations']==[] and 'loaded_ids' not in native
              and native['denied_effects']==native['secondary_errors']==[]
              and all(native[k] is False for k in ('database_opened','network_used','source8_reexecuted','matching_cold_qualification')),
              'zero native methods/entries/returns without denominator reduction')
        check(native['exception']=="builtins.FileNotFoundError: [Errno 2] No such file or directory: '/dev/zero (deleted)'"
              and "support.loaded_file_maps(request,own_maps)" in native['traceback']
              and "Path(fields[5]).resolve(strict=True)" in native['traceback']
              and worker['exception']=='builtins.RuntimeError: finite native child failed',
              'exact original failure cause and parent propagation')
        check(pin_matches(request_pin,worker['request']) and pin_matches(request_pin,final['request']),'original request pins')
        report['results']={'final':fp,'worker':wp,'native':np,'native_returns':0,'native_starts':0,
             'loaded_methods':0,'requested_methods':8,'requested_native_returns':76054,'producer_status':'HOLD',
             'worker_elapsed_ns':worker['elapsed_ns'],'native_elapsed_ns':native['elapsed_ns'],
             'original_exception':native['exception'],'original_traceback':native['traceback'],
             'raw_proc_maps_retained':False,
             'mapping_provenance_scope':'Original exception names the deleted path; the failed assignment retained no complete maps body/address. No VMA identity is reconstructed or claimed.'}
        frozen,source,system=fresh_frozen(request)
        check(equal(native['inputs_before'],frozen) and equal(native['source_before'],source),'child before versus independent current source')
        report['historical_compiler']=compiler_chain(ROOT/'compiler-inputs','B3',True)
        report['new_HIA_compile']=compiler_chain(OUT/'hia-compile','varint')
        check(report['new_HIA_compile']['image_bytes']==14508
              and report['new_HIA_compile']['image_sha256']=='b5dfd6aeceb5d2ae5db59e2db831a776f432f36dea8be7a1596cc1b4c295e3b5','actual HIA image')
        report['C_compiles']=c_compiles(request,system)
        check(worker['HIA_compile_executed'] is True and type(worker['C_compiles_executed'])is int
              and worker['C_compiles_executed']==2 and worker['native_executed'] is True
              and [c['returncode'] for c in worker['commands']]==[0,0,1],'compile success / child-start flag separated from zero calls')
        _,index,_=doc(OUT/'native/trace/INDEX.partial.json')
        check(index['complete'] is False and index['parts']==[] and index['bytes']==index['records']==0
              and index['native_returns'] is None and {p.name for p in (OUT/'native/trace').iterdir()}=={'INDEX.partial.json'},
              'explicit empty partial trace')
        report['trace']={'status':'EMPTY_PARTIAL_ORIGINAL','bytes':0,'records':0,'native_returns':0,'complete':False}
        _,up,_=doc(ROOT/'candidate/reference/UPSTREAM.json');oracles=[]
        for item in up['versions']:
            fp,full=read(ROOT/'candidate/reference'/('sqlite-'+item['version'])/'util.c.original')
            sp,selected=read(ROOT/'candidate/inputs'/item['selected_file'])
            a,b=item['contiguous_byte_range']
            check(full[a:b]==selected and fp['sha256']==item['full_util_original']['sha256']
                  and sp['sha256']==item['selected']['sha256'],'complete upstream selected original')
            oracles.append({'version':item['version'],'full':fp,'selected':sp,'range':[a,b]})
        report['official_C_originals']=oracles
        extras=['root-varint-clean-launch-r1-INTENT.json','root-varint-native-r2-OWNER-READBACK.json',
                'root-varint-native-r2-HJOB-ACK.json','root-varint-native-r2-HJOB-STATUS.json','root-varint-native-r2-HJOB-OUTPUT.json']
        report['root_originals']=[read(ROOT.parent/name)[0] for name in extras]
        report['qualification_result']='HOLD: no finite native calls were started; successful compile artifacts are retained only.'
        report['status']='CLOSED_FAILURE_ORIGINALS_AND_CAUSE_READBACK_PASS'
    except BaseException as e:
        report['status']='READER_HOLD'
        report['errors'].append({'type':type(e).__module__+'.'+type(e).__qualname__,'message':str(e),'traceback':traceback.format_exc()})
    finally:
        report['elapsed_ns']=time.monotonic_ns()-started
        report['scope']='read-only custody and diagnosis of original failure; no retry, SQL, WAL, persistence or matching-cold qualification'
        p=create('READBACK.json',report)
        print(json.dumps({'status':report['status'],'owner_closed':report['owner_closed'],'checks':report['checks'],
                          'errors':report['errors'],'report':p},sort_keys=True))
    return 0 if report['status']=='CLOSED_FAILURE_ORIGINALS_AND_CAUSE_READBACK_PASS' and not report['errors'] else 1
if __name__=='__main__':raise SystemExit(main())
