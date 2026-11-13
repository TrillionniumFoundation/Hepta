"""Independent closed-owner audit of the one WAL snapshot finite-native run.
Reads original bytes only. Does not import product code or invoke any compiler,
HIA image, C oracle, VM, original test, qualification owner, or child process.
"""
from pathlib import Path
import collections,hashlib,json,os,shlex,stat,struct,time,traceback,zlib
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
R=P/'sqlite-wal-snapshot-native-r1'
A=P/'sqlite-wal-snapshot-native-r1-actual'
O=P/'sqlite-wal-snapshot-native-r1-actual-audit-r1'
QSHA='29f0796711fc5c127fa4b355bfd860f99889bbc6af8b622b229c63625559bfa1'
OWNER='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
report={'schema':'hia.wal-snapshot.finite-native-independent-audit.v1','status':'HOLD',
        'request_commit':'5362fc690b3b7664c34f5d565089679778bfcf89','request_sha256':QSHA,
        'owner_closed':False,'owner_natural':False,'child_read_before_closed':False,
        'product_reexecuted':False,'C_or_HIA_or_VM_executed':False,'checks':0,'errors':[]}
def check(v,m):
    report['checks']+=1
    if not v:raise AssertionError(m)
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path,limit=64<<20,system=False):
    p=Path(path);s=p.lstat()
    check(p.is_absolute()and p.resolve(strict=True)==p,'real exact path '+str(p))
    check(stat.S_ISREG(s.st_mode)and s.st_size<=limit,'regular bounded '+str(p))
    check((s.st_uid==0 and s.st_nlink>=1 and not s.st_mode&0o022)if system else s.st_nlink==1,'explicit input role '+str(p))
    fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        check(ident(os.fstat(fd))==ident(s),'fd initial')
        pieces=[];total=0;sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(s.st_size).encode()+b'\0')
        while True:
            b=os.read(fd,1<<20)
            if not b:break
            total+=len(b);check(total<=s.st_size,'file grew');pieces.append(b);sha.update(b);git.update(b)
        check(total==s.st_size and ident(os.fstat(fd))==ident(s)==ident(p.lstat()),'complete stable file')
    finally:os.close(fd)
    return b''.join(pieces),{'path':str(p),'bytes':total,'sha256':sha.hexdigest(),'git_blob':git.hexdigest(),'identity':ident(s)}
def jread(path,limit=64<<20):
    b,p=read(path,limit);return json.loads(b),p
def wire(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def namespace(root):
    files=[];dirs=[]
    for base,sub,names in os.walk(root,followlinks=False):
        for name in sub:
            p=Path(base)/name;check(stat.S_ISDIR(p.lstat().st_mode)and p.resolve()==p,'exact directory')
            dirs.append(str(p.relative_to(root)))
        for name in names:files.append(str((Path(base)/name).relative_to(root)))
    return sorted(files),sorted(dirs)
def equal_pin(a,b,fields=('path','bytes','sha256','git_blob','identity')):
    check(all(a[k]==b[k]for k in fields),'whole pin '+a['path'])
def main():
    started=time.monotonic_ns()
    qraw,qp=read(R/'REQUEST.json');q=json.loads(qraw)
    check(qp['sha256']==QSHA and q['root']==str(R)and q['output']==str(A),'exact execution request')
    check(q['qualification_seconds']==180 and q['cleanup_seconds']==3 and q['expected_methods']==13
        and q['native_returns']==2704 and q['original_VM_calls']==608 and q['C_calls_each']==639,'fixed denominators')
    # These three parent originals only, before any child-body enumeration.
    life,lp=jread(A/'lifecycle.json',4<<20)
    bound,bp=jread(A/'lifecycle.json.request.json',1<<20)
    returned,rp=jread(A/'OWNER-RETURN.json',4<<20)
    projection=dict(returned);supervisor=projection.pop('supervisor_returncode');seal=projection.pop('receipt_sha256')
    cmd=[QSHA if x=='@REQUEST_SHA256@'else x for x in q['command']]
    check(projection==life and seal==lp['sha256']and life['request_sha256']==bp['sha256'],'complete owner/request/wrapper bytes')
    check(life['schema']==bound['schema']=='hepta.hia.selfhost-process-owner.v1'
        and life['implementation_sha256']==bound['implementation_sha256']==OWNER,'original369 owner')
    check(bound['command']==cmd and bound['cwd']==str(R)and bound['env']==q['environment'],'current operation identity')
    check(bound['stdout_path']==str(A/'stdout.log')and bound['stderr_path']==str(A/'stderr.log')
        and bound['receipt_path']==str(A/'lifecycle.json'),'current output paths')
    check(bound['qualification_seconds']==life['qualification_seconds']==180
        and bound['cleanup_seconds']==life['cleanup_seconds']==3
        and bound['deadline_ns']-bound['started_ns']==180000000000,'unchanged owner deadline')
    cleanup=life['cleanup']
    check(life['subreaper_enabled']is True and life['event_overflow']is False
        and cleanup['complete']is True and cleanup['observed_echild']is True
        and cleanup['leader_reaped']is True and cleanup['remaining_direct_children']==[]
        and cleanup['errors']==[] and cleanup['deadline_exceeded']is False,'bound closed ECHILD')
    report['owner_closed']=True
    kinds=[x['kind']for x in life['events']]
    natural=(type(supervisor)is int and supervisor==life['returncode']==0
        and life['status']=='OWNED_PROCESS_COMPLETED'and life['timed_out']is False
        and life['exit_observed_before_deadline']is True and life['owner_error']is None
        and life['interrupted_signals']==[]and kinds==['qualification_started','owned_child_observed',
        'qualification_exit_observed','owned_child_reaped'])
    report['owner_natural']=natural
    report['owner']={'lifecycle':lp,'request':bp,'returned':rp,'events':life['events'],
        'cleanup':cleanup,'status':life['status'],'supervisor_returncode':supervisor}
    # Closed nonzero is retained too; it is never promoted to product PASS.
    names,dirs=namespace(A);pins={};raws={};total=0
    for name in names:
        b,p=read(A/name);pins[name]=p;total+=len(b)
        if not name.startswith('native/trace/'):raws[name]=b
    check(len(names)==len(set(names))<=192 and total<=384<<20,'all actual original count/byte cap')
    report['originals']={'files':pins,'directories':dirs,'count':len(pins),'bytes':total,'all_full_bytes_read':True}
    if not natural:
        report['status']='READBACK_OF_CLOSED_QUALIFICATION_HOLD'
        report['reported_failure']={n:json.loads(b)for n,b in raws.items()if n in ('FINAL.json','WORKER.json','native/REPORT.json')}
        return
    check(all(e['pid']==life['qualification_pid']for e in life['events']),'one natural child event identity')
    elapsed=life['events'][2]['monotonic_ns']-life['events'][0]['monotonic_ns']
    check(0<=elapsed<=180000000000,'actual owner time')
    report['owner']['elapsed_ns']=elapsed
    check(raws['REQUEST.original.json']==qraw,'executed request original')
    final=json.loads(raws['FINAL.json']);worker=json.loads(raws['WORKER.json']);child=json.loads(raws['native/REPORT.json'])
    check(final['status']=='FINITE_NATIVE_WAL_SNAPSHOT_AND_TWO_ORACLES_PASS_ONLY'
        and final['errors']==[]and final['owner_closed']is True and final['owner_natural']is True,'parent final')
    check(worker['status']=='FINITE_NATIVE_WORKER_PASS_ONLY'and worker['exception']is None
        and worker['secondary_errors']==[]and worker['native_executed']is True
        and worker['HIA_compile_executed']is True and worker['C_compiles_executed']==2
        and type(worker['elapsed_ns'])is int and 0<=worker['elapsed_ns']<=180000000000,'complete worker')
    check(child['status']=='FINITE_NATIVE_SNAPSHOT_AND_TWO_C_ORACLES_PASS_ONLY'
        and child['exception']is None and child['secondary_errors']==child['denied_effects']==child['observation_errors']==[]
        and child['source12_VM_reexecuted']is False and child['database_opened']is False
        and child['network_used']is False and child['matching_cold_qualification']is False,'complete finite child only')
    check(final['trace']==worker['full_trace_readback']==child['full_trace_readback'],
        'complete three producer trace receipts identical')
    ids=q['expected_ids']
    check(child['expected_ids']==child['loaded_ids']==child['actual_ids']==child['success_ids']==ids
        and len(ids)==len(set(ids))==child['tests_run']==13
        and all(child[k]==[]for k in ('failures','errors','skipped','expected_failures','unexpected_successes')),'all13 exact IDs/zero5')
    check(child['actual_native_starts']==child['native_returns']==child['validated_native_returns']==2704
        and child['native_counts']==q['native_counts']and sum(child['native_counts'].values())==2704
        and child['C_counts']=={v:{'started':639,'returned':639}for v in ('3.46.0','3.53.2')},'actual entry and C counters')
    report['population']={'methods':13,'ids':ids,'native_returns':2704,'native_counts':child['native_counts'],'C_counts':child['C_counts']}
    # Actual full input/source/system bytes, independently joined to every snapshot.
    inputs={}
    for name,expected in q['inputs'].items():
        _,p=read(R/name);equal_pin(p,expected);inputs[name]=p
    source_map,_=jread(R/'SOURCE-BASE.json');source={}
    for expected in source_map['files']:
        _,p=read(Path(q['source_root'])/expected['path'])
        equal_pin(p,expected,('bytes','sha256','git_blob','identity'));source[expected['path']]=p
    sn,_=namespace(Path(q['source_root']))
    check(len(source)==1686 and set(sn)==set(source)and sum(p['bytes']for p in source.values())==40890650,'all source1686')
    sm,_=jread(R/'SYSTEM-INPUTS.json');system={}
    for expected in sm['files']:
        _,p=read(expected['path'],128<<20,system=True);equal_pin(p,expected);check(p['path']not in system,'unique system');system[p['path']]=p
    check(len(system)==4806 and sum(p['bytes']for p in system.values())==179325490,'all system4806')
    for alias,target in sm['aliases'].items():check(str(Path(alias).resolve(strict=True))==target,'system alias target')
    for label,rows in (('INPUTS',inputs),('SOURCE',source),('SYSTEM',system)):
        for side in ('BEFORE','AFTER'):
            check(json.loads(raws['PARENT-'+label+'-'+side+'.json'])==rows,'parent full '+label+' '+side)
            prefix=''if label=='SYSTEM'else'WORKER-'
            check(json.loads(raws[prefix+label+'-'+side+'.json'])==rows,'worker full '+label+' '+side)
            if label!='SYSTEM':check(json.loads(raws['native/'+label+'-'+side+'.json'])==rows,'native full '+label+' '+side)
    check(len(inputs)==77 and sum(p['bytes']for p in inputs.values())==9647059,'all77 frozen request inputs')
    cn,_=namespace(R/'control');check(set(cn)=={n[8:]for n in inputs if n.startswith('control/')},'exact frozen control namespace')
    report['frozen_inputs']={'count':len(inputs),'bytes':sum(p['bytes']for p in inputs.values()),'all_identity_equal':True}
    report['source']={'count':1686,'bytes':40890650,'all_identity_equal':True}
    report['system']={'count':4806,'bytes':179325490,'all_identity_equal':True}
    # Read every full JSONL body again, independently of the runtime reader/model.
    expected,_=jread(R/'EXPECTED-MATRIX.json');traces={};hia_original=[];c_posts={}
    for kind in ('hia','C'):
        path=A/'native/trace'/kind;index,ip=jread(path/'INDEX.json',1<<20)
        want=expected['streams'][kind]
        check(index['schema']=='hia.wal-snapshot.native-stream.v1'and index['kind']==kind and index['complete']is True
            and index['chunk_limit']==4<<20 and index['shared_total_limit']==256<<20 and index['record_limit']==1<<20,'complete typed trace index')
        check(type(index['parts'])is list and len(index['parts'])==len({p['path']for p in index['parts']}),'unique trace parts')
        sha=hashlib.sha256();nbytes=nrows=maximum=0;previous=None;counts=collections.Counter()
        for number,item in enumerate(index['parts']):
            check(item['path']=='part-%04d.jsonl'%number,'strict part sequence')
            body,p=read(path/item['path'],4<<20);equal_pin(p,item,('bytes','sha256','git_blob'))
            lines=body.splitlines(keepends=True);check(type(item['records'])is int and len(lines)==item['records'],'part rows')
            for line in lines:
                check(line.endswith(b'\n')and len(line)<=1<<20,'complete bounded row')
                row=json.loads(line);check(wire(row)==line,'canonical exact JSON types')
                nrows+=1;maximum=max(maximum,len(line))
                if nrows%2:
                    check(row['event']=='pre'and previous is None,'PRE order');previous=row
                    check(row['method']in ids and type(row['lengths'])is list and len(row['lengths'])==3
                        and all(type(x)is int and x>=0 for x in row['lengths']),'PRE exact extents')
                    check(len(row['buffers_hex'])==3,'three full PRE buffers')
                    for length,value in zip(row['lengths'],row['buffers_hex']):
                        b=bytes.fromhex(value);check(b.hex()==value and len(b)==length+64,'full PRE bytes and canary')
                else:
                    pre=previous;previous=None
                    check(row['event']=='post'and row['actual_returned']is True,'actual POST return')
                    check(len(row['buffers_hex'])==3,'three full POST buffers')
                    for length,before,after in zip(pre['lengths'],pre['buffers_hex'],row['buffers_hex']):
                        b,a=bytes.fromhex(before),bytes.fromhex(after)
                        check(a.hex()==after and len(a)==length+64 and a[-64:]==b[-64:],'whole POST bounds/canaries')
                    check(row['buffers_hex'][0]==pre['buffers_hex'][0],'input not mutated')
                    counts[pre['method']]+=1
                    if kind=='hia':
                        ordinal=nrows//2
                        check(type(row['index'])is int and row['index']==pre['index']==ordinal
                            and type(row['status'])is int and row['status']in (128,0xfffffffd,0xfffffff9,0xfffffff8),'HIA exact ordinal/status')
                        if row['status']!=128:check(row['buffers_hex'][1:]==pre['buffers_hex'][1:],'refusal leaves output/state unchanged')
                        if ordinal<=608:
                            check(pre['population']=='original12','original608 population')
                            item={'case':pre['method'],'actual_returned':True,'status':row['status']}
                            for name,b,a in zip(('source','output','state'),pre['buffers_hex'],row['buffers_hex']):
                                item[name+'_before_hex']=bytes.fromhex(b)[:-64].hex();item[name+'_after_hex']=bytes.fromhex(a)[:-64].hex()
                            hia_original.append(item)
                        else:check(pre['population']=='full-page-extension'and pre['method']==ids[12],'independent added population')
                    else:
                        ordinal=(nrows//2-1)//2+1;version=('3.46.0','3.53.2')[(nrows//2-1)%2]
                        check(row['drive_index']==pre['drive_index']==ordinal and row['version']==pre['version']==version
                            and type(row['adapter_return'])is int and row['adapter_return']==0,'C frozen independent order')
                        words=row['raw_words'];check(type(words)is list and len(words)==32 and all(type(x)is int and 0<=x<1<<64 for x in words),'all32 actual C u64')
                        check(struct.pack('<32Q',*words)==bytes.fromhex(row['buffers_hex'][1])[:256],'raw C words equal actual output bytes')
                        pairbuf=bytes.fromhex(row['buffers_hex'][2]);check(type(words[18])is int and words[18]*16<=pre['lengths'][2],'actual read-pair count')
                        pairs=[list(struct.unpack_from('<2Q',pairbuf,i*16))for i in range(words[18])]
                        c_posts[(ordinal,version)]={'raw_words':words,'pairs':pairs,'source_sha256':hashlib.sha256(bytes.fromhex(pre['buffers_hex'][0])[:-64]).hexdigest()}
            nbytes+=len(body);sha.update(body)
        check(previous is None and nbytes==index['bytes']==want['bytes']and nrows==index['records']==want['records']
            and sha.hexdigest()==want['sha256']and maximum==want['maximum_record_bytes'],'full frozen byte stream digest/population')
        fn,_=namespace(path);check(set(fn)=={'INDEX.json',*(p['path']for p in index['parts'])},'exact trace namespace')
        if kind=='hia':check(dict(counts)=={k:v for k,v in q['native_counts'].items()if v},'HIA per-method trace count')
        else:check(sum(counts.values())==1278,'two639 actual C POSTs')
        traces[kind]={'index':ip,'parts':len(index['parts']),'bytes':nbytes,'rows':nrows,'sha256':sha.hexdigest(),'maximum_record_bytes':maximum,'all_full_body_bytes_read':True}
    original,_=jread(R/'reference/source12-actual/VM-RAW.json')
    check(hia_original==original['calls']and len(hia_original)==608,'all original608 six complete spans exact actual VM bytes')
    check(sum(x['bytes']for x in traces.values())==203187698<=256<<20,'two streams total')
    drives=json.loads(raws['native/DRIVES.json'])
    check(type(drives)is list and len(drives)==639 and len(expected['drives'])==639,'all639 drives')
    for n,(d,e)in enumerate(zip(drives,expected['drives']),1):
        check(all(d[k]==v for k,v in e.items())and d['index']==n and d['semantic_comparison_passed']is True,'independent fixed drive metadata')
        check([x['version']for x in d['actual_C']]==['3.46.0','3.53.2'],'two C versions per drive')
        for r in d['actual_C']:
            actual=c_posts[(n,r['version'])]
            check(r['raw_trace_retained_before_projection']is True and r['raw_words']==actual['raw_words']
                and r['projection']==e['expected_C_projection']and actual['source_sha256']==e['C_view_sha256'],'raw C before independent fixed-prefix projection')
    report['trace']=traces;report['all_original608_complete_buffers_equal']=True;report['C_raw_and_fixed_projection_drives']=639
    # Compiler source, complete output prefix, request/receipt/stdout and both DSO bindings.
    cr=json.loads(raws['hia-compile/snapshot.receipt.json']);cq=json.loads(raws['hia-compile/snapshot.request.json']);cs=json.loads(raws['hia-compile/snapshot.stdout.log'])
    added={'case','input_sha256','input_bytes','artifact_sha256','format','runner_sha256','wall_elapsed_ns','produced_image','produced_bytes','produced_sha256'}
    check(set(cr)-set(cs)==added and {k:v for k,v in cr.items()if k not in added}==cs,'complete compiler receipt/stdout')
    source_bytes=read(R/'reference/source12-actual/sqlite_wal_snapshot.hiaasm')[0];image=raws['hia-compile/snapshot.image.bin'];full=raws['hia-compile/snapshot.output.bin']
    check(raws['hia-compile/snapshot.input.bin']==source_bytes and image==full[:len(image)]and len(full)==1<<20
        and 0<len(image)<=1<<20 and cr['status']=='returned'and cr['source_unchanged']is True
        and type(cr['abi_status'])is int and cr['abi_status']==0 and cr['forbidden_compiler_modules_loaded']==[]
        and cr['core_u32']==cr['result_u64']==cr['produced_bytes']==len(image)
        and cr['source_sha256']==cr['input_sha256']==cq['source_sha256']==hashlib.sha256(source_bytes).hexdigest()
        and cr['produced_sha256']==hashlib.sha256(image).hexdigest()and cr['output_sha256']==hashlib.sha256(full).hexdigest()
        and cr['runner_sha256']==q['original_child_sha256']and cr['wall_elapsed_ns']<=20000000000
        and cq['image_sha256']==cr['image_sha256']==q['development_compiler']['image_sha256'],'new exact original-budget HIA compile')
    check(cq['image']==str(R/'compiler-inputs/B3.image.bin') and cq['source']==str(A/'hia-compile/snapshot.input.bin')
        and cq['output']==str(A/'hia-compile/snapshot.output.bin') and cq['format']=='flat-x86-64'
        and cq['capacity']==cq['workspace_size']==1<<20 and cq['workspace_fill']==0
        and cr['limits']=={'cpu_seconds':10,'address_bytes':256<<20,'core_dumpable':False,
            'stack_bytes':8<<20,'output_capacity':1<<20,'workspace_bytes':1<<20}
        and cr['format']=='flat-x86-64' and cr['input_bytes']==len(source_bytes)
        and cr['produced_image']==str(A/'hia-compile/snapshot.image.bin'),'full new compiler ABI/limits/paths')
    # Historical development compiler remains seven complete originals, not just an image.
    custody,_=jread(R/'reference/B3-ORIGINALS-CUSTODY.json')
    b3b={}
    check(len(custody['members'])==7 and {x['path']for x in custody['members']}==set(namespace(R/'compiler-inputs')[0]),'all seven compiler originals')
    for item in custody['members']:
        body,p=read(R/'compiler-inputs'/item['path'],2<<20)
        check((p['bytes'],p['sha256'],p['git_blob'],zlib.crc32(body)&0xffffffff)==
            (item['size'],item['sha256'],item['git_blob_sha1'],item['zip_crc32']),'complete historical B3 body/CRC')
        b3b[item['path']]=body
    b3r=json.loads(b3b['B3.receipt.json']);b3q=json.loads(b3b['B3.request.json']);b3s=json.loads(b3b['B3.stdout.log'])
    check(set(b3r)-set(b3s)==added and {k:v for k,v in b3r.items()if k not in added}==b3s,'historical B3 receipt whole projection')
    b3image=b3b['B3.image.bin'];b3source=b3b['B3.input.bin'];b3full=b3b['B3.output.bin']
    check(len(b3image)==670467 and len(b3full)==1<<20 and b3image==b3full[:len(b3image)]
        and b3r['status']=='returned' and b3r['source_unchanged']is True and b3r['abi_status']==0
        and b3r['forbidden_compiler_modules_loaded']==[] and b3r['produced_bytes']==b3r['core_u32']==b3r['result_u64']==len(b3image)
        and b3r['output_sha256']==hashlib.sha256(b3full).hexdigest()
        and b3q['source_sha256']==b3r['input_sha256']==b3r['source_sha256']==hashlib.sha256(b3source).hexdigest()
        and b3q['image_sha256']==b3r['artifact_sha256']==b3r['image_sha256']==b3r['produced_sha256']==hashlib.sha256(b3image).hexdigest()
        ==q['development_compiler']['image_sha256'],'historical B3 complete source/output/image joins')
    ccompile={}
    for v in ('3.46.0','3.53.2'):
        directory=A/('C-'+v);adapter=R/'candidate/native-oracles'/('sqlite-'+v)/'adapter.c'
        c=json.loads(raws['C-'+v+'/COMPILE.json']);b=raws['C-'+v+'/oracle.so']
        cqr=json.loads(raws['C-'+v+'/REQUEST.json'])
        wanted_argv=[q['system_binaries']['gcc'],'-std=c11','-O2','-fPIC','-shared','-fno-lto','-fno-common',
            '-fno-strict-aliasing','-fno-fast-math','-g0','-save-temps=obj','-Wl,-Bsymbolic','-Wl,-z,defs',
            '-MD','-MF',str(directory/'oracle.d'),'-MT',str(directory/'oracle.so'),
            '-Wl,-Map,'+str(directory/'oracle.map'),'-o',str(directory/'oracle.so'),str(adapter)]
        check(cqr=={'schema':'hia.wal-snapshot.C-compile-request.v1','version':v,'output':str(directory),
            'cwd':str(directory),'argv':wanted_argv,'environment':{'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C',
            'TZ':'UTC','TMPDIR':str(directory/'tmp')},'source_inputs':{str(adapter):inputs[str(adapter.relative_to(R))]},
            'wall_seconds':20,'cpu_seconds':10,'max_image_bytes':1<<20},'complete C request reconstructed independently')
        check(c['request']==pins['C-'+v+'/REQUEST.json'] and c['argv']==cqr['argv'] and c['cwd']==cqr['cwd']
            and c['environment']==cqr['environment'] and c['inputs_before']==c['inputs_after']==cqr['source_inputs'],'C request/report/full inputs joins')

        check(c['status']=='C_ORIGINAL_ALGORITHMS_COMPILED_ONLY'and c['returncode']==0 and c['timed_out']is False
            and c['exception']is None and c['secondary_errors']==[]and c['attempted']is True
            and c['inputs_before']==c['inputs_after']and 0<=c['elapsed_ns']<=20000000000
            and c['limits']=={'wall_seconds':20,'cpu_seconds':10,'address_bytes':256<<20,'stack_bytes':8<<20,'file_bytes':1<<20,'core_bytes':0}
            and b[:6]==b'\x7fELF\x02\x01'and int.from_bytes(b[16:18],'little')==3 and int.from_bytes(b[18:20],'little')==62
            and hashlib.sha256(b).hexdigest()==c['image']['sha256'],'complete C compile original')
        target,sep,deps=raws['C-'+v+'/oracle.d'].decode().replace('\\\n','').partition(':')
        check(sep and target.strip()==str(directory/'oracle.so'),'original depfile target')
        names=shlex.split(deps);check(bool(names),'nonempty actual whole C depfile')
        allowed_c={**system,str(adapter):inputs[str(adapter.relative_to(R))]}
        dependencies=[]
        for name in names:
            key=str(Path(name).resolve(strict=True));check(key in allowed_c,'actual C dependency in complete frozen closure')
            dependencies.append(allowed_c[key])
        loads=[x[5:].strip()for x in raws['C-'+v+'/oracle.map'].decode().splitlines()if x.startswith('LOAD ')]
        check(bool(loads),'complete actual link LOAD list');loadrows=[]
        for name in loads:
            key=Path(name).resolve(strict=True)
            if key.is_relative_to(directory):
                rel=str(key.relative_to(A));check(rel in pins,'retained actual object link input');loadrows.append(pins[rel])
            else:
                check(str(key)in allowed_c,'actual link dependency in frozen closure');loadrows.append(allowed_c[str(key)])
        saved={name.split('/',1)[1]:p for name,p in pins.items()if name.startswith('C-'+v+'/')}
        check(any(x.endswith('.i')for x in saved)and any(x.endswith('.s')for x in saved)and any(x.endswith('.o')for x in saved)
            and not any(x.startswith('tmp/')for x in saved),'actual preprocessing/assembly/object retained; tmp empty')
        result={'receipt':pins['C-'+v+'/COMPILE.json'],'image':pins['C-'+v+'/oracle.so'],
            'depfile':pins['C-'+v+'/oracle.d'],'dependencies':dependencies,'link_map':pins['C-'+v+'/oracle.map'],
            'link_inputs':loadrows,'whole_case_files':saved}
        check(result==final['C_compiles'][v]==worker['C-'+v],'complete independent C original graph')
        ccompile[v]={'dependencies':len(dependencies),'link_inputs':len(loadrows),'image':pins['C-'+v+'/oracle.so']}
    report['C_compilers']=ccompile

    # Each nested producer pin is joined to the actual complete original in our catalog or immutable inputs.
    allowed={p['path']:p for p in pins.values()};allowed.update({p['path']:p for p in inputs.values()});allowed.update({p['path']:p for p in source.values()});allowed.update(system);allowed[str(R/'REQUEST.json')]=qp
    def join(value):
        if isinstance(value,dict):
            if all(k in value for k in ('path','bytes','sha256','git_blob','identity')):
                check(value['path']in allowed,'producer pin outside exact actual/input/source/system closure')
                equal_pin(allowed[value['path']],value)
            for v in value.values():join(v)
        elif isinstance(value,list):
            for v in value:join(v)
    for doc in (final,worker,child):join(doc)
    check(child['mapped_files_before']['files']==child['mapped_files_after']['files']
        and child['mapped_files_before']['image_binding']==child['mapped_files_after']['image_binding'],'same current native mapping before/after')
    report['actual_elapsed']={'owner_ns':elapsed,'worker_ns':worker['elapsed_ns'],'native_ns':child['elapsed_ns']}
    report['status']='FINITE_NATIVE_ORIGINALS_INDEPENDENT_READBACK_PASS'
    report['matching_current_cold_SQL_locks_durability_or_default_qualified']=False
    report['elapsed_ns']=time.monotonic_ns()-started
created=False
try:
    check(not O.exists(),'new independent audit output')
    O.mkdir(mode=0o700);created=True
    main()
except BaseException as e:
    report['errors'].append({'type':type(e).__module__+'.'+type(e).__qualname__,'message':str(e),'traceback':traceback.format_exc()})
    report['status']='HOLD'
finally:
    body=(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    if created:
        fd=os.open(O/'READBACK.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as f:f.write(body);f.flush();os.fsync(f.fileno())
    print(json.dumps({'status':report['status'],'checks':report['checks'],'owner_closed':report['owner_closed'],'errors':report['errors']}))

raise SystemExit(0 if report['status']=='FINITE_NATIVE_ORIGINALS_INDEPENDENT_READBACK_PASS' else 1)
