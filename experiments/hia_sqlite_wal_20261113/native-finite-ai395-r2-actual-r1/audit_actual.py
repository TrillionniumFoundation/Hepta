"""Independent closed-original WAL audit. Reads evidence only; no HIA/VM/C invocation."""
from pathlib import Path
import ast,collections,hashlib,json,os,shlex,stat,struct,sys,time,traceback
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1');ROOT=P/'sqlite-wal-native-r2';ACT=P/'sqlite-wal-native-r2-actual';OUT=P/'sqlite-wal-native-r2-independent-audit-r1'
sys.path.insert(0,str(ROOT/'control'))
import common,support,compile_io
checks=0
def require(v,label):
    global checks
    checks+=1
    if not v:raise RuntimeError(label)
def wire(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def git(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def read(path):return common.read(Path(path),64<<20)
def doc(path):
    pin,b=read(path);return pin,json.loads(b)
def match(pin,expected):
    return all(pin[k]==expected[k] for k in ('bytes','sha256','git_blob','identity'))
def dump(path,value):
    b=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with path.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    os.chmod(path,0o600);require(read(path)[1]==b,'audit writeback')
    return read(path)[0]
def inventory(path):
    rows=[]
    for p in sorted(path.rglob('*')):
        s=p.lstat()
        if stat.S_ISREG(s.st_mode):
            pin,b=read(p);rows.append({'relative_path':str(p.relative_to(path)),**pin})
        else:require(stat.S_ISDIR(s.st_mode),'no special actual directory')
    return {'files':rows,'file_count':len(rows),'bytes':sum(x['bytes'] for x in rows)}
MASK=(1<<32)-1;MAGIC=int.from_bytes(b'HIASWL01','little')
PROTO,FORMAT,CHECKSUM,SALT,VERSION=0xfffffffd,0xfffffffc,0xfffffffb,0xfffffffa,0xfffffff9
CANARY=bytes(range(64))
def pageok(p):return 512<=p<=65536 and p&(p-1)==0
def sum32(raw,order,s0=0,s1=0):
    require(len(raw)%8==0,'independent sum whole pairs')
    words=struct.unpack(('>' if order else '<')+str(len(raw)//4)+'I',raw)
    for x,y in zip(words[::2],words[1::2]):
        s0=(s0+x+s1)%2**32
        s1=(s1+y+s0)%2**32
    return [s0,s1]
def expectation(raw,out,control):
    # Interpret raw transport independently; never import producer matrix/trace algorithms.
    result={'status':PROTO,'out':out,'operation':None,'C_rc':None,'C_words':None,'seed_before':None,'C_seed_after':None}
    if len(control)!=64:return result
    magic,op,order,s0,s1,page,a,b=struct.unpack('<8Q',control)
    if magic!=MAGIC:return result
    if op==1:
        if len(out)!=8 or len(raw)<8 or len(raw)>65536 or len(raw)%8 or order>1 or s0>MASK or s1>MASK or page or a or b:return result
        pair=sum32(raw,order,s0,s1)
        result.update(status=8,out=struct.pack('<2I',*pair),operation='checksum',C_rc=1,C_words=pair,seed_before=[s0,s1],C_seed_after=pair)
    elif op==2:
        if len(raw)!=32 or len(out)!=32 or any((order,s0,s1,page,a,b)):return result
        magic,version,page,checkpoint,a,b,h0,h1=struct.unpack('>8I',raw)
        words=[0,0,magic,page,0,0,0,0,0,0,0,0]
        result.update(status=FORMAT,operation='header',C_rc=0,C_words=words,seed_before=[0,0],C_seed_after=[0,0])
        if (magic&0xfffffffe)!=0x377f0682 or not pageok(page):return result
        order=magic&1;pair=sum32(raw[:24],order)
        words[5:]=[*pair,checkpoint,a,b,order,page];result.update(status=CHECKSUM,C_seed_after=pair)
        if pair!=[h0,h1]:return result
        words[4]=version;result['status']=VERSION
        if version!=3007000:words[1]=14;return result
        words[0]=1;result.update(status=32,C_rc=1,out=struct.pack('<8I',*pair,page,checkpoint,a,b,order,version))
    elif op==3:
        if len(out)!=16 or order>1 or max(s0,s1,a,b)>MASK or not pageok(page) or len(raw)!=page+24:return result
        pg,commit,ra,rb,h0,h1=struct.unpack('>6I',raw[:24]);words=[s0,s1,0,0]
        result.update(status=SALT,operation='frame',C_rc=0,C_words=words,seed_before=[s0,s1],C_seed_after=[s0,s1])
        if (ra,rb)!=(a,b):return result
        result['status']=FORMAT
        if pg==0:return result
        pair=sum32(raw[:8]+raw[24:],order,s0,s1);words[:2]=pair
        result.update(status=CHECKSUM,C_seed_after=pair)
        if pair!=[h0,h1]:return result
        words[2:]=[pg,commit];result.update(status=16,C_rc=1,out=struct.pack('<4I',*words))
    return result
def parse_maps(raw):
    rows=[];previous=0
    for line in raw.decode('ascii').splitlines():
        f=line.split(None,5);require(len(f) in (5,6),'map columns')
        start,end=[int(x,16) for x in f[0].split('-')]
        row={'line':line,'start':start,'end':end,'permissions':f[1],'offset':int(f[2],16),'device':[int(x,16) for x in f[3].split(':')],'inode':int(f[4]),'name':f[5] if len(f)==6 else ''}
        require(previous<=start<end<=1<<64,'sorted nonoverlap maps');previous=end;rows.append(row)
    return rows
if OUT.exists():raise RuntimeError('new independent audit namespace required')
OUT.mkdir(mode=0o700)
report={'schema':'hia.sqlite.wal.closed-actual-independent-audit.v1','status':'HOLD','errors':[],'qualification_reexecuted':False,'VM_or_native_or_C_called':False}
started=time.monotonic_ns();closed=False
try:
    qpin,q=doc(ROOT/'REQUEST.json')
    require(qpin['sha256']=='f81436adba2e858327e474facfbf54476100d8d046e5eb8fcdf92a7488d52e92','frozen request exact')
    lpin,life=doc(ACT/'lifecycle.json');ppin,parent=doc(ACT/'lifecycle.json.request.json');wpin,wrapper=doc(ACT/'OWNER-RETURN.json')
    closed,natural=support.natural_owner(wrapper,life,parent,q,qpin['sha256'],lpin,ppin)
    require(closed and natural,'closed natural original180/3 bound owner')
    require([x['kind'] for x in life['events']]==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'],'four natural owner events')
    report['owner']={'lifecycle':lpin,'request':ppin,'wrapper':wpin,'closed':closed,'natural':natural,'owner_status':life['status'],'qualification_seconds':180,'cleanup_seconds':3}
    before=inventory(ACT);require(before['file_count']<=192 and before['bytes']<=384<<20,'all actual body quota')
    fpin,final=doc(ACT/'FINAL.json');rpin,result=doc(ACT/'native/REPORT.json');wkp,worker=doc(ACT/'WORKER.json')
    report['producer']={'FINAL':fpin,'WORKER':wkp,'REPORT':rpin}
    require(final['status']=='FINITE_NATIVE_WAL_AND_TWO_ORACLES_PASS_ONLY' and final['errors']==[] and final['owner_closed'] is True and final['owner_natural'] is True,'finite parent PASS fields')
    require(worker['status']=='FINITE_NATIVE_WORKER_PASS_ONLY' and worker['exception'] is None and worker['secondary_errors']==[] and worker['request']==qpin,'worker PASS fields')
    ids=q['expected_ids'];counts=[0,46,56,16,54,32,8,26,0,0]
    require(len(ids)==10 and q['native_counts']==counts and q['native_returns']==238 and sum(counts)==238,'frozen full native denominator')
    require(result['status']=='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY' and result['expected_ids']==result['loaded_ids']==result['actual_ids']==result['success_ids']==ids and result['tests_run']==10,'all original ten methods')
    require(result['native_returns']==result['actual_native_starts']==238 and result['native_counts']==dict(zip(ids,counts)),'full method native counts')
    require(result['exception'] is None and all(result[k]==[] for k in ('secondary_errors','denied_effects','failures','errors','skipped','expected_failures','unexpected_successes')),'all anomalies zero')
    for d,keys in ((final,('source10_VM_reexecuted','matching_cold_qualification','SQL_engine_or_durability_qualification')),(worker,('source10_VM_reexecuted','matching_cold_qualification','SQL_or_durability_closed')),(result,('source10_VM_reexecuted','matching_cold_qualification','database_opened','network_used'))):
        require(all(d[k] is False for k in keys),'scope remains finite native only')
    for value in (worker['elapsed_ns'],result['elapsed_ns']):require(type(value)is int and 0<=value<=180000000000,'finite execution elapsed')
    # Current full fixed/source/system observations; compare every pre/post record.
    fixed=support.input_records(q);source=support.source_records(q);system=support.system_records(q)
    require((len(fixed),len(source),len(system))==(72,1686,4806),'all physical inputs count')
    for label,current in [('INPUTS',fixed),('SOURCE',source),('SYSTEM',system)]:
        prefix='WORKER-' if label!='SYSTEM' else ''
        pb=doc(ACT/('PARENT-'+label+'-BEFORE.json'))[1];pa=doc(ACT/('PARENT-'+label+'-AFTER.json'))[1]
        wb=doc(ACT/(prefix+label+'-BEFORE.json'))[1];wa=doc(ACT/(prefix+label+'-AFTER.json'))[1]
        require(pb==pa==wb==wa==current,'all original and current '+label+' fullbytes/identity')
    require(result['inputs_before']==result['inputs_after']==fixed and result['source_before']==result['source_after']==source,'native child exact physical inputs')
    report['physical_input_full_read']={'fixed':len(fixed),'source':len(source),'system':len(system),'source_bytes':sum(x['bytes'] for x in source.values()),'system_bytes':sum(x['bytes'] for x in system.values()),'all_before_after_and_fresh_equal':True}
    report['new_generation']=support.inspect_source_generation(q)
    report['development_compiler_originals']=support.inspect_compiler_inputs()
    report['HIA_compile']=support.inspect_new_compile(ACT/'hia-compile',q)
    report['C_compiles']={v:compile_io.inspect(q,v,ACT/('C-'+v)) for v in ('3.46.0','3.53.2')}
    report['official_C_fullsources_excerpts']=support.inspect_official_oracles()
    require(report['HIA_compile']==final['HIA_compile']==worker['HIA_compile'],'new complete HIA receipt/fulloutput joins')
    require(report['C_compiles']==final['C_compiles'],'two complete independent C compiles')
    require(report['new_generation']==final['source_caps']==worker['new_source_generation'],'new source generation receipts')
    # No module under hepta/tools/tests was imported by this independent reader.
    require(not any(x=='hepta' or x.startswith('hepta.') or x=='tools' or x.startswith('tools.') or x=='tests' or x.startswith('tests.') for x in sys.modules),'reader invokes no SUT module')
    allowed={str(ROOT/k):v for k,v in fixed.items()};allowed.update({str(Path(q['source_root'])/k):v for k,v in source.items()})
    for side in ('imports',):
        for d in (worker,result):
            for item in d[side]:
                p=item['source'];require(p['path'] in allowed and match(p,allowed[p['path']]),'all imported project source byte pins')
    # Full actual maps from both recorded observation points, never read a dead child's /proc.
    mapsummary=[]
    for which in ('before','after'):
        recorded=result['mapped_files_'+which];binding=recorded['image_binding']
        mp,raw=read(ACT/'native'/('mapping-'+which+'.maps.original'))
        require(mp==recorded['maps_original'],'maps exact rawpin');rows=parse_maps(raw)
        require([r['line'] for r in rows]==[r['line'] for r in recorded['maps']],'all actual map lines present')
        require(binding['image']==report['HIA_compile']['pins']['wal.image.bin'] and binding['logical_bytes']==report['HIA_compile']['image_bytes'] and binding['complete_image_sha256']==report['HIA_compile']['image_sha256'],'logical whole image map seal')
        require(binding['requires_exact_single_segment'] is True and binding['entry_address']==binding['address'] and binding['address']%binding['page_size']==0 and binding['mapping_end']==binding['address']+((binding['logical_bytes']+binding['page_size']-1)//binding['page_size'])*binding['page_size'],'whole page-rounded image and actual entry')
        overlap=[r for r in rows if r['start']<binding['mapping_end'] and r['end']>binding['address']]
        require(len(overlap)==1 and overlap[0]==binding['actual_segment'],'exact actual segment only')
        target=overlap[0];require(target['permissions']=='r-xs' and target['offset']==0,'bound shared RX only')
        require(target['name']=='/dev/zero (deleted)' and target['inode']>0 or target['name']=='' and target['inode']==0 and target['device']==[0,0],'only specifically bound anonymous image')
        for row,typed in zip(rows,recorded['maps']):
            if row is target:require(typed['role']=='current-bound-HIA-image','bound row role');continue
            require(not(target['inode'] and row['inode']==target['inode'] and row['device']==target['device']),'no same backing mapped alias')
            if row['name'].startswith('/'):
                require(not row['name'].endswith(' (deleted)') and typed['role']=='frozen-file','other deleted file rejected')
                pin=recorded['files'][typed['file']]
                require(row['inode']==pin['identity'][1] and row['device']==[os.major(pin['identity'][0]),os.minor(pin['identity'][0])],'mapped dev/inode')
                current=system.get(pin['path']) or allowed.get(pin['path'])
                if current is None:
                    current=report['C_compiles']['3.46.0']['image'] if pin['path']==report['C_compiles']['3.46.0']['image']['path'] else report['C_compiles']['3.53.2']['image']
                require(match(pin,current),'all mapped whole-file pins')
            elif 'x' in row['permissions']:
                require((row['name'],row['permissions']) in (('[vdso]','r-xp'),('[vsyscall]','--xp')) and row['inode']==row['offset']==0 and row['device']==[0,0],'no unbound anonymous executable')
        mapsummary.append({'phase':which,'raw':mp,'rows':len(rows),'files':len(recorded['files']),'binding':binding})
    require(result['mapped_files_before']['files']==result['mapped_files_after']['files'] and result['mapped_files_before']['image_binding']==result['mapped_files_after']['image_binding'],'both observation point identities equal')
    report['mapping_observations']=mapsummary
    # Independent complete raw row and two-C output arithmetic.
    ip,index=doc(ACT/'native/trace/INDEX.json');tp,expected_trace=doc(ROOT/'EXPECTED-TRACE.json')
    require(index['complete'] is True and index['records']==476 and index['native_returns']==238 and index['bytes']==1321832,'complete actual trace denominator')
    body=b'';partpins=[]
    for n,p in enumerate(index['parts']):
        require(p['path']=='part-%04d.jsonl'%n,'contiguous trace names')
        pin,b=read(ACT/'native/trace'/p['path'])
        require(all(pin[k]==p[k] for k in ('bytes','sha256','git_blob')) and len(b.splitlines())==p['records'],'full each trace body seal')
        body+=b;partpins.append(pin)
    require(len(body)==expected_trace['bytes']==index['bytes'] and sha(body)==expected_trace['sha256']=='6ac2ce23ab62b3f2925c054a733ab65618e9de7f7021be554c0a0a42f0ce3652','whole actual trace bytes/SHA')
    lines=body.splitlines(keepends=True);require(len(lines)==476,'whole actual lines')
    method_counts=dict.fromkeys(ids,0);status_counts=collections.Counter();Ccounts={v:collections.Counter() for v in ('3.46.0','3.53.2')};changed={v:0 for v in Ccounts};case_rows=[]
    for n in range(238):
        pre,post=(json.loads(x) for x in lines[2*n:2*n+2])
        require(wire(pre)==lines[2*n] and wire(post)==lines[2*n+1],'full canonical exact typed rows')
        require(pre['event']=='pre' and post['event']=='post' and type(pre['index'])is int and type(post['index'])is int and pre['index']==post['index']==n+1 and post['actual_returned'] is True and type(post['status'])is int,'complete ordered actual return')
        require(pre['method'] in method_counts and [type(x) for x in pre['lengths']]==[int,int,int],'original method identity/extent exact types')
        before_bytes=[bytes.fromhex(x) for x in pre['buffers_hex']];after_bytes=[bytes.fromhex(x) for x in post['buffers_hex']]
        require(len(before_bytes)==len(after_bytes)==3,'three spans')
        for length,b,a in zip(pre['lengths'],before_bytes,after_bytes):
            require(len(b)==len(a)==length+64 and b[-64:]==a[-64:]==CANARY,'all whole spans/canaries')
        source_raw,out_raw,command_raw=[b[:-64] for b in before_bytes]
        expected=expectation(source_raw,out_raw,command_raw)
        require(post['status']==expected['status'] and after_bytes[0]==before_bytes[0] and after_bytes[2]==before_bytes[2] and after_bytes[1]==expected['out']+CANARY,'independent HIA semantics and refusal atomicity')
        require(len(post['oracles'])==2 and [o['version'] for o in post['oracles']]==list(Ccounts),'two actual original C versions in order')
        for oracle in post['oracles']:
            v=oracle['version']
            if expected['operation'] is None:
                require(oracle=={'version':v,'called':False,'reason':'outside_original_C_and_HIA_transport_domain'},'invalid C domain not called');Ccounts[v]['not_called']+=1;continue
            require(oracle['called'] is True and type(oracle['returned'])is int and oracle['operation']==expected['operation'] and oracle['returned']==expected['C_rc'],'C actual return without bool alias')
            require(all(type(x)is int for x in oracle['output_words']) and oracle['output_words']==expected['C_words'],'complete C state not modified for projection')
            require(oracle['seed_before']==expected['seed_before'] and oracle['input_before_hex']==oracle['input_after_hex']==(source_raw+CANARY).hex(),'C complete raw input/seed unchanged')
            out=struct.pack('<'+str(len(expected['C_words']))+'I',*expected['C_words'])
            require(oracle['output_before_hex']==(b'\xa5'*len(out)+CANARY).hex() and oracle['output_after_hex']==(out+CANARY).hex(),'full C actual output and canary')
            require(type(oracle['input_alignment_mod4'])is int and type(oracle['output_alignment_mod4'])is int and oracle['input_alignment_mod4']==oracle['output_alignment_mod4']==0,'actual C alignment')
            change=expected['status'] in (PROTO,FORMAT,CHECKSUM,SALT,VERSION) and expected['C_seed_after']!=expected['seed_before']
            projection={'hia_status':expected['status'],'hia_output_hex':expected['out'].hex(),'C_seed_before':expected['seed_before'],'C_seed_after':expected['C_seed_after'],'C_seed_changed_on_HIA_refusal':change,'C_raw_output_preserved':True,'HIA_control_immutable':True}
            require(wire(oracle['derived_projection'])==wire(projection),'separate refusal projection leaves actual C output intact')
            Ccounts[v][expected['operation']]+=1;changed[v]+=int(change)
        method_counts[pre['method']]+=1;status_counts[str(post['status'])]+=1
        case_rows.append({'index':n+1,'method':pre['method'],'label':pre['label'],'status':post['status'],'pre_sha256':sha(lines[2*n]),'post_sha256':sha(lines[2*n+1]),'C_domain':expected['operation']})
    require(method_counts==dict(zip(ids,counts)),'independent actual all ten counts')
    require(all(dict(c)=={'checksum':102,'header':50,'frame':32,'not_called':54} for c in Ccounts.values()) and all(v==38 for v in changed.values()),'independent both C full denominators')
    require(dict(status_counts)=={'8':102,'32':18,str(PROTO):54,str(FORMAT):14,str(CHECKSUM):32,str(VERSION):6,'16':6,str(SALT):6},'independent status population')
    report['full_trace']={'index':ip,'parts':partpins,'bytes':len(body),'sha256':sha(body),'records':len(lines),'native_returns':238,'methods':method_counts,'C_counts':{v:dict(c) for v,c in Ccounts.items()},'changed_C_seed_on_HIA_refusal':changed,'status_counts':dict(status_counts),'all_raw_HIA_and_C_bytes_independently_recomputed':True,'cases':case_rows}
    after=inventory(ACT);require(before==after,'every actual fullbyte/identity stable after audit')
    report['actual_originals']=after
    root_names={'root-wal-native-r2-r1-INTENT.json':(3708,'6a556aa1f608376ba6abfeae2b19a73a27dd71e0277be0312813512c61831354'),'root-wal-native-r2-r1-OWNER-READBACK.json':(6443,'535ee8739db2d3366d1139d680acd9530cbfa6f48274b5bbf7f1faac688a477c'),'root-wal-native-r2-r1-HJOB.json':(5309,'6ad0cc7dfb7e37dc96a2cec5057518de2eb2abe6ddafd6758acc5429ed7afc2f')}
    report['root_originals']={}
    for name,(size,digest) in root_names.items():
        pin,b=read(P/name);require(pin['bytes']==size and pin['sha256']==digest,'Root stopped original pin');report['root_originals'][name]=pin
    report['timings_ns']={'worker':worker['elapsed_ns'],'native_child':result['elapsed_ns'],'outer_launcher':final['elapsed_ns'],'elapsed_durations_not_CPU_causality':True}
    report['status']='INDEPENDENT_FULL_WAL_NATIVE_TEN_238_AND_TWO_C_READBACK_PASS'
except BaseException as exc:
    report['status']='HOLD';report['errors'].append(type(exc).__name__+': '+str(exc));report['traceback']=traceback.format_exc()
finally:
    report['owner_closed_before_child_enumeration']=closed;report['checks']=checks;report['elapsed_ns']=time.monotonic_ns()-started
    p=dump(OUT/'READBACK.json',report)
    print(json.dumps({'status':report['status'],'errors':report['errors'],'checks':checks,'report':p,'actual_files':report.get('actual_originals',{}).get('file_count'),'actual_bytes':report.get('actual_originals',{}).get('bytes'),'native_reexecuted':False}))
if report['errors']:raise SystemExit(1)
