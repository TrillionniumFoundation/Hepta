"""Independent closed-original RECORD audit. Reads evidence only; no HIA/VM/C invocation."""
from pathlib import Path
import ast,collections,hashlib,json,os,shlex,stat,struct,sys,time,traceback
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1');ROOT=P/'sqlite-record-native-r1';ACT=P/'sqlite-record-native-r1-actual';OUT=P/'sqlite-record-native-r1-independent-audit-r1'
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
MASK64=(1<<64)-1;MAGIC=int.from_bytes(b'HIASRC01','little')
PROTOCOL,TRUNCATED,CAPACITY,FORMAT,RESERVED,LIMIT=0xfffffffd,0xfffffffe,0xfffffffc,0xfffffffb,0xfffffffa,0xfffffff9
CANARY=bytes(range(64))
def decode_varint(data,pos,end):
    number=0
    for n in range(9):
        if pos+n>=end:return None
        b=data[pos+n]
        if n==8:return (number<<8)|b,n+1
        number=(number<<7)|(b&127)
        if not(b&128):return number,n+1
    raise AssertionError('bounded decoder')
def expectation(raw,out,cmd):
    value={'status':PROTOCOL,'out':out,'fields':None,'format':None}
    if len(cmd)!=32:return value
    m,op,version,reserved=struct.unpack('<4Q',cmd)
    if (m,op)!=(MAGIC,1) or version not in (1,2,3,4) or reserved or len(raw)>1048576 or len(out)>80032:return value
    head=decode_varint(raw,0,len(raw));value['status']=TRUNCATED
    if head is None:return value
    extent,used=head
    if extent<used:value['status']=FORMAT;return value
    if extent>len(raw):return value
    position=used;body=extent;fields=[]
    while position<extent:
        pair=decode_varint(raw,position,extent)
        if pair is None:value['status']=FORMAT;return value
        serial,n=pair
        if serial in (10,11):value['status']=RESERVED;return value
        if serial in (8,9) and version!=4:value['status']=FORMAT;return value
        width=(0,1,2,3,4,6,8,8,0,0)[serial] if serial<10 else (serial-12)//2
        if width>len(raw)-body:value['status']=TRUNCATED;return value
        payload=raw[body:body+width];bits=0;kind=0;flags=1
        if 1<=serial<=6:
            unsigned=int.from_bytes(payload,'big')
            signed=unsigned-(1<<(8*width)) if payload[0]&128 else unsigned
            bits=signed&MASK64;kind=1;flags=4
        elif serial in (8,9):bits=serial-8;kind=1;flags=4
        elif serial==7:
            bits=int.from_bytes(payload,'big');nan=(bits>>52)&2047==2047 and (bits&((1<<52)-1))!=0
            kind=0 if nan else 2;flags=1 if nan else 8
        elif serial>=12:kind=3 if serial&1 else 4;flags=0x4002 if serial&1 else 0x4010
        fields.append({'serial_type':serial,'offset':body,'length':width,'bits':bits,'kind':kind,'C_flags':flags})
        position+=n;body+=width
        if len(fields)>2000:value['status']=LIMIT;return value
    if body!=len(raw):value['status']=FORMAT;return value
    size=32+40*len(fields)
    if len(out)<size:value['status']=CAPACITY;return value
    output=struct.pack('<4Q',len(fields),extent,len(raw)-extent,len(raw))
    for field in fields:output+=struct.pack('<5Q',field['serial_type'],field['offset'],field['length'],field['bits'],field['kind'])
    value.update(status=size,out=output+out[size:],fields=fields,format=version)
    return value
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
report={'schema':'hia.sqlite.record.closed-actual-independent-audit.v1','status':'HOLD','errors':[],'qualification_reexecuted':False,'VM_or_native_or_C_called':False}
started=time.monotonic_ns();closed=False
try:
    qpin,q=doc(ROOT/'REQUEST.json')
    require(qpin['sha256']=='48583129f1202d74256190dae479622110e787ae3e744bc1b4f5e596c9fa399c','frozen request exact')
    lpin,life=doc(ACT/'lifecycle.json');ppin,parent=doc(ACT/'lifecycle.json.request.json');wpin,wrapper=doc(ACT/'OWNER-RETURN.json')
    closed,natural=support.natural_owner(wrapper,life,parent,q,qpin['sha256'],lpin,ppin)
    require(closed and natural,'closed natural original180/3 bound owner')
    require([x['kind'] for x in life['events']]==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'],'four natural owner events')
    report['owner']={'lifecycle':lpin,'request':ppin,'wrapper':wpin,'closed':closed,'natural':natural,'owner_status':life['status'],'qualification_seconds':180,'cleanup_seconds':3}
    before=inventory(ACT);require(before['file_count']<=192 and before['bytes']<=384<<20,'all actual body quota')
    fpin,final=doc(ACT/'FINAL.json');rpin,result=doc(ACT/'native/REPORT.json');wkp,worker=doc(ACT/'WORKER.json')
    report['producer']={'FINAL':fpin,'WORKER':wkp,'REPORT':rpin}
    require(final['status']=='FINITE_NATIVE_RECORD_AND_TWO_ORACLES_PASS_ONLY' and final['errors']==[] and final['owner_closed'] is True and final['owner_natural'] is True,'finite parent PASS fields')
    require(worker['status']=='FINITE_NATIVE_WORKER_PASS_ONLY' and worker['exception'] is None and worker['secondary_errors']==[] and worker['request']==qpin,'worker PASS fields')
    ids=q['expected_ids'];counts=[0,42,18,10,7,18,29,11,17,4,3,0]
    require(len(ids)==12 and q['native_counts']==counts and q['native_returns']==159 and sum(counts)==159,'frozen full native denominator')
    require(result['status']=='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY' and result['expected_ids']==result['loaded_ids']==result['actual_ids']==result['success_ids']==ids and result['tests_run']==12,'all original twelve methods')
    require(result['native_returns']==result['validated_returns']==result['actual_native_starts']==159 and result['native_counts']==dict(zip(ids,counts)),'full method native counts')
    require(result['exception'] is None and all(result[k]==[] for k in ('secondary_errors','denied_effects','failures','errors','skipped','expected_failures','unexpected_successes')),'all anomalies zero')
    for d,keys in ((final,('source12_VM_reexecuted','matching_cold_qualification','SQL_engine_or_durability_qualification')),(worker,('source12_VM_reexecuted','matching_cold_qualification','SQL_or_durability_closed')),(result,('source12_VM_reexecuted','matching_cold_qualification','database_opened','network_used'))):
        require(all(d[k] is False for k in keys),'scope remains finite native only')
    for value in (worker['elapsed_ns'],result['elapsed_ns']):require(type(value)is int and 0<=value<=180000000000,'finite execution elapsed')
    # Current full fixed/source/system observations; compare every pre/post record.
    fixed=support.input_records(q);source=support.source_records(q);system=support.system_records(q)
    require((len(fixed),len(source),len(system))==(66,1686,4806),'all physical inputs count')
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
        require(binding['image']==report['HIA_compile']['pins']['record.image.bin'] and binding['logical_bytes']==report['HIA_compile']['image_bytes'] and binding['complete_image_sha256']==report['HIA_compile']['image_sha256'],'logical whole image map seal')
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
    # Re-read every physical chunk; reconstruct all 318 complete records including cross-part rows.
    ip,index=doc(ACT/'native/trace/INDEX.json');tp,expected_trace=doc(ROOT/'EXPECTED-TRACE.json')
    require(index['complete'] is True and index['records']==318 and index['native_returns']==159 and index['bytes']==24830697,'complete actual trace denominator')
    require(index['chunk_limit']==4<<20 and index['record_limit']==16<<20 and index['total_limit']==256<<20 and index['records_may_cross_physical_chunks'] is True,'original physical/record/total caps')
    body=b'';partpins=[]
    for n,p in enumerate(index['parts']):
        require(p['path']=='part-%04d.jsonl'%n,'contiguous trace names')
        pin,b=read(ACT/'native/trace'/p['path'])
        require(all(pin[k]==p[k] for k in ('bytes','sha256','git_blob')) and (len(b)==4<<20 or n==len(index['parts'])-1),'entire physical chunk hash/extent')
        body+=b;partpins.append(pin)
    require(len(body)==expected_trace['bytes']==index['bytes'] and sha(body)==expected_trace['sha256']=='53f17c170870cfabf6cc315ec86e9679abbcddc70dfa30867afe8ad5be0f3714','whole actual trace bytes/SHA')
    lines=body.splitlines(keepends=True);require(len(lines)==318 and max(map(len,lines))==10488665 and all(len(x)<=16<<20 for x in lines),'whole raw records including maximum full buffer row')
    method_counts=dict.fromkeys(ids,0);status_counts=collections.Counter()
    Ccounts={v:{'field_calls':0,'accepted_records':0,'empty_record_extensions':0,'refused_records_not_called':0} for v in ('3.46.0','3.53.2')}
    expected_methods=[method for method,count in zip(ids,counts) for _ in range(count)]
    case_rows=[];accepted=refused=0;fields_total=0
    for n in range(159):
        pre,post=(json.loads(x) for x in lines[2*n:2*n+2])
        require(wire(pre)==lines[2*n] and wire(post)==lines[2*n+1],'complete canonical actual raw rows')
        require(pre['event']=='pre' and post['event']=='post' and type(pre['index'])is int and type(post['index'])is int and pre['index']==post['index']==n+1 and post['actual_returned'] is True and type(post['status'])is int,'actual ordinal/return strict types')
        method=expected_methods[n];method_number=ids.index(method)+1
        require(pre['method']==method and pre['label']=='m%02d-%04d'%(method_number,method_counts[method]+1),'complete original method and case order')
        require(type(pre['lengths'])is list and len(pre['lengths'])==3 and all(type(x)is int and x>=0 for x in pre['lengths']),'all exact declared span lengths')
        before_bytes=[bytes.fromhex(x) for x in pre['buffers_hex']];after_bytes=[bytes.fromhex(x) for x in post['buffers_hex']]
        require(len(before_bytes)==len(after_bytes)==3,'three complete buffers')
        for length,b,a in zip(pre['lengths'],before_bytes,after_bytes):
            require(len(b)==len(a)==length+64 and b[-64:]==a[-64:]==CANARY,'full before/after spans and 64-byte canaries')
        raw,out,cmd=[x[:-64] for x in before_bytes]
        require(out==b'\xa5'*len(out),'original whole output initializer')
        expect=expectation(raw,out,cmd)
        require(post['status']==expect['status'] and after_bytes==[before_bytes[0],expect['out']+CANARY,before_bytes[2]],'independent record parse/descriptors/refusal atomicity')
        fields=expect['fields']
        accepted+=int(fields is not None);refused+=int(fields is None);fields_total+=0 if fields is None else len(fields)
        require(type(post['oracles'])is list and len(post['oracles'])==2 and [x['version'] for x in post['oracles']]==list(Ccounts),'two complete original C versions')
        for oracle in post['oracles']:
            v=oracle['version'];c=Ccounts[v]
            if fields is None:
                correct={'version':v,'called':False,'reason':'whole_record_refused_not_a_C_field_oracle_domain','fields':[]}
                require(wire(oracle)==wire(correct),'whole-record refusal is not an original C field oracle domain')
                c['refused_records_not_called']+=1;continue
            c['accepted_records']+=1
            if not fields:
                correct={'version':v,'called':False,'reason':'explicit_zero_field_byte_API_extension_no_C_call','fields':[]}
                require(wire(oracle)==wire(correct),'explicit zero-field extension performs zero C calls')
                c['empty_record_extensions']+=1;continue
            require(oracle['called'] is True and oracle['operation']=='field' and len(oracle['fields'])==len(fields),'C actual field-call population')
            expected_rows=[]
            for j,field in enumerate(fields,1):
                start,length=field['offset'],field['length'];payload=raw[start:start+length]
                serial=field['serial_type']
                require(0<=serial<=0xffffffff and serial not in (10,11) and (serial not in (8,9) or expect['format']==4),'all called fields satisfy complete original C domain')
                words=[length,field['bits'],field['kind'],field['C_flags']]
                projection={'content_length':length,'scalar_bits':field['bits'],'kind':field['kind'],'original_Mem_flags':field['C_flags'],'whole_record_validity_claim':False}
                expected_rows.append({'field_index':j,'serial_type':serial,'payload_offset':start,'field_bytes':length,'schema_format':expect['format'],
                    'actual_returned':True,'returned':0,'output_words':words,'input_before_hex':(payload+CANARY).hex(),'input_after_hex':(payload+CANARY).hex(),
                    'output_before_hex':(b'\xa5'*32+CANARY).hex(),'output_after_hex':(struct.pack('<4Q',*words)+CANARY).hex(),'output_alignment_mod8':0,'derived_projection':projection})
                c['field_calls']+=1
            correct={'version':v,'called':True,'operation':'field','fields':expected_rows}
            require(wire(oracle)==wire(correct),'all C actual fields/wholebuffers/types/canaries independently recomputed before derived projection')
        method_counts[method]+=1;status_counts[str(post['status'])]+=1
        case_rows.append({'index':n+1,'method':method,'label':pre['label'],'status':post['status'],'field_count':None if fields is None else len(fields),'pre_sha256':sha(lines[2*n]),'post_sha256':sha(lines[2*n+1])})
    require(method_counts==dict(zip(ids,counts)) and (accepted,refused,fields_total)==(100,59,2774),'independent all twelve/159/100accept59refuse/2774fields')
    desired={'field_calls':2774,'accepted_records':100,'empty_record_extensions':3,'refused_records_not_called':59}
    require(all(x==desired for x in Ccounts.values()),'both original C field denominators')
    ep,planned=doc(ROOT/'EXPECTED-MATRIX.json')
    require(dict(status_counts)==planned['status_counts'] and method_counts==planned['counts'],'all planned return populations')
    require(result['C_field_calls']=={v:{'started':2774,'returned':2774} for v in Ccounts},'actual C started/returned both exact')
    report['full_trace']={'index':ip,'parts':partpins,'bytes':len(body),'sha256':sha(body),'records':len(lines),'largest_record_bytes':max(map(len,lines)),'native_returns':159,
        'methods':method_counts,'C_counts':Ccounts,'status_counts':dict(status_counts),'accepted_records':accepted,'refused_records':refused,'fields_each_C':fields_total,
        'C_is_only_scalar_field_oracle_not_whole_record_validator':True,'all_raw_HIA_and_C_bytes_independently_recomputed':True,'cases':case_rows}
    after=inventory(ACT);require(before==after,'every actual fullbyte/identity stable after audit')
    report['actual_originals']=after
    root_names={'root-record-native-r1-INTENT.json':(47111,'19db35a029d28ce2a0734bda8ffbb9aa8a9dacfaf75d0982834169b4c0b38e7f'),'root-record-native-r1-OWNER-READBACK.json':(6145,'60d92c5411d9f0f151b521dd0c4881ca758fdc512de1d891d509d9ec07d1e34f'),'root-record-native-r1-HJOB.json':(7284,'5c7d8c0053203269a55e69a4fcb7827cd55785d60d678a3e85544befabaee7c3')}
    report['root_originals']={}
    for name,(size,digest) in root_names.items():
        pin,b=read(P/name);require(pin['bytes']==size and pin['sha256']==digest,'Root stopped original pin');report['root_originals'][name]=pin
    report['timings_ns']={'worker':worker['elapsed_ns'],'native_child':result['elapsed_ns'],'outer_launcher':final['elapsed_ns'],'elapsed_durations_not_CPU_causality':True}
    report['status']='INDEPENDENT_FULL_RECORD_NATIVE_TWELVE_159_AND_TWO_C_READBACK_PASS'
except BaseException as exc:
    report['status']='HOLD';report['errors'].append(type(exc).__name__+': '+str(exc));report['traceback']=traceback.format_exc()
finally:
    report['owner_closed_before_child_enumeration']=closed;report['checks']=checks;report['elapsed_ns']=time.monotonic_ns()-started
    p=dump(OUT/'READBACK.json',report)
    print(json.dumps({'status':report['status'],'errors':report['errors'],'checks':checks,'report':p,'actual_files':report.get('actual_originals',{}).get('file_count'),'actual_bytes':report.get('actual_originals',{}).get('bytes'),'native_reexecuted':False}))
if report['errors']:raise SystemExit(1)
