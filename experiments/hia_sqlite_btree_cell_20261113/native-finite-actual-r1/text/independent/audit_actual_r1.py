"""Independent closed-original BTREE_CELL audit. Reads evidence only; no HIA/VM/C invocation."""
from pathlib import Path
import ast,collections,hashlib,json,os,shlex,stat,struct,sys,time,traceback
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1');ROOT=P/'sqlite-btree-cell-native-r1';ACT=P/'sqlite-btree-cell-native-r1-actual';OUT=P/'sqlite-btree-cell-native-r1-independent-audit-r1'
# Only readonly control functions are imported, after binding their complete frozen bytes.
for name,wanted in {
 'common.py':'4bbf3343b3b48bf30b553a49db4fa9696e50ac48dc86762832bfecbbacb5ff8b',
 'matrix.py':'22ba40993640eb38f9467ffa978927e720300c292279ed09d8374109b29d4940',
 'support.py':'19984121d6587b56a7a7f86c1e3f764969ca6521620ae1cb21183bbb479e47d9',
 'compile_io.py':'03373c5237e08adcc293543ddba938f950d58079ecd1a59822055ac1818ec315'
}.items():
 p=ROOT/'control'/name;before=p.lstat();raw=p.read_bytes();after=p.lstat()
 if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid() or before.st_mode&0o022 or hashlib.sha256(raw).hexdigest()!=wanted or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise RuntimeError('readonly control binding '+name)
import ctypes,mmap,socket,subprocess
denied_effects=[]
def audit(event,args):
 if any(event==x or event.startswith(x) for x in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty','pty.spawn','mmap.__new__','socket.','sqlite3.connect','ctypes.dlopen','ctypes.dlsym')):
  denied_effects.append(event);raise RuntimeError('readonly audit forbidden effect '+event)
sys.addaudithook(audit)
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
CANARY=bytes(range(64))
REFUSALS={0xfffffffd,0xfffffffe,0xfffffffc,0xfffffffb,0xfffffffa,0xfffffff9}
def need(v,label):require(v,label)
def varint(raw,offset,end):
 x=0
 for j in range(9):
  need(offset<end,'complete successful varint');b=raw[offset];offset+=1
  if j==8:return (x<<8)|b,offset
  x=(x<<7)|(b&127)
  if b<128:return x,offset
 raise AssertionError('unreachable')
def expected_success(raw,control):
 need(len(control)==64,'successful command extent')
 magic,op,size,reserved,page,index,pages,zero=struct.unpack('<8Q',control)
 need(magic==int.from_bytes(b'HIABTC01','little') and op==1 and zero==0,'successful command constants')
 need(size in (512,1024,2048,4096,8192,16384,32768,65536) and len(raw)==size,'successful exact page size')
 need(0<=reserved<=255 and size-reserved>=480 and 1<=page<=pages<=4294967294,'successful page control bounds')
 usable=size-reserved
 def be(at,n):
  need(0<=at<=usable-n,'full big endian scalar span')
  return int.from_bytes(raw[at:at+n],'big')
 h=100 if page==1 else 0
 if page==1:
  need(raw[:16]==b'SQLite format 3\0','database magic')
  encoded=be(16,2);need((65536 if encoded==1 else encoded)==size and raw[20]==reserved,'database size and reserve')
  need(raw[18] in (1,2) and raw[19] in (1,2) and raw[21:24]==bytes((64,32,32)),'header versions and fractions')
  need(1<=be(44,4)<=4 and 1<=be(56,4)<=3 and raw[72:92]==bytes(20),'schema encoding reserved header')
  if be(24,4)==be(92,4) and be(28,4)!=0:need(be(28,4)==pages,'valid in-header database size')
 kind=raw[h];need(kind in (2,5,10,13) and (h!=100 or kind in (5,13)),'declared page kind')
 count,content=be(h+3,2),be(h+5,2);content=65536 if content==0 else content
 ptr=h+(12 if kind in (2,5) else 8)
 if kind in (2,5):need(1<=be(h+8,4)<=pages and be(h+8,4)!=page,'right child bound')
 need(content<=usable and ptr+count*2<=content and raw[h+7]<=60,'pointer-array geometry')
 free=be(h+1,2);need(free==0 or content<=free<=usable-4,'first freeblock position')
 need(index<count,'selected index')
 offset=be(ptr+index*2,2);need(content<=offset<=usable-4,'selected cell offset')
 at=offset;child=0
 if kind in (2,5):
  child=be(at,4);need(1<=child<=pages and child!=page,'left child bound');at+=4
 payload=0
 if kind!=5:
  payload,end=varint(raw,at,usable);need(end-at<=5 and payload<=2147483647,'payload width and numerical domain');at=end
 key=payload
 if kind in (5,13):key,at=varint(raw,at,usable)
 local=payload_at=overflow=overflow_at=overflow_pages=overflow_last=0
 end=at
 if kind!=5:
  payload_at=at;maxlocal=usable-35 if kind==13 else (usable-12)*64//255-23
  minlocal=(usable-12)*32//255-23
  local=payload
  if payload>maxlocal:
   surplus=minlocal+(payload-minlocal)%(usable-4);local=surplus if surplus<=maxlocal else minlocal
  need(local<=usable-at,'complete local payload')
  end=at+local
  if payload>local:
   overflow_at=end;overflow=be(end,4);need(1<=overflow<=pages and overflow!=page,'overflow page bound');end+=4
   overflow_pages,overflow_last=divmod(payload-local,usable-4)
   if overflow_last:overflow_pages+=1
   else:overflow_last=usable-4
  end=max(end,offset+4)
 need(end<=usable,'complete cell and padding')
 return struct.pack('<16Q',page,kind,usable,count,index,offset,end-offset,payload_at,payload,local,child,key,overflow,overflow_at,overflow_pages,overflow_last)

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
report={'schema':'hia.sqlite.btree.cell.closed-actual-independent-audit.v1','status':'HOLD','errors':[],'qualification_reexecuted':False,'VM_or_native_or_C_called':False}
started=time.monotonic_ns();closed=False
try:
    qpin,q=doc(ROOT/'REQUEST.json')
    require(qpin['sha256']=='52a027b7a31642b10f7860e2cafc430244157e258464f84ec28a17eb19c46993','frozen request exact')
    lpin,life=doc(ACT/'lifecycle.json');ppin,parent=doc(ACT/'lifecycle.json.request.json');wpin,wrapper=doc(ACT/'OWNER-RETURN.json')
    closed,natural=support.natural_owner(wrapper,life,parent,q,qpin['sha256'],lpin,ppin)
    require(closed and natural,'closed natural original180/3 bound owner')
    require([x['kind'] for x in life['events']]==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'],'four natural owner events')
    report['audit_runtime']=support.runtime(q)
    report['owner']={'lifecycle':lpin,'request':ppin,'wrapper':wpin,'closed':closed,'natural':natural,'owner_status':life['status'],'qualification_seconds':180,'cleanup_seconds':3}
    before=inventory(ACT);require(before['file_count']<=192 and before['bytes']<=384<<20,'all actual body quota')
    cp,catalog=doc(ACT/'CLOSED-ORIGINAL-CATALOG.json');actual_by_name={r['relative_path']:r for r in before['files']}
    require(catalog['all_bodies_read'] is True and len(catalog['files'])==catalog['file_count']==75 and sum(r['bytes'] for r in catalog['files'])==catalog['bytes'],'original closed catalog size')
    for row in catalog['files']:
        require(row['relative_path'] in actual_by_name and row==actual_by_name[row['relative_path']],'all original catalog whole-body pins')
    require(set(actual_by_name)=={*(r['relative_path'] for r in catalog['files']),'CLOSED-ORIGINAL-CATALOG.json','FINAL.json','PARENT-INPUTS-AFTER.json','PARENT-SOURCE-AFTER.json','PARENT-SYSTEM-AFTER.json'},'complete final namespace with five later parent files')

    fpin,final=doc(ACT/'FINAL.json');rpin,result=doc(ACT/'native/REPORT.json');wkp,worker=doc(ACT/'WORKER.json')
    report['producer']={'FINAL':fpin,'WORKER':wkp,'REPORT':rpin}
    require(final['status']=='FINITE_NATIVE_BTREE_CELL_AND_TWO_ORACLES_PASS_ONLY' and final['errors']==[] and final['owner_closed'] is True and final['owner_natural'] is True,'finite parent PASS fields')
    require(worker['status']=='FINITE_NATIVE_WORKER_PASS_ONLY' and worker['exception'] is None and worker['secondary_errors']==[] and worker['request']==qpin,'worker PASS fields')
    ids=q['expected_ids'];counts=[0,72,36,108,22,14,24,14,30,16,3,0]
    require(len(ids)==12 and q['native_counts']==counts and q['native_returns']==339 and sum(counts)==339,'frozen full native denominator')
    require(result['status']=='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY' and result['expected_ids']==result['loaded_ids']==result['actual_ids']==result['success_ids']==ids and result['tests_run']==12,'all original twelve methods')
    require(result['native_returns']==result['validated_returns']==result['actual_native_starts']==339 and result['native_counts']==dict(zip(ids,counts)),'full method native counts')
    require(result['exception'] is None and all(result[k]==[] for k in ('secondary_errors','denied_effects','failures','errors','skipped','expected_failures','unexpected_successes')),'all anomalies zero')
    for d,keys in ((final,('source12_VM_reexecuted','matching_cold_qualification','SQL_engine_or_durability_qualification')),(worker,('source12_VM_reexecuted','matching_cold_qualification','SQL_or_durability_closed')),(result,('source12_VM_reexecuted','matching_cold_qualification','database_opened','network_used'))):
        require(all(d[k] is False for k in keys),'scope remains finite native only')
    for value in (worker['elapsed_ns'],result['elapsed_ns']):require(type(value)is int and 0<=value<=180000000000,'finite execution elapsed')
    # Current full fixed/source/system observations; compare every pre/post record.
    fixed=support.input_records(q);source=support.source_records(q);system=support.system_records(q)
    require((len(fixed),len(source),len(system))==(136,1686,4806),'all physical inputs count')
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
    # Bind actual subordinate argv/cwd/environment and the original bounds; do not launch them.
    commands=worker['commands'];require(len(commands)==3,'two C children and one native child records')
    for num,version in enumerate(('3.46.0','3.53.2')):
        directory=ACT/('C-'+version);cqp=read(directory/'REQUEST.json')[0]
        expected_argv=[q['runtime']['path'],'-I','-S','-B',str(ROOT/'control/compile_child.py'),str(directory/'REQUEST.json'),cqp['sha256']]
        row=commands[num];require(row['argv']==expected_argv and row['cwd']==str(ROOT) and row['env']==q['environment'] and row['wall_seconds']==20 and type(row['returncode'])is int and row['returncode']==0 and type(row['elapsed_ns'])is int and 0<=row['elapsed_ns']<=20000000000,'exact bounded C child command')
    row=commands[2];require(row['argv']==[q['runtime']['path'],'-I','-S','-B',str(ROOT/'control/native_cases.py'),str(ROOT/'REQUEST.json'),qpin['sha256']] and row['cwd']==str(ROOT) and row['env']==q['environment'] and row['separate_wall_budget'] is None and type(row['returncode'])is int and row['returncode']==0,'native child under same single owner')
    require([r['start_ns'] for r in commands]==sorted(r['start_ns'] for r in commands),'actual subordinate order')
    native_spec=doc(ACT/'native/NATIVE-INPUTS.json')[1]
    require(native_spec['image']==report['HIA_compile']['pins']['btree_cell.image.bin'] and native_spec['oracles']=={v:report['C_compiles'][v]['image'] for v in ('3.46.0','3.53.2')} and native_spec['limits']=={'cpu_seconds':180,'address_bytes':256<<20,'stack_bytes':8<<20,'file_bytes':4<<20,'outer_wall_seconds':180},'actual native image/C inputs/limits')
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
        require(binding['image']==report['HIA_compile']['pins']['btree_cell.image.bin'] and binding['logical_bytes']==report['HIA_compile']['image_bytes'] and binding['complete_image_sha256']==report['HIA_compile']['image_sha256'],'logical whole image map seal')
        bp,initial_binding=doc(ACT/'native'/('mapping-'+which+'.binding-start.json'))
        require({k:v for k,v in binding.items() if k not in ('actual_segment','complete_image_sha256','page_rounding_tail_not_hashed_as_image')}==initial_binding,'complete initial mapping binding retained')
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
                    own_images={report['C_compiles'][v]['image']['path']:report['C_compiles'][v]['image'] for v in ('3.46.0','3.53.2')}
                    require(pin['path'] in own_images,'mapped non-system file is one exact C image');current=own_images[pin['path']]
                require(match(pin,current),'all mapped whole-file pins')
            elif 'x' in row['permissions']:
                require((row['name'],row['permissions']) in (('[vdso]','r-xp'),('[vsyscall]','--xp')) and row['inode']==row['offset']==0 and row['device']==[0,0],'no unbound anonymous executable')
        mapsummary.append({'phase':which,'raw':mp,'rows':len(rows),'files':len(recorded['files']),'binding':binding})
    require(result['mapped_files_before']['files']==result['mapped_files_after']['files'] and result['mapped_files_before']['image_binding']==result['mapped_files_after']['image_binding'],'both observation point identities equal')
    report['mapping_observations']=mapsummary
    # Full frozen Source12 records are input evidence, never replayed on the VM.
    oldpin,oldraw=read(ROOT/'reference/source12-actual/tests/VM-RAW.json')
    require(oldpin['bytes']==16366443 and oldpin['sha256']=='d1e23200de22b2a39aafc6258e74155fd667fea08489cdff913fd6acdf6b7cca','whole original339 raw matrix')
    old=json.loads(oldraw);require(old['schema']=='hia.sqlite-btree-cell.source-vm-raw.v1' and old['native_executed'] is False and old['compiler_executed'] is False and len(old['calls'])==339,'old actual input scope')
    ip,index=doc(ACT/'native/trace/INDEX.json');tp,expected_trace=doc(ROOT/'EXPECTED-TRACE.json')
    require(index['schema']=='hia.sqlite.btree.cell.full-native-trace.v1' and index['complete'] is True and index['records']==678 and index['native_returns']==339 and index['bytes']==48281463,'complete actual trace denominator')
    require(index['chunk_limit']==4<<20 and index['record_limit']==16<<20 and index['total_limit']==256<<20 and index['records_may_cross_physical_chunks'] is True,'original physical/record/total caps')
    body=b'';partpins=[]
    for number,item in enumerate(index['parts']):
        require(item['path']=='part-%04d.jsonl'%number,'contiguous trace names')
        pin,b=read(ACT/'native/trace'/item['path'])
        require(all(pin[k]==item[k] for k in ('bytes','sha256','git_blob')) and (len(b)==4<<20 or number==len(index['parts'])-1),'entire physical chunk hash/extent')
        body+=b;partpins.append(pin)
    require({p.name for p in (ACT/'native/trace').iterdir()}=={'INDEX.json',*(p['path'] for p in index['parts'])},'exact trace namespace')
    require(len(body)==expected_trace['bytes']==index['bytes'] and sha(body)==expected_trace['sha256']=='4341a8b00ff94589cd43a8fbce3608c5f64e992bf1c7b797bb04919c75083891','whole actual trace bytes/SHA')
    lines=body.splitlines(keepends=True);require(len(lines)==678 and max(map(len,lines))==expected_trace['largest_record_bytes']==658584 and all(len(x)<=16<<20 for x in lines),'whole raw records including cross-part/fullpage rows')
    method_counts=dict.fromkeys(ids,0);status_counts=collections.Counter();matrix_digest=hashlib.sha256()
    Ccounts={v:{'cell_calls':0,'accepted_cells':0,'refused_cells_not_called':0} for v in ('3.46.0','3.53.2')}
    expected_methods=[method for method,count in zip(ids,counts) for _ in range(count)]
    case_rows=[];accepted=refused=0
    for number,oldrow in enumerate(old['calls'],1):
        pre,post=(json.loads(x) for x in lines[2*(number-1):2*number])
        require(wire(pre)==lines[2*(number-1)] and wire(post)==lines[2*number-1],'complete canonical actual raw rows')
        require(pre['event']=='pre' and post['event']=='post' and type(pre['index'])is int and type(post['index'])is int and pre['index']==post['index']==number and post['actual_returned'] is True and type(post['status'])is int,'actual ordinal/return strict types')
        method=expected_methods[number-1];method_number=ids.index(method)+1
        label='m%02d-%04d'%(method_number,method_counts[method]+1)
        require(pre['method']==oldrow['case']==method and pre['label']==label and oldrow['actual_returned'] is True and type(oldrow['status'])is int and 'exception_type' not in oldrow,'complete original method/case/actual matrix order')
        before_names=('source_before_hex','output_before_hex','control_before_hex')
        after_names=('source_after_hex','output_after_hex','control_after_hex')
        before_original=[bytes.fromhex(oldrow[k]) for k in before_names]
        after_original=[bytes.fromhex(oldrow[k]) for k in after_names]
        require(all(b.hex()==oldrow[k] for b,k in zip(before_original,before_names)) and all(b.hex()==oldrow[k] for b,k in zip(after_original,after_names)),'original entire buffers canonical')
        require(type(pre['lengths'])is list and len(pre['lengths'])==3 and all(type(x)is int and x>=0 for x in pre['lengths']) and pre['lengths']==list(map(len,before_original)),'all exact declared span lengths')
        require(type(pre['buffers_hex'])is list and type(post['buffers_hex'])is list and len(pre['buffers_hex'])==len(post['buffers_hex'])==3,'three complete buffers')
        before_bytes=[bytes.fromhex(x) for x in pre['buffers_hex']];after_bytes=[bytes.fromhex(x) for x in post['buffers_hex']]
        for length,b,a,ob,oa in zip(pre['lengths'],before_bytes,after_bytes,before_original,after_original):
            require(len(b)==len(a)==length+64 and b[-64:]==a[-64:]==CANARY and b==ob+CANARY and a==oa+CANARY,'full original before/after spans and64-byte canaries')
        raw,out,cmd=before_original
        require(after_original[0]==raw and after_original[2]==cmd and post['status']==oldrow['status'],'original immutable source/command and result')
        status=oldrow['status'];cell=words=None
        if status in REFUSALS:
            require(after_original[1]==out,'entire refusal output untouched');refused+=1
        else:
            require(status==128 and len(out)==128,'success declared status/extent')
            layout=expected_success(raw,cmd)
            require(layout==after_original[1],'independent complete accepted-cell layout equals both Source12 and native')
            words=list(struct.unpack('<16Q',layout));kind=words[1]
            cell=[words[11],int(kind==5),0 if kind==5 else words[7],words[8],words[9],words[6]];accepted+=1
        expected_pre={'event':'pre','index':number,'method':method,'label':label,
                      'lengths':list(map(len,before_original)),'buffers_hex':[(b+CANARY).hex() for b in before_original]}
        expected_oracles=[]
        require(type(post['oracles'])is list and len(post['oracles'])==2 and [x['version'] for x in post['oracles']]==list(Ccounts),'two complete original C versions')
        for version,observed in zip(Ccounts,post['oracles']):
            c=Ccounts[version]
            if cell is None:
                correct={'version':version,'called':False,'reason':'frozen_refused_cell_not_a_C_parser_domain'}
                c['refused_cells_not_called']+=1
            else:
                # Full raw C buffers/return are compared before using their projected fields.
                projection=dict(zip(('nKey_bits','payload_is_NULL','payload_page_offset','nPayload','nLocal','nSize'),cell))
                correct={'version':version,'called':True,'operation':'cell','page_bytes':len(raw),'usable':words[2],
                    'page_kind':words[1],'cell_offset':words[5],'actual_returned':True,'returned':0,'output_words':cell,
                    'input_before_hex':(raw+CANARY).hex(),'input_after_hex':(raw+CANARY).hex(),
                    'output_before_hex':(b'\xa5'*48+CANARY).hex(),'output_after_hex':(struct.pack('<6Q',*cell)+CANARY).hex(),
                    'output_alignment_mod8':0,'derived_projection':projection}
                c['cell_calls']+=1;c['accepted_cells']+=1
            require(wire(observed)==wire(correct),'entire C return/CellInfo/buffers/canary or explicit NOT_CALLED')
            expected_oracles.append(correct)
        expected_post={'event':'post','index':number,'actual_returned':True,'status':status,
                       'buffers_hex':[(b+CANARY).hex() for b in after_original],'oracles':expected_oracles}
        require(wire(expected_pre)==lines[2*(number-1)] and wire(expected_post)==lines[2*number-1],'every exact full PRE/POST byte; no ignored extra fields')
        spec={'index':number,'method':method,'label':label,'source_hex':raw.hex(),'output_hex':out.hex(),'command_hex':cmd.hex(),
              'expected':{'status':status,'source_after_hex':raw.hex(),'output_after_hex':after_original[1].hex(),
              'command_after_hex':cmd.hex(),'words':words,'cell_info':cell,'C_applicability':'PREVALIDATED_COMPLETE_CELL' if cell is not None else 'NOT_CALLED_FROZEN_REFUSAL'}}
        matrix_digest.update(wire(spec));method_counts[method]+=1;status_counts[str(status)]+=1
        case_rows.append({'index':number,'method':method,'label':label,'status':status,'C_called_each':cell is not None,
                          'pre_sha256':sha(lines[2*(number-1)]),'post_sha256':sha(lines[2*number-1])})
    require(method_counts==dict(zip(ids,counts)) and (accepted,refused)==(253,86),'independent all12/339/253accept86refuse')
    desired={'cell_calls':253,'accepted_cells':253,'refused_cells_not_called':86}
    require(all(x==desired for x in Ccounts.values()),'both original complete-cell C denominators')
    ep,planned=doc(ROOT/'EXPECTED-MATRIX.json')
    require(dict(status_counts)==planned['status_counts'] and method_counts==planned['counts'] and matrix_digest.hexdigest()==planned['ordered_expected_rows_sha256'],'all planned return populations and entire ordered frozen matrix')
    require(result['C_cell_calls']=={v:{'started':253,'returned':253} for v in Ccounts},'actual C started/returned both exact')
    for producer_trace in (final['trace'],worker['full_trace_readback'],result['full_trace_readback']):
        require(producer_trace['index']==ip and producer_trace['parts']==partpins and producer_trace['bytes']==len(body) and producer_trace['records']==len(lines)
            and producer_trace['sha256']==sha(body) and producer_trace['counts']==method_counts and producer_trace['oracle_counts']==Ccounts
            and producer_trace['expected_rows_sha256']==matrix_digest.hexdigest(),'all three original full trace reports match independently read bytes')
    report['full_trace']={'index':ip,'parts':partpins,'bytes':len(body),'sha256':sha(body),'records':len(lines),'largest_record_bytes':max(map(len,lines)),'native_returns':339,
        'methods':method_counts,'C_counts':Ccounts,'status_counts':dict(status_counts),'accepted_cells':accepted,'refused_cells':refused,
        'C_is_only_prevalidated_complete_cell_oracle_not_wholepage_or_tree':True,'all_raw_HIA_and_C_bytes_independently_recomputed':True,'cases':case_rows}
    after=inventory(ACT);require(before==after,'every actual fullbyte/identity stable after audit')
    report['actual_originals']=after
    root_names={'root-btree-cell-native-two-c-r1-INTENT.json':(95697,'6bc1a6687f41109899e1653c5dcf530d0d1529c86b2e19c5e225ebb012b6ba80'),'root-btree-cell-native-two-c-r1-OWNER-READBACK.json':(7596,'641486891a7ec7d939564d98e1deb02dfc32ce623d770b19f05ecf225e48b3e8'),'root-btree-cell-native-two-c-r1-HJOB.json':(9461,'f217229b4bff5a0d890c55b95fb26bace9a642161812c837ea2d15616ebc9f74')}
    report['root_originals']={}
    for name,(size,digest) in root_names.items():
        pin,b=read(P/name);require(pin['bytes']==size and pin['sha256']==digest,'Root stopped original pin');report['root_originals'][name]=pin
    require(denied_effects==[],'reader produced no forbidden effect')
    report['reader_scope']={'reused_readonly_controls':['common','support','compile_io'],'no_SUT_imports':True,'denied_effects':denied_effects,'separate_independent_cell_and_trace_model':True,
       'not_reexecuted':['source_tests','generation','VM','C_compiler','HIA_compiler','native','SQL']}
    report['authoring_readonly_type_error_preserved']={'error':'q.inputs.slice is not a function','correction':'Use keyed frozen input map; no product/file mutation'}
    report['timings_ns']={'worker':worker['elapsed_ns'],'native_child':result['elapsed_ns'],'outer_launcher':final['elapsed_ns'],'elapsed_durations_not_CPU_causality':True}
    report['status']='INDEPENDENT_FULL_BTREE_CELL_NATIVE_TWELVE_339_AND_TWO_C_READBACK_PASS'
except BaseException as exc:
    report['status']='HOLD';report['errors'].append(type(exc).__name__+': '+str(exc));report['traceback']=traceback.format_exc()
finally:
    report['owner_closed_before_child_enumeration']=closed;report['checks']=checks;report['elapsed_ns']=time.monotonic_ns()-started
    p=dump(OUT/'READBACK.json',report)
    print(json.dumps({'status':report['status'],'errors':report['errors'],'checks':checks,'report':p,'actual_files':report.get('actual_originals',{}).get('file_count'),'actual_bytes':report.get('actual_originals',{}).get('bytes'),'native_reexecuted':False}))
if report['errors']:raise SystemExit(1)
