"""Independent read-only custody audit. Never imports product or runs a test."""
from pathlib import Path
import collections
import hashlib
import json
import os
import stat
import struct
import sys
import time
import traceback

P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
R=P/'sqlite-database-header-source-r2'
A=P/'sqlite-database-header-source12-actual-r2'
O=P/'sqlite-database-header-source12-actual-audit-r1'
REQUEST_SHA='be3b92c8190acfeaca8465f90cb4e8e56491ad4c8d5f64e85e837dd51076426d'
OWNER_SHA='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
ROOT_PINS={
  "root-database-header-generation-source12-r2-INTENT.json": [
    35944,
    "c10d1ef8d61ecfa047289d95f800b6a775b4dc4066185eace1df7ef331366d86"
  ],
  "root-database-header-generation-source12-r2-OWNER-READBACK.json": [
    6561,
    "d47e77bf8687248bea0bf833b96fa960798403fe3948357a6eacb22165728a84"
  ],
  "root-database-header-generation-source12-r2-HJOB.json": [
    45097,
    "ce78e24d5bf696fa283b8a3c8401955305480f81b4ad4b98688dd726c0ed5ecf"
  ]
}
EXPECTED_ACTUAL={
  "FINAL.json": [
    805,
    "e9671b018d8a6ed9137943c499c6501272f8a56cca6d67391e100107b0795425"
  ],
  "tests/REPORT.json": [
    28866,
    "a4d45bce74e7a3faae6705229c7754321ef9d33c0b0189224aebfd3dce94fdb8"
  ]
}
report={'schema':'hia.sqlite-database-header.source12-independent-readback.v1','status':'HOLD',
        'request_commit':None,'publication_after_actual':True,'planned_sole_parent':'2cb2861bb8b836cf86997cf06152c1361a775e9f',
        'request_sha256':REQUEST_SHA,'check_count':0,'closed_before_child_read':False,
        'product_reexecuted':False,'C_or_native_or_SQL_executed':False,'errors':[]}
def check(ok,message):
    report['check_count']+=1
    if not ok:raise AssertionError(message)
def identity(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path,limit=64<<20):
    path=Path(path);b=path.lstat()
    check(path.is_absolute() and path.resolve(strict=True)==path,'resolved regular path '+str(path))
    check(stat.S_ISREG(b.st_mode) and b.st_nlink==1 and b.st_size<=limit,'regular/nlink/size '+str(path))
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb') as f:
        check(identity(os.fstat(f.fileno()))==identity(b),'descriptor initial '+str(path))
        raw=f.read()
        check(identity(os.fstat(f.fileno()))==identity(b),'descriptor final '+str(path))
    check(len(raw)==b.st_size and identity(path.lstat())==identity(b),'path final '+str(path))
    return raw,{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
                'identity':identity(b),'mode':'100755' if b.st_mode&0o111 else '100644'}
def projection(pin):return {k:pin[k] for k in ('path','bytes','sha256','identity')}
def tree_hash(rows):
    root={}
    for name,pin in rows.items():
        parts=name.split('/');node=root
        for part in parts[:-1]:node=node.setdefault(part,{})
        check(parts[-1] not in node,'duplicate tree leaf');node[parts[-1]]=(pin['mode'],pin['git_blob'])
    def encode(node):
        chunks=[]
        for name,value in sorted(node.items(),key=lambda kv:(kv[0]+'/' if isinstance(kv[1],dict) else kv[0]).encode()):
            mode,digest=('40000',encode(value)) if isinstance(value,dict) else value
            chunks.append(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest))
        raw=b''.join(chunks)
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return encode(root)
def namespace(root):
    names=[];dirs=[]
    for parent,children,files in os.walk(root,followlinks=False):
        for name in children:
            path=Path(parent)/name
            check(stat.S_ISDIR(path.lstat().st_mode) and path.resolve()==path,'unaliased directory')
            dirs.append(str(path.relative_to(root)))
        for name in files:names.append(str((Path(parent)/name).relative_to(root)))
    return sorted(names),sorted(dirs)
def main():
    started=time.monotonic()
    O.mkdir(mode=0o700,exist_ok=False)
    qraw,qpin=read(R/'REQUEST.json');check(qpin['sha256']==REQUEST_SHA,'frozen request digest')
    q=json.loads(qraw)
    check(q['qualification_seconds']==180 and q['cleanup_seconds']==3 and q['expected_vm_returns']==670,'frozen denominators')
    # This current request/owner/wrapper binding precedes any child-output read.
    lraw,lp=read(A/'owner.json');braw,bp=read(A/'owner.json.request.json');wraw,wp=read(A/'OWNER-WRAPPER.json')
    life,bound,wrapper=map(json.loads,(lraw,braw,wraw))
    command=[q['runtime']['executable'],'-I','-S','-B',str(R/'control/source12.py'),'--request',str(R/'REQUEST.json'),'--sha256',REQUEST_SHA,'--worker']
    check(all(wrapper.get(k)==v for k,v in life.items()),'wrapper/life complete projection')
    check(wrapper['receipt_sha256']==lp['sha256'] and life['request_sha256']==bp['sha256'],'full owner hashes')
    check(life['implementation_sha256']==bound['implementation_sha256']==OWNER_SHA,'original owner')
    check(life['schema']==bound['schema']==wrapper['schema']=='hepta.hia.selfhost-process-owner.v1','owner schema')
    check(bound['command']==command and bound['cwd']==str(R) and bound['env']==q['environment'],'owned operation')
    check(bound['receipt_path']==str(A/'owner.json') and bound['stdout_path']==str(A/'stdout.log') and bound['stderr_path']==str(A/'stderr.log'),'owned output paths')
    check(life['qualification_seconds']==bound['qualification_seconds']==180 and life['cleanup_seconds']==bound['cleanup_seconds']==3,'owner limits')
    c=life['cleanup']
    check(life['subreaper_enabled'] is True and life['qualification_started'] is True and
          all(c[k] is True for k in ('attempted','complete','observed_echild','leader_reaped')) and
          c['deadline_exceeded'] is False and c['errors']==[] and c['remaining_direct_children']==[],'bound ECHILD')
    report['closed_before_child_read']=True
    kinds=[x['kind'] for x in life['events']]
    check(kinds==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'],'four original events')
    check(wrapper['supervisor_returncode']==life['returncode']==0 and life['status']=='OWNED_PROCESS_COMPLETED'
          and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
          and life['event_overflow'] is False and life['interrupted_signals']==[] and life.get('owner_error') is None,'natural terminal')
    check(all(e['pid']==life['qualification_pid'] for e in life['events']),'events same actual child')
    check(len(life['direct_and_adopted_children'])==1 and life['direct_and_adopted_children'][0]['pid']==life['qualification_pid'],'one actual child')
    check(life['events'][2]['si_code']==1 and life['events'][2]['si_status']==0 and life['events'][3]['returncode']==0,'natural exit/reap')
    elapsed=(life['events'][2]['monotonic_ns']-life['events'][0]['monotonic_ns'])/1e9
    check(0<=elapsed<=180 and bound['deadline_ns']-bound['started_ns']==180000000000,'actual original deadline')
    report['owner']={'life':lp,'request':bp,'wrapper':wp,'start_to_exit_seconds':elapsed,'limits':[180,3],'events':kinds,'natural':True,'ECHILD':True}
    roots={}
    for name,(size,digest) in ROOT_PINS.items():
        raw,pin=read(P/name);check((len(raw),pin['sha256'])==(size,digest),'Root original '+name)
        roots[name]={'raw':raw,'pin':pin,'value':json.loads(raw)}
    rr=roots['root-database-header-generation-source12-r2-OWNER-READBACK.json']['value']
    check(all(rr['checks'].values()),'Root owner readback checks')
    for row in rr['originals']:
        raw,pin=read(row['path']);check(raw.decode()==row['text'] and pin['sha256']==row['sha256'] and pin['bytes']==row['size'],'Root owner fullraw join')
    root_intent=roots['root-database-header-generation-source12-r2-INTENT.json']['value']
    check(root_intent['request']['text']==qraw.decode() and all(root_intent['checks'].values()),'Root intent exact frozen request')
    hj=roots['root-database-header-generation-source12-r2-HJOB.json']['value']
    terminal=hj['terminal_status']
    check(terminal['exit_code']==0 and terminal['automatic_retry'] is False and terminal['output_complete'] is True
          and terminal['timed_out'] is False and all(hj['checks'].values()),'Root unique hjob terminal')
    report['root_originals']=[x['pin'] for x in roots.values()]
    names,dirs=namespace(A);raws={};pins={}
    for name in names:raws[name],pins[name]=read(A/name,16<<20)
    check(len(names)==len(set(names)) and len(names)<=q['output_limits']['files']==64 and sum(x['bytes'] for x in pins.values())<=q['output_limits']['bytes']==128<<20,'all actual namespace/limits')
    for name,expected in EXPECTED_ACTUAL.items():check([pins[name]['bytes'],pins[name]['sha256']]==expected,'reported full original '+name)
    check(raws['REQUEST.original.json']==qraw,'executed request full raw')
    final=json.loads(raws['FINAL.json']);originals=json.loads(raws['ORIGINALS.json']);worker=json.loads(raws['tests/REPORT.json'])
    check(final['closed'] is True and final['natural'] is True and final['errors']==[] and final['native_or_SQL_executed'] is False,'original final boundary')
    check(final['status']==final['worker_status']=='SOURCE12_DATABASE_HEADER_VM_PASS_ONLY' and final['request_sha256']==REQUEST_SHA,'original final status')
    check(final['originals']==projection(pins['ORIGINALS.json']),'originals index full identity')
    index=originals['files'];check(len(index)==len({x['path'] for x in index})==len(names)-2,'original index unique complete')
    check({str(A/n) for n in names}- {str(A/'FINAL.json'),str(A/'ORIGINALS.json')}=={x['path'] for x in index},'all indexed actual originals')
    for row in index:check(row==projection(pins[str(Path(row['path']).relative_to(A))]),'indexed full original '+row['path'])
    check(originals['after_bound_ECHILD'] is True and originals['bytes']==sum(x['bytes'] for x in index),'original byte sum')
    for row in hj['complete_originals']:
        rel=str(Path(row['path']).relative_to(A))
        check(row['text']==raws[rel].decode() and row['size']==pins[rel]['bytes'] and row['sha256']==pins[rel]['sha256'],'Root complete original join '+rel)
    check(worker['schema']=='hia.sqlite-database-header.source12-report.v1' and worker['status']=='SOURCE12_DATABASE_HEADER_VM_PASS_ONLY','worker scope')
    ids=q['expected_ids'];check(len(ids)==len(set(ids))==12,'12 original ids')
    for key in ('expected_ids','loaded_ids','actual_ids','success_ids'):check(worker[key]==ids,'ordered exact '+key)
    check(type(worker['tests_run']) is int and worker['tests_run']==12 and worker['exception'] is None and worker['inputs_unchanged'] is True,'actual 12 completion')
    for key in ('failures','errors','skips','expected_failures','unexpected_successes','loader_errors','denied_effects','secondary_errors'):check(worker[key]==[],'no '+key)
    for key in ('native_executed','C_compiler_or_oracle_executed','database_opened','network_used'):check(worker[key] is False,'recorded source-only '+key)
    inputs=[]
    for row in q['inputs']:
        _,pin=read(row['path']);check(all(pin[k]==row[k] for k in ('path','bytes','sha256','identity')),'frozen input all9 identity')
        inputs.append(projection(pin))
    check(len(inputs)==len({x['path'] for x in inputs})==26,'26 unique frozen inputs')
    for name in ('INPUTS-BEFORE.json','INPUTS-AFTER.json','tests/INPUTS-BEFORE.json','tests/INPUTS-AFTER.json'):
        check(json.loads(raws[name])==inputs,'full before/after input '+name)
    catraw,catpin=read(q['source_catalog']);catalog=json.loads(catraw);source={}
    for name,row in catalog.items():
        check(not name.startswith('/') and '..' not in Path(name).parts,'relative source name')
        _,pin=read(Path(q['source_root'])/name)
        check(all(pin[k]==row[k] for k in ('path','bytes','sha256','identity','git_blob')),'full source9/git identity '+name)
        source[name]=pin
    source_names,_=namespace(Path(q['source_root']))
    check(source_names==sorted(catalog) and len(source)==q['source_file_count']==1686,'complete source namespace')
    check(sum(x['bytes'] for x in source.values())==q['source_total_bytes']==40890650,'complete source total')
    for name in ('tests/SOURCE-BEFORE.json','tests/SOURCE-AFTER.json'):check(raws[name]==catraw,'source before/after complete bytes')
    mapraw,mappin=read(P/'sqlite-wal-snapshot-source12-actual-audit-r2/SOURCE-SUBSET-MAP.json')
    check(mappin['sha256']=='664dd38290ffe9f6f0207a8f4317d191940b2d4d82912e15284637b001ed232d','independent complete-tree/subset mapping')
    mapping=json.loads(mapraw)
    check(mapping['source_commit']==q['source_commit'] and mapping['source_tree']==q['source_tree']==mapping['full_source_tree_reconstructed'] and mapping['full_source_leaf_count']==4125,'complete upstream source tree')
    actual_tree=tree_hash(source)
    check(actual_tree==mapping['physical_source_subset_tree'] and len(source)==mapping['physical_source_count'],'physical source subset tree')
    observed_leaves=[{'path':name,'mode':row['mode'],'type':'blob','sha':row['git_blob'],'size':row['bytes']} for name,row in source.items()]
    check(observed_leaves==mapping['physical_subset'],'all physical leaves in upstream full tree')
    report['source_tree_binding']={'upstream_complete_tree':q['source_tree'],'upstream_complete_files':4125,'physical_subset_tree':actual_tree,'physical_files':1686,'exact_all_leaf_mapping':mappin,'reused_exact_upstream_subset_map_from_prior_readback':True}
    expected_paths={v['path']:v for v in catalog.values()}
    expected_paths.update({v['path']:v for v in q['inputs']})
    for row in worker['imports']:
        if 'source' in row:check(row['source']=={k:expected_paths[row['source']['path']][k] for k in row['source']},'import source bound')
        else:check(row=={'module':'tools','namespace_only':True},'only declared namespace')
    check(len(worker['imports'])==len({x['module'] for x in worker['imports']}),'unique imported module names')
    report['source_readback']={'count':len(source),'bytes':sum(x['bytes'] for x in source.values()),'tree':actual_tree,'catalog':catpin,'frozen_inputs':inputs,'all_actual_metadata_unchanged':True,'before_after_equal':True,'imports':len(worker['imports'])}
    # Independently reread all recorded spans; never import or invoke VM/product.
    vm=json.loads(raws['tests/VM-RAW.json'])
    check(vm['schema']=='hia.sqlite-database-header.source-vm-raw.v1' and vm['native_executed'] is False and vm['compiler_executed'] is False,'VM raw scope')
    calls=vm['calls'];check(len(calls)==670,'VM670 full records')
    counts={name:0 for name in ids};statuses=collections.Counter();actions=collections.Counter();spanbytes=0
    for row in calls:
        check(row['case'] in counts and row['actual_returned'] is True and type(row['status']) is int and 'exception_type' not in row,'actual VM return')
        buffers={}
        for k in ('source_before_hex','source_after_hex','output_before_hex','output_after_hex','control_before_hex','control_after_hex'):
            check(type(row[k]) is str,'raw hex string');buffers[k]=bytes.fromhex(row[k]);check(buffers[k].hex()==row[k],'canonical entire raw hex')
        s,s2,o,o2,w,w2=[buffers[k] for k in ('source_before_hex','source_after_hex','output_before_hex','output_after_hex','control_before_hex','control_after_hex')]
        check(s==s2 and w==w2 and len(o)==len(o2),'complete immutable spans and output extent')
        expected=row['expected_words_before_call']
        if row['status']==0xfffffffd:
            check(o==o2 and expected is None,'protocol refusal all spans unchanged')
        else:
            check(row['status']==256 and [len(s),len(o),len(w)]==[100,256,128],'semantic return complete extents')
            check(type(expected) is list and len(expected)==32 and all(type(v) is int and 0<=v<1<<64 for v in expected),'precall recorded oracle exact words')
            check(o2==struct.pack('<32Q',*expected),'full reply equals recorded precall words')
            check(expected[0]==int.from_bytes(b'HIADBR01','little') and expected[1] in (1,2,3,4),'reply envelope')
            actions[str(expected[1])]+=1
        counts[row['case']]+=1;statuses[str(row['status'])]+=1;spanbytes+=sum(map(len,buffers.values()))
    check(counts==q['expected_vm_by_id']==worker['VM']['by_id'],'per-ID original fixed VM denominator')
    check([x['case'] for x in calls]==[name for name in ids for _ in range(counts[name])],'all670 original sequence')
    check(statuses=={str(256):634,str(0xfffffffd):36},'634 semantic and36 protocol population')
    check(worker['VM']['pin']==projection(pins['tests/VM-RAW.json']) and worker['VM']['calls']==670 and worker['VM']['whole_raw_buffers_read'] is True,'worker VM/fullraw join')
    labels=['source_byte','control_byte','output_canary','entry_replacement','boolean_status','reserved_output_word']
    faults=vm['post_return_faults'];check(len(faults)==6 and [v['fault'] for v in faults]==labels,'six exact post-return faults')
    used=set();canary=bytes(range(64))
    for f in faults:
        n=f['call_index'];check(type(n) is int and n not in used and 0<=n<670,'unique fault call');used.add(n);row=calls[n]
        check(f['test_id']==row['case']==ids[8] and row['status']==256 and f['exception_observed']=='SQLiteDatabaseHeaderProtocolError','fault bound to successful VM and bridge refusal')
        a=[bytes.fromhex(v) for v in f['before_fault']];b=[bytes.fromhex(v) for v in f['after_fault']]
        check(list(map(len,a))==list(map(len,b))==[164,320,192],'whole fault buffers and canaries')
        check(a==[bytes.fromhex(row['source_after_hex'])+canary,bytes.fromhex(row['output_after_hex'])+canary,bytes.fromhex(row['control_after_hex'])+canary],'fault strictly after recorded entry return')
        exp=[bytearray(v) for v in a];name=f['fault']
        if name=='source_byte':exp[0][0]^=1
        elif name=='control_byte':exp[2][0]^=1
        elif name=='output_canary':exp[1][256]^=1
        elif name=='reserved_output_word':exp[1][128:136]=struct.pack('<Q',1)
        check(b==[bytes(v) for v in exp] and f['returned_status_type']==('bool' if name=='boolean_status' else 'int'),'exact declared fault only')
    check(worker['VM']['semantic_decisions']==q['expected_semantic_decisions']==634
          and worker['VM']['protocol_refusals']==q['expected_protocol_refusals']==36
          and worker['VM']['post_return_custody_faults']==q['expected_post_return_faults']==6,'all fixed denominators')
    report['VM']={'calls':670,'by_id':counts,'statuses':dict(statuses),'semantic_actions':dict(actions),'all_six_spans_bytes':spanbytes,
                  'semantic_decisions':634,'protocol_refusals':36,'post_return_custody_faults':6,'all_buffers_reread':True,'no_VM_or_oracle_reexecution':True,'raw_pin':pins['tests/VM-RAW.json']}
    doc=json.loads(raws['tests/CORE.json']);functions=doc['functions'];blocks=[b for f in functions for b in f['blocks']]
    measured={'assembly_bytes':len(raws['tests/sqlite_database_header.hiaasm']),'assembly_lines':len(raws['tests/sqlite_database_header.hiaasm'].decode().split('\n')),'functions':len(functions),'total_blocks':len(blocks),'operations':sum(len(b['ops']) for b in blocks),'blocks_per_function':max(len(f['blocks']) for f in functions),'returns':max([len(f['returns']) for f in functions]+[len(op.get('out',[])) for b in blocks for op in b['ops']]),'arguments':0,'maximum_ssa':0}
    def walk(node):
        if isinstance(node,dict):
            for key,value in node.items():
                if key in ('args','params') and isinstance(value,list):measured['arguments']=max(measured['arguments'],len(value))
                walk(value)
        elif isinstance(node,list):
            for value in node:walk(value)
        elif isinstance(node,str) and node.startswith('v') and node[1:].isdigit():measured['maximum_ssa']=max(measured['maximum_ssa'],int(node[1:]))
    walk(doc)
    check(len(functions)==11 and set(measured)==set(q['original_caps']),'11 functions/all nine caps')
    for key,value in measured.items():check(value<=q['original_caps'][key],'retained cap '+key)
    report['Core_static_readback']={'measured':measured,'original_caps':q['original_caps'],'roundtrip_executed_only_by_original_source12':True,'auditor_did_not_import_Core_or_render':True}
    log=raws['tests/unittest.log'].decode()
    for name in ids:check(name in log and name.rsplit('.',1)[1]+' (' in log,'original method text log')
    check('\nRan 12 tests in ' in log and log.rstrip().endswith('OK'),'complete unittest summary')
    for name in ('stderr.log','owner.json.stderr.log','owner.json.stdout.log'):check(raws[name]==b'','empty original stream '+name)
    line=json.loads(raws['stdout.log']);check(line['status']==worker['status'] and line['tests']==12 and line['seconds']==worker['seconds'],'actual child output/report')
    report['actual_files']=[{'relative':name,**pins[name]} for name in names]
    report['actual_directories']=dirs;report['actual_total_bytes']=sum(x['bytes'] for x in pins.values())
    report['tests']={'expected':12,'loaded':12,'executed':12,'success':12,'ids':ids,'worker_seconds':worker['seconds'],'zero_all_anomalies':True}
    report['limitations']=['Only Source12/Core VM evidence. No C/native/SQL/default AgentStore qualification.',
       'Header byte decisions and ordered retry requests do not perform real Pager/WAL/lock effects.',
       'Source12 original request was locally frozen before execution; this combined Git preservation is after actual, with no invented pre-execution Git commit.']
    report['status']='PASS_READBACK_SOURCE12_VM_ONLY';report['audit_seconds']=time.monotonic()-started
    return 0
try:
    rc=main()
except BaseException as exc:
    report['errors'].append({'type':type(exc).__name__,'traceback':traceback.format_exc()});rc=1
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
fd=os.open(O/'READBACK.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
print(json.dumps({'status':report['status'],'checks':report['check_count'],'errors':report['errors'],'report_sha256':hashlib.sha256(raw).hexdigest()}),flush=True)
raise SystemExit(rc)
