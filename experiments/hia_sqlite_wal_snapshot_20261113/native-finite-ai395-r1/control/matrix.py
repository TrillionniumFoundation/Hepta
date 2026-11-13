"""Frozen original 12/608 population plus a separate full-page finite group."""
from pathlib import Path
import hashlib,json,struct
import model
VERSIONS=('3.46.0','3.53.2')
ORIGINAL_IDS=("tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_01_Core_roundtrip_and_original_nine_caps","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_02_last_commit_and_latest_same_page_in_both_orders","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_03_checksum_valid_uncommitted_frames_are_not_visible","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_04_partial_tail_at_header_and_frame_structural_edges","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_05_first_corrupt_frame_stops_before_later_valid_commit","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_06_header_admission_order_and_all_page_sizes","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_07_fixed_snapshot_ignores_later_append_and_rejects_changed_prefix","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_08_commit_truncation_database_fallback_and_u32_pages","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_09_large_extent_uses_bounded_packets_without_whole_WAL_limit","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_10_protocol_refusals_and_one_use_states_preserve_spans","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_11_bridge_caught_reentry_exception_identity_and_custody","tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.test_12_retained_official_recovery_and_reused_arithmetic_are_exact",)
NAMES=tuple(x.rsplit('.',1)[1] for x in ORIGINAL_IDS)
COUNTS=(0,76,46,141,108,136,24,43,7,13,14,0)
PAGE_ID='tests.hia_wal_snapshot_native_pages_r1.FullPageSizesNativeTests.test_13_complete_frames_lookup_and_recovery_all_page_sizes'
IDS=ORIGINAL_IDS+(PAGE_ID,)
CANARY=model.CANARY
def wire(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def require(v,message):
    if not v:raise ValueError(message)
def digest(raw):return hashlib.sha256(raw).hexdigest()

def drive_spec(method,label,raw,*,page=None,snapshot=None,base_size=512,base_pages=9,error=None):
    if snapshot is not None:
        base_size=snapshot['base_size'];base_pages=snapshot['base_pages']
    view=raw if snapshot is None or not snapshot['committed_frame'] else raw[:snapshot['committed_end_offset']]
    require(type(raw)is bytes and type(view)is bytes and len(view)<=8<<20,'fixed finite C view')
    target=0 if page is None else page
    words,reads,current=model.c_words(view,target)
    return {'method':method,'label':label,'raw':raw,'view':view,'target':target,'snapshot':snapshot,
            'base_size':base_size,'base_pages':base_pages,'expected_error':error,
            'expected_words':words,'expected_reads':reads,'view_model':current}

def group(method,label,raw,pages=(1,2,3),base_size=512,base_pages=9):
    d=model.parse(raw,base_size,base_pages)
    yield drive_spec(method,label+'/scan',raw,base_size=base_size,base_pages=base_pages,
                     error=0xfffffff9 if d['unsupported'] else None)
    if not d['unsupported']:
        for page in pages:yield drive_spec(method,label+'/page-'+str(page),raw,page=page,snapshot=d)

def original_drives():
    mid=lambda n:ORIGINAL_IDS[n-1]
    for order in ('little','big'):
        raw=model.wal(((1,0,11),(2,2,22),(1,0,33),(1,2,44),(1,0,55)),order)
        yield from group(mid(2),order,raw)
        d=model.parse(raw)
        for page in (1,2):yield drive_spec(mid(2),order+'/extra-'+str(page),raw,page=page,snapshot=d)
    for order in ('little','big'):
        raw=model.wal(((1,0,17),(2,0,29)),order)
        yield from group(mid(3),order,raw,(1,3,4),base_pages=3)
        yield drive_spec(mid(3),order+'/uncommitted-extra',raw,page=1,snapshot=model.parse(raw,512,3))
    for n in (0,1,7,31,32):yield from group(mid(3),'empty-'+str(n),b'\xff'*n,(1,),base_pages=0)
    raw=model.wal(((1,1,3),(1,1,7)));boundary=568
    cuts=(0,1,7,8,23,24,31,32,33,boundary-1,boundary,
          *(boundary+n for n in (1,7,8,15,16,23,24,25,511,535)),len(raw))
    for cut in cuts:yield from group(mid(4),'cut-'+str(cut),raw[:cut],(1,))
    raw=model.wal(((1,1,9),(1,0,10),(1,1,11)));start=568
    for offset in (8,12,15,4,7,16,20,24,535):
        b=bytearray(raw);b[start+offset]^=1
        yield from group(mid(5),'bad-second-'+str(offset),bytes(b),(1,))
    b=bytearray(raw);b[start:start+4]=b'\0'*4
    yield from group(mid(5),'zero-second-page',bytes(b),(1,))
    for offset in (8,16,24):
        b=bytearray(raw);b[32+offset]^=1
        yield from group(mid(5),'bad-first-'+str(offset),bytes(b),(1,))
    for order in ('little','big'):
        for exponent in range(9,17):
            size=1<<exponent
            yield from group(mid(6),'header-'+order+'-'+str(size),model.header(order,size)+b'x',(1,),base_size=size)
    for magic in (0,0x377f0680,0xffffffff):
        yield from group(mid(6),'magic-'+str(magic),model.header(magic=magic)+b'x',(1,))
    for size in (0,1,511,513,65535,65537):
        yield from group(mid(6),'size-'+str(size),model.header(page_size=size)+b'x',(1,))
    b=bytearray(model.header(version=0));b[24]^=1
    yield from group(mid(6),'checksum-before-version',bytes(b)+b'x',(1,))
    for version in (0,3007001,0xffffffff):
        raw=model.header(version=version)+b'x'
        yield drive_spec(mid(6),'unsupported-'+str(version),raw,error=0xfffffff9)
    raw=model.wal(((1,0,19),(1,2,21)));d=model.parse(raw)
    yield drive_spec(mid(7),'capture',raw)
    later=model.wal(((1,0,19),(1,2,21),(1,0,31),(1,2,41)))
    yield drive_spec(mid(7),'ignore-later-append',later,page=1,snapshot=d)
    b=bytearray(raw);b[12]^=1;b[24:32]=struct.pack('>2I',*model.checksum(bytes(b[:24]),'little'))
    yield drive_spec(mid(7),'changed-header',bytes(b),page=1,snapshot=d,error=0xfffffff8)
    b=bytearray(raw);b[56]^=1
    yield drive_spec(mid(7),'changed-page',bytes(b),page=1,snapshot=d,error=0xfffffff8)
    different=model.wal(((1,0,88),(1,2,21)))
    yield drive_spec(mid(7),'changed-valid-prefix',different,page=1,snapshot=d,error=0xfffffff8)
    yield drive_spec(mid(7),'original-prefix-again',raw,page=1,snapshot=d)
    raw=model.wal(((5,5,8),(1,0,9),(1,2,10),(5,0,11)));d=model.parse(raw)
    yield from group(mid(8),'truncate',raw,(1,2,3,5))
    for page in (5,2):yield drive_spec(mid(8),'truncate-extra-'+str(page),raw,page=page,snapshot=d)
    yield drive_spec(mid(8),'empty-u32-geometry',b'',base_size=65536,base_pages=0xffffffff)
    d=model.parse(b'',65536,0xffffffff)
    yield drive_spec(mid(8),'empty-u32-lookup',b'',page=0xffffffff,snapshot=d)
    yield from group(mid(8),'u32-frame',model.wal(((0xffffffff,0xffffffff,99),)),(0xffffffff,))
    yield drive_spec(mid(10),'issued-empty-snapshot',b'')

def full_page_groups():
    for size in (512,1024,2048,4096,8192,16384,32768,65536):
        for order in ('little','big'):
            prefix=str(size)+'/'+order
            def item(label,raw,pages,base_pages=9):
                return {'label':prefix+'/'+label,'raw':raw,'pages':pages,'page_size':size,
                        'order':order,'base_pages':base_pages}
            yield item('latest-and-uncommitted-tail',model.wal(((1,0,11),(2,3,22),(1,0,33),(1,3,44),(1,0,55)),order,size),(1,2,3,4))
            yield item('no-commit',model.wal(((1,0,17),(2,0,29)),order,size),(1,3),3)
            raw=model.wal(((1,3,9),(1,0,10),(1,3,11)),order,size)
            start=32+size+24
            for label,offset in (('salt',8),('checksum',16),('page',size+23)):
                b=bytearray(raw);b[start+offset]^=1
                yield item('invalid-tail-'+label,bytes(b),(1,))
            raw=model.wal(((1,3,3),(2,3,7)),order,size);boundary=32+size+24
            yield item('truncated-frame-header',raw[:boundary+23],(1,2))
            yield item('truncated-page-body',raw[:-1],(1,2))
            yield item('commit-shrinks-database',model.wal(((5,5,8),(1,0,9),(1,2,10),(5,0,11)),order,size),(1,2,5))
            yield item('only-uncommitted-and-absent-page',model.wal(((1,3,8),(2,0,9)),order,size),(2,3,4,1))

def drives():
    i=0
    for spec in original_drives():
        i+=1;yield {'index':i,**spec,'population':'original12'}
    for g in full_page_groups():
        for spec in group(PAGE_ID,g['label'],g['raw'],g['pages'],g['page_size'],g['base_pages']):
            i+=1;yield {'index':i,**spec,'population':'full-page-extension'}

def original_calls(root):
    p=Path(root)/'reference/source12-actual/VM-RAW.json';raw=p.read_bytes()
    require(len(raw)==1518008 and digest(raw)=='9e8f17b9fb353bf249e072ea6f93e6e6efa11c8dbb3de2d0f0e540458fbff182','original VM raw pin')
    data=json.loads(raw)
    require(data['schema']=='hia.sqlite.wal-snapshot.vm-raw.v1' and data['native_executed'] is False
            and data['compiler_executed'] is False and len(data['calls'])==608,'original VM actual scope')
    counts={x:0 for x in ORIGINAL_IDS}
    for row in data['calls']:
        require(row['case'] in counts and row['actual_returned'] is True and type(row['status'])is int,'original VM row')
        counts[row['case']]+=1;yield dict(row)
    require(list(counts.values())==list(COUNTS),'original VM per-method count')

def hia_calls(root):
    i=0
    for row in original_calls(root):
        i+=1;yield {'index':i,'population':'original12',**row}
    for g in full_page_groups():
        rows,ranges,d=model.full_page_protocol(g['raw'],g['pages'],g['page_size'],g['base_pages'])
        for j,row in enumerate(rows):
            i+=1;yield {'index':i,'population':'full-page-extension','case':PAGE_ID,
                       'group':g['label'],'group_call':j+1,**row}

def hia_records(row):
    fields=('source','output','state')
    before=[bytes.fromhex(row[x+'_before_hex'])+CANARY for x in fields]
    after=[bytes.fromhex(row[x+'_after_hex'])+CANARY for x in fields]
    return ({'event':'pre','index':row['index'],'method':row['case'],'population':row['population'],
             'lengths':[len(x)-64 for x in before],'buffers_hex':[x.hex() for x in before]},
            {'event':'post','index':row['index'],'actual_returned':True,'status':row['status'],
             'buffers_hex':[x.hex() for x in after]})

def oracle_records(spec,version):
    n=len(spec['view']);read_words=2*(n//536+2)
    before=[spec['view']+CANARY,b'\xa5'*256+CANARY,b'\xa5'*(read_words*8)+CANARY]
    words=spec['expected_words'];reads=spec['expected_reads']
    used=b''.join(struct.pack('<2Q',*x) for x in reads)
    read_after=used+before[2][len(used):]
    after=[before[0],struct.pack('<32Q',*words)+CANARY,read_after]
    return ({'event':'pre','drive_index':spec['index'],'method':spec['method'],'label':spec['label'],
             'version':version,'target':spec['target'],'lengths':[n,256,read_words*8],
             'alignment_mod8':[0,0],'buffers_hex':[x.hex() for x in before]},
            {'event':'post','drive_index':spec['index'],'version':version,'actual_returned':True,
             'adapter_return':0,'raw_words':words,'buffers_hex':[x.hex() for x in after]})

def expected_stream(root,kind):
    if kind=='hia':
        for row in hia_calls(root):yield from hia_records(row)
    elif kind=='C':
        for spec in drives():
            for version in VERSIONS:yield from oracle_records(spec,version)
    else:raise ValueError('unknown frozen stream')

def metadata(spec):
    return {'index':spec['index'],'method':spec['method'],'label':spec['label'],'population':spec['population'],
            'input_bytes':len(spec['raw']),'input_sha256':digest(spec['raw']),
            'C_view_bytes':len(spec['view']),'C_view_sha256':digest(spec['view']),'target':spec['target'],
            'base_size':spec['base_size'],'base_pages':spec['base_pages'],'expected_error':spec['expected_error'],
            'snapshot':None if spec['snapshot'] is None else model.snapshot_fields(spec['snapshot']),
            'expected_C_projection':model.c_projection(spec['expected_words'],spec['view'],spec['target'],spec['base_size'],spec['base_pages'])}

def manifest(root):
    per={x:0 for x in IDS};returns=0;by_population={}
    for row in hia_calls(root):
        returns+=1;per[row['case']]+=1;by_population[row['population']]=by_population.get(row['population'],0)+1
    ds=[metadata(s) for s in drives()];streams={}
    for kind in ('hia','C'):
        sha=hashlib.sha256();total=count=largest=0
        for row in expected_stream(root,kind):
            raw=wire(row);sha.update(raw);total+=len(raw);count+=1;largest=max(largest,len(raw))
        streams[kind]={'bytes':total,'records':count,'sha256':sha.hexdigest(),'maximum_record_bytes':largest}
    return {'schema':'hia.wal-snapshot.native-fixed-matrix.v1','expected_ids':list(IDS),
            'original_ids':list(ORIGINAL_IDS),'original_methods':12,'added_methods':1,
            'original_VM_calls':608,'native_returns':returns,'counts':per,'populations':by_population,
            'full_page_groups':144,'page_sizes':[512,1024,2048,4096,8192,16384,32768,65536],
            'checksum_orders':['little','big'],'drives':ds,'C_calls_each':len(ds),
            'C_views_chosen_without_HIA_status':True,'streams':streams,
            'combined_trace_bytes':sum(x['bytes'] for x in streams.values()),
            'whole_WAL_limit_applies_only_to_C':8<<20}
