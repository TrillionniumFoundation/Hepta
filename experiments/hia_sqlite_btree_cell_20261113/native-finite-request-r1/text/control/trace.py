"""Complete selected-cell PRE/POST stream; physical chunks retain every byte of large records."""
from pathlib import Path
import hashlib,json,os
import common,matrix
CHUNK_BYTES=4<<20
MAX_BYTES=256<<20
# Every complete page appears in HIA and both original C before/after transports.
# Records may cross fixed 4 MiB physical files; no buffer is truncated or omitted.
MAX_BTREE_CELL_BYTES=16<<20
RESERVE=512<<20
MIN_INODES=4096
def capacity(path):
    v=os.statvfs(path)
    common.require(v.f_bavail*v.f_frsize>=RESERVE+CHUNK_BYTES and v.f_favail>=MIN_INODES,
                   'trace write reserve/inode gate differs')
def expected_buffers(spec):
    before=[bytes.fromhex(spec[k])+matrix.CANARY for k in ('source_hex','output_hex','command_hex')]
    after=[bytes.fromhex(spec['expected'][k])+matrix.CANARY for k in ('source_after_hex','output_after_hex','command_after_hex')]
    return before,after
def expected_oracle(spec,version):
    cell=spec['expected']['cell_info']
    if cell is None:
        return {'version':version,'called':False,'reason':'frozen_refused_cell_not_a_C_parser_domain'}
    raw=bytes.fromhex(spec['source_hex']);words=spec['expected']['words']
    before_source=raw+matrix.CANARY;before=b'\xa5'*48+matrix.CANARY
    after=b''.join(x.to_bytes(8,'little') for x in cell)+matrix.CANARY
    return {'version':version,'called':True,'operation':'cell','page_bytes':len(raw),'usable':words[2],
        'page_kind':words[1],'cell_offset':words[5],'actual_returned':True,'returned':0,'output_words':cell,
        'input_before_hex':before_source.hex(),'input_after_hex':before_source.hex(),
        'output_before_hex':before.hex(),'output_after_hex':after.hex(),'output_alignment_mod8':0,
        'derived_projection':matrix.project_cell(cell,0,cell)}
def expected_records(spec):
    before,after=expected_buffers(spec)
    return ({'event':'pre','index':spec['index'],'method':spec['method'],'label':spec['label'],
             'lengths':[len(bytes.fromhex(spec[k])) for k in ('source_hex','output_hex','command_hex')],
             'buffers_hex':[b.hex() for b in before]},
            {'event':'post','index':spec['index'],'actual_returned':True,'status':spec['expected']['status'],
             'buffers_hex':[b.hex() for b in after],
             'oracles':[expected_oracle(spec,v) for v in matrix.VERSIONS]})
class Writer:
    def __init__(self,path):
        self.path=Path(path);self.path.mkdir(mode=0o700)
        self.fd=None;self.part=None;self.part_bytes=0
        self.parts=[];self.bytes=0;self.records=0;self.closed=False
    def _close(self):
        if self.fd is None:return
        os.fsync(self.fd);os.close(self.fd);self.fd=None
        pin,_=common.read(self.path/self.part,CHUNK_BYTES)
        common.require(pin['bytes']==self.part_bytes,'trace part complete length')
        self.parts.append({'path':self.part,'bytes':pin['bytes'],'sha256':pin['sha256'],'git_blob':pin['git_blob']})
    def write(self,row):
        common.require(not self.closed,'trace writer closed')
        raw=matrix.wire(row)
        common.require(len(raw)<=MAX_BTREE_CELL_BYTES and self.bytes+len(raw)<=MAX_BYTES,'full trace capacity')
        pos=0
        while pos<len(raw):
            if self.fd is None or self.part_bytes==CHUNK_BYTES:
                self._close();capacity(self.path)
                self.part='part-%04d.jsonl'%len(self.parts);self.part_bytes=0
                self.fd=os.open(self.path/self.part,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            block=memoryview(raw)[pos:pos+CHUNK_BYTES-self.part_bytes]
            while block:
                n=os.write(self.fd,block);common.require(n>0,'trace short write')
                pos+=n;self.part_bytes+=n;self.bytes+=n;block=block[n:]
        self.records+=1
    def finish(self,complete):
        common.require(not self.closed,'trace finish twice')
        self._close();self.closed=True
        doc={'schema':'hia.sqlite.btree.cell.full-native-trace.v1','complete':complete,
            'parts':self.parts,'bytes':self.bytes,'records':self.records,
            'native_returns':self.records//2 if complete else None,
            'chunk_limit':CHUNK_BYTES,'total_limit':MAX_BYTES,'record_limit':MAX_BTREE_CELL_BYTES,
            'records_may_cross_physical_chunks':True}
        common.create(self.path/('INDEX.json' if complete else 'INDEX.partial.json'),doc)
        return doc
def inspect(root,path,expected_manifest):
    root,path=Path(root),Path(path)
    pin,raw=common.read(path/'INDEX.json',1<<20);index=json.loads(raw)
    common.require(index.get('schema')=='hia.sqlite.btree.cell.full-native-trace.v1'
        and index.get('complete') is True and type(index['bytes'])is int and 0<index['bytes']<=MAX_BYTES
        and type(index['records'])is int and index['records']==2*sum(matrix.COUNTS)
        and type(index['native_returns'])is int and index['native_returns']==sum(matrix.COUNTS)
        and index['chunk_limit']==CHUNK_BYTES and index['total_limit']==MAX_BYTES
        and index['record_limit']==MAX_BTREE_CELL_BYTES and index['records_may_cross_physical_chunks'] is True,
        'complete trace index population')
    sequence=iter(matrix.specifications(root));spec=None;counts={x:0 for x in matrix.IDS}
    matrix_hash=hashlib.sha256();full_hash=hashlib.sha256();total=records=0;observed=[]
    oracle_counts={v:{'cell_calls':0,'accepted_cells':0,'refused_cells_not_called':0} for v in matrix.VERSIONS}
    pending=b''
    for number,item in enumerate(index['parts']):
        name='part-%04d.jsonl'%number
        common.require(item['path']==name,'contiguous physical trace order')
        p,b=common.read(path/name,CHUNK_BYTES)
        common.require(all(p[k]==item[k] for k in ('bytes','sha256','git_blob'))
            and (p['bytes']==CHUNK_BYTES or number==len(index['parts'])-1),'whole physical trace chunk SHA/Git/extent')
        total+=len(b);full_hash.update(b);observed.append(p);pending+=b
        while True:
            at=pending.find(b'\n')
            if at<0:break
            line,pending=pending[:at+1],pending[at+1:]
            common.require(len(line)<=MAX_BTREE_CELL_BYTES,'complete record exceeds frozen bound')
            row=json.loads(line);common.require(matrix.wire(row)==line,'canonical raw JSON types')
            if records%2==0:
                try:spec=next(sequence)
                except StopIteration:raise RuntimeError('extra native PRE')
                matrix_hash.update(matrix.wire(spec))
                expected_pre,_=expected_records(spec)
                common.require(line==matrix.wire(expected_pre),'actual full PRE bytes/order/types differ')
            else:
                _,expected_post=expected_records(spec)
                common.require(line==matrix.wire(expected_post),'actual full native/C POST bytes/types differ')
                counts[spec['method']]+=1;cell=spec['expected']['cell_info']
                for v in matrix.VERSIONS:
                    count=oracle_counts[v]
                    if cell is None:count['refused_cells_not_called']+=1
                    else:
                        count['accepted_cells']+=1;count['cell_calls']+=1
            records+=1
        common.require(len(pending)<=MAX_BTREE_CELL_BYTES,'unterminated record exceeds bound')
    common.require(pending==b'','partial final JSON record')
    try:next(sequence)
    except StopIteration:pass
    else:raise RuntimeError('missing native records')
    common.require(total==index['bytes'] and records==index['records'] and counts==expected_manifest['counts']
        and matrix_hash.hexdigest()==expected_manifest['ordered_expected_rows_sha256']
        and all(v==expected_manifest['oracle_calls_each'] for v in oracle_counts.values()),'whole complete native/C denominator')
    _,raw=common.read(root/'EXPECTED-TRACE.json',1<<20);expected=json.loads(raw)
    common.require(total==expected['bytes'] and records==expected['records'] and full_hash.hexdigest()==expected['sha256'],
        'frozen complete trace byte SHA/length')
    common.require({p.name for p in path.iterdir()}=={'INDEX.json',*(x['path'] for x in index['parts'])},'trace namespace exact')
    return {'index':pin,'parts':observed,'bytes':total,'records':records,'native_returns':records//2,
            'sha256':full_hash.hexdigest(),'counts':counts,'oracle_counts':oracle_counts,
            'expected_rows_sha256':matrix_hash.hexdigest(),'all_pre_post_and_full_C_buffers_read':True,
            'physical_chunk_join_is_byte_exact':True}
