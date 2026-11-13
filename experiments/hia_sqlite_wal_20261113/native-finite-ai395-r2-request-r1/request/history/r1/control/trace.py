"""Complete original 238 native PRE/POST buffers and both C raw-state outputs."""
from pathlib import Path
import hashlib,json,os
import common,matrix
CHUNK_BYTES=4<<20
MAX_BYTES=256<<20
# New WAL protocol-refusal input 65,537 bytes requires a larger record than varint.
# This is a new trace shape; the existing 4 MiB chunks and 256 MiB total stay fixed.
MAX_RECORD_BYTES=1<<20
RESERVE=512<<20
MIN_INODES=4096
def capacity(path):
    v=os.statvfs(path)
    common.require(v.f_bavail*v.f_frsize>=RESERVE+CHUNK_BYTES and v.f_favail>=MIN_INODES,
                   'trace write reserve/inode gate differs')
def checked_hex(value):
    common.require(type(value)is str,'trace hex type')
    b=bytes.fromhex(value);common.require(b.hex()==value,'trace hex canonical');return b
def expected_buffers(spec):
    before=[bytes.fromhex(spec[k])+matrix.CANARY for k in ('source_hex','output_hex','command_hex')]
    after=[bytes.fromhex(spec['expected'][k])+matrix.CANARY for k in ('source_after_hex','output_after_hex','command_after_hex')]
    return before,after
def expected_oracle(spec,version):
    o=spec['expected']['oracle']
    if o is None:return {'version':version,'called':False,'reason':'outside_original_C_and_HIA_transport_domain'}
    source=bytes.fromhex(spec['source_hex'])+matrix.CANARY
    n=4*len(o['output_words']);before=b'\xa5'*n+matrix.CANARY
    after=b''.join(x.to_bytes(4,'little') for x in o['output_words'])+matrix.CANARY
    return {'version':version,'called':True,'operation':o['operation'],'returned':o['returned'],
            'seed_before':o['seed_before'],'output_words':o['output_words'],
            'input_before_hex':source.hex(),'input_after_hex':source.hex(),
            'output_before_hex':before.hex(),'output_after_hex':after.hex(),
            'input_alignment_mod4':0,'output_alignment_mod4':0,
            'derived_projection':matrix.project_oracle(spec,o['returned'],o['output_words'])}
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
        self.fd=None;self.part=None;self.part_bytes=0;self.part_records=0
        self.parts=[];self.bytes=0;self.records=0;self.closed=False
    def _close(self):
        if self.fd is None:return
        os.fsync(self.fd);os.close(self.fd);self.fd=None
        pin,_=common.read(self.path/self.part,CHUNK_BYTES)
        common.require(pin['bytes']==self.part_bytes,'trace part length')
        self.parts.append({'path':self.part,'bytes':pin['bytes'],'sha256':pin['sha256'],
                           'git_blob':pin['git_blob'],'records':self.part_records})
    def write(self,row):
        common.require(not self.closed,'trace writer closed')
        raw=matrix.wire(row)
        common.require(len(raw)<=MAX_RECORD_BYTES and self.bytes+len(raw)<=MAX_BYTES,'whole trace capacity')
        if self.fd is None or self.part_bytes+len(raw)>CHUNK_BYTES:
            self._close();capacity(self.path)
            self.part='part-%04d.jsonl'%len(self.parts);self.part_bytes=0;self.part_records=0
            self.fd=os.open(self.path/self.part,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        b=memoryview(raw)
        while b:
            n=os.write(self.fd,b)
            common.require(n>0,'trace short write');b=b[n:]
        self.bytes+=len(raw);self.records+=1;self.part_bytes+=len(raw);self.part_records+=1
    def finish(self,complete):
        common.require(not self.closed,'trace finish twice')
        self._close();self.closed=True
        doc={'schema':'hia.sqlite.wal.full-native-trace.v1','complete':complete,
             'parts':self.parts,'bytes':self.bytes,'records':self.records,
             'native_returns':self.records//2 if complete else None,
             'chunk_limit':CHUNK_BYTES,'total_limit':MAX_BYTES,'record_limit':MAX_RECORD_BYTES}
        common.create(self.path/('INDEX.json' if complete else 'INDEX.partial.json'),doc)
        return doc
def inspect(root,path,expected_manifest):
    root,path=Path(root),Path(path)
    pin,raw=common.read(path/'INDEX.json',1<<20);index=json.loads(raw)
    common.require(index.get('schema')=='hia.sqlite.wal.full-native-trace.v1'
        and index.get('complete') is True and index['bytes']<=MAX_BYTES
        and index['records']==2*sum(matrix.COUNTS) and index['native_returns']==sum(matrix.COUNTS)
        and index['chunk_limit']==CHUNK_BYTES and index['total_limit']==MAX_BYTES
        and index['record_limit']==MAX_RECORD_BYTES,'complete trace index population')
    expected_iter=iter(matrix.specifications(root));spec=None;counts={x:0 for x in matrix.IDS}
    matrix_hash=hashlib.sha256();total=records=0;observed_parts=[]
    oracle_counts={v:{'checksum':0,'header':0,'frame':0,'not_called':0} for v in matrix.VERSIONS}
    for number,item in enumerate(index['parts']):
        name='part-%04d.jsonl'%number
        common.require(item['path']==name,'contiguous trace part order')
        p,b=common.read(path/name,CHUNK_BYTES)
        common.require(all(p[k]==item[k] for k in ('bytes','sha256','git_blob')),'full trace part SHA/Git')
        lines=b.splitlines(keepends=True)
        common.require(len(lines)==item['records'] and all(x.endswith(b'\n') and len(x)<=MAX_RECORD_BYTES for x in lines),'whole records in each chunk')
        for line in lines:
            row=json.loads(line);common.require(matrix.wire(row)==line,'canonical trace raw row')
            if records%2==0:
                try:spec=next(expected_iter)
                except StopIteration:raise RuntimeError('extra native PRE')
                matrix_hash.update(matrix.wire(spec))
                expected_pre,_=expected_records(spec)
                common.require(line==matrix.wire(expected_pre),'actual full PRE bytes/order differ')
            else:
                _,expected_post=expected_records(spec)
                common.require(line==matrix.wire(expected_post),'actual native/C complete POST differs')
                counts[spec['method']]+=1
                for v in matrix.VERSIONS:
                    o=spec['expected']['oracle'];oracle_counts[v][o['operation'] if o else 'not_called']+=1
            records+=1
        total+=len(b);observed_parts.append(p)
    try:next(expected_iter)
    except StopIteration:pass
    else:raise RuntimeError('missing native records')
    common.require(total==index['bytes'] and records==index['records']
        and counts==expected_manifest['counts']
        and matrix_hash.hexdigest()==expected_manifest['ordered_expected_rows_sha256']
        and all(x==expected_manifest['oracle_calls_each'] for x in oracle_counts.values()),
        'whole native trace matrix denominator')
    observed={p.name for p in path.iterdir()}
    common.require(observed=={'INDEX.json',*(p['path'] for p in index['parts'])},'unexpected trace namespace')
    return {'index':pin,'parts':observed_parts,'bytes':total,'records':records,'native_returns':records//2,
            'counts':counts,'oracle_counts':oracle_counts,'expected_rows_sha256':matrix_hash.hexdigest(),
            'all_pre_post_and_full_C_buffers_read':True}
