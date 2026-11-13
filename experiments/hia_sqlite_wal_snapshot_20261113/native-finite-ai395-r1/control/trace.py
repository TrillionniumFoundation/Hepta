"""Two complete, separately typed streams share the original 256 MiB ceiling."""
from pathlib import Path
import hashlib,json,os
import common,matrix
CHUNK_BYTES=4<<20
MAX_BYTES=256<<20
MAX_RECORD_BYTES=1<<20
RESERVE=512<<20
MIN_INODES=4096
class Budget:
    def __init__(self):self.bytes=0
    def charge(self,n):
        common.require(type(n)is int and n>0 and self.bytes+n<=MAX_BYTES,'shared full trace byte ceiling')
        self.bytes+=n

def capacity(path):
    v=os.statvfs(path)
    common.require(v.f_bavail*v.f_frsize>=RESERVE+CHUNK_BYTES and v.f_favail>=MIN_INODES,
                   'trace original free reserve/inodes')

class Writer:
    def __init__(self,path,kind,budget):
        common.require(kind in ('hia','C') and type(budget)is Budget,'trace fixed kind/budget')
        self.path=Path(path);self.path.mkdir(mode=0o700);self.kind=kind;self.budget=budget
        self.fd=None;self.part=None;self.part_bytes=0;self.part_records=0
        self.parts=[];self.bytes=0;self.records=0;self.closed=False
    def _close(self):
        if self.fd is None:return
        os.fsync(self.fd);os.close(self.fd);self.fd=None
        pin,_=common.read(self.path/self.part,CHUNK_BYTES)
        common.require(pin['bytes']==self.part_bytes,'trace whole part length')
        self.parts.append({'path':self.part,'bytes':pin['bytes'],'sha256':pin['sha256'],
                           'git_blob':pin['git_blob'],'records':self.part_records})
    def write(self,row):
        common.require(not self.closed,'trace write after close')
        raw=matrix.wire(row)
        common.require(0<len(raw)<=MAX_RECORD_BYTES,'original 1 MiB complete record bound')
        self.budget.charge(len(raw))
        if self.fd is None or self.part_bytes+len(raw)>CHUNK_BYTES:
            self._close();capacity(self.path)
            self.part='part-%04d.jsonl'%len(self.parts);self.part_bytes=0;self.part_records=0
            self.fd=os.open(self.path/self.part,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        b=memoryview(raw)
        while b:
            n=os.write(self.fd,b);common.require(n>0,'trace partial write');b=b[n:]
        self.bytes+=len(raw);self.records+=1;self.part_bytes+=len(raw);self.part_records+=1
    def finish(self,complete):
        common.require(not self.closed and type(complete)is bool,'trace finish once')
        self._close();self.closed=True
        doc={'schema':'hia.wal-snapshot.native-stream.v1','kind':self.kind,'complete':complete,
             'parts':self.parts,'bytes':self.bytes,'records':self.records,
             'chunk_limit':CHUNK_BYTES,'shared_total_limit':MAX_BYTES,'record_limit':MAX_RECORD_BYTES}
        common.create(self.path/('INDEX.json' if complete else 'INDEX.partial.json'),doc)
        return doc

def inspect_stream(root,path,kind,expected):
    root,path=Path(root),Path(path);pin,raw=common.read(path/'INDEX.json',1<<20);index=json.loads(raw)
    common.require(index.get('schema')=='hia.wal-snapshot.native-stream.v1' and index.get('kind')==kind
        and index.get('complete')is True and type(index['bytes'])is int and 0<index['bytes']<=MAX_BYTES
        and type(index['records'])is int and index['records']==expected['records']
        and index['chunk_limit']==CHUNK_BYTES and index['shared_total_limit']==MAX_BYTES
        and index['record_limit']==MAX_RECORD_BYTES,'strict complete stream index')
    common.require(type(index['parts'])is list and index['parts']
        and len(index['parts'])==len({x['path']for x in index['parts']}),'unique original part sequence')
    iterator=iter(matrix.expected_stream(root,kind));sha=hashlib.sha256();total=count=largest=0;parts=[]
    for number,item in enumerate(index['parts']):
        name='part-%04d.jsonl'%number
        common.require(item['path']==name,'contiguous trace ordinal')
        p,body=common.read(path/name,CHUNK_BYTES)
        common.require(all(p[k]==item[k]for k in ('bytes','sha256','git_blob')),'full trace chunk hash')
        lines=body.splitlines(keepends=True)
        common.require(type(item['records'])is int and len(lines)==item['records'],'chunk full row population')
        for line in lines:
            common.require(line.endswith(b'\n') and len(line)<=MAX_RECORD_BYTES,'bounded complete row')
            row=json.loads(line);common.require(matrix.wire(row)==line,'canonical actual JSONL original')
            try:wanted=next(iterator)
            except StopIteration:raise RuntimeError('extra actual trace row')
            common.require(line==matrix.wire(wanted),'complete actual row differs at '+kind+':'+str(count))
            count+=1;largest=max(largest,len(line))
        total+=len(body);sha.update(body);parts.append(p)
    try:next(iterator)
    except StopIteration:pass
    else:raise RuntimeError('missing expected trace row')
    common.require(total==index['bytes']==expected['bytes'] and count==expected['records']
        and sha.hexdigest()==expected['sha256'] and largest==expected['maximum_record_bytes'],'whole stream byte/predicate readback')
    common.require({p.name for p in path.iterdir()}=={'INDEX.json',*(p['path']for p in index['parts'])},
                   'trace namespace differs')
    return {'index':pin,'parts':parts,'bytes':total,'records':count,'sha256':sha.hexdigest(),
            'maximum_record_bytes':largest,'complete_original_buffers_and_order':True}

def inspect(root,path,expected):
    path=Path(path);result={kind:inspect_stream(root,path/kind,kind,expected['streams'][kind])for kind in ('hia','C')}
    total=sum(v['bytes']for v in result.values())
    common.require(total==expected['combined_trace_bytes']<=MAX_BYTES,'combined original trace limit')
    return {'streams':result,'bytes':total,'native_returns':expected['native_returns'],
            'C_calls_each':expected['C_calls_each'],'original_VM_calls':608,'all_full_bodies_read':True}
