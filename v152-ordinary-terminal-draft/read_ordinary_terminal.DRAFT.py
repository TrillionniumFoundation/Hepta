"""Recoverable ordinary terminal-reader DRAFT, authored from exact Git payloads.

AUTHOR_ONLY_UNBOUND. Not a frozen launch. No Python execution or Python AST
validation occurred while this draft was written; the filesystem was unavailable.
Actual product session 67922 and R12 boundary session 54384 remain UNKNOWN.
The explicit execution gate and unresolved Root-outer adapter both fail closed.
No inputs, old statistics, missing frames or actual terminal results are invented.
"""
from __future__ import annotations
import argparse,ast,base64,hashlib,io,itertools,json,os,re,sqlite3,stat,struct,time,traceback,zipfile,zlib
from collections.abc import Mapping
from pathlib import Path

EXECUTION_BOUND=False
AUTHOR=None
OUTER=None
SCOPE=Path('/home/agent/hia-cli-owner-bundle-qualification-r2-20261115-dda7')
FIXED_SCOPE=SCOPE
ACTUAL_SOURCE='/workspace/hia-cli-owner-bundle-generation-r1-20261115-dda7/source'
GEN_SCOPE=Path(ACTUAL_SOURCE).parent
GEN_OUTER=Path('/workspace/hia-cli-owner-bundle-generation-outer-r1-20261115-dda7')
PACKAGING_ROOT=Path('/workspace/hia-cli-as-dict-packaging-r1-dda7')
SOURCE_TREE=TREE='6c506654638513dbe10623da9458d3904a208cc8'
SCHEMA='hepta.hia.cli-owner-bundle.qualification.v1'
SUCCESS='PASS_EXPLICIT_ORDINARY_SELECTOR_CURRENT_DOMAIN'
CAPACITY=1048576
MINIMUM_FREE=1073741824
CHUNK_BYTES=65536
VALUE_BYTES=16<<20
SHARD_BYTES=8<<20
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
COMPONENTS=('control','format','discovery','routing','parser_context','verified_report','inspect','patch')
REPORT_COMPONENTS=COMPONENTS[:6]
ROLES=('selection',*COMPONENTS)
FRAME_KEYS=('source_before','output_before','workspace_before','source_after','output_after','workspace_after')
VM_KEYS=('start','claim','ack','normal-terminal','known-error-terminal',
         'retirement-start','retirement-ack','lost-claim-return')
GENERATED=('examples/hia_bootstrap/cli_owner_selection.hepta',
           'hepta/hia_cli_owner_bundle_ports.py','hepta/hia_cli_owner_bundle_data.py')
LIMITS={'owner_seconds':180,'cleanup_seconds':3,'compile_seconds':20,'native_capacity':1048576,
        'vm_steps':10000000,'vm_heap':8388608,'vm_call_depth':128}
SELECTOR_LIMITS={**LIMITS,'cpu_seconds':10,'minimum_free_bytes':MINIMUM_FREE}
B3_PIN={'bytes':673413,'mode':'100644','git_blob':'315c6b5f36a1ec679deb68abdca24bd4d1bef9f8',
        'sha256':'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'}
READS=0
BYTES=0
SEEN=None
OBSERVED_READS=None
LEDGER=None
LINK_TARGET_READS=0
LINK_TARGET_BYTES=0
PHYSICAL_BUFFER_READS=0



def require(v,m):
    if not v:raise AssertionError(m)


def seven(s):return {k:getattr(s,k)for k in FIELDS}


def pin(b,mode=None):
    r={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if mode is not None:r['mode']=mode
    return r


def pairs(rows):
    d={}
    for k,v in rows:
        require(type(k)is str and k not in d,'duplicate JSON key');d[k]=v
    return d


def decode(b):return json.loads(b,object_pairs_hook=pairs)


def read(path,expected=None,expected_stat=None):
    global READS,BYTES
    p=Path(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);before=seven(s)
        require(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and before==seven(p.lstat()),'unique regular held/named input required')
        parts=[];left=s.st_size+1
        while left:
            b=os.read(fd,min(1048576,left))
            if not b:break
            parts.append(b);left-=len(b)
        b=b''.join(parts);require(len(b)==s.st_size and before==seven(os.fstat(fd))==seven(p.lstat()),'input changed around fresh full read')
    finally:os.close(fd)
    mode='100755'if s.st_mode&0o111 else'100644';actual=pin(b,mode)
    if expected is not None:require({k:actual[k]for k in expected}==expected,'complete content/mode pin differs: '+str(p))
    if expected_stat is not None:require(before==expected_stat,'seven-stat authority differs: '+str(p))
    if str(p)in SEEN:require(SEEN[str(p)]['stat']==before,'repeated fresh input identity changed')
    SEEN[str(p)]={'path':str(p),'pin':actual,'stat':before};READS+=1;BYTES+=len(b)
    return b


def fixed(r):return read(r['path'],r['pin'],r['stat'])


def metadata(root):
    root=Path(root);out=LEDGER.mapping('physical-path-state');out['.']=seven(root.lstat());require(stat.S_ISDIR(out['.']['st_mode']),'ordinary root required')
    def walk(p,prefix):
        for e in sorted(os.scandir(p),key=lambda x:x.name):
            s=e.stat(follow_symlinks=False);name=prefix+e.name
            require(stat.S_ISDIR(s.st_mode)or(stat.S_ISREG(s.st_mode)and s.st_nlink==1),'unknown/multilink member')
            out[name]=seven(s)
            if stat.S_ISDIR(s.st_mode):walk(e.path,name+'/')
    walk(root,'');return out


def tree(flat):
    root={}
    for name,r in flat.items():
        n=root;p=name.split('/')
        for part in p[:-1]:n=n.setdefault(part,{})
        n[p[-1]]=(r['mode'],r['git_blob'])
    def digest(n):
        chunks=[]
        for name,v in sorted(n.items(),key=lambda x:(x[0]+('/'if isinstance(x[1],dict)else'')).encode()):
            mode,key=('40000',digest(v))if isinstance(v,dict)else v
            chunks.append(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(key))
        b=b''.join(chunks);return hashlib.sha1(b'tree '+str(len(b)).encode()+b'\0'+b).hexdigest()
    return digest(root)


def directories(rows):
    for r in rows:
        s=Path(r['path']).lstat();require(stat.S_ISDIR(s.st_mode),'directory path changed type')
        require({'path':r['path'],'dev':s.st_dev,'ino':s.st_ino,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid}==r,'ancestor authority changed')


class Ledger:
    """Private metadata only. No input payload is cached or returned by this index."""
    def __init__(self,root):
        self.root=Path(root);self.db_path=self.root/'BOOKKEEPING.sqlite'
        fd=os.open(self.db_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        os.close(fd)
        self.db=sqlite3.connect(str(self.db_path))
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA temp_store=FILE')
        self.db.execute('PRAGMA mmap_size=0')
        self.db.execute('PRAGMA cache_size=-8192')
        self.db.execute('CREATE TABLE collections (id INTEGER PRIMARY KEY, label TEXT NOT NULL)')
        self.db.execute('CREATE TABLE records (collection INTEGER NOT NULL, key TEXT NOT NULL, ordinal INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY (collection,key), UNIQUE(collection,ordinal))')
        self.db.commit();self.next_collection=0;self.pending=0;self.read_count=0
        self.read_log_path=self.root/'FULL-READS.jsonl'
        self.read_log=self.read_log_path.open('xb',buffering=65536)
        self.read_log_bytes=0;self.read_log_sha=hashlib.sha256()
    def change(self):
        self.pending+=1
        if self.pending>=2048:
            self.db.commit();self.read_log.flush();self.pending=0
    def collection(self,label):
        self.next_collection+=1
        self.db.execute('INSERT INTO collections VALUES (?,?)',(self.next_collection,label))
        self.change();return self.next_collection
    def mapping(self,label,*,full_reads=False):return DiskMap(self,label,full_reads=full_reads)
    def sequence(self,label):return DiskSequence(self,label)
    def record_read(self,row):
        raw=(json.dumps({'ordinal':self.read_count,'descriptor':row},sort_keys=True)+'\n').encode()
        self.read_log.write(raw);self.read_log_bytes+=len(raw);self.read_log_sha.update(raw);self.read_count+=1
    def close_and_capture(self):
        self.db.commit();self.db.close();self.read_log.flush();self.read_log.close()
        records=[]
        for path in (self.db_path,self.read_log_path):
            descriptor=stream_file_pin(path)
            if path==self.read_log_path:
                require(descriptor['pin']['bytes']==self.read_log_bytes
                    and descriptor['pin']['sha256']==self.read_log_sha.hexdigest(),
                    'complete fresh-read ledger independent full-byte readback differs')
            records.append(descriptor)
        return {'files':records,'metadata_collections':self.next_collection,
            'fresh_read_rows':self.read_count,'sqlite_cache_kib':8192,'sqlite_mmap_bytes':0,
            'input_payload_cache':False,'metadata_only':True}


class DiskMap(Mapping):
    def __init__(self,ledger,label,*,full_reads=False):
        self.ledger=ledger;self.collection=ledger.collection(label);self.size=0;self.full_reads=full_reads
    def __len__(self):return self.size
    def __iter__(self):
        for row in self.ledger.db.execute('SELECT key FROM records WHERE collection=? ORDER BY ordinal',(self.collection,)):
            yield row[0]
    def __contains__(self,key):
        return self.ledger.db.execute('SELECT 1 FROM records WHERE collection=? AND key=?',(self.collection,key)).fetchone()is not None
    def __getitem__(self,key):
        row=self.ledger.db.execute('SELECT value FROM records WHERE collection=? AND key=?',(self.collection,key)).fetchone()
        if row is None:raise KeyError(key)
        return decode(row[0])
    def __setitem__(self,key,value):
        require(type(key)is str,'disk metadata key must be an exact string')
        raw=json.dumps(value,sort_keys=True,separators=(',',':'))
        old=self.ledger.db.execute('SELECT ordinal FROM records WHERE collection=? AND key=?',(self.collection,key)).fetchone()
        if old is None:
            self.ledger.db.execute('INSERT INTO records VALUES (?,?,?,?)',(self.collection,key,self.size,raw));self.size+=1
        else:self.ledger.db.execute('UPDATE records SET value=? WHERE collection=? AND key=?',(raw,self.collection,key))
        if self.full_reads:self.ledger.record_read(value)
        self.ledger.change()
    def items(self):
        for key,raw in self.ledger.db.execute('SELECT key,value FROM records WHERE collection=? ORDER BY ordinal',(self.collection,)):
            yield key,decode(raw)
    def sorted_items(self):
        for key,raw in self.ledger.db.execute('SELECT key,value FROM records WHERE collection=? ORDER BY key COLLATE BINARY',(self.collection,)):
            yield key,decode(raw)
    def values(self):
        for row in self.ledger.db.execute('SELECT value FROM records WHERE collection=? ORDER BY ordinal',(self.collection,)):
            yield decode(row[0])
    def __eq__(self,other):
        if not isinstance(other,Mapping):return False
        if len(self)!=len(other):return False
        return all(key in other and value==other[key]for key,value in self.items())
    def __ne__(self,other):return not self==other


class DiskSequence:
    def __init__(self,ledger,label):self.rows=ledger.mapping(label)
    def __len__(self):return len(self.rows)
    def __iter__(self):return self.rows.values()
    def append(self,value):self.rows[str(len(self.rows))]=value
    def extend(self,values):
        for value in values:self.append(value)


class DiskSet:
    def __init__(self,ledger,label):self.rows=ledger.mapping(label)
    def __contains__(self,key):return key in self.rows
    def add(self,key):
        if key not in self.rows:self.rows[key]=True


class StreamValues:
    def __init__(self,mapping):self.mapping=mapping
    def __len__(self):return len(self.mapping)
    def __iter__(self):return self.mapping.values()


def sequence_equal(left,right):
    sentinel=object()
    for a,b in itertools.zip_longest(left,right,fillvalue=sentinel):
        if a is sentinel or b is sentinel or a!=b:return False
    return True


def json_chunks(value,level=0,*,allow_nan=True):
    """Exact original sort_keys=True/indent=2 formatting, including nested disk views."""
    if isinstance(value,Mapping):
        if not value:yield '{}';return
        yield '{'
        items=value.sorted_items()if isinstance(value,DiskMap)else sorted(value.items())
        for i,(key,item)in enumerate(items):
            require(type(key)is str,'report JSON object keys must be exact strings')
            yield (','if i else'')+'\n'+'  '*(level+1)
            yield json.dumps(key);yield ': '
            yield from json_chunks(item,level+1,allow_nan=allow_nan)
        yield '\n'+'  '*level+'}'
    elif isinstance(value,(list,tuple,DiskSequence,StreamValues)):
        if not len(value):yield '[]';return
        yield '['
        for i,item in enumerate(value):
            yield (','if i else'')+'\n'+'  '*(level+1)
            yield from json_chunks(item,level+1,allow_nan=allow_nan)
        yield '\n'+'  '*level+']'
    else:
        yield json.dumps(value,sort_keys=True,indent=2,allow_nan=allow_nan)


def stream_json_pin(value,*,allow_nan=True):
    length=0;first=hashlib.sha256()
    for text in json_chunks(value,allow_nan=allow_nan):
        raw=text.encode();length+=len(raw);first.update(raw)
    length+=1;first.update(b'\n');second=hashlib.sha256()
    git=hashlib.sha1(b'blob '+str(length).encode()+b'\0');count=0
    for text in json_chunks(value,allow_nan=allow_nan):
        raw=text.encode();count+=len(raw);second.update(raw);git.update(raw)
    count+=1;second.update(b'\n');git.update(b'\n')
    require(count==length and second.digest()==first.digest(),'streamed ordered JSON metadata changed between passes')
    return {'bytes':length,'sha256':second.hexdigest(),'git_blob':git.hexdigest()}


def stream_file_pin(path):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);before=seven(s)
        require(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and before==seven(path.lstat()),'ordinary held/named ledger file required')
        length=0;sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(s.st_size).encode()+b'\0')
        while True:
            raw=os.read(fd,1048576)
            if not raw:break
            length+=len(raw);sha.update(raw);git.update(raw)
        require(length==s.st_size and before==seven(os.fstat(fd))==seven(path.lstat()),'complete ledger output changed around independent stream read')
    finally:os.close(fd)
    return {'path':str(path),'pin':{'bytes':length,'sha256':sha.hexdigest(),'git_blob':git.hexdigest(),
        'mode':'100755'if s.st_mode&0o111 else'100644'},'stat':before}


def publish(path,value):
    # Same JSONEncoder options, ordering, indentation and trailing LF as R1.
    # Count the exact encoding before creation so the Git header is known.
    expected_bytes=0;expected_sha=hashlib.sha256()
    for text in json_chunks(value):
        chunk=text.encode();expected_bytes+=len(chunk);expected_sha.update(chunk)
    expected_bytes+=1;expected_sha.update(b'\n')
    written_bytes=0;written_sha=hashlib.sha256()
    written_git=hashlib.sha1(b'blob '+str(expected_bytes).encode()+b'\0')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
    with os.fdopen(fd,'wb')as stream:
        for text in json_chunks(value):
            chunk=text.encode();stream.write(chunk);written_bytes+=len(chunk)
            written_sha.update(chunk);written_git.update(chunk)
        stream.write(b'\n');written_bytes+=1;written_sha.update(b'\n');written_git.update(b'\n')
    require(written_bytes==expected_bytes and written_sha.digest()==expected_sha.digest(),
        'reader JSON encoding changed between exact streamed passes')
    # Independent held/named complete readback; no complete JSON string/bytes copy.
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=seven(os.fstat(fd))
        require(stat.S_ISREG(before['st_mode'])and before['st_nlink']==1
            and before==seven(Path(path).lstat())and before['st_size']==expected_bytes,
            'reader streamed output physical identity differs')
        actual_bytes=0;actual_sha=hashlib.sha256()
        actual_git=hashlib.sha1(b'blob '+str(expected_bytes).encode()+b'\0')
        while True:
            chunk=os.read(fd,1048576)
            if not chunk:break
            actual_bytes+=len(chunk);actual_sha.update(chunk);actual_git.update(chunk)
        require(actual_bytes==written_bytes and actual_sha.digest()==written_sha.digest()
            and actual_git.digest()==written_git.digest()
            and before==seven(os.fstat(fd))==seven(Path(path).lstat()),
            'reader independent streamed full-byte double-hash verification failed')
    finally:os.close(fd)


def owner_readback(directory,command,stage,source_map,code):
 req,_,reqraw=jsread(directory/'OWNER.json.request.json','owner-request');raw,_,rawbytes=jsread(directory/'OWNER.json','owner-raw');returned,_,_=jsread(directory/'OWNER-RETURNED.json','owner-returned')
 require(returned=={**raw,'supervisor_returncode':code,'receipt_sha256':hashlib.sha256(rawbytes).hexdigest()}and stage['owner_returned']==returned,'returned owner not exact raw plus two fields')
 require(req['implementation_sha256']==raw['implementation_sha256']==source_map['tools/hia_selfhost_process_owner.py']['sha256']and req['qualification_seconds']==raw['qualification_seconds']==command['qualification_seconds']==180 and req['cleanup_seconds']==raw['cleanup_seconds']==command['cleanup_seconds']==3,'owner implementation/limits differ')
 require(req['deadline_ns']-req['started_ns']==180_000_000_000 and req['command']==command['command']and req['cwd']==command['cwd']and req['env']==command['environment']==command['supervisor_environment'],'owner argv/environment/deadline differs')
 require(req['receipt_path']==str(directory/'OWNER.json')and req['stdout_path']==str(directory/'stdout.raw')and req['stderr_path']==str(directory/'stderr.raw')and raw['request_sha256']==hashlib.sha256(reqraw).hexdigest(),'owner raw request binding differs')
 require(raw['returncode']==code and raw['qualification_started']is True and raw['timed_out']is False and raw['exit_observed_before_deadline']is True and raw['event_overflow']is False and raw['interrupted_signals']==[]and raw['subreaper_enabled']is True and raw['status']==('OWNED_PROCESS_COMPLETED'if code==0 else'QUALIFICATION_FAILED'),'owner actual termination differs')
 c=raw['cleanup'];require(c['attempted']is True and c['complete']is True and c['leader_reaped']is True and c['observed_echild']is True and c['deadline_exceeded']is False and c['errors']==[]and c['remaining_direct_children']==[]and 0<=c['elapsed_ns']<=3_000_000_000,'owner cleanup incomplete')
 starts=[e for e in raw['events']if e['kind']=='qualification_started'];exits=[e for e in raw['events']if e['kind']=='qualification_exit_observed'];reaped=[e for e in raw['events']if e['kind']=='owned_child_reaped'and e['pid']==raw['qualification_pid']]
 require(len(starts)==len(exits)==len(reaped)==1 and starts[0]['pid']==exits[0]['pid']==raw['qualification_pid']and req['started_ns']<=starts[0]['monotonic_ns']<=exits[0]['monotonic_ns']<=req['deadline_ns']and reaped[0]['returncode']==code,'owner actual start/exit/reap differs')
 return {'directory':str(directory),'returncode':code,'status':raw['status'],'observed_ECHILD':True,'deadline_interval_ns':req['deadline_ns']-req['started_ns'],'raw_plus_exact_two_fields':True,'cleanup':c}


def physical_pin(raw,mode='100644'):
    return pin(raw,mode)


def observed_read(path,role,*,expected=None,expected_stat=None,maximum=None):
    path=Path(path)
    require(path.is_absolute()and '..'not in path.parts,'absolute observation path required')
    if maximum is None:maximum=expected['bytes']if expected is not None else 16<<20
    require(0<=path.lstat().st_size<=maximum,'original bounded observation extent differs')
    raw=read(path,expected,expected_stat);row=SEEN[str(path)]
    OBSERVED_READS.append({'role':role,**row})
    return raw,row


def observed_fixed(row,role):
    require(type(row)is dict and set(row)=={'path','pin','stat'},'complete observation descriptor required')
    return observed_read(row['path'],role,expected=row['pin'],expected_stat=row['stat'])[0]


def jsread(path,role,**kwargs):
    raw,row=observed_read(path,role,**kwargs)
    return decode(raw),row,raw


def environment(bound):
    return {'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':bound['attempt'],
        'TMPDIR':str(Path(bound['attempt'])/'tmp'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC',
        'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','LD_LIBRARY_PATH':bound['runtime']['library_directory']}


def runtime_authority(plan):
    value=decode(fixed(plan['runtime_map']));root=Path(value['root']);before=metadata(root)
    rows=value['files'];names=[row['path']for row in rows]
    require(len(rows)==len(set(names))==2496
        and {n for n,s in before.items()if stat.S_ISREG(s['st_mode'])}==set(names)
        and {n for n,s in before.items()if stat.S_ISDIR(s['st_mode'])}=={'.',*value['new_directories']},
        'complete runtime file/directory sets differ')
    inodes=set()
    for row in rows:
        s=dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),row['new_file_seven_stat']))
        require(stat.S_IMODE(s['st_mode'])==row['mode'],'full runtime POSIX mode differs')
        read(root/row['path'],{**row['pin'],'mode':'100755'if row['mode']&0o111 else'100644'},s)
        inode=(s['st_dev'],s['st_ino']);require(inode not in inodes,'runtime alias');inodes.add(inode)
    require(metadata(root)==before,'runtime complete pathset/seven stats changed')
    for role,row in plan['expected_runtime'].items():
        fixed(row);context=plan['runtime'][role];s=row['stat'];p=row['pin']
        require(context=={'path':row['path'],'bytes':p['bytes'],'sha256':p['sha256'],
            'mode':stat.S_IMODE(s['st_mode']),'device':s['st_dev'],'inode':s['st_ino'],
            'mtime_ns':s['st_mtime_ns'],'ctime_ns':s['st_ctime_ns']},'actual runtime context binding differs')
    require(plan['runtime']['version']==[3,14,4]
        and plan['runtime']['launch_executable']==plan['expected_runtime']['executable']['path']
        and plan['runtime']['library_directory']==str(Path(plan['expected_runtime']['library']['path']).parent),
        'fixed actual runtime launch differs')
    return {'files':2496,'all_bytes_read':True,'map':plan['runtime_map']['pin']},before,inodes


def complete_source(value):
    root=Path(value['root']);expected=decode(checked(value['map']))
    state=decode(checked(value['state']))
    require(metadata(root)==state and len(expected)==value['files'],
            'complete immutable source pathset/seven-stat binding differs')
    require(observer.snapshot(root)==expected and metadata(root)==state
            and observer.tree_digest(expected)==value['tree'],
            'complete immutable source bytes/modes/tree differ')
    return {'files':len(expected),'all_bytes_read':True,'map':value['map']['pin'],
            'state':value['state']['pin'],'tree':value['tree']}


def protected_source(plan):
    value=plan['protected_source'];root=Path(value['root'])
    original=decode(checked(value['map']));state=decode(checked(value['state']))
    require(len(original)==3180 and metadata(root)==state,'protected R8 source state differs')
    expected={name:{'bytes':row['identity']['bytes'],'mode':row['identity']['git_mode'],
        'git_blob':row['identity']['git_blob'],'sha256':row['identity']['sha256']}
        for name,row in original.items()}
    require(observer.snapshot(root)==expected and metadata(root)==state,
            'protected R8 complete source bytes/mode/stat changed')
    return {'files':3180,'all_bytes_read':True,'map':value['map']['pin']}


def control_guard(plan):
    for name, row in plan['controls'].items():
        checked(row)
    for row in plan['provenance'].values():
        checked(row)
    require(plan['compiler']['pin'] == B3_PIN and len(checked(plan['compiler'])) == 673413,
            'exact ordinary B3 required; no compiler substitution')
    require(plan['limits'] == LIMITS and plan['storage_floor'] == MINIMUM_FREE,
            'original limits changed')
    guard_directories(plan['scope_ancestors'])
    guard_directories(plan['author_ancestors'])


def runtime_files_guard(plan):
    value = decode(checked(plan['runtime_map']))
    root = Path(value['root'])
    wanted = {row['path']: row for row in value['files']}
    before = metadata(root)
    require({name for name, st in before.items() if stat.S_ISREG(st['st_mode'])} == set(wanted)
            and len(wanted) == 2496
            and {name for name, st in before.items() if stat.S_ISDIR(st['st_mode'])}
                == {'.', *value['new_directories']}, 'complete restored runtime pathset differs')
    for name, row in wanted.items():
        old = row['new_file_seven_stat']
        expected_stat = dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),old))
        wanted_pin = {**row['pin'], 'mode': '100755' if row['mode'] & 0o111 else '100644'}
        require(stat.S_IMODE(before[name]['st_mode']) == row['mode'], 'runtime file mode differs')
        checked({'path': str(root / name), 'pin': wanted_pin, 'stat': expected_stat})
    require(metadata(root) == before, 'restored runtime metadata changed during full read')
    return {'files': len(wanted), 'map': plan['runtime_map']['pin'], 'all_bytes_read': True}


def packaging_origins(plan):
    value = decode(checked(plan['packaging_inputs']))
    require(value['schema'] == 'hepta.hia.op8-isolated-packaging-inputs.v1'
            and value['status'] == 'AUTHORING_ONLY_NOT_COPIED_OR_EXECUTED'
            and value['destination'] == str(PACKAGING_ROOT)
            and value['site'] == str(PACKAGING_ROOT / 'site')
            and value['products_executed'] == 0, 'fixed packaging input contract required')
    checked(value['pip'])
    names = []
    for root in value['selected_roots']:
        require(metadata(Path(root['path'])) == root['state'], 'packaging origin pathset/stat changed')
        names.extend(root['name'] + '/' + name for name, info in sorted(root['state'].items())
                     if stat.S_ISREG(info['st_mode']))
    require([r['relative'] for r in value['files']] == names
            and len(names) == len(set(names)) == value['file_count'], 'complete packaging origins differ')
    for row in value['files']:
        require(checked(row['descriptor']) is not None
                and stat.S_IMODE(row['descriptor']['stat']['st_mode']) == row['mode'],
                'packaging origin bytes/mode changed')
    for root in value['selected_roots']:
        require(metadata(Path(root['path'])) == root['state'], 'packaging origin changed during capture')
    return value


def packaging_guard(plan):
    value = packaging_origins(plan)
    binding = decode(checked(plan['packaging_binding']))
    require(binding['status'] == 'PASS_ISOLATED_PACKAGING_DATA_ONLY'
            and binding['inputs'] == plan['packaging_inputs']
            and binding['products_executed'] == 0 and binding['source_copy_performed'] is False,
            'actual independent packaging data binding required')
    state = decode(checked(binding['state'])); rows = decode(checked(binding['map']))
    root = PACKAGING_ROOT / 'site'
    expected_directories = {'.'}
    for original_root in value['selected_roots']:
        expected_directories.update(original_root['name'] + ('/' + name if name != '.' else '')
            for name,info in original_root['state'].items() if stat.S_ISDIR(info['st_mode']))
    require(metadata(root) == state and [r['relative'] for r in rows] == [r['relative'] for r in value['files']],
            'complete new packaging pathset/stat differs')
    require({n for n,s in state.items() if stat.S_ISREG(s['st_mode'])} == {r['relative'] for r in rows}
            and {n for n,s in state.items() if stat.S_ISDIR(s['st_mode'])} == expected_directories,
            'packaging view has a missing or additional path')
    require(len({(r['descriptor']['stat']['st_dev'],r['descriptor']['stat']['st_ino']) for r in rows}) == len(rows),
            'every packaging target must have an independent inode')
    for original, current in zip(value['files'], rows):
        require(current['source'] == original['descriptor']
                and current['descriptor']['path'] == str(root / current['relative'])
                and current['descriptor']['pin'] == original['descriptor']['pin']
                and current['descriptor']['stat'] == state[current['relative']]
                and current['descriptor']['stat']['st_nlink'] == 1
                and (current['descriptor']['stat']['st_dev'],current['descriptor']['stat']['st_ino'])
                    != (original['descriptor']['stat']['st_dev'],original['descriptor']['stat']['st_ino'])
                and stat.S_IMODE(current['descriptor']['stat']['st_mode']) == original['mode'],
                'packaging data must be exact independent inodes')
        require(checked(current['descriptor']) == checked(original['descriptor']), 'packaging full bytes differ')
    require(metadata(root) == state, 'new packaging data changed during full read')
    guard_directories(binding['site_ancestors'])
    return {'files':len(rows),'inputs':plan['packaging_inputs']['pin'],
            'map':binding['map']['pin'],'state':binding['state']['pin'],'every_byte_read':True}


def capture(path, *, maximum=16 << 20):
    return observed_read(path, 'fresh-static-descriptor', maximum=maximum)[1]


class IndependentObserver:
    """Only independent stdlib byte reads; no import of the product observer."""
    def tree_digest(self, flat):
        return tree(flat)
    def snapshot(self, root):
        before = metadata(root)
        result = {}
        inodes = set()
        for name, state in before.items():
            if not stat.S_ISREG(state['st_mode']):
                continue
            key = (state['st_dev'], state['st_ino'])
            require(key not in inodes, 'source path aliases another inode')
            inodes.add(key)
            path = Path(root) / name
            read(path, expected_stat=state)
            result[name] = SEEN[str(path)]['pin']
        require(metadata(root) == before, 'source snapshot changed around complete reads')
        return result


def fresh_stream_pin(path, role, expected_stat=None):
    global READS, BYTES
    row = stream_file_pin(path)
    if expected_stat is not None:
        require(row['stat'] == expected_stat, 'streamed original seven-stat authority differs')
    if row['path'] in SEEN:
        require(SEEN[row['path']]['stat'] == row['stat'], 'streamed repeated original changed')
    SEEN[row['path']] = row
    READS += 1
    BYTES += row['pin']['bytes']
    OBSERVED_READS.append({'role':role, **row})
    return row


def fresh_json_lines(path, role):
    """One complete held/named journal read, bounded only per original 16 MiB line."""
    global READS, BYTES
    path = Path(path)
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info = os.fstat(fd); before = seven(info)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and before == seven(path.lstat()), 'ordinary complete journal required')
        sha = hashlib.sha256(); git = hashlib.sha1(b'blob '+str(info.st_size).encode()+b'\0')
        count = 0
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            while True:
                line = stream.readline((16 << 20)+1)
                if not line:
                    break
                require(len(line) <= 16 << 20 and line.endswith(b'\n'), 'partial or oversized original journal line')
                sha.update(line); git.update(line); count += len(line)
                yield decode(line)
        require(count == info.st_size and before == seven(os.fstat(fd)) == seven(path.lstat()),
                'complete journal changed around bounded full read')
    finally:
        os.close(fd)
    row = {'path':str(path),'pin':{'bytes':count,'sha256':sha.hexdigest(),'git_blob':git.hexdigest(),
            'mode':'100755' if before['st_mode'] & 0o111 else '100644'},'stat':before}
    if str(path) in SEEN:
        require(SEEN[str(path)]['stat'] == before, 'repeated journal stat changed')
    SEEN[str(path)] = row; READS += 1; BYTES += count
    OBSERVED_READS.append({'role':role, **row})


def evidence_metadata(root):
    """Typed evidence-only metadata; original source/runtime metadata stays unchanged."""
    global LINK_TARGET_READS,LINK_TARGET_BYTES
    root=Path(root)
    require(root in (SCOPE,SCOPE/'attempt-r1',OUTER), 'typed metadata is confined to the actual evidence roots')
    result=LEDGER.mapping('typed-original-evidence-state');result['.']=seven(root.lstat())
    require(stat.S_ISDIR(result['.']['st_mode']),'ordinary actual evidence root required')
    def walk(path,prefix):
        global LINK_TARGET_READS,LINK_TARGET_BYTES
        for entry in sorted(os.scandir(path),key=lambda row:row.name):
            name=prefix+entry.name;target=Path(entry.path);s=entry.stat(follow_symlinks=False);row=seven(s)
            if stat.S_ISLNK(s.st_mode):
                first=os.readlink(os.fsencode(target));second=os.readlink(os.fsencode(target))
                LINK_TARGET_READS+=2;LINK_TARGET_BYTES+=len(first)+len(second)
                require(first==second and seven(target.lstat())==row,'symlink identity/target changed during no-follow reads')
                row['link_target']={'base64':base64.b64encode(first).decode(),
                    'pin':pin(first,'120000'),'followed':False}
            elif stat.S_ISREG(s.st_mode):
                require(s.st_nlink==1,'unexpected multi-link evidence regular file; original regular read guard is not weakened')
            elif not stat.S_ISDIR(s.st_mode):
                # Preserve its identity without ever opening a FIFO/socket/device payload.
                row['opaque_special']={'type':stat.S_IFMT(s.st_mode),'device':s.st_rdev,'payload_read':False}
            result[name]=row
            if stat.S_ISDIR(s.st_mode):walk(target,name+'/')
    walk(root,'')
    return result


def evidence_link_descriptor(path,expected):
    global LINK_TARGET_READS,LINK_TARGET_BYTES
    path=Path(path);before=seven(path.lstat())
    require(stat.S_ISLNK(before['st_mode']) and before=={k:expected[k]for k in FIELDS},
        'special evidence is not the admitted original symlink')
    raw=os.readlink(os.fsencode(path));again=os.readlink(os.fsencode(path))
    LINK_TARGET_READS+=2;LINK_TARGET_BYTES+=len(raw)+len(again)
    require(raw==again and before==seven(path.lstat()) and expected['link_target']=={
        'base64':base64.b64encode(raw).decode(),'pin':pin(raw,'120000'),'followed':False},
        'complete original symlink target/stat changed')
    return {'path':str(path),'pin':pin(raw,'120000'),'stat':before,'entry_type':'symlink',
        'link_target_base64':base64.b64encode(raw).decode(),'target_followed':False,
        'regular_payload_read':False,'complete_link_target_read':True}


def source_guard(request, observer):
    expected = decode(fixed(request['source_map']))
    state = decode(fixed(request['source_state']))
    root = Path(request['source'])
    require(root.is_absolute() and '..' not in root.parts and len(expected) == 3225,
            'complete 3225 source scope required')
    before = metadata(root)
    require(before == state, 'actual complete source identity differs before read')
    # Reuse the exact original reader. It reads every regular source file;
    # this call never replaces contents by a cached digest or receipt.
    actual = observer.snapshot(root)
    require(actual == expected and metadata(root) == before,
            'source bytes/modes/pathset/seven stats changed')
    return {'files': len(actual), 'source_map': request['source_map']['pin'],
            'source_state': request['source_state']['pin'], 'all_bytes_read': True}


def all_guards(plan, runtime_guard=None):
    control_guard(plan)
    value = source_guard(plan, observer)
    expected = decode(checked(plan['source_map']))
    require(observer.tree_digest(expected) == plan['source_tree'], 'complete new source tree differs')
    runtime_files_guard(plan)
    if runtime_guard is not None:
        runtime_guard(plan['runtime'])
    return value


def matrix_for(plan):
    value = decode(checked(plan['controls']['QUALIFICATION-MATRIX.json']))
    source = decode(checked(plan['source_group_matrix']))
    core = decode(checked(plan['original_core_matrix']))
    old_cli = next(row for row in core['groups'] if row['label'] == 'original-cli43')
    require(value['schema'] == SCHEMA + '.matrix' and value['owner_count'] == 18
            and value['method_invocations'] == 85 and value['build_count'] == 9
            and value['limits'] == LIMITS and value['selector_limits'] == SELECTOR_LIMITS
            and value['vm_keys'] == list(VM_KEYS), 'all explicit groups and original limits required')
    groups = value['groups']
    labels = ['source8-successor','source11-successor','selection-source6',
              'build-report-six','build-inspect','build-patch','build-selection'] + [
              'selection-native-%02d' % n for n in range(1,10)] + ['selection-vm8','original-cli43']
    require([row['label'] for row in groups] == labels and len(set(labels)) == len(groups) == 18
            and sum(len(row['ids']) for row in groups) == 85, 'complete ordered owner selection differs')
    for group, original in zip(groups[:2], source['groups']):
        require(group['ids'] == [row['successor_id'] for row in original['methods']],
                'explicit Source-domain successor IDs changed')
    require(groups[-1]['ids'] == old_cli['ids'] and groups[-1]['flags'] == old_cli['flags'] == ['-B'],
            'all original CLI43 IDs or -B environment contract changed')
    require(all(row['flags'] == ['-I','-B'] for row in groups[:-1])
            and [len(row['ids']) for row in groups] == [8,11,6,0,0,0,0]+[1]*9+[8,43],
            'exact cohort cardinalities or interpreter flags changed')
    return value


def declared_ids(raw, relative):
    module = relative[:-3].replace('/','.')
    return [module+'.'+cls.name+'.'+method.name for cls in ast.parse(raw).body
            if isinstance(cls, ast.ClassDef) for method in cls.body
            if isinstance(method,ast.FunctionDef) and method.name.startswith('test_')]


def cohort_guard(plan):
    matrix = matrix_for(plan)
    required = {
        'tests/test_hia_cli_owner_bundle_patch_cli_source.py':matrix['groups'][0]['ids'],
        'tests/test_hia_cli_owner_bundle_patch_result_source.py':matrix['groups'][1]['ids'],
        'tests/test_hia_cli_owner_bundle_source.py':matrix['groups'][2]['ids'],
        'tests/test_hia_cli_owner_bundle_native.py':[row['ids'][0] for row in matrix['groups'][7:16]],
        'tests/test_hia_cli_owner_bundle_vm.py':matrix['groups'][16]['ids']}
    current = decode(checked(plan['source_map']))
    state = decode(checked(plan['source_state']))
    for name, ids in required.items():
        raw = checked({'path':str(Path(plan['source'])/name),'pin':current[name],'stat':state[name]})
        require(declared_ids(raw,name) == ids, 'full current declared IDs/order differ: '+name)
    retained = decode(checked(capture(Path(plan['source'])/'tests/fixtures/hia_cli_routing_retained.json')))
    require(retained['original_ids'] == matrix['groups'][-1]['ids'], 'original retained CLI43 fixture differs')
    return matrix


def fixed_shape(plan):
    require(plan['schema'] == SCHEMA and plan['state'] in (
                'AUTHORING_ONLY_AWAITING_ROOT_AUTHORIZATION','BOUND_AWAITING_ROOT_AUTHORIZATION')
            and plan['scope'] == str(FIXED_SCOPE) and plan['attempt'] == str(FIXED_SCOPE/'attempt-r1')
            and plan['source'] == ACTUAL_SOURCE and plan['source_files'] == 3225
            and plan['source_copy_performed'] is False and plan['limits'] == LIMITS
            and plan['selector_limits'] == SELECTOR_LIMITS and plan['storage_floor'] == MINIMUM_FREE
            and plan['future_image_pins'] is None and plan['future_native_vm_pins'] is None,
            'explicit new current source and unchanged product bounds required')
    require(set(plan['component_sources']) == set(ROLES)
            and plan['component_sources']['selection'] == GENERATED[0], 'all nine actual component sources required')
    matrix_for(plan)


def selector_generation_guard(plan):
    author = decode(checked(plan['selector_generation_plan']))
    result = decode(checked(plan['selector_generation_result']))
    terminal = decode(checked(plan['selector_generation_terminal']))
    bound = decode(checked(plan['selector_generation_bound']))
    require(result['status'] == 'PASS_GENERATION_ONLY_TWO_RUNS_AND_ORIGINAL_CHECK'
            and result['actual_owner_launch_attempts'] == 3 and result['copy_rows'] == 3222
            and all(result[key] == 0 for key in ('tests_run','compilations','native_calls','vm_calls'))
            and result['immutable_before'] == result['immutable_after']
            and [row['label'] for row in result['stages']] == author['stages']
            and all(row['status'] == 'PASS' for row in result['stages']),
            'actual complete selector generation is required')
    final = result['final_source']
    require(final['source'] == plan['source'] and final['files'] == plan['source_files'] == 3225
            and final['tree'] == plan['source_tree'] and final['map'] == plan['source_map']
            and final['state'] == plan['source_state'] and final['changed_existing_bytes'] == []
            and final['added_paths'] == final['installed_paths'] == list(GENERATED),
            'actual generated current source identity differs')
    require(terminal['status'] == 'PASS_COMPLETE_ORDINARY_SELECTOR_GENERATION_READBACK'
            and terminal['source_files'] == 3225 and terminal['actual_owners'] == 3
            and terminal['source_tree'] == plan['source_tree']
            and terminal['actual_generation_result'] == plan['selector_generation_result']
            and terminal['all24host_bindings_current'] is True
            and terminal['all_current_pathsets_and_seven_stats_equal'] is True,
            'independent complete actual generation readback required')
    for name in ('selector_generation_state','selector_outer_state'):
        expected = decode(checked(plan[name]))
        root = GEN_SCOPE if name == 'selector_generation_state' else GEN_OUTER
        require(metadata(root) == expected, 'complete frozen generation pathset/stat changed')
    inventory = decode(checked(plan['selector_generation_inventory']))
    require(len(inventory) == terminal['raw_files']
            and sum(row['pin']['bytes'] for row in inventory) == terminal['raw_bytes'],
            'complete independent generation evidence inventory differs')
    seen = set()
    for row in inventory:
        require(row['path'] not in seen, 'duplicate generation inventory path');seen.add(row['path']);checked(row)
    for root, key in ((GEN_SCOPE,'selector_generation_state'),(GEN_OUTER,'selector_outer_state')):
        state = decode(checked(plan[key]))
        expected = {str(root/name) for name,item in state.items() if stat.S_ISREG(item['st_mode'])
                    and not(root == GEN_SCOPE and name.startswith('source/'))}
        require(expected <= seen and metadata(root) == state, 'generation evidence pathset differs after complete reads')
    domain = decode(checked(plan['source_domain']))
    actual_domain = decode(checked(capture(Path(author['attempt'])/'ACTUAL-SOURCE-DOMAIN.json')))
    require(actual_domain == result['actual_authority_maps']
            and actual_domain['source_domain'] == plan['source_domain']
            and actual_domain['source_map'] == plan['source_map']
            and bound['runtime'] == plan['runtime'] == author['previous_runtime_context']
            and actual_domain['original_r5_map'] == domain['r5_source_map']
            and actual_domain['original_patch14_map'] == domain['patch14_map'],
            'generated source-domain or runtime authority differs')
    return {'files':len(inventory),'bytes':sum(row['pin']['bytes'] for row in inventory),
            'actual_result':plan['selector_generation_result']['pin'],
            'independent_terminal':plan['selector_generation_terminal']['pin'],'every_reference_fresh':True}


def immutable_guard(plan):
    fixed_shape(plan);control_guard(plan)
    for row in plan['expected_runtime'].values():checked(row)
    for row in plan['source_authorities'].values():checked(row)
    checked(plan['source_domain']);checked(plan['source_projection']);checked(plan['source_group_matrix'])
    base = complete_source(plan['base_source']);mother = complete_source(plan['mother_source'])
    prior = complete_source(plan['prior_base']);protected = protected_source(plan)
    runtime = runtime_files_guard(plan);generated = selector_generation_guard(plan)
    packaging = packaging_guard(plan);cohort_guard(plan)
    return {'base3210':base,'mother3211':mother,'prior3210':prior,'protected3180':protected,
            'runtime2496':runtime,'generation':generated,'packaging':packaging}


def bound_guard(plan, runtime_guard=None):
    require(plan['state'] == 'BOUND_AWAITING_ROOT_AUTHORIZATION','actual qualification binding required')
    immutable = immutable_guard(plan)
    guard_directories(plan['source_ancestors'])
    current = all_guards(plan,runtime_guard)
    return {'immutable':immutable,'candidate3225':current}


def normalized(row):
    return {**row,'posix_mode':stat.S_IMODE(row['stat']['st_mode'])}


def stage_environment(plan, row, directory, report):
    env = environment(plan)
    if row['label'] == 'original-cli43':
        require(report is not None,'actual report-v2 manifest required by original CLI43 fixture')
        packaging = decode(checked(plan['packaging_inputs']))
        env.update(PYTHONPATH=packaging['pythonpath'],
            HEPTA_HIA_TEST_PACKAGING_PYTHON=plan['runtime']['launch_executable'],
            PIP_NO_CACHE_DIR='1',PIP_DISABLE_PIP_VERSION_CHECK='1',
            HEPTA_HIA_CLI_VERIFIED_REPORT_DEVELOPMENT_MANIFEST=report['path'],
            HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST=report['path'],
            HEPTA_HIA_CLI_VERIFIED_REPORT_EVIDENCE=str(directory/'report-evidence'),
            HEPTA_HIA_CLI_FIXTURE_EVIDENCE=str(directory/'cli-evidence'))
    return env


def _require(value, message):
    if not value:
        raise AssertionError(message)


def _seven(info):
    return {key: getattr(info, key) for key in FIELDS}


def _pairs(items):
    value = {}
    for key, item in items:
        _require(type(key) is str and key not in value,
                 'duplicate/nonstring JSON key')
        value[key] = item
    return value


def _decode(raw):
    return json.loads(raw, object_pairs_hook=_pairs)


class _Reader:
    def __init__(self, path, expected=None):
        self.path = Path(path)
        _require(self.path.is_absolute() and '..' not in self.path.parts,
                 'absolute fixed path required')
        if expected is not None:
            _require(type(expected) is dict and set(expected) == {'path', 'pin', 'stat'}
                     and expected['path'] == str(self.path)
                     and set(expected['stat']) == set(FIELDS),
                     'complete expected streaming binding required')
        self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC |
                          os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(self.fd)
            self.before = _seven(before)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and before.st_size >= 0
                     and self.before == _seven(self.path.lstat()),
                     'unique held/named regular input required')
            if expected is not None:
                _require(self.before == expected['stat']
                         and before.st_size == expected['pin']['bytes'],
                         'expected streaming identity changed before read')
            self.expected = expected
            self.length = before.st_size
            self.mode = '100755' if before.st_mode & 0o111 else '100644'
            self.sha = hashlib.sha256()
            self.git = hashlib.sha1(b'blob ' + str(self.length).encode() + b'\0')
            self.total = 0
            self.buffer = b''
            self.position = 0
            self.eof = False
        except BaseException:
            os.close(self.fd)
            raise

    def _fill(self):
        if self.position < len(self.buffer):
            return True
        if self.eof:
            return False
        self.buffer = os.read(self.fd, CHUNK_BYTES)
        self.position = 0
        if not self.buffer:
            self.eof = True
            return False
        self.total += len(self.buffer)
        _require(self.total <= self.length, 'streaming input grew during read')
        self.sha.update(self.buffer)
        self.git.update(self.buffer)
        return True

    def peek(self):
        return self.buffer[self.position] if self._fill() else None

    def take(self):
        value = self.peek()
        _require(value is not None, 'truncated streaming JSON')
        self.position += 1
        return value

    def white(self):
        while self.peek() in (9, 10, 13, 32):
            self.position += 1

    def expect(self, expected):
        self.white()
        _require(self.take() == expected, 'unexpected streaming JSON delimiter')

    def value(self):
        self.white()
        first = self.take()
        raw = bytearray((first,))
        stack = [first] if first in (91, 123) else []
        quoted = first == 34
        string_root = quoted
        escaped = False
        if stack or quoted:
            while stack or quoted:
                token = self.take()
                raw.append(token)
                _require(len(raw) <= VALUE_BYTES, 'one JSON value exceeds original 16 MiB bound')
                if quoted:
                    if escaped:
                        escaped = False
                    elif token == 92:
                        escaped = True
                    elif token == 34:
                        quoted = False
                        if string_root:
                            break
                elif token == 34:
                    quoted = True
                elif token in (91, 123):
                    stack.append(token)
                elif token in (93, 125):
                    _require(stack and stack[-1] == (91 if token == 93 else 123),
                             'mismatched streaming JSON delimiter')
                    stack.pop()
        else:
            while self.peek() not in (None, 9, 10, 13, 32, 44, 93, 125):
                raw.append(self.take())
                _require(len(raw) <= VALUE_BYTES, 'one JSON value exceeds original 16 MiB bound')
        return _decode(raw)

    def finish(self):
        self.white()
        _require(self.peek() is None and self.total == self.length,
                 'trailing data or incomplete streaming read')
        _require(_seven(os.fstat(self.fd)) == self.before == _seven(self.path.lstat()),
                 'streaming input changed during full read')
        row = {'path': str(self.path), 'pin': {'bytes': self.length, 'mode': self.mode,
            'sha256': self.sha.hexdigest(), 'git_blob': self.git.hexdigest()},
            'stat': self.before}
        if self.expected is not None:
            _require(row == self.expected, 'complete streaming bytes or mode differ')
        return row

    def close(self):
        os.close(self.fd)


def walking(root):
    root=Path(root);initial=seven(root.lstat())
    require(stat.S_ISDIR(initial['st_mode']),'Native evidence root must be an actual directory')
    yield '.',initial
    def visit(directory,prefix):
        for entry in sorted(os.scandir(directory),key=lambda item:item.name):
            info=entry.stat(follow_symlinks=False);name=prefix+entry.name
            require(stat.S_ISDIR(info.st_mode) or(stat.S_ISREG(info.st_mode) and info.st_nlink==1),
                    'unexpected Native predecessor member type/link count')
            yield name,seven(info)
            if stat.S_ISDIR(info.st_mode):yield from visit(entry.path,name+'/')
    yield from visit(root,'')


def iterate_shards(bindings):
    for binding in bindings:
        require(binding['pin']['bytes'] <= SHARD_BYTES,'metadata shard cap changed')
        value=decode(checked(binding));require(type(value) is list,'complete ordered shard must be a list')
        yield from value


def installed_wheel_readback(bound,stage_result):
    base=Path(bound['attempt'])/'18-original-cli43/cli-evidence/CliNativeTests/installed-control'
    if not base.exists():
        require(not any(r['label']=='original-cli43' and r['status']=='PASS' for r in stage_result['stages']),
                'successful original43 lacks its actual installed fixture')
        return {'present':False,'not_inferred':True}
    report,descriptor,_=jsread(base/'report.json','actual-installed-cli-control-report')
    installed,execution_descriptor,execution_raw=jsread(base/'installed-execution.json','actual-isolated-installed-execution')
    processes=decode(read(base/'processes.json'))
    require(report['schema']=='hepta.hia.cli-installed-control.v1'
        and report['status']=='PASS_INSTALLED_NATIVE_CLI_CONTROL' and report['scope']=='EXPLICIT_DEVELOPMENT_ONLY'
        and report['installed_execution']==installed and report['processes']==processes
        and report['original_sources_preserved'] is True and report['packaging_uses_declared_resources_only'] is True
        and report['whole_native_delivery_qualified'] is False
        and report['source_sha256_before']==report['source_sha256_after']==installed['source_sha256'],
        'actual installed control report differs')
    wheel=Path(report['wheel']['path']);require(wheel.parent==base/'wheels','wheel outside actual fixture')
    wheel_raw,wheel_descriptor=observed_read(wheel,'actual-built-wheel',expected=
        {k:report['wheel'][k] for k in ('bytes','sha256')})
    require([p['label'] for p in processes]==['wheel-build','wheel-install','installed-execution']
        and all(p['returncode']==0 for p in processes), 'actual wheel/install/isolated process result differs')
    python=bound['runtime']['launch_executable']
    commands=[
        [python,'-B','-m','pip','wheel','--no-cache-dir','--no-deps','--no-index','--no-build-isolation',
         '--wheel-dir',str(base/'wheels'),str(base/'source')],
        [python,'-B','-m','pip','install','--no-cache-dir','--no-deps','--no-index',
         '--target',str(base/'installed'),str(wheel)],
        [python,'-I','-S','-B',str(base/'installed-control.py'),str(base/'installed'),
         str(base/'bundle/verified-report-bundle.json'),str(base/'input.hia')]]
    process_evidence=[]
    for row,command in zip(processes,commands):
        require(row['argv']==command, 'actual installed-process argv differs')
        logs={}
        for channel in ('stdout','stderr'):
            raw,desc=observed_read(base/(row['label']+'.'+channel),'installed-process-'+row['label']+'-'+channel)
            require(hashlib.sha256(raw).hexdigest()==row[channel+'_sha256'],'complete installed-process log differs')
            logs[channel]=desc
            if row['label']=='installed-execution' and channel=='stdout':
                require(decode(raw)==installed,'actual isolated process stdout is not the recorded result')
        process_evidence.append({'process':row,'logs':logs})
    require(installed['schema']=='hepta.hia.cli-installed-execution.v1'
        and installed['status']=='PASS_INSTALLED_NATIVE_CLI_CONTROL'
        and installed['console_entry_point']=='hepta.cli:hia_main'
        and installed['empty_PATH'] is True and installed['isolated_without_site'] is True
        and installed['forbidden_entries']=={'retained_cli':[],'retained_parser':[],'tools':[]}
        and installed['sources_and_bundle_restored'] is True
        and installed['whole_native_delivery_qualified'] is False
        and installed['python']==bound['runtime']['python'], 'actual installed process scope differs')
    labels=['changed-installed-control','missing-installed-control','changed-installed-format','missing-installed-format',
            'bundle-schema','bundle-child-traversal','bundle-child-hash','missing-selected-bundle','empty-selected-bundle']
    require([r['case'] for r in installed['refusals']]==labels
        and all(type(r['type']) is str and r['type'] and type(r['message']) is str for r in installed['refusals'])
        and len(installed['calls'])==8 and [r['code'] for r in installed['calls']]==[0,0,0,0,2,2,0,0]
        and set(installed['native_returns'])=={'control','format'}
        and all(values and all(type(n) is int for n in values) for values in installed['native_returns'].values()),
        'original installed positive/refusal observations incomplete')
    for name in ('control','format'):
        path=base/'installed/hepta/_data/examples/hia_bootstrap'/('cli_'+name+'.hepta')
        require(installed['installed_source_paths'][name]==str(path), 'installed resource path differs')
        source=observed_fixed(stage_result['components'][name]['source'],'actual-compiled-installed-resource-'+name)
        target,_=observed_read(path,'actual-installed-resource-'+name)
        require(source==target and hashlib.sha256(target).hexdigest()==installed['source_sha256'][name],
                'installed resources are not the actual compiled original source bytes')
    selected=stage_result['bundle'];require(selected is not None and report['original_manifest']==selected['path']
        and report['manifest']==str(base/'bundle/verified-report-bundle.json'),'installed bundle selection differs')
    actual_manifest=observed_fixed(selected,'actual-selected-bundle-for-installed-fixture')
    local_manifest,_=observed_read(Path(report['manifest']),'actual-installed-bundle')
    require(local_manifest==actual_manifest and hashlib.sha256(local_manifest).hexdigest()==installed['bundle_sha256'],
            'installed bundle was not restored to complete actual bytes')
    members=LEDGER.sequence('every-full-wheel-member');names=set();compared=0;record_exception=[]
    with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
        for member in archive.infolist():
            name=member.filename;path=Path(name);mode=member.external_attr>>16
            require(name not in names and name and not path.is_absolute() and '..' not in path.parts
                and '\\' not in name and not member.is_dir() and stat.S_ISREG(mode),
                'wheel contains a duplicate or unsafe/nonregular member')
            names.add(name)
            # ZipExtFile validates every member CRC on a complete read.
            data=archive.read(member)
            require(len(data)==member.file_size and zlib.crc32(data)&0xffffffff==member.CRC,
                    'complete wheel member length/CRC differs')
            target=base/'installed'/name
            current,current_descriptor=observed_read(target,'fresh-installed-wheel-member:'+name,
                                                    maximum=max(member.file_size,target.lstat().st_size))
            mutable_record=name.endswith('.dist-info/RECORD')
            if mutable_record:
                record_exception.append({'path':name,'wheel_pin':pin(data),'installed':current_descriptor,
                    'reason':'pip rewrites its installation RECORD; both complete originals are retained'})
            else:
                require(data==current,'installed package member bytes differ from the actual wheel')
                compared+=1
            members.append({'path':name,'zip_mode':mode,'crc32':member.CRC,'pin':pin(data),
                            'installed':current_descriptor,'installation_record_rewritten':mutable_record})
    require(len(record_exception)==1 and compared==len(names)-1 and any(n.startswith('hepta/')for n in names),
            'complete wheel/install comparison boundary differs')
    return {'present':True,'report':descriptor,'execution':execution_descriptor,'wheel':wheel_descriptor,
        'processes':process_evidence,'wheel_members':members,'member_count':len(members),
        'all_member_crc_verified':True,'exact_installed_members':compared,'record_exception':record_exception,
        'all_original_refusals':installed['refusals'],'all_original_calls':installed['calls'],
        'native_return_values':installed['native_returns'],'physical_frames_for_installed_calls_claimed':False,
        'whole_native_delivery_qualified':False,'new_processes_executed':0}


def tests_readback(directory, ids, child, stage_status):
    tests, descriptor, _ = jsread(directory/'TESTS.json', 'actual-ordinary-exact-tests')
    require(tests['declared_ids'] == tests['loaded_ids'] == tests['started_ids'] == tests['stopped_ids'] == ids
            and tests['events'] == [event for name in ids for event in (['start',name],['stop',name])]
            and tests['tests_run'] == len(ids), 'original ordered IDs/events are incomplete')
    for key in ('loader_errors','skipped','expected_failures','unexpected_successes'):
        require(tests[key] == [], 'incomplete original test suite: '+key)
    require(all(row['parent'] in ids and row['status'] in ('PASS','FAIL','ERROR')
                for row in tests['subtests']), 'subtest parent/status differs')
    actual = 'FAIL' if tests['failures'] or tests['errors'] or any(
        row['status'] != 'PASS' for row in tests['subtests']) else 'PASS'
    require(tests['status'] == actual, 'raw assertions and test status differ')
    if actual == 'PASS':
        require(child.get('tests') == tests, 'successful full test report differs')
    else:
        require(stage_status == 'FAIL' and type(child.get('error')) is str and child['error'],
                'failed ordinary child lacks its original error traceback')
        if 'tests' in child:
            require(child['tests'] == tests, 'failed child changed its raw test report')
    return {'raw':descriptor,'ids':ids,'events':len(tests['events']),'tests_run':tests['tests_run'],
            'subtests':tests['subtests'],'failures':tests['failures'],'errors':tests['errors'],'status':actual}


def stream_checked(row, role='complete-fresh-stream-reference'):
    require(type(row) is dict and set(row) <= {'path','pin','stat','posix_mode'}
            and {'path','pin','stat'} <= set(row), 'complete streaming descriptor required')
    actual = fresh_stream_pin(row['path'], role, row['stat'])
    require(actual['pin'] == row['pin'], 'complete fresh streamed bytes/mode differ')
    if 'posix_mode' in row:
        require(stat.S_IMODE(actual['stat']['st_mode']) == row['posix_mode'],
                'normalized descriptor POSIX mode differs')
    return actual


def strict_fixed(row, role):
    require(type(row) is dict and set(row) <= {'path','pin','stat','posix_mode'}
            and {'path','pin','stat'} <= set(row), 'complete fixed descriptor required')
    raw, actual = observed_read(row['path'], role, expected=row['pin'], expected_stat=row['stat'])
    if 'posix_mode' in row:
        require(stat.S_IMODE(actual['stat']['st_mode']) == row['posix_mode'],
                'normalized fixed-file mode differs')
    return raw


def register_stream_read(row, role):
    global READS,BYTES
    if row['path'] in SEEN:
        require(SEEN[row['path']]['stat'] == row['stat'], 'repeated parsed stream identity changed')
    SEEN[row['path']] = row
    READS += 1
    BYTES += row['pin']['bytes']
    OBSERVED_READS.append({'role':role, **row})
    return row


def full_buffer(directory, row, role='complete-physical-buffer'):
    global PHYSICAL_BUFFER_READS
    require(type(row) is dict and set(row) == {'bytes','mode','sha256','git_blob','file'}
            and type(row['bytes']) is int and 0 <= row['bytes'] <= CAPACITY
            and row['mode'] == '100644' and row['file'] == row['sha256']+'.zlib'
            and re.fullmatch(r'[0-9a-f]{64}\.zlib', row['file']) is not None,
            'all five original BufferStore fields and original capacity required')
    compressed, descriptor = observed_read(Path(directory)/row['file'], role)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, row['bytes']+1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
            and pin(raw,'100644') == {key:row[key] for key in ('bytes','mode','sha256','git_blob')},
            'complete physical buffer or strict single-zlib EOF differs')
    PHYSICAL_BUFFER_READS += 1
    return raw


def frame_shape(row, before, index, allowed):
    require(type(row) is dict and row['index'] == index and row['image_sha256'] in allowed
            and type(row['returned']) is bool and type(row['case']) is str,
            'physical frame identity or returned marker differs')
    required = FRAME_KEYS[:3] if before else FRAME_KEYS
    require(all(key in row for key in required), 'actual frame lacks required observed buffer fields')
    if before:
        require(row['returned'] is False and not any(key in row for key in FRAME_KEYS[3:]),
                'BEFORE contains invented after data or an observed return')
    elif row['returned']:
        require(type(row['result']) is int and 'machine_call_exception' not in row,
                'real returned frame lacks its exact integer result')
    else:
        require(type(row.get('machine_call_exception')) is dict
                and set(row['machine_call_exception']) == {'type','text'},
                'nonreturned frame lacks its actual exception record')


def stream_index_readback(path, after_paths, started_calls):
    binding = fresh_stream_pin(path, 'complete-index-first-fresh-stream')
    second = stream_checked(binding, 'complete-index-second-fresh-stream')
    reader = _Reader(path, second)
    try:
        reader.expect(123)
        keys, header, count = set(), {}, 0
        after_iterator = iter(after_paths)
        reader.white()
        if reader.peek() != 125:
            while True:
                key = reader.value()
                require(type(key) is str and key not in keys, 'duplicate/nonstring aggregate INDEX key')
                keys.add(key); reader.expect(58)
                if key == 'frames':
                    reader.expect(91); reader.white()
                    if reader.peek() != 93:
                        while True:
                            value = reader.value()
                            require(count < len(after_paths), 'aggregate INDEX has an extra frame')
                            actual_path = Path(next(after_iterator))
                            actual = decode(observed_read(actual_path,
                                'index-versus-fresh-actual-AFTER')[0])
                            require(value == actual, 'aggregate INDEX row differs from actual AFTER')
                            buffers = actual_path.parent.parent/'buffers'
                            for field in FRAME_KEYS:
                                full_buffer(buffers,value[field],'fresh-INDEX-buffer-reference')
                                full_buffer(buffers,actual[field],'fresh-comparison-AFTER-buffer-reference')
                            count += 1; reader.white()
                            if reader.peek() == 93:
                                break
                            reader.expect(44)
                    reader.expect(93)
                else:
                    header[key] = reader.value()
                reader.white()
                if reader.peek() == 125:
                    break
                reader.expect(44)
        reader.expect(125)
        actual = register_stream_read(reader.finish(), 'complete-index-third-parsed-stream')
        require(keys == {'schema','frames','started_calls','complete_calls','all_source_unchanged'}
                and header['schema'] == 'hepta.hia.inspect-full-machine-frames.v1'
                and header['started_calls'] == started_calls and header['complete_calls'] == count
                and count == len(after_paths), 'full INDEX schema/counts differ')
        unchanged = True
        for path in after_paths:
            row = decode(observed_read(path,'index-source-unchanged-fresh-AFTER')[0])
            unchanged = unchanged and row['source_unchanged']
        require(header['all_source_unchanged'] is unchanged, 'INDEX source-unchanged summary differs')
        return actual
    finally:
        reader.close()


def frames_readback(bound, stages):
    buffer_reads_at_start = PHYSICAL_BUFFER_READS
    summaries = LEDGER.sequence('all-current-native-stage-frame-summaries')
    journals = LEDGER.sequence('every-current-native-journal')
    rows = LEDGER.sequence('every-current-native-AFTER')
    totals = {'started_calls':0,'complete_calls':0,'returned_calls':0,'exception_calls':0,
              'buffer_reference_reads':0,'physical_objects':0,'orphan_objects':0,'unfinalized_journals':0}
    allowed = {item['image']['pin']['sha256'] for item in stages['components'].values()}
    for stage in stages['stages']:
        if stage['kind'] != 'native':
            continue
        directory = Path(stage['directory'])
        expected_journals = []
        stage_counts = {'started_calls':0,'complete_calls':0,'buffer_reference_reads':0}
        for frames in sorted(directory.rglob('frames')):
            require(stat.S_ISDIR(frames.lstat().st_mode), 'actual frames node is not an ordinary directory')
            journal = frames.parent
            names = []
            for item in sorted(frames.iterdir()):
                require(re.fullmatch(r'[0-9]{8}-(?:BEFORE|AFTER)\.json',item.name) is not None,
                        'unknown actual physical frame member')
                require(stat.S_ISREG(item.lstat().st_mode) and item.lstat().st_nlink == 1,
                        'physical frame must remain a unique regular original')
                names.append(item.name)
            before_indices = [int(name[:8]) for name in names if name.endswith('-BEFORE.json')]
            require(before_indices == list(range(len(before_indices))), 'actual entry order has a gap')
            after_paths = LEDGER.sequence('ordered-journal-after-paths')
            references = LEDGER.mapping('all-journal-buffer-reference-names')
            missing = []
            for name in names:
                path = frames/name; index = int(name[:8]); is_before = name.endswith('-BEFORE.json')
                value, descriptor, _ = jsread(path, 'actual-physical-'+('BEFORE' if is_before else 'AFTER'))
                frame_shape(value,is_before,index,allowed)
                for key in FRAME_KEYS[:3] if is_before else FRAME_KEYS:
                    full_buffer(journal/'buffers',value[key],'native-'+key)
                    references[value[key]['file']] = value[key]
                    totals['buffer_reference_reads'] += 1; stage_counts['buffer_reference_reads'] += 1
                if not is_before:
                    before = decode(observed_read(frames/('%08d-BEFORE.json'%index),
                                    'fresh-before-for-full-after-projection')[0])
                    inverse = dict(value)
                    for key in (*FRAME_KEYS[3:],'result','source_unchanged','machine_call_exception'):
                        inverse.pop(key,None)
                    inverse['returned'] = False
                    require(inverse == before and value['source_unchanged'] is (
                        value['source_before'] == value['source_after']),
                        'full actual BEFORE/AFTER projection differs')
                    after_paths.append(str(path))
                    totals['returned_calls' if value['returned'] else 'exception_calls'] += 1
                    rows.append({'path':str(path),'descriptor':descriptor,'journal':str(journal),
                                 'stage':stage['label'],'frame':value})
            after_set = {int(Path(path).name[:8]) for path in after_paths}
            missing.extend(index for index in before_indices if index not in after_set)
            physical = sorted((journal/'buffers').iterdir())
            actual_names = set()
            orphan = []
            for path in physical:
                require(re.fullmatch(r'[0-9a-f]{64}\.zlib',path.name) is not None,
                        'unknown physical buffer filename')
                require(stat.S_ISREG(path.lstat().st_mode) and path.lstat().st_nlink == 1,
                        'physical buffer object is not an original unique regular file')
                actual_names.add(path.name)
                if path.name in references:
                    full_buffer(path.parent,references[path.name],'independent-every-physical-object')
                    totals['buffer_reference_reads'] += 1
                else:
                    packed, desc = observed_read(path,'complete-orphan-buffer-original')
                    decoder = zlib.decompressobj(); raw = decoder.decompress(packed,CAPACITY+1)
                    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
                            and len(raw) <= CAPACITY and hashlib.sha256(raw).hexdigest()==path.stem,
                            'orphan object lacks a complete exact original payload')
                    orphan.append({'path':str(path),'stored':desc,'decoded':pin(raw,'100644')})
            require(set(references) <= actual_names, 'a referenced buffer object is absent')
            index_path = journal/'INDEX.json'; index_binding = None
            if os.path.lexists(index_path):
                index_binding = stream_index_readback(index_path,after_paths,len(before_indices))
            complete = not missing and len(after_paths)==len(before_indices)
            one = {'path':str(journal),'started':len(before_indices),'after':len(after_paths),
                   'missing_fields':[],'has_final_index':index_binding is not None,
                   'index':index_binding,'complete':complete,'physical_objects':len(physical)}
            expected_journals.append(one)
            journals.append({**one,'missing_after_indices':missing,'orphans':orphan,
                'every_buffer_reference_fresh':True,'all_frames_retired':False})
            totals['started_calls'] += len(before_indices); totals['complete_calls'] += len(after_paths)
            totals['physical_objects'] += len(physical); totals['orphan_objects'] += len(orphan)
            totals['unfinalized_journals'] += index_binding is None
            stage_counts['started_calls'] += len(before_indices); stage_counts['complete_calls'] += len(after_paths)
            if stage['status']=='PASS':
                require(complete and index_binding is not None and not orphan,
                        'successful Native stage lacks complete original frame/INDEX custody')
        producer = {**stage_counts,'journals':expected_journals,'all_frames_retired':False,
                    'payload_cache':False,'aggregate_indexes_streamed':True,
                    'all_observed_frames_complete':all(item['complete'] for item in expected_journals)}
        path = directory/'FRAME-READBACK.json'
        if os.path.lexists(path):
            recorded, _, _ = jsread(path,'actual-parent-frame-readback')
            require(recorded==producer,'parent frame summary differs from independent complete originals')
        else:
            require(stage['status']=='FAIL','successful Native stage lacks its actual frame readback')
        summaries.append({'stage':stage['label'],'producer_summary':producer})
    return {**totals,'all_physical_buffer_reads':PHYSICAL_BUFFER_READS-buffer_reads_at_start,'journals':journals,'frames':rows,'stage_summaries':summaries,
            'complete_every_present_BEFORE_and_AFTER':True,'absent_after_payloads_reconstructed':False,
            'all_frames_retired':False,'all_native_frames_vm_replayed':False,'input_payload_cache':False}


def predecessor_readback(binding, stages, matrix):
    value = decode(strict_fixed(binding,'actual-complete-native-nine-predecessor'))
    require(value['status']=='PASS_COMPLETE_NATIVE_NINE_PREDECESSOR' and value['method_count']==9
            and value['selector_limits']==SELECTOR_LIMITS
            and value['all_frames_retired'] is False and value['all_native_frames_replayed'] is False,
            'complete actual Native9 predecessor contract differs')
    actual_stages=[row for row in stages['stages'] if row['kind']=='native']
    require(len(actual_stages)==len(value['roots'])==9
            and all(row['status']=='PASS' for row in actual_stages),
            'finite VM catalog cannot borrow incomplete Native predecessors')
    count=0
    for offset,root in enumerate(value['roots']):
        require(root['path']==actual_stages[offset]['directory'], 'Native predecessor group order differs')
        current=walking(root['path']); wanted=iterate_shards(root['rows']); rows=files=0
        for saved,actual in itertools.zip_longest(wanted,current):
            require(saved is not None and actual is not None and saved['relative']==actual[0]
                    and saved['stat']==actual[1], 'full Native predecessor row order/pathset/stat differs')
            rows+=1
            if saved['file'] is not None:
                require(stat.S_ISREG(saved['stat']['st_mode'])
                        and saved['file']['path']==str(Path(root['path'])/saved['relative'])
                        and saved['file']['stat']==saved['stat'],'Native predecessor file binding differs')
                stream_checked(saved['file'],'each-full-Native-predecessor-original'); files+=1
            else:
                require(stat.S_ISDIR(saved['stat']['st_mode']),'nonfile predecessor is not a directory')
        require(rows==root['row_count'] and files==root['files'], 'Native predecessor exact counts differ')
        count+=files
    require(count==value['file_count'],'complete Native predecessor file total differs')
    native=decode(strict_fixed(value['native_result'],'actual-Native9-result'))
    readback=decode(strict_fixed(value['native_readback'],'actual-Native9-aggregate-readback'))
    exact=[row['ids'][0] for row in matrix['groups'][7:16]]
    require(native['status']=='PASS_ALL_CLI_OWNER_BUNDLE_NATIVE_CONTROLS'
            and native['exact_ids']==exact and native['tests_run']==9
            and native['failures']==native['errors']==native['skips']==0
            and native['stages']==actual_stages and native['all_frames_retired'] is False,
            'actual complete original Native9 results differ')
    require(readback['status']=='PASS_FULL_NATIVE_NINE_FRAME_READBACK'
            and [row['id'] for row in readback['groups']]==exact
            and readback['all_frames_retired'] is False
            and readback['every_physical_buffer_reference_read'] is True
            and readback['all_native_frames_replayed'] is False,
            'actual Native9 full-readback scope differs')
    actual_indexes=[]; complete=0
    for row,stage in zip(readback['groups'],actual_stages):
        summary=decode(strict_fixed(stage['frame_readback'],'Native9-actual-stage-frame-summary'))
        require(row=={'id':stage['ids'][0],'frame_readback':stage['frame_readback'],
                      'started_calls':summary['started_calls'],'complete_calls':summary['complete_calls']},
                'Native predecessor per-group actual counts differ')
        complete+=summary['complete_calls']
        actual_indexes.extend(item['index'] for item in summary['journals'] if item['index'] is not None)
    require(value['all_indexes']==actual_indexes and readback['complete_calls']==complete,
            'Native predecessor all INDEX order or full count differs')
    for row in value['all_indexes']:
        stream_checked(row,'fresh-every-original-Native-INDEX')
    require(value['selection_image']==stages['components']['selection']['image'],
            'finite VM image is not the actual ninth development build')
    return value


def catalog_readback(binding, predecessor, bound, stages, matrix):
    value=predecessor_readback(predecessor,stages,matrix)
    catalog=decode(strict_fixed(binding,'actual-finite-eight-frame-catalog'))
    image=value['selection_image']['pin']['sha256']; selected={}; losses=set(); inputs=[]
    for root in value['roots']:
        inputs.extend(root['rows'])
        for item in iterate_shards(root['rows']):
            if item['file'] is None or Path(item['relative']).name!='FINAL.json':
                continue
            final=decode(strict_fixed(item['file'],'actual-gate-loss-final-original'))
            require(len(final['origins'])==len(final['losses']), 'gate origin/loss order differs')
            for origin, group in zip(final['origins'],final['losses']):
                for loss in group:
                    if origin['role']=='selection' and loss['command']==2:
                        require(origin['image_sha256']==image and loss['actual_result']==4,
                                'lost claim is not a real returned claim4 on the actual selector')
                        losses.add(str(Path(origin['journal'])/'frames'/('%08d-AFTER.json'%loss['actual_index'])))
    require(len(losses)==1,'one exact real lost-claim frame is required')
    for root in value['roots']:
        for item in iterate_shards(root['rows']):
            if item['file'] is None or not item['relative'].endswith('-AFTER.json'):
                continue
            frame=decode(strict_fixed(item['file'],'ordered-fresh-selector-selection-candidate'))
            if frame['image_sha256']!=image:
                continue
            require(frame['returned'] is True,'catalog candidate did not physically return')
            path=Path(item['file']['path']); buffers=path.parent.parent/'buffers'
            before=full_buffer(buffers,frame['workspace_before'],'finite-catalog-command-workspace')
            require(len(before)>=48 and frame['command']==struct.unpack_from('<Q',before)[0],
                    'catalog command differs from complete actual workspace')
            command,status=frame['command'],frame['result']
            predicates={'start':command==0 and status==1,'claim':command==2 and status==4,
                'ack':command==1 and status==1,'normal-terminal':command==1 and status==0,
                'known-error-terminal':command==1 and status==3,'retirement-start':command==4 and status in(1,5),
                'retirement-ack':command==1 and status==5,
                'lost-claim-return':str(path) in losses and command==2 and status==4}
            for key,match in predicates.items():
                if match and key not in selected:
                    selected[key]={'after':normalized(item['file']),'frame':frame,'buffers':str(buffers)}
    inputs.extend(value['all_indexes'])
    expected={'schema':'hepta.hia.cli-owner-selection.actual-native-catalog.v1',
        'selection_order':list(VM_KEYS),'selected':selected,'limits':SELECTOR_LIMITS,
        'all_native_frames_replayed':False,'all_frames_retired':False,'image_sha256':image,
        'native_result':normalized(value['native_result']),'native_readback':normalized(value['native_readback']),
        'inputs':[normalized(row) for row in inputs],'predecessor':predecessor,
        'selection_policy':'first actual matching frame in original Native group and physical path order',
        'lost_claim_from_actual_gate_final':sorted(losses)}
    require(set(selected)==set(VM_KEYS) and catalog==expected,
            'entire actual finite catalog differs from first real matching frames')
    for row in catalog['inputs']:
        stream_checked(row,'fresh-catalog-input-including-every-duplicate')
    predecessor_readback(predecessor,stages,matrix)
    return catalog


def vm_readback(bound, stages, matrix):
    matching=[stage for stage in stages['stages'] if stage['kind']=='vm']
    require(len(matching)<=1,'VM owner repeated')
    if not matching:
        return {'started':False,'observations':[],'buffer_reads':0,'all_native_frames_replayed':False}
    stage=matching[0];directory=Path(stage['directory'])
    request=decode(observed_read(directory/'REQUEST.json','actual-VM-request')[0])
    require(request['native_predecessor'] is not None and request['catalog'] is not None,
            'actual VM owner lacks a complete new Native9 predecessor')
    catalog=catalog_readback(request['catalog'],request['native_predecessor'],bound,stages,matrix)
    root=directory/'controls/vm'
    result={'started':True,'all_native_frames_replayed':False,'all_frames_retired':False,
            'observations':[],'buffer_reads':0,'complete_selected_equal':False,
            'actual_catalog':request['catalog'],'predecessor':request['native_predecessor']}
    if not os.path.lexists(root):
        require(stage['status']=='FAIL','successful VM8 has no actual observation root')
        return result
    found={path.stem:path for path in root.glob('*.json') if path.name!='INDEX.json'}
    require(set(found)<=set(VM_KEYS),'unknown actual VM case file')
    original=[];references={}
    for key in VM_KEYS:
        if key not in found:
            continue
        row=decode(observed_read(found[key],'actual-finite-VM-observation')[0])
        chosen=catalog['selected'][key]
        expected=decode(strict_fixed(chosen['after'],'fresh-selected-native-AFTER-for-VM'))
        require(expected==chosen['frame'] and expected['returned'] is True
                and row['key']==key and row['native_frame']==expected['index']
                and row['native_case']==expected['case'] and row['native_result']==expected['result'],
                'VM observation did not use its finite actual selected frame')
        same=True
        for side in ('before','after'):
            require(set(row[side])=={'source','output','workspace'},'VM physical buffer set differs')
            for name in ('source','output','workspace'):
                left=full_buffer(root/'buffers',row[side][name],'actual-VM-'+side+'-'+name)
                right=full_buffer(chosen['buffers'],expected[name+'_'+side],
                                  'fresh-selected-Native-'+side+'-'+name)
                result['buffer_reads']+=2
                references[row[side][name]['file']]=row[side][name]
                same=same and left==right
        source_before=full_buffer(root/'buffers',row['before']['source'],'VM-source-before-identity')
        source_after=full_buffer(root/'buffers',row['after']['source'],'VM-source-after-identity')
        require(type(row['steps']) is int and row['steps']>=0
                and row['source_unchanged'] is (source_before==source_after)
                and row['exact_native_buffers'] is same, 'actual VM summary differs from complete physical buffers')
        if row['status']=='PASS':
            require(same and type(row['result']) is int and row['result']==expected['result']
                    and row['source_unchanged'] is True and row['steps']<=LIMITS['vm_steps'],
                    'VM finite result or original step bound differs')
        else:
            require(stage['status']=='FAIL' and row['status']=='FAIL' and row.get('traceback'),
                    'actual VM failure was rewritten or lacks its original traceback')
        original.append(row)
        result['observations'].append({'key':key,'status':row['status'],'steps':row['steps'],
                                       'complete_bytes_equal':same})
    physical=sorted((root/'buffers').iterdir()) if (root/'buffers').is_dir() else []
    require({path.name for path in physical}==set(references),'VM CAS has missing or orphan physical objects')
    for path in physical:
        full_buffer(path.parent,references[path.name],'independent-every-VM-physical-object')
    index_path=root/'INDEX.json'
    if os.path.lexists(index_path):
        index=decode(observed_read(index_path,'complete-actual-VM-INDEX')[0])
        require(index=={'schema':'hepta.hia.cli-owner-selection.vm-observations.v1',
            'observations':original,'max_steps_per_frame':LIMITS['vm_steps'],
            'all_native_frames_replayed':False,'whole_native':False,'current_source_cold':False},
            'full actual VM INDEX differs from individual observations')
    else:
        require(stage['status']=='FAIL','successful VM8 lacks final INDEX')
    if stage['status']=='PASS':
        require(len(original)==8 and all(row['status']=='PASS' for row in original),
                'successful VM8 lacks all eight original finite replay results')
        result['complete_selected_equal']=True
    summary_path=directory/'VM-READBACK.json'
    if os.path.lexists(summary_path):
        recorded=decode(observed_read(summary_path,'actual-parent-VM-readback')[0])
        expected={key:result[key] for key in ('all_native_frames_replayed','all_frames_retired',
                                             'observations','buffer_reads','complete_selected_equal')}
        require(recorded==expected,'parent VM summary differs from complete fresh selected buffers')
    else:
        require(stage['status']=='FAIL','successful VM8 lacks parent readback')
    return result


def components_readback(directory,bound,source_map,names):
 envelope,_,_=jsread(directory/'ACTUAL-COMPONENTS.json','actual-components');require(set(envelope)=={'components','report_bundle','ordinary_artifacts'}and set(envelope['components'])==set(names),'actual component set differs');rows=[]
 if envelope['report_bundle']is not None:observed_fixed(envelope['report_bundle'],'actual-six-image-bundle')
 for name,desc in envelope['components'].items():
  require(set(desc)=={'image','manifest','source'},'component descriptor differs');image=observed_fixed(desc['image'],'new-image:'+name);manifest=decode(observed_fixed(desc['manifest'],'new-manifest:'+name));source=observed_fixed(desc['source'],'new-compile-source:'+name);relative=bound['component_sources'][name]
  require(desc['source']['path']==str(Path(bound['source'])/relative)and desc['source']['pin']==source_map[relative]and 0<len(image)<=1048576,'component source/image differs')
  ip=Path(desc['image']['path']);base=ip.name.removesuffix('.image.bin');require(ip.parent.is_relative_to(directory),'component outside actual build')
  req,_,_=jsread(ip.parent/(base+'.request.json'),'compile-request');rec,recdesc,_=jsread(ip.parent/(base+'.receipt.json'),'compile-receipt')
  require(req['image']==bound['compiler']['path']and req['image_sha256']==bound['compiler']['pin']['sha256']and req['capacity']==req['workspace_size']==1048576 and req['workspace_fill']==0 and req['format']=='flat-x86-64','compile request/budget differs')
  sp=ip.parent/(base+'.input.bin');op=ip.parent/(base+'.output.bin');require(req['source']==str(sp)and req['output']==str(op),'compile physical path differs');inp,_=observed_read(sp,'compile-input',maximum=len(source));out,_=observed_read(op,'compile-full-output',maximum=1048576)
  require(inp==source and len(out)==1048576 and out[:len(image)]==image,'actual full compile bytes differ')
  require(rec['status']=='returned'and rec['abi_status']==0 and rec['source_unchanged']is True and rec['forbidden_compiler_modules_loaded']==[]and rec['result_u64']==rec['core_u32']==rec['produced_bytes']==len(image)and rec['produced_image']==str(ip)and rec['produced_sha256']==desc['image']['pin']['sha256']and rec['artifact_sha256']==rec['image_sha256']==bound['compiler']['pin']['sha256']and rec['input_bytes']==len(source)and rec['input_sha256']==rec['source_sha256']==req['source_sha256']==hashlib.sha256(source).hexdigest()and rec['output_sha256']==hashlib.sha256(out).hexdigest(),'actual compile receipt identity differs')
  require(rec['limits']=={'address_bytes':268435456,'core_dumpable':False,'cpu_seconds':10,'output_capacity':1048576,'stack_bytes':8388608,'workspace_bytes':1048576}and 0<=rec['native_elapsed_ns']<=rec['wall_elapsed_ns']<=20_000_000_000 and rec['runner_sha256']==source_map['tools/hia_selfhost_child.py']['sha256'],'compile original limits/child differ')
  require(manifest['image_path']==ip.name and manifest['image_sha256']==desc['image']['pin']['sha256']and manifest['source_sha256']==desc['source']['pin']['sha256']and manifest['compiler_sha256']==bound['compiler']['pin']['sha256'],'actual manifest differs')
  for host,sha in manifest.get('host_sources',{}).items():require('/'not in host and source_map['hepta/'+host]['sha256']==sha,'manifest host differs')
  rows.append({'name':name,'component':desc,'compile_receipt':recdesc,'full_compile_input_output_image_equal':True,'full_compile_workspace_observed':False})
 return envelope,rows


def artifacts_readback(value, components):
    if value is None:
        return None
    root=Path(value['root']);before=metadata(root)
    require(before==value['state'] and {name for name,item in before.items() if stat.S_ISREG(item['st_mode'])}
            ==set(value['files']),'complete new nine-image artifact pathset/stat differs')
    inodes=set()
    for name, expected in value['files'].items():
        state=before[name];inode=(state['st_dev'],state['st_ino'])
        require(inode not in inodes,'ordinary fixture paths alias');inodes.add(inode)
        observed_read(root/name,'every-original-ordinary-artifact',expected=expected,expected_stat=state)
    require(set(value['images'])==set(ROLES),'ordinary artifact image-role set differs')
    for role,row in value['images'].items():
        copied=strict_fixed(row,'ordinary-artifact-image:'+role)
        actual=strict_fixed(components[role]['image'],'actual-built-origin-image:'+role)
        require(copied==actual,'ordinary artifact is not the complete new actual image')
    require(len({row['pin']['sha256'] for row in value['images'].values()})==9,
            'the nine actual image identities alias')
    strict_fixed(value['bundle'],'actual-data-only-nine-image-bundle')
    for row in value['copy_records']:
        left=strict_fixed(row['origin'],'fresh-ordinary-artifact-copy-origin')
        right=strict_fixed(row['copied'],'fresh-ordinary-artifact-copy-target')
        require(left==right and (row['origin']['stat']['st_dev'],row['origin']['stat']['st_ino'])!=(
            row['copied']['stat']['st_dev'],row['copied']['stat']['st_ino']),
            'ordinary actual artifact copy differs or aliases its origin')
    require(metadata(root)==before,'ordinary artifact state changed around complete readback')
    return value


def authorities(authority):
    bound_raw=fixed(authority['bound']);bound=decode(bound_raw)
    binding=decode(fixed(authority['binding']))
    template_raw=fixed(bound['template']);template=decode(template_raw)
    require(binding['schema']==SCHEMA+'.binding-result' and binding['status']=='BOUND_NOT_EXECUTED'
            and binding['products_executed']==0 and binding['source_copy_performed'] is False
            and binding['bound_source_files']==3225 and binding['old_PASS_transferred'] is False
            and binding['plan']==authority['bound'] and binding['author_plan']==bound['template']
            and bound['template']==authority['author_plan'],
            'actual ordinary source-in-place preparation binding differs')
    require(set(bound)==set(template)|{'template'}
            and all(bound[key]==value for key,value in template.items()
                    if key not in ('state','scope_ancestors','source_ancestors')),
            'whole original bound-plan inverse differs')
    require(bound['source_tree']==TREE and bound['scope']==str(SCOPE)
            and bound['source']==ACTUAL_SOURCE and bound['attempt']==str(SCOPE/'attempt-r1'),
            'actual ordinary source/tree/attempt differs')
    guarded=bound_guard(bound)
    require(binding['full_before']==binding['full_after']==guarded['immutable']
            and binding['source_before']==binding['source_after']==guarded['candidate3225']
            and binding['runtime']==bound['runtime'] and binding['source_tree']==TREE
            and binding['source_map']==bound['source_map'] and binding['source_state']==bound['source_state'],
            'preparation and independently fresh current guards differ')
    flat=decode(fixed(bound['source_map']));state=decode(fixed(bound['source_state']))
    inodes={(state[name]['st_dev'],state[name]['st_ino']) for name in flat}
    require(len(inodes)==len(flat)==3225,'complete current source inode set differs')
    for name in ('base_source','mother_source','prior_base'):
        prior=decode(fixed(bound[name]['state']))
        require(not inodes & {(row['st_dev'],row['st_ino']) for row in prior.values()
                                if stat.S_ISREG(row['st_mode'])},
                'current generated source aliases a protected original source')
    matrix=matrix_for(bound)
    return bound,binding,flat,state,matrix,guarded


def stages_readback(authority, bound, parent, matrix, source_map, guarded):
    require(parent['schema']==SCHEMA+'.result' and parent['status'] in (SUCCESS,'FAIL')
            and parent['plan_pin']==authority['bound']['pin'] and parent['binding_pin']==authority['binding']['pin']
            and parent['required_owners']==18 and parent['required_method_invocations']==85
            and parent['required_compile_calls']==9 and parent['actual_source_files']==3225
            and parent['original_cli43_flags']==['-B']
            and parent['original_cli43_scope']=='ORIGINAL_REPORT_V2_SCHEMA_ON_CURRENT_EXTENDED_SOURCE',
            'actual ordinary parent schema or scope differs')
    for key in ('current_cold','whole_native','all_frames_retired','all_native_frames_replayed',
                'source_copy_performed','default_activation','old_PASS_transferred','compile_full_workspace_observed'):
        require(parent[key] is False,'actual product expanded a qualification boundary: '+key)
    require(parent['old_Source8_Source11_domains_unchanged'] is True
            and 0<=len(parent['stages'])<=18
            and parent['actual_owner_launch_attempts']==len(parent['stages']),
            'actual ordered owner attempt count differs')
    owners=[];tests=[];compiles=[];components={};report=None;artifacts=None
    observed=[];failures=[]
    for offset,stage in enumerate(parent['stages']):
        planned=matrix['groups'][offset]
        directory=Path(bound['attempt'])/('%02d-'%(offset+1)+planned['label'])
        require(stage['label']==planned['label'] and stage['kind']==planned['kind']
                and stage['ids']==planned['ids'] and stage['directory']==str(directory)
                and stage['status'] in ('PASS','FAIL'), 'actual stage differs from original ordered matrix')
        sealed,stage_descriptor,_=jsread(directory/'STAGE.json','actual-sealed-stage')
        require(sealed==stage,'parent stage is not the full original STAGE bytes')
        request,request_descriptor,request_raw=jsread(directory/'REQUEST.json','actual-stage-request')
        expected_request={'schema':SCHEMA+'.child-request','plan':authority['bound'],'limits':LIMITS,
            'group':planned['label'],'ids':planned['ids'],'flags':planned['flags'],'directory':str(directory),
            'environment':stage_environment(bound,planned,directory,report),
            'product_root_binding':request['product_root_binding'],
            'native_inputs':components,'report_bundle':report,'artifacts':artifacts,
            'native_predecessor':request['native_predecessor'] if planned['kind']=='vm' else None,
            'catalog':request['catalog'] if planned['kind']=='vm' else None}
        require(request==expected_request,'entire actual stage request differs')
        guard_directories(request['product_root_binding'])
        command,_,_=jsread(directory/'COMMAND.json','actual-stage-command')
        expected_command=[bound['runtime']['launch_executable'],*planned['flags'],
            bound['controls']['run_qualification_child.py']['path'],'--request',request_descriptor['path'],
            '--request-sha256',request_descriptor['pin']['sha256']]
        require(command=={'command':expected_command,'cwd':bound['source'],'environment':request['environment'],
            'supervisor_environment':request['environment'],'qualification_seconds':180,'cleanup_seconds':3},
            'actual owned argv/cwd/environment/limits differ')
        owner_raw=decode(observed_read(directory/'OWNER.json','actual-owner-for-real-returncode')[0])
        code=owner_raw['returncode']
        require(type(code) is int and code in (0,1),'owner did not complete with an admitted child result')
        owners.append(owner_readback(directory,command,stage,source_map,code))
        for channel in ('stdout','stderr'):
            fresh_stream_pin(directory/(channel+'.raw'),'complete-original-owned-'+channel)
        child,child_descriptor,_=jsread(directory/'BUNDLE-CHILD-RESULT.json','actual-ordinary-child-result')
        require(stage['child_result']==child_descriptor and child['schema']==SCHEMA+'.child-result'
                and child['request_pin']==request_descriptor['pin'] and child['group']==planned['label']
                and child['nested_owner_launches']==0 and child['test_bodies_changed'] is False
                and child['native_capability'] is (planned['kind'] in ('native','vm','cli')),
                'actual child identity/scope differs')
        flags=child['runtime_flags'];isolated=int('-I' in planned['flags'])
        require(flags['isolated']==flags['ignore_environment']==isolated
                and flags['dont_write_bytecode']==1
                and flags['executable']==bound['runtime']['launch_executable']
                and flags['python']==bound['runtime']['python'],
                'actual child interpreter flags or captured runtime differ')
        for key in ('source_copy_performed','all_frames_retired','all_native_frames_replayed',
                    'current_cold','whole_native'):
            require(child[key] is False,'child expanded its original boundary')
        require(child['source_before']==child['source_after']==guarded
                and not child.get('terminal_guard_errors') and stage['source_after']==guarded
                and not stage.get('terminal_guard_errors'),
                'actual child/parent fixed-source/runtime guards did not close')
        if stage['status']=='PASS':
            require(code==0 and child['status']=='PASS','successful stage has a failed real owner/child')
        else:
            require(offset==len(parent['stages'])-1 and parent['status']=='FAIL'
                    and stage.get('error') and parent.get('halted_after_first_failure') is True,
                    'first failure did not stop the original ordered chain')
            failures.append(stage['label'])
        if planned['kind']=='build':
            nested,nested_descriptor,_=jsread(directory/'BUILD-REQUEST.json','actual-original-build-request')
            require(nested=={'schema':SCHEMA+'.build-request','plan':authority['bound'],
                'group':planned['label'],'directory':str(directory),'limits':LIMITS,
                'native_inputs':components,'report_bundle':report},'entire nested original build request differs')
            build=decode(strict_fixed(child['build_result'],'actual-original-build-result'))
            require(child['build_returncode']==0 and build['status']=='PASS'
                    and build['request_pin']==nested_descriptor['pin']
                    and build['source_before']==build['source_after']==guarded['candidate3225']
                    and not build.get('terminal_guard_errors'),
                    'actual original build did not close; raw remains preserved')
            names=list(REPORT_COMPONENTS) if planned['label']=='build-report-six' else [
                {'build-inspect':'inspect','build-patch':'patch','build-selection':'selection'}[planned['label']]]
            envelope,rows=components_readback(directory,bound,source_map,names)
            require(not set(components)&set(envelope['components']),'component was built more than once')
            components.update(envelope['components']);compiles.extend(rows)
            if envelope['report_bundle'] is not None:
                require(report is None,'report bundle was produced more than once');report=envelope['report_bundle']
            if envelope['ordinary_artifacts'] is not None:
                require(artifacts is None and set(components)==set(ROLES),
                        'ordinary artifacts appeared without exactly nine actual builds')
                artifacts=artifacts_readback(envelope['ordinary_artifacts'],components)
        else:
            value=tests_readback(directory,planned['ids'],child,stage['status'])
            value.update(label=planned['label'],kind=planned['kind'])
            tests.append(value)
        observed.append(stage)
    if parent['status']==SUCCESS:
        require(len(observed)==18 and not failures and len(compiles)==9 and set(components)==set(ROLES)
                and parent['native_inputs']==components and parent['report_bundle']==report
                and parent['ordinary_artifacts']==artifacts and parent['new_build_count']==9
                and parent['method_invocations']==85
                and parent['completed_cohorts']=={'source8_successor':8,'source11_successor':11,
                    'selection_source':6,'selection_native':9,'selection_vm':8,'original_cli43':43},
                'successful actual parent lacks all explicit cohorts/new builds')
    else:
        require(parent.get('error') and parent.get('halted_after_first_failure') is True,
                'actual failed parent lacks its original failure')
    require(parent['source_after']==guarded and not parent.get('terminal_guard_error'),
            'parent final full current guard did not close')
    not_started=matrix['groups'][len(observed):]
    for offset,row in enumerate(not_started,start=len(observed)+1):
        directory=Path(bound['attempt'])/('%02d-'%offset+row['label'])
        require(not(directory/'OWNER.json.request.json').exists() and not(directory/'OWNER.json').exists()
                and not(directory/'STAGE.json').exists(),'a later owner/stage exists after failure stop')
    return {'owners':owners,'tests':tests,'compiles':compiles,'components':components,
            'bundle':report,'ordinary_artifacts':artifacts,'stages':observed,
            'not_started':[row['label'] for row in not_started],'failed_stages':failures}


def evidence_type_admission(authority, attempt_state, outer_state, scope_state):
    original=decode(fixed(authority['evidence_types']))
    require(original['schema']=='hepta.hia.ordinary.actual-evidence-types.v1'
            and original['product_execution']==0 and original['regular_payload_reads']==0,
            'independently captured typed original-evidence authority required')
    for label,current in (('attempt',attempt_state),('outer',outer_state),('scope',scope_state)):
        wanted=original['roots'][label]
        require(current==wanted['state'],'complete typed pathset/seven-stat/link-target differs')
        inodes={};links=[];opaque=[]
        for name,row in current.items():
            if stat.S_ISREG(row['st_mode']):
                inodes.setdefault((row['st_dev'],row['st_ino']),[]).append(name)
            if stat.S_ISLNK(row['st_mode']):
                links.append(name)
            if 'opaque_special' in row:
                opaque.append(name)
        aliases=[names for names in inodes.values() if len(names)>1]
        require(aliases==wanted['regular_aliases']==[] and links==wanted['symbolic_links']
                and opaque==wanted['opaque_specials'],
                'raw evidence alias/type authority differs; regular single-link policy remains strict')
    allowed='18-original-cli43/cli-evidence/CliNativeTests/bounded-inputs/input-link'
    require(set(original['roots']['attempt']['symbolic_links'])<={allowed}
            and original['roots']['outer']['symbolic_links']==[],
            'unreviewed evidence symlink set')
    return original


def opaque_descriptor(path, expected):
    before=seven(Path(path).lstat())
    require(before=={key:expected[key] for key in FIELDS}
            and 'opaque_special' in expected and not any(check(before['st_mode'])
                for check in (stat.S_ISREG,stat.S_ISDIR,stat.S_ISLNK))
            and expected['opaque_special']=={'type':stat.S_IFMT(before['st_mode']),
                'device':Path(path).lstat().st_rdev,'payload_read':False},
            'opaque original evidence identity differs')
    require(seven(Path(path).lstat())==before,'opaque evidence identity changed')
    return {'path':str(path),'stat':before,'entry_type':'opaque_special',
            'opaque_special':expected['opaque_special'],'payload_read':False,'payload_pin':None}


def inventory_readback(attempt, attempt_state, outer_state, scope_state):
    rows=LEDGER.sequence('complete-typed-actual-original-inventory')
    counters={'regular_files':0,'symlink_entries':0,'opaque_entries':0,'regular_bytes':0,'link_target_bytes':0}
    for label,root,state in (('attempt',attempt,attempt_state),('outer',OUTER,outer_state)):
        for name,item in state.sorted_items():
            if stat.S_ISDIR(item['st_mode']):
                continue
            if stat.S_ISREG(item['st_mode']):
                row=fresh_stream_pin(root/name,'complete-original-raw:'+label+'/'+name,item)
                counters['regular_files']+=1;counters['regular_bytes']+=row['pin']['bytes']
            elif stat.S_ISLNK(item['st_mode']):
                row=evidence_link_descriptor(root/name,item)
                counters['symlink_entries']+=1;counters['link_target_bytes']+=row['pin']['bytes']
            else:
                row=opaque_descriptor(root/name,item);counters['opaque_entries']+=1
            rows.append({'logical':label+'/'+name,**row})
        require(evidence_metadata(root)==state,'complete raw pathset/stat/type changed during full readback')
    for name,item in scope_state.sorted_items():
        if name=='.' or name=='attempt-r1' or name.startswith('attempt-r1/') or stat.S_ISDIR(item['st_mode']):
            continue
        require(stat.S_ISREG(item['st_mode']),'scope metadata outside actual attempt is not an ordinary regular file')
        row=fresh_stream_pin(SCOPE/name,'complete-original-scope:'+name,item)
        rows.append({'logical':'scope/'+name,**row})
        counters['regular_files']+=1;counters['regular_bytes']+=row['pin']['bytes']
    return {'schema':'hepta.hia.ordinary.complete-typed-actual-raw.v1',
            'roots':{'attempt':{'path':str(attempt),'state':attempt_state},
                     'outer':{'path':str(OUTER),'state':outer_state}},
            'scope_state':scope_state,'files':rows,'entry_count':len(rows),**counters,
            'all_actual_raw_retained':True,'symlink_targets_followed':False,
            'opaque_payloads_claimed_read':False,'all_frames_retired':False}


def outer_terminal(authority, bound, parent):
    """Blocked adapter: the actual Root ordinary outer source/shape was not recovered.

    The known product launch can be checked without guessing its parent schema.
    The old Core outer adapter is retained as a separate comparison source, not
    silently reused for a different launcher. A successor must bind and review
    the complete actual INTENT/SPAWNED/RESULT/stdout/stderr protocol before this
    deliberate stop can be replaced. No missing terminal or cleanup is inferred.
    """
    launch=decode(fixed(authority['product_launch']))
    env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(SCOPE),'TMPDIR':str(SCOPE/'parent-tmp'),
         'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1',
         'PYTHONHASHSEED':'0','LD_LIBRARY_PATH':bound['runtime']['library_directory']}
    command=[bound['runtime']['launch_executable'],'-I','-B',
        bound['controls']['run_qualification.py']['path'],'--plan',authority['bound']['path'],
        '--plan-sha256',authority['bound']['pin']['sha256'],'--binding',authority['binding']['path'],
        '--binding-sha256',authority['binding']['pin']['sha256']]
    require(launch=={'schema':SCHEMA+'.product-launch','state':'BOUND_NOT_EXECUTED_ROOT_SOLE_LAUNCHER',
        'cwd':bound['source'],'environment':env,'command':command,
        'exact_clean_env_argv':['/usr/bin/env','-i',*[key+'='+env[key] for key in sorted(env)],*command],
        'plan':authority['bound'],'binding':authority['binding'],'owner_count':18,
        'test_method_invocations':85,'actual_compile_calls_required':9,
        'qualification_seconds_each':180,'cleanup_seconds_each':3,
        'outer_watchdog_seconds':1800,'outer_cleanup_seconds':3,'automatic_retry':False,
        'products_executed':0,'current_cold':False,'whole_native':False},
        'complete original generated product-launch contract differs')
    raise RuntimeError('AUTHOR_ONLY_UNBOUND: actual ordinary Root outer schema/source, '
                       'terminal status, cleanup and full raw bindings are not recovered')


def verify_terminal(plan_path, expected_sha, output):
    global SEEN,OBSERVED_READS,LEDGER,OUTER
    require(EXECUTION_BOUND is True,
            'AUTHOR_ONLY_UNBOUND draft: no approved actual terminal binding or launch exists')
    started=time.monotonic_ns()
    require(not os.path.lexists(output),'independent output already exists')
    output.mkdir(mode=0o700)
    LEDGER=Ledger(output);SEEN=LEDGER.mapping('unique-input-descriptors',full_reads=True)
    OBSERVED_READS=LEDGER.sequence('ordered-observation-reads')
    result={'schema':'hepta.hia.ordinary.independent-terminal-result.draft.v1','status':'FAIL',
        'product_execution':0,'project_imports':0,'binder_execution':0,'source_copy':False,
        'all_frames_retired':False,'full_compile_workspaces_observed':False,
        'all_native_frames_vm_replayed':False,'whole_native':False,'current_cold':False,
        'started_ns':started,'draft_execution_claimed':False}
    try:
        raw=read(plan_path);require(hashlib.sha256(raw).hexdigest()==expected_sha,'exact reader plan SHA differs')
        authority=decode(raw)
        require(authority['schema']=='hepta.hia.ordinary.independent-terminal-plan.draft.v1'
                and authority['state']=='ROOT_REVIEWED_ACTUAL_BINDING'
                and authority['scope']==str(SCOPE) and authority['actual_source']==ACTUAL_SOURCE
                and authority['source_tree']==TREE and authority['source_files']==3225
                and authority['original_owners']==18 and authority['original_methods']==85
                and authority['original_compiles']==9 and authority['finite_vm_frames']==8,
                'explicit new actual terminal authority required')
        require(authority['reader']['path']==str(Path(__file__).absolute()),'actual reader source is not fixed')
        fixed(authority['reader'])
        for descriptor in authority['root_metadata'].values():
            fixed(descriptor)
        OUTER=Path(authority['outer'])
        require(OUTER.is_absolute() and '..' not in OUTER.parts and OUTER!=SCOPE
                and authority['output']==str(output)
                and not output.is_relative_to(SCOPE) and not output.is_relative_to(OUTER),
                'new output must be outside immutable actual original evidence roots')
        bound,binding,source_map,source_state,matrix,guarded=authorities(authority)
        runtime,runtime_state,_=runtime_authority(bound)
        parent=decode(fixed(authority['actual_result']))
        attempt=Path(bound['attempt'])
        require(authority['actual_result']['path']==str(attempt/'RESULT.json'),
                'actual parent result path differs')
        initial_attempt=evidence_metadata(attempt);initial_outer=evidence_metadata(OUTER)
        initial_scope=evidence_metadata(SCOPE)
        evidence_type_admission(authority,initial_attempt,initial_outer,initial_scope)
        # Preserve a complete typed inventory before interpreting any failed group.
        # It does not confer a product PASS and does not follow a negative-test link.
        inventory=inventory_readback(attempt,initial_attempt,initial_outer,initial_scope)
        publish(output/'INVENTORY.json',inventory)
        outer=outer_terminal(authority,bound,parent)
        stages=stages_readback(authority,bound,parent,matrix,source_map,guarded)
        frames=frames_readback(bound,stages)
        vm=vm_readback(bound,stages,matrix)
        installed=installed_wheel_readback(bound,stages)
        final_guard=bound_guard(bound);final_runtime,final_runtime_state,_=runtime_authority(bound)
        require(final_guard==guarded and final_runtime==runtime and final_runtime_state==runtime_state,
                'complete source/runtime/control/generation/packaging guards changed')
        require(evidence_metadata(attempt)==initial_attempt and evidence_metadata(OUTER)==initial_outer
                and evidence_metadata(SCOPE)==initial_scope,
                'full original typed pathsets/seven-stat identities changed')
        for descriptor in SEEN.values():
            require(seven(Path(descriptor['path']).lstat())==descriptor['stat'],
                    'final repeated input seven-stat identity differs')
        methods=sum(item['tests_run'] for item in stages['tests'])
        events=sum(item['events'] for item in stages['tests'])
        if parent['status']==SUCCESS:
            require(len(stages['owners'])==18 and methods==85 and events==170
                    and len(stages['compiles'])==9 and not stages['not_started']
                    and all(row['status']=='PASS' for row in stages['tests'])
                    and vm['complete_selected_equal'] is True and len(vm['observations'])==8
                    and frames['orphan_objects']==frames['unfinalized_journals']==0
                    and frames['started_calls']==frames['complete_calls']
                    and installed['present'] is True,
                    'complete current-domain cohorts/builds/frame/VM/CLI43 evidence required')
        publish(output/'STAGES.json',stages);publish(output/'FRAMES.json',frames)
        publish(output/'VM.json',vm);publish(output/'INSTALLED-WHEEL.json',installed)
        result.update(status='PASS_COMPLETE_ORDINARY_TERMINAL_READBACK' if parent['status']==SUCCESS
                else 'PASS_FAILURE_EVIDENCE_VERIFIED',
            product_status=parent['status'],original_result=authority['actual_result'],
            actual_owners=len(stages['owners']),actual_test_methods=methods,actual_test_events=events,
            actual_compiles=len(stages['compiles']),
            actual_test_subtests=sum(len(row['subtests']) for row in stages['tests']),
            actual_test_failures=sum(len(row['failures']) for row in stages['tests']),
            actual_test_errors=sum(len(row['errors']) for row in stages['tests']),
            actual_native_started=frames['started_calls'],actual_native_complete=frames['complete_calls'],
            actual_native_returned=frames['returned_calls'],actual_native_exceptions=frames['exception_calls'],
            complete_native_buffer_reference_reads=frames['all_physical_buffer_reads'],
            finite_vm_observations=len(vm['observations']),finite_vm_buffer_reads=vm['buffer_reads'],
            native_frames_all_replayed=False,original_cli43_flags=['-B'],
            installed_cli43_uses_original_report_v2=True,ordinary_bundle_has_distinct_native9_gate=True,
            wheel_member_count=installed.get('member_count',0),
            installed_native_return_values_are_not_physical_frames=True,
            source_files=3225,source_tree=TREE,runtime_files=2496,packaging_files=667,
            raw_entries=inventory['entry_count'],raw_regular_files=inventory['regular_files'],
            raw_regular_bytes=inventory['regular_bytes'],raw_symlinks=inventory['symlink_entries'],
            raw_link_target_bytes=inventory['link_target_bytes'],raw_opaque_entries=inventory['opaque_entries'],
            symlink_targets_followed=False,opaque_payloads_read=False,outer_process_only=outer)
    except BaseException:
        result['traceback']=traceback.format_exc()
    finally:
        result.update(finished_ns=time.monotonic_ns(),fresh_full_reads=READS,fresh_full_bytes=BYTES,
            unique_input_paths=len(SEEN),every_reference_fresh=True,result_cache_used=False,
            complete_symlink_target_reads=LINK_TARGET_READS,complete_symlink_target_bytes=LINK_TARGET_BYTES)
        publish(output/'READ-INPUTS.json',StreamValues(SEEN))
        with (output/'OBSERVATION-READS.jsonl').open('xb') as stream:
            for row in OBSERVED_READS:
                stream.write((json.dumps(row,sort_keys=True)+'\n').encode())
        require(LEDGER.read_count==READS,'complete fresh-read ledger count differs')
        result['disk_bookkeeping']=LEDGER.close_and_capture()
        result['input_payload_cache_used']=False
        publish(output/'RESULT.json',result)
    return 0 if result['status'] in ('PASS_COMPLETE_ORDINARY_TERMINAL_READBACK','PASS_FAILURE_EVIDENCE_VERIFIED') else 1


# The retained guards resolve only to the independent standard-library readers.
checked=fixed
guard_directories=directories
observer=IndependentObserver()

if __name__=='__main__':
    raise SystemExit('AUTHOR_ONLY_UNBOUND: no actual terminal binding, fresh-stat authority, '
                     'Root-outer codec, frozen plan or execution authorization exists for this draft')

