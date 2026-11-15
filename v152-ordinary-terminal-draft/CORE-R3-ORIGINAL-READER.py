"""Independent op8 core terminal readback. Stdlib only, no project or product execution."""
from __future__ import annotations
import argparse,ast,base64,hashlib,io,itertools,json,os,re,sqlite3,stat,struct,time,traceback,zipfile,zlib
from collections.abc import Mapping
from pathlib import Path
AUTHOR=Path('/workspace/hia-cli-as-dict-core-terminal-reader-r3-dda7')
SCOPE=Path('/workspace/hia-cli-as-dict-core-qualification-r1-dda7')
FIXED_SCOPE=SCOPE
OUTER=Path('/workspace/hia-cli-as-dict-core-qualification-outer-r1-dda7')
OUTPUT=Path('/workspace/hia-cli-as-dict-core-terminal-actual-r3-dda7')
ACTUAL_SOURCE='/workspace/hia-cli-as-dict-generation-r1-dda7/source'
PACKAGING_ROOT=Path('/workspace/hia-cli-as-dict-packaging-r1-dda7')
SOURCE_TREE=TREE='7f694b80c7ab76eb9d62402aeea4c331503ddc16'
SCHEMA='hepta.hia.cli-as-dict.qualification.v1'
SUCCESS='PASS_EXPLICIT_OP8_CORE_ONLY_FULL_INTEGRATION_PENDING'
CAPACITY=1048576
MINIMUM_FREE=1073741824
COMPONENTS=('control','format','discovery','routing','parser_context','verified_report','inspect','patch')
REPORT_COMPONENTS=COMPONENTS[:6]
LABELS=('report-source12','build-report-six','report-native2','original-cli43','external-op8-eight')
FRAME_KEYS=('source_before','output_before','workspace_before','source_after','output_after','workspace_after')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
LIMITS={'cleanup_seconds':3,'compile_seconds':20,'native_capacity':1048576,'owner_seconds':180,'vm_call_depth':128,'vm_heap':8388608,'vm_steps':10000000}
B3_PIN={'bytes':673413,'mode':'100644','git_blob':'315c6b5f36a1ec679deb68abdca24bd4d1bef9f8','sha256':'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'}
READS=0;BYTES=0;SEEN=None;OBSERVED_READS=None;LEDGER=None

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



def tests_readback(directory,ids,child,status):
 tests,desc,_=jsread(directory/'TESTS.json','actual-original-tests');require(tests['declared_ids']==tests['loaded_ids']==ids and tests['events']==[e for n in ids for e in(['start',n],['stop',n])]and tests['tests_run']==len(ids),'original IDs/events incomplete')
 for k in('loader_errors','skipped','expected_failures','unexpected_successes'):require(tests[k]==[],'test suite incomplete: '+k)
 require(all(s['parent']in ids and s['status']in('PASS','FAIL','ERROR')for s in tests['subtests']),'subtest parent/status differs')
 failures=len(tests['failures']);errors=len(tests['errors']);bad=sum(s['status']!='PASS'for s in tests['subtests']);actual='FAIL'if failures or errors or bad else'PASS';require(tests['status']==status==actual,'original assertions and stage status differ')
 if actual=='PASS':require(child['tests']==tests,'successful full test report differs')
 else:
  require(bool(child.get('traceback')),'failed child lacks real traceback')
  if'tests'in child:require(child['tests']==tests,'failed child changed test report')
 return {'raw':desc,'ids':ids,'events':len(tests['events']),'tests_run':tests['tests_run'],'subtests':tests['subtests'],'failures':tests['failures'],'errors':tests['errors'],'status':actual}



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



def product_source_summary(bound):
    return {'files':3210,'all_bytes_read':True,'source_map':bound['source_map']['pin'],
        'source_state':bound['source_state']['pin']}



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



def source_guard(request, observer):
    expected = decode(fixed(request['source_map']))
    state = decode(fixed(request['source_state']))
    root = Path(request['source'])
    require(root.is_absolute() and '..' not in root.parts and len(expected) == 3210,
            'complete 3210 source scope required')
    before = metadata(root)
    require(before == state, 'actual complete source identity differs before read')
    # Reuse the exact original reader. It reads every regular source file;
    # this call never replaces contents by a cached digest or receipt.
    actual = observer.snapshot(root)
    require(actual == expected and metadata(root) == before,
            'source bytes/modes/pathset/seven stats changed')
    return {'files': len(actual), 'source_map': request['source_map']['pin'],
            'source_state': request['source_state']['pin'], 'all_bytes_read': True}



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



def all_guards(plan, runtime_guard=None):
    control_guard(plan)
    value = source_guard(plan, observer)
    expected = decode(checked(plan['source_map']))
    require(observer.tree_digest(expected) == SOURCE_TREE, 'complete new source tree differs')
    runtime_files_guard(plan)
    if runtime_guard is not None:
        runtime_guard(plan['runtime'])
    return value



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



def matrix_for(plan):
    matrix = decode(checked(plan['controls']['CORE-MATRIX.json']))
    retained = decode(checked(plan['controls']['OP8-ORIGINAL-TEST-INVENTORY.json']))
    require(matrix['schema'] == 'hepta.hia.cli-as-dict.core-matrix.v1'
            and matrix['limits'] == LIMITS and matrix['owners'] == 5
            and matrix['methods'] == 65 and matrix['compile_calls'] == 6
            and [r['label'] for r in matrix['groups']] == list(LABELS)
            and [r['ids'] for r in matrix['groups']] == [retained['report_source_ids'],[],
                retained['report_native_ids'],retained['original_cli_ids'],retained['new_controls']]
            and matrix['report_cases'] == retained['original140_case_names']
            and len(matrix['report_cases']) == 140, 'complete original core selection required')
    require([r['flags'] for r in matrix['groups']] == [['-I','-B']]*3 + [['-B']]*2,
            'original CLI43 -B/ignore_environment=0 must be retained')
    for flag in ('current_cold','default','whole'):
        require(matrix[flag] is False, 'core scope cannot grant full/default/cold qualification')
    return matrix



def fixed_shape(plan):
    require(plan['schema'] == SCHEMA and plan['state'] in (
                'AUTHORING_ONLY_AWAITING_ROOT_AUTHORIZATION','BOUND_AWAITING_ROOT_AUTHORIZATION')
            and plan['scope'] == str(FIXED_SCOPE) and plan['attempt'] == str(FIXED_SCOPE/'attempt-r1')
            and plan['source'] == ACTUAL_SOURCE and plan['source_files'] == 3210
            and plan['source_tree'] == SOURCE_TREE and plan['limits'] == LIMITS
            and plan['storage_floor'] == MINIMUM_FREE and plan['source_copy_performed'] is False,
            'explicit actual op8 source and unchanged core budgets required')
    matrix_for(plan)



def old_generation_guard(plan):
    return evidence_guard({'generation_evidence':plan['prior_generation_evidence'],
        'generation_result':plan['prior_generation_result'],
        'generation_terminal':plan['prior_generation_terminal'],
        'mother_source':plan['mother_source']})



def evidence_guard(plan):
    value = decode(checked(plan['generation_evidence']))
    require(value['schema'] == 'hepta.hia.patch-terminal.generation-evidence.v1'
            and value['product_execution'] == 0, 'fixed static predecessor map required')
    before = {}
    for root in value['roots']:
        current = metadata(Path(root['path']))
        filtered = {name:info for name, info in current.items()
                    if not any(name == prefix or name.startswith(prefix + '/') for prefix in root['exclude'])}
        require(filtered == root['state'], 'actual generation evidence complete pathset/stat differs')
        before[root['path']] = filtered
    for row in value['files']:
        checked(row)
    for row in value['directories']:
        path = Path(row['path'])
        require(seven(path.lstat()) == row['stat'] and stat.S_ISDIR(path.lstat().st_mode),
                'frozen generation evidence directory changed')
    for root in value['roots']:
        current = metadata(Path(root['path']))
        filtered = {name:info for name, info in current.items()
                    if not any(name == prefix or name.startswith(prefix + '/') for prefix in root['exclude'])}
        require(filtered == before[root['path']], 'generation evidence changed during complete reads')
    result = decode(checked(plan['generation_result']))
    terminal = decode(checked(plan['generation_terminal']))
    require(result['status'] == 'PASS_GENERATION_ONLY_TWO_RUNS_AND_ORIGINAL_CHECK'
            and terminal['status'] == 'PASS_COMPLETE_GENERATION_TERMINAL_READBACK'
            and terminal['source_files'] == 3211 and terminal['actual_owners'] == 3
            and terminal['source_tree'] == plan['mother_source']['tree'],
            'actual generation and independent terminal predecessor required')
    return {'actual_generation_files':len(value['files']), 'every_file_fresh_read':True,
            'actual_root_terminal':plan['generation_terminal']['pin']}



def actual_generation_guard(plan):
    manifest = decode(checked(plan['generation_custody_manifest']))
    require(manifest['file_count'] == 140 and manifest['logical_bytes'] == 34477797
            and len(manifest['files']) == 140, 'complete actual generation custody map differs')
    for logical, row in sorted(manifest['files'].items()):
        expected = dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),row['seven_stats']))
        descriptor = {'path':row['source_path'],'pin':{**row['identity'],
            'mode':'100755' if row['mode'] & 0o111 else '100644'},'stat':expected}
        require(stat.S_IMODE(expected['st_mode']) == row['mode'], 'actual generation mode differs')
        checked(descriptor)
    result = decode(checked(plan['generation_result'])); terminal = decode(checked(plan['generation_terminal']))
    require(result['status'] == 'PASS_GENERATION_ONLY_BOTH_TWO_RUNS_AND_ORIGINAL_CHECKS'
            and result['actual_owner_launch_attempts'] == 6 and result['all_six_owner_results_pass'] is True
            and terminal['status'] == 'PASS_COMPLETE_OP8_TWO_GENERATOR_TERMINAL_READBACK',
            'actual six-owner generation and full terminal proof required')
    return {'files':140,'all_bytes_read':True,'result':plan['generation_result']['pin'],
            'terminal':plan['generation_terminal']['pin']}



def actual_maps_guard(plan):
    current = decode(checked(plan['source_map']))
    authority = decode(checked(plan['actual_authority_maps']))
    r5 = decode(checked(plan['r5_actual'])); patch14 = decode(checked(plan['patch14_actual']))
    require(authority['status'] == 'ACTUAL_GENERATED_AUTHORITY_MAPS_NOT_QUALIFICATION'
            and authority['source_tree'] == SOURCE_TREE
            and authority['source_map'] == plan['source_map']
            and authority['r5_actual'] == plan['r5_actual']
            and authority['patch14_actual'] == plan['patch14_actual']
            and authority['old_R5_or_Patch14_PASS_transferred'] is False
            and len(current) == 3210 and len(r5) == 3191 and len(patch14) == 14
            and not set(r5) & set(patch14)
            and set(current) == set(r5) | set(patch14) | set(plan['cli_five_paths'])
            and all(current[n] == p for table in (r5,patch14) for n,p in table.items()),
            'actual 3191+14+5 complete new source authorities required')
    for name, row in plan['external_tests'].items():
        require(row == authority['external_tests'][name], 'external controls must use original fixed authority')
        checked(row)
        require(not Path(row['path']).is_relative_to(Path(plan['source'])), 'new controls must remain external')
    return {'r5':3191,'patch14':14,'source':3210,'old_pass_inherited':False}



def cohort_guard(plan):
    matrix = matrix_for(plan)
    retained = decode(checked(plan['controls']['OP8-ORIGINAL-TEST-INVENTORY.json']))
    current = decode(checked(plan['source_map'])); state = decode(checked(plan['source_state']))
    for original in retained['retained_test_bytes']:
        name = original['path']
        identity = {k:original[k] for k in ('bytes','sha256','git_blob')}
        identity['mode'] = '100755' if original['mode'] & 0o111 else '100644'
        require(current[name] == identity and stat.S_IMODE(state[name]['st_mode']) == original['mode'],
                'original complete test file differs')
        checked({'path':str(Path(plan['source'])/name),'pin':current[name],'stat':state[name]})
    for label, relative, cls, module in (
        ('report-source12','tests/test_hia_cli_verified_report_native.py','CliVerifiedReportSourceTests',
         'tests.test_hia_cli_verified_report_native'),
        ('report-native2','tests/test_hia_cli_verified_report_native.py','CliVerifiedReportNativeTests',
         'tests.test_hia_cli_verified_report_native'),
        ('external-op8-eight',None,'CliAsDictBoundaryTests','__main__')):
        row = plan['external_tests']['op8_external8'] if relative is None else {
            'path':str(Path(plan['source'])/relative),'pin':current[relative],'stat':state[relative]}
        tree = ast.parse(checked(row))
        owner = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name == cls)
        ids = sorted(module+'.'+cls+'.'+n.name for n in owner.body
                     if isinstance(n,ast.FunctionDef) and n.name.startswith('test_'))
        require(ids == next(r for r in matrix['groups'] if r['label'] == label)['ids'],
                'complete original or external test method set differs')
    return matrix



def immutable_guard(plan):
    fixed_shape(plan); control_guard(plan)
    for row in plan['expected_runtime'].values(): checked(row)
    runtime = runtime_files_guard(plan)
    base = complete_source(plan['base_source']); mother = complete_source(plan['mother_source'])
    prior = complete_source(plan['prior_base']); protected = protected_source(plan)
    old = old_generation_guard(plan); current = actual_generation_guard(plan)
    maps = actual_maps_guard(plan); cohort_guard(plan)
    return {'base3210':base,'mother3211':mother,'prior3210':prior,'protected3180':protected,
            'runtime2496':runtime,'old_generation':old,'actual_generation':current,'actual_maps':maps}



def bound_guard(plan, runtime_guard=None):
    require(plan['state'] == 'BOUND_AWAITING_ROOT_AUTHORIZATION', 'actual preparation binding required')
    value = immutable_guard(plan); guard_directories(plan['source_ancestors'])
    current = all_guards(plan, runtime_guard); packaging = packaging_guard(plan)
    return {'immutable':value,'candidate3210':current,'packaging':packaging}



def core_environment(plan, row, directory, bundle):
    env = environment(plan)
    value = decode(checked(plan['packaging_inputs']))
    if row['label'] == 'original-cli43':
        env['PYTHONPATH'] = value['pythonpath']
        env['HEPTA_HIA_TEST_PACKAGING_PYTHON'] = plan['runtime']['launch_executable']
        env['PIP_NO_CACHE_DIR'] = '1'
        env['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    if row['label'] in ('report-native2','original-cli43','external-op8-eight'):
        require(bundle is not None, 'actual six-image build must precede Native tests')
        env['HEPTA_HIA_CLI_VERIFIED_REPORT_DEVELOPMENT_MANIFEST'] = bundle['path']
        env['HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST'] = bundle['path']
        env['HEPTA_HIA_CLI_VERIFIED_REPORT_EVIDENCE'] = str(directory/'report-evidence')
        env['HEPTA_HIA_CLI_FIXTURE_EVIDENCE'] = str(directory/'cli-evidence')
    return env



def packed_bytes(value, directory):
    extent = value['bytes']; require(type(extent) is int and 0 <= extent <= CAPACITY, 'frame extent exceeds original cap')
    if 'fixed_file' in value:
        name = value['fixed_file']; require(Path(name).name == name and name not in ('','.','..'), 'unsafe fixed frame member')
        raw = checked(capture(directory/name, maximum=CAPACITY))
    else:
        compressed = base64.b64decode(value['zlib_base64'], validate=True)
        decoder = zlib.decompressobj(); raw = decoder.decompress(compressed, extent+1)
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, 'partial or excess frame payload')
    require(len(raw) == extent and hashlib.sha256(raw).hexdigest() == value['sha256'], 'complete frame bytes differ')
    if 'git_blob' in value: require(pin(raw)['git_blob'] == value['git_blob'], 'frame Git identity differs')
    return raw



def components_readback(directory,bound,source_map,names,image_history):
 envelope,_,_=jsread(directory/'ACTUAL-COMPONENTS.json','actual-components');require(set(envelope)=={'bundle','components'}and set(envelope['components'])==set(names),'actual component set differs');rows=[]
 if envelope['bundle']is not None:observed_fixed(envelope['bundle'],'actual-six-image-bundle')
 for name,desc in envelope['components'].items():
  require(set(desc)=={'image','manifest','source'},'component descriptor differs');image=native_artifact(desc['image'],'new-image:'+name,image_history);manifest=decode(observed_fixed(desc['manifest'],'new-manifest:'+name));source=observed_fixed(desc['source'],'new-compile-source:'+name);relative=bound['component_sources'][name]
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



checked = fixed
guard_directories = directories


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


observer = IndependentObserver()


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


def image_history_readback(attempt):
    directory = Path(attempt) / '03-report-native2'
    names = ('CHILD-REPORT-IMAGE-TIMESTAMPS.json','REPORT-IMAGE-TIMESTAMPS.json')
    if not all((directory / name).is_file() for name in names):
        return {}
    values = [decode(read(directory / name)) for name in names]
    require(values[0] == values[1], 'child and parent image restore witnesses differ')
    row = values[0]; before = row['before']; after = row['after']
    require(row['allowed_change'] == ['st_mtime_ns','st_ctime_ns']
            and row['original_test_writes_preserved'] is True
            and before['path'] == after['path'] and before['pin'] == after['pin']
            and all(before['stat'][k] == after['stat'][k]
                for k in ('st_dev','st_ino','st_mode','st_nlink','st_size')),
            'image witness changed bytes, mode, inode, extent or links')
    require(Path(after['path']).is_relative_to(Path(attempt)/'02-build-report-six')
            and Path(after['path']).name == 'verified-report.image.bin', 'unexpected mutable image')
    observed_fixed(after, 'actual-restored-verified-report-image')
    return {after['path']:row}


def native_artifact(row, role, image_history):
    transition = image_history.get(row['path'])
    if transition is None:
        return observed_fixed(row, role)
    require(row in (transition['before'],transition['after']), 'unrecognized image timestamp descriptor')
    return observed_fixed(transition['after'], role+':actual-restored-bytes-and-seven-stat')


def authorities(authority):
    bound_raw = fixed(authority['bound']); bound = decode(bound_raw)
    binding = decode(fixed(authority['binding'])); template_raw = fixed(bound['template'])
    template = decode(template_raw)
    require(binding['plan'] == authority['bound'] and binding['author_plan'] == bound['template']
            and binding['status'] == 'BOUND_NOT_EXECUTED' and binding['products_executed'] == 0
            and binding['copied_source_files'] == 0 and binding['source_copy_performed'] is False
            and binding['copied_packaging_files'] == 667 and binding['old_qualification_inherited'] is False,
            'actual source-in-place and packaging binding differs')
    require(set(bound) == set(template) | {'template'}
            and all(bound[k] == v for k,v in template.items()
                if k not in ('state','scope_ancestors','source_ancestors','packaging_binding')),
            'whole original bound-plan inverse differs')
    require(bound['template'] == authority['author_plan'] and bound['scope'] == str(SCOPE)
            and bound['source'] == ACTUAL_SOURCE and bound['attempt'] == str(SCOPE/'attempt-r1')
            and bound['source_tree'] == TREE and bound['source_files'] == 3210
            and bound['limits'] == LIMITS and bound['storage_floor'] == 1 << 30,
            'actual source tree, paths or original budgets differ')
    summary = bound_guard(bound)
    require(binding['immutable_before'] == binding['immutable_after'] == summary['immutable']
            and binding['source_before'] == binding['source_after'] == summary['candidate3210'],
            'preparation and independently fresh current source/runtime summaries differ')
    package = decode(fixed(bound['packaging_binding']))
    package_rows = decode(fixed(package['map']))
    require(binding['packaging_binding'] == bound['packaging_binding']
            and binding['packaging_copy_rows'] == package_rows
            and len(package_rows) == 667, 'actual independent packaging COPY rows differ')
    flat = decode(fixed(bound['source_map'])); state = decode(fixed(bound['source_state']))
    inodes = {(s['st_dev'],s['st_ino']) for n,s in state.items() if n in flat}
    require(len(inodes) == 3210, 'actual source independent inode count differs')
    for name in ('base_source','mother_source','prior_base'):
        other = decode(fixed(bound[name]['state']))
        require(not inodes & {(s['st_dev'],s['st_ino']) for s in other.values() if stat.S_ISREG(s['st_mode'])},
                'actual op8 source aliases a protected original source')
    matrix = matrix_for(bound)
    return bound,binding,flat,state,matrix,summary


def stages_readback(authority, bound, parent, matrix, source_map, guarded, image_history):
    attempt=Path(bound['attempt']); stages=parent['stages']; expected=matrix['groups']
    require(parent['status'] in (SUCCESS,'FAIL') and 0 < len(stages) <= 5
            and parent['actual_owner_launch_attempts'] == len(stages)
            and [r['label'] for r in stages] == [r['label'] for r in expected[:len(stages)]],
            'actual owners are not the original ordered prefix')
    if parent['status'] == SUCCESS:
        require(len(stages) == 5 and all(r['status']=='PASS' for r in stages), 'successful core lacks all five owners')
    else:
        require(all(r['status']=='PASS' for r in stages[:-1]) and stages[-1]['status']=='FAIL'
                and parent['halted_after_first_failure'] is True, 'actual failure did not stop later groups')
    names=['%02d-'%(i+1)+r['label'] for i,r in enumerate(expected[:len(stages)])]
    require(sorted(p.name for p in attempt.iterdir() if p.is_dir() and re.match(r'^[0-9]{2}-',p.name))==names,
            'missing or extra stage output directory')
    require(decode(read(attempt/'PLAN-USED.json'))==bound
            and decode(read(attempt/'RUNTIME.json'))==bound['runtime'], 'actual parent plan/runtime differs')
    owners=[]; tests=[]; compiles=[]; native={}; bundle=None; details=[]
    for ordinal,(declared,stage) in enumerate(zip(expected,stages),1):
        directory=attempt/('%02d-'%ordinal+declared['label']); label=declared['label']; passed=stage['status']=='PASS'
        require(decode(read(directory/'STAGE.json'))==stage and stage['directory']==str(directory)
                and stage['ids']==declared['ids'] and stage['finished_ns']>=stage['started_ns']>0,
                'actual stage does not match exact declared owner')
        request,rdesc,rraw=jsread(directory/'REQUEST.json','original-core-request')
        env=core_environment(bound,declared,directory,bundle)
        wanted={'schema':SCHEMA+'.core-request','plan':authority['bound'],'limits':LIMITS,
                'group':label,'ids':declared['ids'],'flags':declared['flags'],'directory':str(directory),
                'environment':env,'product_root_binding':request['product_root_binding'],
                'native_inputs':native,'report_bundle':bundle}
        require(request==wanted, 'complete actual core request or previous build binding differs')
        directories(request['product_root_binding'])
        require(request['product_root_binding'][-1]['path']==str(attempt), 'owner output-root authority differs')
        command=decode(read(directory/'COMMAND.json'))
        require(command=={'command':[bound['runtime']['launch_executable'],*declared['flags'],
                bound['controls']['run_core_child.py']['path'],'--request',str(directory/'REQUEST.json'),
                '--request-sha256',rdesc['pin']['sha256']], 'cwd':bound['source'],
                'environment':env,'supervisor_environment':env,'qualification_seconds':180,'cleanup_seconds':3},
                'exact original child argv/environment/limits differ')
        owner=decode(read(directory/'OWNER.json')); code=owner['returncode']
        if passed:require(code==0,'successful owner returned nonzero')
        owners.append(owner_readback(directory,command,stage,source_map,code))
        child=decode(observed_fixed(stage['child_result'],'actual-core-child-result'))
        require(stage['child_result']['path']==str(directory/'CORE-CHILD-RESULT.json')
                and child['request_pin']==physical_pin(rraw) and child['group']==label
                and child['schema']==SCHEMA+'.core-child-result' and child['nested_owner_launches']==0
                and child['test_body_changed'] is False and child['source_copy'] is False,
                'actual guarded child identity differs')
        flags=child['runtime_flags']; isolated=int('-I' in declared['flags'])
        require(flags['isolated']==flags['ignore_environment']==isolated
                and flags['dont_write_bytecode']==1
                and flags['executable']==bound['runtime']['launch_executable']
                and flags['python'].startswith('3.14.4 '), 'actual child flags/runtime differ')
        if passed:
            require(child['status']=='PASS' and child['full_before']==child['full_after']==guarded
                    and stage['source_after']==guarded and not child.get('terminal_guard_errors')
                    and not stage.get('terminal_errors'), 'actual successful child lacks complete guards')
        require(all(child[k] is False for k in ('current_cold','default','whole')), 'child expands qualification scope')
        if declared['kind']=='build':
            require(label=='build-report-six' and native=={} and bundle is None, 'unexpected or repeated build group')
            nested,ndesc,nraw=jsread(directory/'BUILD-REQUEST.json','original-six-build-request')
            require(nested=={'schema':SCHEMA+'.build-request','plan':authority['bound'],
                    'group':label,'directory':str(directory),'limits':LIMITS}, 'actual inner build request differs')
            build_result=decode(read(directory/'RESULT.json')); build=decode(read(directory/'BUILD.json'))
            require(child['original_build_returncode']==0 and child['build_result']['path']==str(directory/'RESULT.json')
                    and decode(observed_fixed(child['build_result'],'actual-original-six-build-result'))==build_result
                    and build_result['status']=='PASS' and build_result['request_pin']==physical_pin(nraw)
                    and build_result['source_before']==build_result['source_after']==product_source_summary(bound)
                    and build_result['build']==build and build_result['all_compile_workspaces_observed'] is False
                    and build['matching_current_cold'] is False and build['six_real_compilations'] is True,
                    'actual six development compilations are incomplete or overclaimed')
            envelope,rows=components_readback(directory,bound,source_map,REPORT_COMPONENTS,image_history)
            native=envelope['components']; bundle=envelope['bundle']; compiles.extend(rows)
            require(bundle is not None, 'actual six-image bundle missing')
        else:
            tests.append(tests_readback(directory,declared['ids'],child,
                                       decode(read(directory/'TESTS.json'))['status']))
            if passed:require(tests[-1]['status']=='PASS','successful owner contains failed original assertions')
            require(child['external_test_loaded'] is (label=='external-op8-eight'), 'external test selection differs')
            if label=='external-op8-eight':
                t=decode(read(directory/'TESTS.json')); original=decode(observed_fixed(t['original_result'],'external8-original-main-result'))
                require(t['original_launcher_has_no_subtest_recording'] is True and t['subtests']==[]
                        and original['passed'] is True and original['loaded_ids']==declared['ids']
                        and original['events']==t['events'] and original['tests_run']==8
                        and all(original[k]==t[k] for k in ('failures','errors','skipped','expected_failures','unexpected_successes')),
                        'complete original external8 main result differs')
        for name,component in request['native_inputs'].items():
            for kind,descriptor in component.items():native_artifact(descriptor,'fresh-stage-'+name+'-'+kind,image_history)
        if request['report_bundle'] is not None:observed_fixed(request['report_bundle'],'fresh-stage-selected-report-bundle')
        if label=='report-native2':
            require(len(image_history)==1,'original warm/strict image witnesses missing')
            transition=next(iter(image_history.values()))
            require(native['verified_report']['image']==transition['before'], 'warm/strict prior image is not the new build')
            native['verified_report']['image']=transition['after']
        details.append({'label':label,'directory':str(directory),'status':stage['status'],
                        'ids':declared['ids'],'flags':declared['flags'],'request':rdesc,'child':stage['child_result']})
    require(parent['required_owners']==5 and parent['required_methods']==65 and parent['required_compile_calls']==6
            and parent['free_before']>=1<<30 and parent['source_after']==guarded
            and parent['original_cli43_flags']==['-B'] and parent['source_copy'] is False
            and parent['automatic_retry'] is False and parent['old_PASS_transferred'] is False
            and parent['full_Patch_Inspect_R6_integration_complete'] is False
            and parent['original_R5_witness10']=='HISTORICAL_FAIL_UNCHANGED_REQUIRES_EXPLICIT_R6_SUCCESSOR'
            and all(parent[k] is False for k in ('current_cold','default','whole')), 'actual core boundary expanded')
    if parent['status']==SUCCESS:
        require(parent['native_inputs']==native and parent['report_bundle']==bundle
                and parent['original140_executed'] is True and parent['original_cli43_executed'] is True
                and parent['external8_executed'] is True and len(compiles)==6, 'complete core result differs')
    return {'owners':owners,'tests':tests,'compiles':compiles,'components':native,'bundle':bundle,
            'stages':details,'not_started':[r['label']for r in expected[len(stages):]],'image_history':image_history}


def report140_readback(path, bound, matrix, source_map, source_state, calls, journal_pin):
    report, descriptor, _ = jsread(path, 'complete-original140-report')
    require(report['schema']=='hepta.verified-report.actual-observations.v1'
            and report['scope']=='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
            and report['status']=='PASS' and report['new_whole_verify_claim'] is False
            and report['case_count']==len(report['cases'])==140
            and [row['name'] for row in report['cases']]==matrix['report_cases']
            and report['failed_cases']==[] and report['actual_machine_frames']==calls
            and report['actual_machine_frames_file']=={k:journal_pin[k] for k in ('bytes','sha256')}
            and report['source_unchanged'] is True and report['session_released_without_gc'] is True,
            'complete original140 report and actual journal disagree')
    for row in report['cases']:
        require(row['actual']==row['expected'] and row['equal'] is True
                and type(row['actual_hia_entries']) is int and row['actual_hia_entries']>=0
                and row['passed'] is (row['equal'] and
                    (row['actual_hia_entries']>0 or not row['require_native']) and
                    (not row['original_policy_frames'] or not row['require_no_original_frames']))
                and row['passed'] is True, 'original case values, effects or policy-frame predicate differ')
    for key, filename in (('actual_selected_manifest','verified-report-bundle.json'),
                          ('actual_companion_manifest','manifest.json')):
        row=report[key]
        wanted=Path(bound['attempt'])/'02-build-report-six/six-image-bundle'/filename
        require(row['path']==str(wanted), 'original140 selected an unexpected actual manifest')
        raw,_=observed_read(wanted,'original140-'+key,expected={k:row[k] for k in ('bytes','sha256')})
    snapshots=[]
    for filename in ('SOURCE-BEFORE.json','SOURCE-AFTER.json'):
        snapshot=decode(read(path.parent/filename));snapshots.append(snapshot)
        require(set(snapshot)==set(source_map), 'original140 source snapshot pathset differs')
        for name,row in snapshot.items():
            expected={'bytes':source_map[name]['bytes'],'sha256':source_map[name]['sha256'],
                      'mode':stat.S_IMODE(source_state[name]['st_mode'])}
            require(row==expected, 'original140 original source bytes/mode snapshot differs')
            observed_fixed({'path':str(Path(bound['source'])/name),'pin':source_map[name],
                            'stat':source_state[name]},'original140-'+filename+':'+name)
    require(snapshots[0]==snapshots[1], 'original140 complete source snapshots differ')
    return {'report':descriptor,'cases':report['cases'],'case_count':140,
            'selected_manifest':report['actual_selected_manifest'],
            'companion_manifest':report['actual_companion_manifest'],
            'native_entries_self_report':report['native_entries'],
            'session_released_without_gc':True,'complete_snapshots_equal':True,
            'only_returned_calls_journaled':True,'absent_exception_frames_proved':False}


def frames_readback(bound,parent,matrix,source_map,source_state,initial_attempt):
    attempt=Path(bound['attempt']);journals=[];reports=[];total=0;returned=0;exceptions=0;buffer_reads=0
    calls=LEDGER.sequence('every-original-native-call-with-six-full-buffer-pins')
    processed=set();report140=None
    for stage in parent['stages']:
        if stage['label'] not in ('report-native2','external-op8-eight'):
            require('frame_readback' not in stage,'unrecognized stage frame protocol')
            continue
        directory=Path(stage['directory']);external=stage['label']=='external-op8-eight'
        basename='REPORT-FULL-SIX-BUFFERS.jsonl' if external else 'ACTUAL-MACHINE-FRAMES.jsonl'
        paths=sorted(attempt/name for name,state in initial_attempt.items()
            if stat.S_ISREG(state['st_mode']) and (attempt/name).is_relative_to(directory)
            and Path(name).name==basename)
        rows=[];stage_calls=0;stage_buffers=0
        if stage['status']=='PASS':require(len(paths)==1,'complete actual journal missing')
        for path in paths:
            processed.add(str(path));count=0;images={};local_returns=0;local_errors=0
            for row in fresh_json_lines(path,'original-full-native-journal:'+stage['label']):
                require(type(row['index']) is int and row['index']==count,'actual Native journal order gap')
                if external:
                    require(set(row)=={'index','return','exception','before','after'}
                        and len(row['before'])==len(row['after'])==3,'external finally six-buffer record differs')
                    values=row['before']+row['after'];image='verified_report'
                    require((type(row['return']) is int and row['exception'] is None)
                        or (row['return'] is None and row['exception'] is not None),
                        'actual external returned/exception observation ambiguous')
                else:
                    require(set(row)=={'index','image','return',*FRAME_KEYS}
                        and row['image'] in ('report','cli-control') and type(row['return']) is int,
                        'original returned-only report journal schema differs')
                    values=[row[k] for k in FRAME_KEYS];image=row['image']
                # Each occurrence is fully decoded or freshly read. No payload/digest cache.
                buffers=[]
                for value in values:
                    raw=packed_bytes(value,path.parent)
                    buffers.append({'pin':physical_pin(raw),'record':value})
                    # Keep metadata only; never retain the inline compressed input payload.
                    buffers[-1]['record']={k:v for k,v in value.items() if k!='zlib_base64'}
                    del raw
                ordered=buffers
                require(all(buffers[i]['pin']['bytes']==buffers[i+3]['pin']['bytes'] for i in range(3)),
                        'physical buffer extents changed within one call')
                did_return=type(row['return']) is int
                calls.append({'journal':str(path),'index':count,'image':image,'return':row['return'],
                    'exception':row.get('exception'),'buffer_order':
                        ['source_before','output_before','workspace_before','source_after','output_after','workspace_after']
                        if external else list(FRAME_KEYS),
                    'six_complete_buffers':ordered,'capture_boundary':'finally' if external else 'returned_only'})
                count+=1;stage_buffers+=6;images[image]=images.get(image,0)+1
                local_returns+=int(did_return);local_errors+=int(not did_return)
            descriptor=SEEN[str(path)]
            require(descriptor['stat']==initial_attempt[str(path.relative_to(attempt))],
                    'actual journal identity changed since terminal snapshot')
            rows.append({'path':str(path),'calls':count,'stat':descriptor['stat']})
            journals.append({'journal':descriptor,'calls':count,'returned_calls':local_returns,
                             'exception_calls':local_errors,'images':images,
                             'capture_boundary':'finally' if external else 'returned_only'})
            if not external and stage['status']=='PASS':
                report140=report140_readback(path.parent/'REPORT.json',bound,matrix,
                                            source_map,source_state,count,descriptor['pin'])
            stage_calls+=count;returned+=local_returns;exceptions+=local_errors
        expected={'journals':rows,'calls':stage_calls,'complete_buffer_reads':stage_buffers,
            'producer_finally_limit':'original140 only records returned Native calls; external8 records in finally',
            'not_a_claim_of_absent_exception_frames':True}
        if 'frame_readback' in stage:
            require(stage['frame_readback']['path']==str(directory/'FRAME-READBACK.json')
                    and decode(observed_fixed(stage['frame_readback'],'actual-parent-frame-report'))==expected,
                    'parent frame report differs from independent full journal reads')
        reports.append({'label':stage['label'],**expected});total+=stage_calls;buffer_reads+=stage_buffers
    actual_jsonl={str(attempt/name)for name,state in initial_attempt.items()
        if stat.S_ISREG(state['st_mode']) and name.endswith('.jsonl')}
    require(actual_jsonl==processed,'additional actual journal lacks an explicit complete protocol reader')
    require(len(calls)==total and returned+exceptions==total and buffer_reads==6*total,
            'complete native six-buffer accounting differs')
    return {'journals':journals,'calls':calls,'actual_calls':total,'actual_returned_calls':returned,
        'actual_exception_calls':exceptions,'complete_buffer_reference_reads':buffer_reads,
        'parent_reports':reports,'original140':report140,
        'every_record_fresh_decoded':True,'buffer_payload_cache':False,
        'original140_capture_boundary':'only calls that returned from the wrapped machine entry',
        'external8_capture_boundary':'finally after attempted machine entry',
        'absent_exception_frames_proved':False,'all_frames_retired':False,'native_vm_replayed':False}


def installed_wheel_readback(bound,stage_result):
    base=Path(bound['attempt'])/'04-original-cli43/cli-evidence/CliNativeTests/installed-control'
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


LINK_TARGET_READS=0
LINK_TARGET_BYTES=0


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


def evidence_type_admission(authority,attempt_state,outer_state,scope_state):
    original=decode(fixed(authority['evidence_types']))
    require(original['schema']=='hepta.hia.op8-core.actual-evidence-types.v1'
        and original['product_execution']==0 and original['regular_payload_reads']==0,
        'actual no-follow type authority differs')
    for label,current in (('attempt',attempt_state),('outer',outer_state),('scope',scope_state)):
        wanted=original['roots'][label]
        require(current==wanted['state'],'actual evidence complete typed pathset/seven-stat/target differs')
        inodes={};links=[];opaque=[]
        for name,row in current.items():
            if stat.S_ISREG(row['st_mode']):inodes.setdefault((row['st_dev'],row['st_ino']),[]).append(name)
            if stat.S_ISLNK(row['st_mode']):links.append(name)
            if 'opaque_special'in row:opaque.append(name)
        aliases=[names for names in inodes.values()if len(names)>1]
        require(aliases==wanted['regular_aliases']==[] and links==wanted['symbolic_links']
            and opaque==wanted['opaque_specials']==[], 'unexpected alias or special evidence node')
    require(original['roots']['attempt']['symbolic_links']==[
        '04-original-cli43/cli-evidence/CliNativeTests/bounded-inputs/input-link'],
        'unexpected original test symlink set')
    return original


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


def outer_terminal(authority,bound,parent):
    launch_raw=fixed(authority['product_launch']);launch=decode(launch_raw)
    command=[bound['runtime']['launch_executable'],'-I','-B',bound['controls']['run_core.py']['path'],
        '--plan',authority['bound']['path'],'--plan-sha256',authority['bound']['pin']['sha256'],
        '--binding',authority['binding']['path'],'--binding-sha256',authority['binding']['pin']['sha256'],
        '--author-plan-sha256',authority['author_plan']['pin']['sha256']]
    env={'HOME':'/workspace','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
        'LD_LIBRARY_PATH':bound['runtime']['library_directory'],'PATH':'/usr/local/bin:/usr/bin:/bin',
        'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','TZ':'UTC'}
    require(launch['schema']=='hepta.hia.op8-core.actual-preparation-product-intent.v1'
        and launch['state']=='NOT_EXECUTED_ROOT_ONLY' and launch['products_executed']==0
        and launch['plan']==authority['bound'] and launch['binding']==authority['binding']
        and launch['author_plan']==authority['author_plan'] and launch['parent']==bound['controls']['run_core.py']
        and launch['actual_source_tree']==TREE and launch['command']==command
        and launch['environment']==env and launch['cwd']==str(Path(bound['controls']['run_core.py']['path']).parent.parent)
        and launch['inner_owners']==5 and launch['original_inner_owner_seconds']==180
        and launch['original_inner_cleanup_seconds']==3 and launch['outer_watchdog_seconds']==1800
        and launch['outer_cleanup_seconds']==3 and launch['no_automatic_retry'] is True,
        'complete actual original product launch differs')
    values={name:fixed(row)for name,row in authority['outer_files'].items()}
    require(set(values)=={'INTENT.json','RESULT.json','SPAWNED.json','stdout.bin','stderr.bin'}
        and all(row['path']==str(OUTER/name)for name,row in authority['outer_files'].items()),
        'complete actual outer file set or path differs')
    intent=decode(values['INTENT.json']);result=decode(values['RESULT.json']);spawn=decode(values['SPAWNED.json'])
    require(intent['argv']==['/usr/bin/env','-i']+[k+'='+v for k,v in env.items()]+command
        and intent['product_argv']==command and intent['environment']==env and intent['cwd']==launch['cwd']
        and intent['status']=='ROOT_AUTHORIZED_OP8_CORE_QUALIFICATION_ONCE'
        and intent['original_owner_seconds']==180 and intent['outer_watchdog_seconds']==1800
        and intent['cleanup_seconds']==3 and intent['maximum_attempts']==1
        and intent['planned_owner_count']==5 and intent['planned_methods']==65
        and intent['planned_compile_calls']==6 and intent['source_files']==3210
        and intent['report_cases']==140 and intent['new_external_methods']==8
        and intent['fail_stop'] is True and intent['original_cli43_complete'] is True
        and intent['old_failures_retained'] is True and intent['whole_native'] is False
        and intent['source_full_guards_required_by_original_parent_and_children'] is True
        and intent['launch']==pin(launch_raw), 'actual outer clean invocation or scope differs')
    s=authority['product_launch']['stat']
    require(intent['launch_seven_stats']==[s[k]for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
        and intent['review']==pin(fixed(authority['root_author_review']))
        and intent['data_preparation_review']==pin(fixed(authority['preparation_readback'])),
        'actual outer predecessor binding differs')
    code=0 if parent['status']==SUCCESS else 1
    require(result['schema']=='hia.root.op8-core.qualification.outer-result.v1'
        and result['returncode']==code and result['timeout'] is False and result['ECHILD'] is True
        and result['process_group_absent'] is True and result['adopted']==[] and result['subreaper'] is True
        and result['direct_restored_interpreter_invocations']==result['maximum_attempts']==1
        and result['pid']==spawn['pid']==spawn['pgid'] and spawn['started_monotonic_ns']>0
        and result['elapsed_ns']>=parent['finished_ns']-parent['started_ns']>0
        and result['product_counts_require_original_journals'] is True
        and result['requires_actual_original_phase_and_full_frame_readback'] is True,
        'actual outer process termination or cleanup differs')
    if code==0:require(result['status']=='PASS_OP8_CORE_QUALIFICATION_PARENT_PROCESS_ONLY','successful outer status differs')
    require(pin(values['stdout.bin'])==result['stdout'] and pin(values['stderr.bin'])==result['stderr'],
            'complete outer stdout/stderr differs')
    return result


def verify_terminal(plan_path,expected_sha,output):
    global SEEN,OBSERVED_READS,LEDGER
    started=time.monotonic_ns()
    require(plan_path==AUTHOR/'READBACK-PLAN.json' and output==OUTPUT and not os.path.lexists(output),
            'fixed independent plan and new output required')
    output.mkdir(mode=0o700)
    LEDGER=Ledger(output);SEEN=LEDGER.mapping('unique-input-descriptors',full_reads=True)
    OBSERVED_READS=LEDGER.sequence('ordered-observation-reads')
    result={'schema':'hepta.hia.op8-core.independent-terminal-result.v1','status':'FAIL',
        'product_execution':0,'project_imports':0,'binder_execution':0,'source_copy':False,
        'all_frames_retired':False,'full_compile_workspaces_observed':False,
        'all_native_frames_vm_replayed':False,'whole_native':False,'current_cold':False,
        'started_ns':started}
    try:
        raw=read(plan_path);require(hashlib.sha256(raw).hexdigest()==expected_sha,'reader plan SHA differs')
        authority=decode(raw)
        require(authority['schema']=='hepta.hia.op8-core.independent-terminal-plan.v1'
            and authority['scope']==str(SCOPE) and authority['outer']==str(OUTER)
            and authority['output']==str(OUTPUT) and authority['product_execution']==0
            and authority['original_owners']==5 and authority['original_methods']==65
            and authority['original_compiles']==6 and authority['original_report_cases']==140,
            'exact independent reader authority differs')
        fixed(authority['reader'])
        for descriptor in authority['root_metadata'].values():fixed(descriptor)
        bound,binding,source_map,source_state,matrix,guarded=authorities(authority)
        runtime,runtime_state,runtime_inodes=runtime_authority(bound)
        parent=decode(fixed(authority['actual_result']));attempt=Path(bound['attempt'])
        require(authority['actual_result']['path']==str(attempt/'RESULT.json')
            and parent['schema']==SCHEMA+'.core-result'
            and parent['plan_pin']==authority['bound']['pin'] and parent['binding_pin']==authority['binding']['pin'],
            'actual core result identity differs')
        initial_attempt=evidence_metadata(attempt);initial_outer=evidence_metadata(OUTER);initial_scope=evidence_metadata(SCOPE)
        require({p.name for p in SCOPE.iterdir()}=={'attempt-r1','BOUND-PLAN.json','BINDING-RESULT.json'},
                'unknown or missing actual scope member')
        evidence_type_admission(authority,initial_attempt,initial_outer,initial_scope)
        outer=outer_terminal(authority,bound,parent)
        image_history=image_history_readback(attempt)
        stages=stages_readback(authority,bound,parent,matrix,source_map,guarded,image_history)
        frames=frames_readback(bound,parent,matrix,source_map,source_state,initial_attempt)
        installed=installed_wheel_readback(bound,stages)
        inventory=LEDGER.sequence('complete-actual-original-file-inventory')
        for prefix,root,original in (('attempt',attempt,initial_attempt),('outer',OUTER,initial_outer)):
            for name,state in original.sorted_items():
                if stat.S_ISDIR(state['st_mode']):continue
                if stat.S_ISREG(state['st_mode']):
                    descriptor=fresh_stream_pin(root/name,'complete-original-raw:'+prefix+'/'+name,state)
                else:
                    descriptor=evidence_link_descriptor(root/name,state)
                inventory.append({'logical':prefix+'/'+name,**descriptor})
            require(evidence_metadata(root)==original,'complete actual raw pathset/seven-stat changed during readback')
        for name in ('BOUND-PLAN.json','BINDING-RESULT.json'):
            descriptor=fresh_stream_pin(SCOPE/name,'complete-original-scope:'+name,initial_scope[name])
            inventory.append({'logical':'scope/'+name,**descriptor})
        final_guard=bound_guard(bound);final_runtime,final_runtime_state,_=runtime_authority(bound)
        require(final_guard==guarded and final_runtime==runtime and final_runtime_state==runtime_state,
                'protected source/runtime/controls/packaging identity changed')
        require(evidence_metadata(attempt)==initial_attempt and evidence_metadata(OUTER)==initial_outer and evidence_metadata(SCOPE)==initial_scope,
                'actual evidence paths/stats changed after final full source guards')
        for descriptor in SEEN.values():
            require(seven(Path(descriptor['path']).lstat())==descriptor['stat'], 'final input seven-stat changed')
        methods=sum(row['tests_run']for row in stages['tests']);events=sum(row['events']for row in stages['tests'])
        if parent['status']==SUCCESS:
            require(len(stages['owners'])==5 and len(stages['compiles'])==6 and methods==65 and events==130
                and all(row['status']=='PASS'for row in stages['tests']) and not stages['not_started']
                and len(stages['components'])==6 and frames['original140'] is not None
                and len(frames['journals'])==2 and frames['actual_calls']>0 and installed['present'] is True,
                'successful terminal lacks a complete original core cohort/build/frame/installation')
        full_inventory={'schema':'hepta.hia.op8-core.complete-actual-raw.v1',
            'roots':{'attempt':{'path':str(attempt),'state':initial_attempt},
                     'outer':{'path':str(OUTER),'state':initial_outer}},
            'scope_state':initial_scope,'files':inventory,'file_count':len(inventory),
            'logical_bytes':sum(row['pin']['bytes']for row in inventory),'all_actual_raw_retained':True,
            'all_frames_retired':False}
        publish(output/'STAGES.json',stages);publish(output/'FRAMES.json',frames)
        publish(output/'INSTALLED-WHEEL.json',installed);publish(output/'INVENTORY.json',full_inventory)
        result.update(status='PASS_COMPLETE_OP8_CORE_TERMINAL_READBACK' if parent['status']==SUCCESS
            else 'PASS_FAILURE_EVIDENCE_VERIFIED',product_status=parent['status'],original_result=authority['actual_result'],
            actual_owners=len(stages['owners']),actual_test_methods=methods,actual_test_events=events,
            actual_test_subtests=sum(len(row['subtests'])for row in stages['tests']),
            actual_test_failures=sum(len(row['failures'])for row in stages['tests']),
            actual_test_errors=sum(len(row['errors'])for row in stages['tests']),actual_compiles=len(stages['compiles']),
            actual_native_calls=frames['actual_calls'],actual_native_returned_calls=frames['actual_returned_calls'],
            actual_native_exception_calls=frames['actual_exception_calls'],actual_native_journals=len(frames['journals']),
            complete_native_buffer_reads=frames['complete_buffer_reference_reads'],
            original140_cases=0 if frames['original140'] is None else frames['original140']['case_count'],
            original140_only_returned_calls_journaled=True,external8_finally_six_buffers_journaled=True,
            absent_exception_frames_proved=False,original_cli43_complete=any(row['label']=='original-cli43'
                and row['status']=='PASS'for row in stages['stages']),original_cli43_flags=['-B'],
            wheel_member_count=installed.get('member_count',0),wheel_all_crc_verified=installed.get('all_member_crc_verified',False),
            installed_native_values_are_not_physical_frame_observations=True,
            source_files=3210,source_tree=TREE,runtime_files=2496,packaging_files=667,
            raw_files=len(inventory),raw_bytes=full_inventory['logical_bytes'],outer_process_only=outer,
            raw_regular_files=sum(row['pin']['mode']!='120000'for row in inventory),
            raw_symlink_entries=sum(row['pin']['mode']=='120000'for row in inventory),
            raw_bytes_include_link_target_bytes=True,symlink_targets_followed=False,
            full_Patch_Inspect_R6_integration_complete=False,default=False,
            original_R5_witness10='HISTORICAL_FAIL_UNCHANGED_REQUIRES_EXPLICIT_R6_SUCCESSOR')
    except BaseException:
        result['traceback']=traceback.format_exc()
    finally:
        result.update(finished_ns=time.monotonic_ns(),fresh_full_reads=READS,fresh_full_bytes=BYTES,
            unique_input_paths=len(SEEN),every_reference_fresh=True,result_cache_used=False,
            complete_symlink_target_reads=LINK_TARGET_READS,complete_symlink_target_bytes=LINK_TARGET_BYTES)
        publish(output/'READ-INPUTS.json',StreamValues(SEEN))
        with (output/'OBSERVATION-READS.jsonl').open('xb')as stream:
            for row in OBSERVED_READS:stream.write((json.dumps(row,sort_keys=True)+'\n').encode())
        require(LEDGER.read_count==READS,'complete full-read ledger count differs')
        result['disk_bookkeeping']=LEDGER.close_and_capture();result['input_payload_cache_used']=False
        publish(output/'RESULT.json',result)
    return 0 if result['status'] in ('PASS_COMPLETE_OP8_CORE_TERMINAL_READBACK','PASS_FAILURE_EVIDENCE_VERIFIED') else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--output',required=True);args=parser.parse_args()
    raise SystemExit(verify_terminal(Path(args.plan),args.plan_sha256,Path(args.output)))

