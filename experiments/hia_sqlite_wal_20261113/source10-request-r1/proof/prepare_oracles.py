"""Extract unchanged upstream C functions; do not compile or execute them."""
from pathlib import Path
import hashlib
import json
import os

ROOT=Path(__file__).resolve().parents[1]
COMMITS={'3.46.0':'bebe2d8be8acfd02592c4972f4ba32c3b4e4a33f','3.53.2':'ccc132c5be20ab5c755c97a08d06b1b592fef330'}
EXPECTED={'3.46.0':(174376,'d4a104b5f3cb807e026a9dbcdb77519358b06b66f76cb6b6ef70e3793379dd62'),'3.53.2':(177651,'64d2a6695fbf5d661a9ccb82d160a5fb18698d7175e41828c5ed9428992c7752')}

def function(text,signature):
    start=text.index(signature);opening=text.index('{',start);depth=0;state='code';i=opening
    while i<len(text):
        c=text[i];n=text[i:i+2]
        if state=='block':
            if n=='*/':state='code';i+=2;continue
        elif state=='line':
            if c=='\n':state='code'
        elif state in ('string','char'):
            if c=='\\':i+=2;continue
            if c==('"' if state=='string' else "'"):state='code'
        elif n=='/*':state='block';i+=2;continue
        elif n=='//':state='line';i+=2;continue
        elif c=='"':state='string'
        elif c=="'":state='char'
        elif c=='{':depth+=1
        elif c=='}':
            depth-=1
            if depth==0:return text[start:i+1]+'\n',start,i+1
        i+=1
    raise AssertionError('unterminated C function')

def write(path,raw):
    if not isinstance(raw,bytes):raw=raw.encode()
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    assert path.read_bytes()==raw
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

records=[]
for version,commit in COMMITS.items():
    directory=ROOT/('reference/sqlite-'+version);raw=(directory/'wal.c.original').read_bytes()
    assert (len(raw),hashlib.sha256(raw).hexdigest())==EXPECTED[version]
    excerpts=[]
    for filename,signature in [('checksum.inc','static void walChecksumBytes('),('decode-frame.inc','static int walDecodeFrame(')]:
        body,start,end=function(raw.decode(),signature)
        excerpts.append({'file':filename,'start_byte':start,'end_byte_exclusive':end,**write(directory/filename,body)})
    records.append({'version':version,'git_commit':commit,'url':'https://raw.githubusercontent.com/sqlite/sqlite/'+commit+'/src/wal.c',
                    'whole_source_bytes':len(raw),'whole_source_sha256':hashlib.sha256(raw).hexdigest(),
                    'whole_source_git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
                    'exact_function_excerpts':excerpts})
result={'schema':'hia.sqlite-wal.official-oracle-sources.v1','status':'SOURCES_RETAINED_NOT_COMPILED_OR_EXECUTED',
        'sources':records,'specification':'https://sqlite.org/fileformat.html#walformat',
        'all_source_files_fully_read':True,'source_date':'2026-11-13',
        'implementation_executed':False,'native_executed':False,
        'comment_code_discrepancy':'walDecodeFrame comment says first16 header bytes; executable upstream code checks first8 then page data. The HIA kernel follows code and file-format specification.',
        'C_error_state_difference':'The internal C frame decoder mutates running checksum on checksum failure. The HIA byte API retains immutable controls and leaves output unchanged on any refusal.'}
pin=write(ROOT/'reference/UPSTREAM.json',json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({'upstream':pin,'sources':records}))
