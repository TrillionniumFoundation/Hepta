"""Reconstruct the small author capsule solely from actual full Git GET payloads."""
import base64, hashlib, json, os, stat, zlib
from pathlib import Path
ROOT=Path('/workspace/hia-op8-terminal-readers-author-custody-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def seven(s):return {key:getattr(s,key)for key in FIELDS}
def pin(raw,mode='100644'):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':mode}
def capture(path):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        s=os.fstat(fd);before=seven(s)
        assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<16<<20
        assert before==seven(path.lstat())
        with os.fdopen(fd,'rb',closefd=False)as stream:raw=stream.read(s.st_size+1)
        assert len(raw)==s.st_size and before==seven(os.fstat(fd))==seven(path.lstat())
    finally:os.close(fd)
    return raw,{'path':str(path),'pin':pin(raw,'100755'if s.st_mode&0o111 else'100644'),'stat':before}
publication=json.loads((ROOT/'PUBLICATION-INPUTS.json').read_bytes())
retrieved={};observed=[]
for index,row in enumerate(publication['leaves']):
    actual,actual_descriptor=capture(ROOT/'GIT'/('%03d-GET.txt'%index))
    assert pin(actual)==row['pin']
    ack=json.loads((ROOT/'GIT'/('%03d-ACK.json'%index)).read_bytes())
    verified=json.loads((ROOT/'GIT'/('%03d-VERIFIED.json'%index)).read_bytes())
    assert ack=={'name':row['logical'],'sha':row['pin']['git_blob']}
    assert verified=={'sha':row['pin']['git_blob'],'bytes':len(actual),
        'sha256':row['pin']['sha256'],'full_get_exact':True}
    local,local_descriptor=capture(row['path'])
    assert actual==local and local_descriptor=={key:row[key]for key in ('path','pin','stat')}
    assert row['logical']not in retrieved
    retrieved[row['logical']]=actual
    observed.append({'logical':row['logical'],'pin':row['pin'],'actual_GET':actual_descriptor})
index=json.loads(retrieved['INDEX.json']);manifest=json.loads(retrieved['MEMBERS.json'])
chunks=[]
for ordinal,part in enumerate(index['parts']):
    actual=retrieved[part['logical']];assert pin(actual)==part['pin']
    value=json.loads(actual)
    assert value['schema']=='hepta.hia.complete-zlib-base64-part.v1'
    assert value['index']==ordinal and value['total']==len(index['parts'])
    assert value['payload_pin']==index['payload_pin']and value['compressed_pin']==index['compressed_pin']
    chunks.append(value['data'])
packed=base64.b64decode(''.join(chunks),validate=True)
assert pin(packed)==index['compressed_pin']
decoder=zlib.decompressobj();raw=decoder.decompress(packed)+decoder.flush()
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
assert pin(raw)==index['payload_pin']
payload=json.loads(raw)
assert (json.dumps(payload,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()==raw
assert payload['schema']=='hepta.hia.op8-terminal-readers.author-and-small-failure-capsule.v1'
assert payload['whole_product_raw_custody']is False and payload['API_responses_included']is False
assert payload['reader_execution']==payload['control_execution']==payload['product_execution']==0
assert set(payload['files'])==set(manifest['files'])
logical_bytes=0;final=[]
for logical,row in payload['files'].items():
    content=row['text'].encode('utf-8');descriptor=row['descriptor']
    assert descriptor==manifest['files'][logical]
    assert pin(content,descriptor['pin']['mode'])==descriptor['pin']
    current,current_descriptor=capture(descriptor['path'])
    assert current==content and current_descriptor==descriptor
    logical_bytes+=len(content);final.append(descriptor)
for label,row in payload['author_roots'].items():
    path=Path(row['path'])
    assert row==manifest['author_roots'][label]
    assert seven(path.lstat())==row['stat']and sorted(p.name for p in path.iterdir())==row['members']
for label,row in payload['failure_output_metadata'].items():
    path=Path(row['path'])
    assert row==manifest['failure_output_metadata'][label]
    assert seven(path.lstat())==row['stat']
    assert {p.name:seven(p.lstat())for p in sorted(path.iterdir())}==row['members']
for descriptor in final:assert seven(Path(descriptor['path']).lstat())==descriptor['stat']
assert len(payload['files'])==index['file_count']==manifest['file_count']
assert logical_bytes==index['logical_bytes']==manifest['logical_bytes']
result={'schema':'hepta.hia.op8-terminal-readers.actual-git-readback.v1',
    'status':'PASS_FULL_ACTUAL_GIT_GET_DECODE_AND_CURRENT_AUTHOR_COMPARISON',
    'leaves':observed,'parts':len(chunks),'files':len(payload['files']),'logical_bytes':logical_bytes,
    'payload_pin':index['payload_pin'],'compressed_pin':index['compressed_pin'],
    'strict_zlib_end':True,'full_json_inverse':True,'all_member_full_bytes_modes_and_sevenstats':True,
    'all_frozen_author_pathsets':True,'failure_partial_output_metadata_unchanged':True,
    'partial_large_failure_output_payloads_included':False,'whole_product_raw_custody':False,
    'reader_or_control_or_product_executions':0,'new_source_or_runtime_copies':0}
out=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
with (ROOT/'ACTUAL-GIT-READBACK.json').open('xb')as stream:stream.write(out)
print(json.dumps({'status':result['status'],'parts':len(chunks),'files':len(payload['files']),
    'logical_bytes':logical_bytes,'proof_pin':pin(out)},sort_keys=True))
