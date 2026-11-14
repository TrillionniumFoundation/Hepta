"""Small author/failure metadata custody only; no product or terminal-reader execution."""
import base64, hashlib, json, os, stat, zlib
from pathlib import Path

ROOT=Path('/workspace/hia-op8-terminal-readers-author-custody-r1-dda7')
AUTHOR_ROOTS={
    'core-reader-r1':Path('/workspace/hia-cli-as-dict-core-terminal-reader-r1-dda7'),
    'core-reader-r2':Path('/workspace/hia-cli-as-dict-core-terminal-reader-r2-dda7'),
    'core-reader-r3':Path('/workspace/hia-cli-as-dict-core-terminal-reader-r3-dda7'),
    'patch-reader-r1':Path('/workspace/hia-cli-as-dict-patch-terminal-reader-r1-dda7'),
}
PROGRESS=Path('/tmp/hia-progress-v151-20261114-dda7')
FAILURES={
    'core-reader-r1':Path('/workspace/hia-cli-as-dict-core-terminal-actual-r1-dda7'),
    'core-reader-r2':Path('/workspace/hia-cli-as-dict-core-terminal-actual-r2-dda7'),
}
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def seven(s):return {k:getattr(s,k)for k in FIELDS}
def pin(raw,mode='100644'):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':mode}
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()
def capture(path):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);before=seven(s)
        assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<16<<20
        assert before==seven(path.lstat())
        with os.fdopen(fd,'rb',closefd=False)as stream:raw=stream.read(s.st_size+1)
        assert len(raw)==s.st_size and before==seven(os.fstat(fd))==seven(path.lstat())
    finally:os.close(fd)
    mode='100755'if s.st_mode&0o111 else'100644'
    text=raw.decode('utf-8');assert text.encode()==raw
    return raw,{'path':str(path),'pin':pin(raw,mode),'stat':before}
def write(name,value):
    path=ROOT/name;raw=encoded(value)
    with path.open('xb')as stream:stream.write(raw)
    return capture(path)[1]

assert not (ROOT/'PUBLICATION-INPUTS.json').exists()
members={};root_states={}
for label,root in AUTHOR_ROOTS.items():
    initial=seven(root.lstat());assert stat.S_ISDIR(initial['st_mode'])
    paths=sorted(root.iterdir());names=[p.name for p in paths]
    root_states[label]={'path':str(root),'stat':initial,'members':names}
    for path in paths:
        raw,descriptor=capture(path)
        members[label+'/'+path.name]={'descriptor':descriptor,'text':raw.decode()}
    assert seven(root.lstat())==initial and sorted(p.name for p in root.iterdir())==names
extra={}
failure_outputs={}
for label,root in FAILURES.items():
    extra['actual-failure/'+label+'/RESULT.json']=root/'RESULT.json'
    failure_outputs[label]={'path':str(root),'stat':seven(root.lstat()),
        'members':{p.name:seven(p.lstat())for p in sorted(root.iterdir())},
        'large_partial_payloads_in_this_small_capsule':False,
        'all_original_partial_outputs_remain_at_original_paths':True}
for path in sorted(PROGRESS.iterdir()):
    if path.name.startswith('OP8-CORE-TERMINAL-')and path.is_file():
        extra['root-metadata/'+path.name]=path
    if path.name.startswith('review_op8_core_terminal_')and path.suffix=='.py':
        extra['root-metadata/'+path.name]=path
failure=Path('/workspace/hia-patch-qualification-custody-failure-r1-dda7/FAILURE-OBSERVATION.json')
if failure.is_file():extra['previous-sealer-failure/FAILURE-OBSERVATION.json']=failure
for logical,path in extra.items():
    assert logical not in members
    raw,descriptor=capture(path);members[logical]={'descriptor':descriptor,'text':raw.decode()}

payload={'schema':'hepta.hia.op8-terminal-readers.author-and-small-failure-capsule.v1',
    'author_roots':root_states,'failure_output_metadata':failure_outputs,'files':members,
    'reader_execution':0,'control_execution':0,'product_execution':0,
    'whole_product_raw_custody':False,'old_reader_failures_retained':True,
    'API_responses_included':False}
raw=encoded(payload);packed=zlib.compress(raw,6)
decoder=zlib.decompressobj();restored=decoder.decompress(packed)+decoder.flush()
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and restored==raw
decoded=json.loads(restored);assert decoded==payload
for logical,row in members.items():
    current,descriptor=capture(row['descriptor']['path'])
    assert descriptor==row['descriptor'] and current==decoded['files'][logical]['text'].encode()
for label,row in root_states.items():
    root=Path(row['path'])
    assert seven(root.lstat())==row['stat']and sorted(p.name for p in root.iterdir())==row['members']

parts_dir=ROOT/'parts';parts_dir.mkdir(mode=0o700)
transport=base64.b64encode(packed).decode('ascii');parts=[]
chunks=[transport[n:n+160000]for n in range(0,len(transport),160000)]
for index,chunk in enumerate(chunks):
    desc=write('parts/part-%04d.json'%index,{
        'schema':'hepta.hia.complete-zlib-base64-part.v1','index':index,'total':len(chunks),
        'encoding':'base64-zlib','data':chunk,'payload_pin':pin(raw),
        'compressed_pin':pin(packed)})
    parts.append({'index':index,'logical':'parts/part-%04d.json'%index,**desc})
manifest=write('MEMBERS.json',{'schema':payload['schema']+'.members',
    'files':{key:value['descriptor']for key,value in members.items()},
    'author_roots':root_states,'failure_output_metadata':failure_outputs,
    'file_count':len(members),'logical_bytes':sum(r['descriptor']['pin']['bytes']for r in members.values()),
    'whole_product_raw_custody':False})
index=write('INDEX.json',{'schema':'hepta.hia.op8-terminal-readers.author-capsule.index.v1',
    'payload_pin':pin(raw),'compressed_pin':pin(packed),'parts':parts,
    'file_count':len(members),'logical_bytes':sum(r['descriptor']['pin']['bytes']for r in members.values()),
    'manifest':manifest,'whole_product_raw_custody':False})
readback=write('LOCAL-READBACK.json',{'status':'PASS_COMPLETE_AUTHOR_AND_SMALL_FAILURE_LOCAL_INVERSE',
    'index':index,'manifest':manifest,'payload_pin':pin(raw),'compressed_pin':pin(packed),
    'files':len(members),'all_full_bytes_modes_sevenstats_and_author_pathsets_equal':True,
    'strict_zlib_end_and_full_json_inverse':True,'old_product_or_reader_execution':0,
    'whole_product_raw_custody':False})
publication=[]
for row in parts:publication.append({k:row[k]for k in ('logical','path','pin','stat')})
for logical,desc in [('INDEX.json',index),('MEMBERS.json',manifest),('LOCAL-READBACK.json',readback),
                     ('prepare.py',capture(Path(__file__))[1])]:
    publication.append({'logical':logical,**desc})
write('PUBLICATION-INPUTS.json',{'schema':'hepta.hia.immutable-blob-publication.v1',
    'repository':'TrillionniumFoundation/Hepta','leaves':publication})
print(json.dumps({'files':len(members),'logical_bytes':payload and sum(r['descriptor']['pin']['bytes']for r in members.values()),
    'payload_bytes':len(raw),'compressed_bytes':len(packed),'parts':len(parts),
    'index':index['pin'],'publication_leaves':len(publication)},sort_keys=True))
