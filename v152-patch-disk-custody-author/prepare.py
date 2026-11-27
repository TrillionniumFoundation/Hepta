"""Small immutable author capsule, excluding original bulk input and actual products."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/hia-patch-disk-custody-author-capsule-r1-dda7')
SOURCES={'tool':Path('/workspace/hia-patch-complete-custody-tool-r3-dda7'),
         'author':Path('/workspace/hia-patch-qualification-custody-author-r3-dda7')}
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(path):return {key:getattr(Path(path).lstat(),key)for key in FIELDS}
def pin(raw,mode='100644'):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':mode}
def capture(path):
    path=Path(path);before=seven(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<16<<20
        assert before=={key:getattr(s,key)for key in FIELDS}
        with os.fdopen(fd,'rb',closefd=False)as stream:raw=stream.read(s.st_size+1)
        assert len(raw)==s.st_size and before==seven(path)=={key:getattr(os.fstat(fd),key)for key in FIELDS}
    finally:os.close(fd)
    assert raw.decode().encode()==raw
    return raw,{'path':str(path),'pin':pin(raw,'100755'if s.st_mode&0o111 else'100644'),'stat':before}
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def save(name,value):
    raw=encoded(value)
    with (ROOT/name).open('xb')as stream:stream.write(raw)
    return capture(ROOT/name)[1]
roots={};files={}
for label,root in SOURCES.items():
    names=sorted(path.name for path in root.iterdir());roots[label]={'path':str(root),'stat':seven(root),'files':names}
    for name in names:
        raw,desc=capture(root/name);files[label+'/'+name]={'descriptor':desc,'text':raw.decode()}
    assert seven(root)==roots[label]['stat']and sorted(path.name for path in root.iterdir())==names
payload={'schema':'hepta.hia.patch.disk-custody.author-payload.v1','roots':roots,'files':files,
    'author_only':True,'seal_or_control_or_reader_or_product_executions':0,
    'original_bulk_input_or_product_payload_included':False,'API_responses_included':False}
raw=encoded(payload);compressed=zlib.compress(raw,6)
decoder=zlib.decompressobj();restored=decoder.decompress(compressed)+decoder.flush()
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and restored==raw
for name,row in files.items():
    current,desc=capture(row['descriptor']['path']);assert desc==row['descriptor']and current==row['text'].encode()
transport=save('AUTHOR-CAPSULE.json',{'schema':'hepta.hia.complete-zlib-base64-capsule.v1',
    'encoding':'base64-zlib','payload_pin':pin(raw),'compressed_pin':pin(compressed),
    'data':base64.b64encode(compressed).decode()})
manifest=save('MEMBERS.json',{'schema':payload['schema']+'.members','roots':roots,
    'files':{name:row['descriptor']for name,row in files.items()},'files_count':len(files),
    'logical_bytes':sum(row['descriptor']['pin']['bytes']for row in files.values())})
readback=save('LOCAL-READBACK.json',{'status':'PASS_COMPLETE_AUTHOR_CAPSULE_LOCAL_INVERSE',
    'transport':transport,'manifest':manifest,'files':len(files),
    'logical_bytes':sum(row['descriptor']['pin']['bytes']for row in files.values()),
    'payload_pin':pin(raw),'compressed_pin':pin(compressed),'all_full_bytes_modes_sevenstats_pathsets':True,
    'actual_seal_or_control_or_reader_or_product_executions':0})
leaves=[{'logical':name,**desc}for name,desc in [('AUTHOR-CAPSULE.json',transport),
    ('MEMBERS.json',manifest),('LOCAL-READBACK.json',readback),('prepare.py',capture(Path(__file__))[1])]]
save('PUBLICATION-INPUTS.json',{'repository':'TrillionniumFoundation/Hepta','leaves':leaves})
print(json.dumps({'files':len(files),'logical_bytes':sum(row['descriptor']['pin']['bytes']for row in files.values()),
    'compressed_bytes':len(compressed),'transport':transport['pin'],'manifest':manifest['pin']},sort_keys=True))
