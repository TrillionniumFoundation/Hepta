"""Capture the frozen small R4 authoring only; no original bulk payloads."""
import base64,hashlib,json,os,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/hia-patch-disk-custody-author-capsule-r4-dda7')
SOURCES={'tool':Path('/workspace/hia-patch-complete-custody-tool-r4-dda7'),
         'author':Path('/workspace/hia-patch-qualification-custody-author-r4-dda7')}
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(path):
    value=Path(path).lstat();return {key:getattr(value,key)for key in FIELDS}
def pin(raw,mode='100644'):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':mode}
def capture(path):
    path=Path(path);before=seven(path)
    assert stat.S_ISREG(before['st_mode'])and before['st_nlink']==1 and before['st_size']<16<<20
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        assert before=={key:getattr(os.fstat(fd),key)for key in FIELDS}
        with os.fdopen(fd,'rb',closefd=False)as stream:raw=stream.read(before['st_size']+1)
        assert len(raw)==before['st_size']and before==seven(path)=={key:getattr(os.fstat(fd),key)for key in FIELDS}
    finally:os.close(fd)
    assert raw.decode().encode()==raw
    return raw,{'path':str(path),'pin':pin(raw,'100755'if before['st_mode']&0o111 else'100644'),'stat':before}
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def save(name,value):
    raw=encoded(value)
    with(ROOT/name).open('xb')as stream:assert stream.write(raw)==len(raw)
    return capture(ROOT/name)[1]
def inventory(root):
    files={};dirs={}
    def walk(path):
        before=seven(path);assert stat.S_ISDIR(before['st_mode'])
        dirs[str(path.relative_to(root))]=before
        names=sorted(p.name for p in path.iterdir())
        for name in names:
            child=path/name;info=child.lstat()
            if stat.S_ISDIR(info.st_mode):walk(child)
            else:
                raw,desc=capture(child)
                files[str(child.relative_to(root))]={'descriptor':desc,'text':raw.decode()}
        assert seven(path)==before and sorted(p.name for p in path.iterdir())==names
    walk(root);return files,dirs
roots={};files={}
for label,root in SOURCES.items():
    current,dirs=inventory(root)
    roots[label]={'path':str(root),'directories':dirs,'file_paths':sorted(current)}
    for name,row in current.items():files[label+'/'+name]=row
payload={'schema':'hepta.hia.patch.disk-custody.author-payload.v1','roots':roots,'files':files,
    'author_only':True,'seal_control_reader_product_executions':0,'API_responses_included':False}
raw=encoded(payload);compressed=zlib.compress(raw,6)
dec=zlib.decompressobj();restored=dec.decompress(compressed)+dec.flush()
assert dec.eof and not dec.unused_data and not dec.unconsumed_tail and restored==raw
for label,root in SOURCES.items():
    current,dirs=inventory(root)
    assert dirs==roots[label]['directories']and sorted(current)==roots[label]['file_paths']
    assert all(files[label+'/'+name]==row for name,row in current.items())
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
    'seal_control_reader_product_executions':0})
leaves=[{'logical':name,**desc}for name,desc in [('AUTHOR-CAPSULE.json',transport),
    ('MEMBERS.json',manifest),('LOCAL-READBACK.json',readback),('prepare.py',capture(__file__)[1])]]
save('PUBLICATION-INPUTS.json',{'repository':'TrillionniumFoundation/Hepta','leaves':leaves})
print(json.dumps({'files':len(files),'logical_bytes':sum(r['descriptor']['pin']['bytes']for r in files.values()),
                 'transport':transport['pin'],'manifest':manifest['pin']},sort_keys=True))
