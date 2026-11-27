"""Read actual full-GET bodies and independently reconstruct every author file."""
from pathlib import Path
import base64,hashlib,json,stat,zlib

OUT=Path(__file__).resolve().parent
AUTHOR=OUT.parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def pin(b,m=None):
    value={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if m is not None:value.update(mode=m,git_mode='100755' if m&0o111 else '100644')
    return value
def git_body(name):
    stem=''.join(c if c.isalnum() or c in '_-' else '_' for c in name)
    result=json.loads((OUT/'git-receipts'/(stem+'.GET.json')).read_bytes())
    assert not result.get('isError')
    return result['structuredContent']['content'].encode('utf-8')
index=json.loads((OUT/'PUBLICATION-INPUTS.json').read_bytes())
for row in index['files']:
    remote=git_body(row['path']);local=(OUT/row['path']).read_bytes()
    assert remote==local and pin(remote,row['identity']['mode'])==row['identity']
capsule=git_body('AUTHOR-CAPSULE.json');wrapper=json.loads(capsule)
packed=base64.b64decode(wrapper['data'],validate=True)
assert pin(packed)==wrapper['compressed']
decoder=zlib.decompressobj();decoded=decoder.decompress(packed,wrapper['decoded']['bytes']+1)
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(decoded)==wrapper['decoded']
manifest=json.loads(git_body('AUTHOR-MANIFEST.json'));expected={r['path']:r for r in manifest['files']}
seen=set();total=0
for row in json.loads(decoded)['files']:
    name=row['path'];assert name not in seen and name in expected;seen.add(name)
    assert not Path(name).is_absolute() and '..' not in Path(name).parts
    raw=base64.b64decode(row['data_base64'],validate=True)
    assert row['identity']==expected[name]['identity']==pin(raw,row['identity']['mode'])
    path=AUTHOR/name;before=path.lstat();assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
    stamp=[getattr(before,k) for k in FIELDS]
    assert stamp==expected[name]['local_seven_stats'] and stat.S_IMODE(before.st_mode)==row['identity']['mode']
    assert path.read_bytes()==raw and [getattr(path.lstat(),k) for k in FIELDS]==stamp
    total+=len(raw)
assert seen==set(expected) and len(seen)==manifest['file_count']==37 and total==manifest['logical_bytes']==426776
result={'schema':'hia.R9.prefix-Git-complete-readback.v1','status':'PASS_FULL_GET_AND_LOSSLESS_AUTHOR_DECODE',
    'Git_full_GET_leaves':len(index['files']),'author_files':len(seen),'author_logical_bytes':total,
    'capsule':pin(capsule),'compressed':pin(packed),'decoded':pin(decoded),
    'all_original_author_bytes_modes_seven_stats_unchanged':True,'source_runtime_payload_not_duplicated':True,
    'future_generated_HIA_or_image_not_claimed':True,'product_executions':0,'refs':0}
destination=OUT/'GIT-FULL-READBACK.json'
with destination.open('xb') as f:f.write((json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
destination.chmod(0o644)
print(json.dumps({'result':pin(destination.read_bytes(),0o644),'files':len(seen),'bytes':total},sort_keys=True))
