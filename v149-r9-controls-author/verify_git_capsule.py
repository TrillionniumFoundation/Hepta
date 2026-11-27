"""Reconstruct all author bytes from actual full Git GET bodies; no product."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
OUT=Path(__file__).resolve().parent
AUTHOR=OUT.parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def pin(b,m=None):
    p={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if m is not None:p.update(mode=m,git_mode='100755' if m&0o111 else '100644')
    return p
def git_body(name):
    stem=''.join(c if c.isalnum() or c in '_-' else '_' for c in name)
    r=json.loads((OUT/'git-receipts'/(stem+'.GET.json')).read_bytes())
    assert not r.get('isError');return r['structuredContent']['content'].encode('utf-8')
publication=json.loads((OUT/'PUBLICATION-INPUTS.json').read_bytes())
for row in publication['files']:
    b=git_body(row['path']);assert b==(OUT/row['path']).read_bytes() and pin(b,row['identity']['mode'])==row['identity']
index_bytes=git_body('AUTHOR-CAPSULE-INDEX.json');index=json.loads(index_bytes)
pieces=[];offset=0
for number,row in enumerate(index['parts']):
    b=git_body(row['path']);assert pin(b,0o644)==row['identity']
    part=json.loads(b);decoded=base64.b64decode(part['data'],validate=True)
    assert part['index']==number and part['offset']==row['offset']==offset
    assert part['encoding']=='base64' and pin(decoded)==part['decoded']==row['decoded']
    pieces.append(decoded);offset+=len(decoded)
packed=b''.join(pieces);assert pin(packed)==index['compressed']
decoder=zlib.decompressobj();raw=decoder.decompress(packed,index['decoded']['bytes']+1)
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(raw)==index['decoded']
manifest=json.loads(git_body('AUTHOR-MANIFEST.json'));expected={r['path']:r for r in manifest['files']}
assert len(expected)==len(manifest['files'])
seen=set();total=0
for row in json.loads(raw)['files']:
    n=row['path'];assert n not in seen and n in expected and not Path(n).is_absolute() and '..' not in Path(n).parts
    seen.add(n);b=base64.b64decode(row['data_base64'],validate=True)
    assert pin(b,row['identity']['mode'])==row['identity']==expected[n]['identity']
    p=AUTHOR/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    stamp=[getattr(s,k) for k in FIELDS]
    assert stamp==expected[n]['local_seven_stats'] and stat.S_IMODE(s.st_mode)==row['identity']['mode']
    assert p.read_bytes()==b and [getattr(p.lstat(),k) for k in FIELDS]==stamp
    total+=len(b)
assert seen==set(expected) and len(seen)==manifest['file_count']==index['files']==87
assert total==manifest['logical_bytes']==index['logical_bytes']==7327296
result={'schema':'hia.R9.controls-Git-full-author-readback.v1','status':'PASS_FULL_GET_AND_WHOLE_AUTHOR_DECODE',
    'Git_full_GET_leaves':len(publication['files']),'transport_parts':len(pieces),
    'author_files':len(seen),'author_logical_bytes':total,'index':pin(index_bytes),
    'compressed':pin(packed),'decoded':pin(raw),'all_original_author_bytes_modes_seven_stats_unchanged':True,
    'complete_product_or_source_or_runtime_payload_included':False,
    'actual_prefix_identity_bound_without_semantic_qualification_transfer':True,'project_imports':0,'products':0,'refs':0}
b=(json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
destination=OUT/'GIT-FULL-READBACK.json'
with destination.open('xb') as f:f.write(b)
destination.chmod(0o644)
print(json.dumps({'status':result['status'],'result':pin(b,0o644),'files':len(seen),'bytes':total,'products':0},sort_keys=True))
