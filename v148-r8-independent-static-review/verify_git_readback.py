from pathlib import Path
import base64,hashlib,json,stat,zlib

ROOT=Path(__file__).parent
def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
      'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def get(name):
    stem=''.join(c if c.isascii() and (c.isalnum() or c in '_-') else '_' for c in name)
    value=json.loads((ROOT/'git-receipts'/f'{stem}.GET.json').read_bytes())
    assert not value.get('isError')
    raw=value['structuredContent']['content'].encode()
    assert raw==(ROOT/name).read_bytes()
    return raw
index=json.loads(get('INDEX.json')); compressed=b''
for i,row in enumerate(index['parts']):
    raw=get(row['path']); assert pin(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
    part=json.loads(raw);fragment=base64.b64decode(part['base64'],validate=True)
    assert part['index']==i and part['offset']==len(compressed)
    assert pin(fragment)==part['fragment_identity']
    assert part['compressed_identity']==index['compressed_identity']
    assert part['payload_identity']==index['payload_identity']
    compressed+=fragment
assert pin(compressed)==index['compressed_identity']
d=zlib.decompressobj();raw=d.decompress(compressed)+d.flush()
assert d.eof and not d.unused_data and not d.unconsumed_tail
assert pin(raw)==index['payload_identity']
payload=json.loads(raw);assert len(payload['files'])==index['logical_files']==13
assert [{k:v for k,v in r.items() if k!='content_base64'} for r in payload['files']]==index['files']
total=0
for row in payload['files']:
    b=base64.b64decode(row['content_base64'],validate=True)
    assert pin(b)=={k:row[k] for k in ('bytes','sha256','git_blob')}
    part,name=row['path'].split('/',1);version=part.removeprefix('reviewer-r')
    p=Path(f'/tmp/hia-r8-r3-surface-static-review-r{version}-dda7')/name
    assert b==p.read_bytes() and stat.S_IMODE(p.lstat().st_mode)==row['mode']
    total+=len(b)
assert total==index['logical_bytes']
for name in ('REPORT.json','verify_static.py'):get(name)
result={'schema':'hepta.r8.r3.static-review-full-git-readback.v1','status':'PASS',
  'git_leaves':8,'parts':5,'logical_files':13,'logical_bytes':total,
  'all_original_bytes_and_modes_equal':True,'original_review_failures_preserved':2,
  'products':0,'binder':0,'project_imports':0,'refs':0}
output=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
with (ROOT/'GIT-FULL-READBACK.json').open('xb') as f:f.write(output)
print(json.dumps({'result':result,'identity':pin(output)},sort_keys=True))
