from pathlib import Path
import base64,gzip,hashlib,io,json,tarfile,sys
root=Path(sys.argv[1]);out=Path(sys.argv[2])
m=json.loads((root/'ARCHIVE-MANIFEST.json').read_text())
def sha(b):return hashlib.sha256(b).hexdigest()
packed=bytearray()
for row in m['carriers']:
 b=(root/row['path']).read_bytes()
 if len(b)!=row['bytes'] or sha(b)!=row['sha256']:raise ValueError('full carrier')
 raw=base64.b64decode(b,validate=False)
 if len(raw)!=row['decoded_bytes'] or sha(raw)!=row['decoded_sha256'] or len(packed)!=row['offset']:raise ValueError('complete decoded carrier')
 packed.extend(raw)
if len(packed)!=m['gzip']['bytes'] or sha(packed)!=m['gzip']['sha256']:raise ValueError('whole gzip')
raw=gzip.decompress(packed)
if len(raw)!=m['tar']['bytes'] or sha(raw)!=m['tar']['sha256']:raise ValueError('whole tar')
expected={r['name']:r for r in m['originals']};seen=set();out.mkdir(mode=0o700,parents=False,exist_ok=False)
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:
 for item in tar:
  if not item.isfile() or item.name not in expected or item.name in seen or item.name.startswith('/') or '..' in Path(item.name).parts:raise ValueError('archive namespace')
  row=expected[item.name];b=tar.extractfile(item).read()
  if len(b)!=row['bytes'] or sha(b)!=row['sha256'] or item.mode!=row['mode']:raise ValueError('complete member')
  p=out/item.name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  with p.open('xb') as f:f.write(b)
  p.chmod(row['mode']);seen.add(item.name)
if seen!=set(expected):raise ValueError('missing member')
print(json.dumps({'originals':len(seen),'bytes':m['original_bytes'],'qualification_executed':False}))
