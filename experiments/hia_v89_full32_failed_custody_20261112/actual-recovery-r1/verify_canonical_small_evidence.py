"""Verify canonical small-evidence parts and every archived raw byte; no extraction."""
from pathlib import Path
import hashlib,io,json,tarfile,base64
ROOT=Path(__file__).resolve().parent
p=json.loads((ROOT/'ARCHIVE-PARTS.json').read_bytes())
m=json.loads((ROOT/'RAW-MANIFEST.json').read_bytes())
parts=[];offset=0
for row in p['parts']:
 transport=(ROOT/row['path']).read_bytes()
 assert len(transport)==row['transport_bytes'] and hashlib.sha256(transport).hexdigest()==row['transport_sha256'] and transport.endswith(b'\n')
 raw=base64.b64decode(transport[:-1],validate=True)
 assert row['offset']==offset and len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 offset+=len(raw);parts.append(raw)
raw=b''.join(parts)
assert len(raw)==p['archive_bytes'] and hashlib.sha256(raw).hexdigest()==p['archive_sha256']
expected={x['path']:x for x in m['files']};seen=set()
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
 for item in t:
  assert item.isfile() and item.name not in seen;seen.add(item.name)
  body=t.extractfile(item).read()
  if item.name=='BUNDLE-RAW-MANIFEST.json':assert body==(ROOT/'RAW-MANIFEST.json').read_bytes()
  else:
   row=expected[item.name]
   assert len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256'] and item.mode==row['mode']
   assert hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()==row['git_blob']
assert seen==set(expected)|{'BUNDLE-RAW-MANIFEST.json'}
print(json.dumps({'status':'ALL_SELECTED_SMALL_EVIDENCE_BYTES_VERIFIED','files':len(expected),'bytes':sum(x['bytes'] for x in expected.values()),'original_full32_status':'HOLD','large_original_zip_payload_included':False},sort_keys=True))
