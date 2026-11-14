import base64
import hashlib
import json
from pathlib import Path
import zlib

ROOT=Path('/workspace/scratch/dda74a4fae35')
OUT=Path(__file__).parent
def pin(b):
    return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
paths=[]
for directory in ['v95-audit-mount-r1/v124-root-review','v120-native-publication-independent-review-r1',
                  'v120-derived-source-retirement-r1','v122-prepared-r19-source-retirement-r1',
                  'v123-old-authoring-cache-retirement-r1','v124-r19-restored-copy-retirement-r1']:
    paths.extend(p for p in (ROOT/directory).iterdir() if p.is_file() and p.suffix in ('.json','.py') and p.name!='PREPARED-DIFFERENCES.zlib.json')
paths += [ROOT/p for p in [
    'v95-audit-mount-r1/v123-c0-review/ROOT-C0-R2-REVIEW.json',
    'v95-audit-mount-r1/v123-c0-review/FUNCTION-REVIEW-R1-REFUSAL.json',
    'v95-audit-mount-r1/ROOT-LOCAL-PATH-REPAIR-V121.json',
    'v95-audit-mount-r1/v121-candidate-core-readbacks/ROOT-STRING-SHA-CORRECTION.json',
    'v121-selfhost-small-constant-r1/ROOT-AUTHORING-REVIEW.json',
    'v121-selfhost-small-constant-r1/ROOT-GENERATION-REVIEW.json',
    'v121-selfhost-small-constant-r1/ROOT-SOURCE9-REVIEW.json',
    'v121-selfhost-small-constant-r1/handoff-generation-source-r1/FRAME-RETIREMENT-PROPOSAL.json']]
records=[]
for p in sorted(set(paths)):
    b=p.read_bytes()
    records.append(dict(path=str(p.relative_to(ROOT)),mode=p.stat().st_mode&0o777,**pin(b),base64=base64.b64encode(b).decode()))
payload=json.dumps({'schema':'hia.root-selected-originals.payload.v1','files':records},sort_keys=True,separators=(',',':')).encode()
compressed=zlib.compress(payload,9)
capsule={'schema':'hia.root-selected-originals.zlib.v1','scope':'Complete selected Root reviews, independent Native plan review, prior derived-copy retirements, correction records and proposed Source9 frame retirement; not a substitute for separately mounted complete raw product evidence.',
         'encoding':'base64+zlib+json; every file is lossless base64','payload':pin(payload),'compressed':pin(compressed),
         'file_count':len(records),'logical_bytes':sum(x['bytes'] for x in records),'data':base64.b64encode(compressed).decode()}
decoded=json.loads(zlib.decompress(base64.b64decode(capsule['data'])))
assert decoded['files']==records
for r in decoded['files']:
    raw=base64.b64decode(r['base64']); p=ROOT/r['path']
    assert raw==p.read_bytes() and pin(raw)=={k:r[k] for k in ('bytes','git_blob','sha256')}
    assert r['mode']==p.stat().st_mode&0o777
index={'schema':'hia.root-selected-originals.index.v1','all_complete_local_decode_bytes_modes_verified':True,
       'files':[{k:v for k,v in r.items() if k!='base64'} for r in records],
       'count':len(records),'logical_bytes':capsule['logical_bytes'],'scope':capsule['scope']}
for name,obj in [('ROOT-RECORDS.zlib.json',capsule),('ROOT-RECORDS-INDEX.json',index)]:
    (OUT/name).write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n')
pins=[]
for name in ['ROOT-RECORDS.zlib.json','ROOT-RECORDS-INDEX.json','prepare_records.py']:
    p=OUT/name;pins.append(dict(local_path=str(p),**pin(p.read_bytes())))
(OUT/'ROOT-RECORDS-PINS.json').write_text(json.dumps(pins,indent=2,sort_keys=True)+'\n')
print(json.dumps({'files':len(records),'logical_bytes':capsule['logical_bytes'],'artifacts':pins},sort_keys=True))
