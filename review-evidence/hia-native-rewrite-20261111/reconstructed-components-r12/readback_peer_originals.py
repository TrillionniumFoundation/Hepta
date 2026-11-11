"""Independent streaming readback of complete peer archives and their indices."""
from pathlib import Path
from hashlib import sha256
import json,tarfile,time
ROOT=Path(__file__).resolve().parent.parent;OUT=Path(__file__).resolve().parent
RUNTIME=Path('/workspace/scratch/hia-audit-runtime-recovery-20261111')
items=[
 ('core-diagnostics',ROOT/'hia-core-diagnostics-native-r2-development.tar.xz','e4c2a842ee89971cab9b3406470cff50ef0f05fa9f1616c4ff3c140bfb352604',ROOT/'hia-core-diagnostics-native-r2-development.tar.members.json'),
 ('edit-mode2',ROOT/'hia-edit-executor-mode2-r1-development.tar.xz','3039c709809a40829c1e4fd750d7bfedb7126e11e6e0160658efdf793c902b7a',ROOT/'hia-edit-executor-mode2-r1-development.tar.xz.custody.json'),
 ('namespace-objects',RUNTIME/'namespace-reconstruction/objects-r1-complete-01/namespace-objects-r1-development.tar.xz','6fda9cc8a579096eb71c5fbaa6cda26f54c2ed2a1c4b19a04af7edfa6967a4af',RUNTIME/'namespace-reconstruction/objects-r1-complete-01/custody.json'),
 ('prerequisite-lifecycle',RUNTIME/'prerequisite-lifecycle-readback-r1/ndu-prerequisite-lifecycle-readback-r1.tar.xz','343999da7623c7810ed248ad56abff8dee831a5e697d800d0ae1da6f7d5693be',RUNTIME/'prerequisite-lifecycle-readback-r1/custody.json'),
 ('prerequisite-diagnostic-originals',RUNTIME/'prerequisite-diagnostic-originals-readback-r1/diagnostic-originals.tar.xz','2c6bfeca39502f58b4815f6261ba6f322d4608757593d2ae93692e32c47e993e',RUNTIME/'prerequisite-diagnostic-originals-readback-r1/custody.remote-original.json'),
]
reports=[]
for label,archive,pin,index in items:
    start=time.monotonic_ns();data=archive.read_bytes();assert sha256(data).hexdigest()==pin
    iraw=index.read_bytes();value=json.loads(iraw);rows=value if type(value)is list else value['members']
    expected={r.get('path',r.get('name')):r for r in rows};assert len(expected)==len(rows)
    seen=set();extras=[];total=0
    with tarfile.open(archive,'r|xz') as tf:
        for member in tf:
            assert member.isfile() and member.name not in seen;seen.add(member.name)
            h=sha256();size=0;f=tf.extractfile(member)
            while block:=f.read(1<<20):h.update(block);size+=len(block)
            total+=size;assert size==member.size
            row=expected.get(member.name)
            if row is None:
                assert h.hexdigest()==sha256(iraw).hexdigest() and size==len(iraw),('unknown member',label,member.name)
                extras.append(dict(name=member.name,bytes=size,sha256=h.hexdigest(),mode=member.mode,exact_index_bytes=True))
            else:
                assert (size,h.hexdigest(),member.mode)==(row['bytes'],row['sha256'],row['mode']),(label,member.name)
    assert set(expected)<=seen and len(seen)==len(expected)+len(extras)
    report=dict(label=label,status='PASS',archive=str(archive),archive_bytes=len(data),archive_sha256=pin,
        index=str(index),index_sha256=sha256(iraw).hexdigest(),members=len(seen),original_stored_bytes=total,
        all_indexed_full_bytes_hashes_modes_equal=True,exact_index_members=extras,elapsed_ns=time.monotonic_ns()-start)
    reports.append(report);(OUT/'peer-root-readback.json').write_text(json.dumps(reports,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True),flush=True)
