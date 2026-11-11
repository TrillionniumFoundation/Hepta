"""Independent streaming readback of complete peer archives and their indices."""
from pathlib import Path
from hashlib import sha256
import json,tarfile,time
ROOT=Path(__file__).resolve().parent.parent;OUT=Path(__file__).resolve().parent
RUNTIME=Path('/workspace/scratch/hia-audit-runtime-recovery-20261111')
items=[('application59',ROOT/'hia-native-edit-apply-r1-development.tar.xz','b464f3bd3ea24a701e710c1d8d77032f37ad27ce64f80119f717c5e682bbfea9',ROOT/'hia-native-edit-apply-r1-development.tar.members.json')]
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
    reports.append(report);(OUT/'peer-root-readback-r4.json').write_text(json.dumps(reports,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True),flush=True)
