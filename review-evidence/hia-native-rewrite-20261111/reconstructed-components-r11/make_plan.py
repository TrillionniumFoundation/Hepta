from pathlib import Path
from hashlib import sha256,sha1
import json
root=Path('/workspace/scratch/9acdfa9f5639');out=root/'recovery-completed-r11';rows=[]
def add(p,name):
    raw=p.read_bytes();rows.append(dict(local_path=str(p),path='review-evidence/hia-native-rewrite-20261111/reconstructed-components-r11/'+name,
        bytes=len(raw),sha256=sha256(raw).hexdigest(),git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),mode='100644'))
for p in sorted(out.iterdir()):
    if p.is_file() and p.name not in ['publication-plan.json','publication.json']:add(p,p.name)
for local,name in [('hia-edit-render-batch-r2-development.tar.xz','batch-renderer-r2-development.tar.xz'),
    ('hia-edit-render-batch-r2-development.tar.xz.custody.json.xz','batch-renderer-r2-original-custody.json.xz'),
    ('hia-edit-render-batch-r2-final-handoff.json','batch-renderer-r2-final-handoff.json'),
    ('native-agent-edit-render-next/docs/HIA_EDIT_RENDER_BATCH_DEVELOPMENT_R2.md','HIA_EDIT_RENDER_BATCH_DEVELOPMENT_R2.md'),
    ('native-agent-edit-render-next/docs/HIA_EDIT_RENDER_BATCH_ABI.md','HIA_EDIT_RENDER_BATCH_ABI.md')]:add(root/local,name)
(out/'publication-plan.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(files=len(rows),bytes=sum(r['bytes'] for r in rows)),sort_keys=True))
