from pathlib import Path
from hashlib import sha256,sha1
import json
root=Path('/workspace/scratch/9acdfa9f5639');out=root/'recovery-completed-r10';items=[]
def add(local,relative):
    raw=local.read_bytes();items.append(dict(local_path=str(local),path='review-evidence/hia-native-rewrite-20261111/reconstructed-components-r10/'+relative,
        bytes=len(raw),sha256=sha256(raw).hexdigest(),git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),mode='100644'))
for p in sorted(out.iterdir()):
    if p.is_file() and p.name not in ['publication-plan.json','publication.json']:add(p,p.name)
for suffix,label in [('tar.xz','program-admission-r1.tar.xz'),('custody.json','program-admission-r1-custody.json'),('seal.log','program-admission-r1-seal.log')]:
    add(root/('hia-program-admission-native-r1-development.'+suffix),label)
add(root/'native-edit-controller-next/docs/HIA_EDIT_CONTROLLER_NATIVE_DESIGN.md','HIA_EDIT_CONTROLLER_NATIVE_DESIGN.md')
(out/'publication-plan.json').write_text(json.dumps(items,indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(files=len(items),bytes=sum(i['bytes'] for i in items)),sort_keys=True))
