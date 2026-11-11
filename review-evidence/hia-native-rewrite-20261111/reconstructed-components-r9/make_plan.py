from pathlib import Path
from hashlib import sha256,sha1
import json
root=Path('/workspace/scratch/9acdfa9f5639');out=root/'recovery-completed-r9'
affinity=Path('/workspace/scratch/hia-audit-runtime-recovery-20261111/namespace-reconstruction/affinity-r1-complete-01')
items=[]
def add(local,relative):
    raw=local.read_bytes();items.append(dict(local_path=str(local),path='review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/'+relative,
        bytes=len(raw),sha256=sha256(raw).hexdigest(),git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),mode='100644'))
for p in sorted(out.iterdir()):
    if p.is_file() and p.name not in ['publication-plan.json','publication.json']:add(p,p.name)
for name,label in [('hia-edit-decode-r2-development.tar.xz','edit-decode-r2.tar.xz'),
                   ('hia-legacy-composite-native-import-r3-development.tar.xz','legacy-import-r3.tar.xz'),
                   ('hia-legacy-composite-native-import-r3-development.custody.json','legacy-import-r3-custody.json'),
                   ('hia-legacy-composite-native-import-r3-development.seal-log.json','legacy-import-r3-seal-log.json')]:add(root/name,label)
for name in ['HIA_AGENT_EDIT_SELECTION_NATIVE.md','HIA_AGENT_EDIT_INPUT_PREFIX_NATIVE.md','HIA_AGENT_EDIT_BOUNDED_INPUT_ABI.md']:
    add(root/'Hepta-agent-edit-native/docs'/name,name)
add(root/'native-agent-edit-render-next/docs/HIA_EDIT_DECODE_DEVELOPMENT_R2.md','edit-decode-r2.md')
add(affinity/'namespace-affinity-r1-development.tar.xz','namespace-affinity-r1.tar.xz')
add(affinity/'custody.json','namespace-affinity-r1-custody.json')
(out/'publication-plan.json').write_text(json.dumps(items,indent=2,sort_keys=True)+'\n')
print(json.dumps(items,sort_keys=True))
