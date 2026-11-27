from pathlib import Path
import ast,hashlib,json
ROOT=Path('/tmp/hia-progress-v150-20261114-dda7')
old=Path('/tmp/hia-progress-v149-20261114-dda7/verify_root_metadata_actual_get.py').read_bytes()
changes=[(b"ROOT=Path('/tmp/hia-progress-v149-20261114-dda7')",b"ROOT=Path('/tmp/hia-progress-v150-20261114-dda7')"),(b"OUT=Path('/tmp/hia-v149-root-metadata-custody-r1-dda7')",b"OUT=Path('/workspace/hia-v150-root-metadata-custody-r1-dda7')"),(b"==118",b"==63"),(b"==12841988",b"==9601875"),(b"('r9-prefix-independent-terminal','r9-controls-admission')",b"('patch-generation-independent-terminal','patch-generation-admission')"),(b"hia.root.v149.metadata.complete-actual-GET-decode.v1",b"hia.root.v150.metadata.complete-actual-GET-decode.v1"),(b"'logical_files':118",b"'logical_files':63")]
new=old
for a,b in changes:
 assert new.count(a)==1,(a,new.count(a));new=new.replace(a,b,1)
restored=new
for a,b in reversed(changes):
 assert restored.count(b)==1,(b,restored.count(b));restored=restored.replace(b,a,1)
assert restored==old and ast.dump(ast.parse(restored))==ast.dump(ast.parse(old))
def pin(raw):return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
p=ROOT/'verify_root_metadata_actual_get.py'
with p.open('xb')as f:f.write(new)
proof={'schema':'hia.root.v150.metadata-reader-inverse.v1','before':pin(old),'after':pin(new),'replacements':[[a.decode(),b.decode()]for a,b in changes],'whole_byte_inverse':restored==old,'whole_AST_inverse':True,'products':0}
with (ROOT/'ROOT-METADATA-READER-INVERSE.json').open('xb')as f:f.write((json.dumps(proof,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps(proof,sort_keys=True))
