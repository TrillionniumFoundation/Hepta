from pathlib import Path
from hashlib import sha256,sha1
import io,json,stat,tarfile
D=Path('/workspace/scratch/9acdfa9f5639/hia-v67-reconstructed-development');R=Path('/workspace/scratch/9acdfa9f5639/Hepta-v67-reconstructed')
assert json.loads((D/'freeze-receipt.json').read_text())['source_preserved']
assert json.loads((D/'full-compiler-attempt1/summary.json').read_text())['status']=='PASS'
assert json.loads((D/'native-graph-attempt1/case-counts.json').read_text())['actual_native_entries']==192
paths=[]
for folder in ('native-graph-attempt1','full-compiler-attempt1'):
 paths += [(p,'actual/'+str(p.relative_to(D))) for p in sorted((D/folder).rglob('*')) if p.is_file() and not p.is_symlink()]
for name in ('RECONSTRUCTION.md','previous-check-calls-generator.txt','generate-attempt1.stdout.log','generate-attempt1.stderr.log','source-tests-reconstructed-r1.stdout.log','source-tests-reconstructed-r1.stderr.log','native-graph-attempt1.stdout.log','native-graph-attempt1.stderr.log','full_compiler_difference.py','full-compiler-attempt1.stdout.log','full-compiler-attempt1.stderr.log','generation.json','source-frozen.json','source-frozen.tar.xz','freeze-receipt.json','prepare_frozen_source_attempt2.py','run_full_source.py','prepare-source-attempt2.stdout.log','prepare-source-attempt2.stderr.log'):
 paths.append((D/name,'control/'+name))
for folder in ('prepare-attempt2-logs','failures/prepare-attempt1'):
 paths += [(p,'control/'+str(p.relative_to(D))) for p in sorted((D/folder).rglob('*')) if p.is_file() and not p.is_symlink()]
frozen=json.loads((D/'source-frozen.json').read_text())
for row in frozen['owned_files']:paths.append((R/row['path'],'source/'+row['path']))
rows=[];data={}
for p,name in paths:
 assert not p.is_symlink();b=p.read_bytes();rows.append({'path':name,'bytes':len(b),'sha256':sha256(b).hexdigest(),'mode':stat.S_IMODE(p.stat().st_mode),'origin':str(p)});data[name]=b
assert len(data)==len(rows)
manifest={'scope':'NEW_ORIGINAL_RECONSTRUCTED_COMPONENT_RUNS_NOT_RECREATED_LOST_OUTPUT','source_base_commit':frozen['base_commit'],'source_manifest_sha256':sha256((D/'source-frozen.json').read_bytes()).hexdigest(),'native_graph_cases':96,'native_graph_entries':192,'full_compiler_cases':14,'full_compiler_entries':28,'full_source_and_cold_gates_pending':True,'files':rows,'whole_stack_closed':False}
encoded=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode();archive=D/'v67-reconstructed-component-originals.tar.xz'
with tarfile.open(archive,'x:xz',preset=3) as tf:
 for row in rows:
  info=tarfile.TarInfo(row['path']);info.size=row['bytes'];info.mode=row['mode'];tf.addfile(info,io.BytesIO(data[row['path']]))
 info=tarfile.TarInfo('MANIFEST.json');info.size=len(encoded);info.mode=0o644;tf.addfile(info,io.BytesIO(encoded))
with tarfile.open(archive,'r:xz') as tf:
 assert len(tf.getmembers())==len(rows)+1
 for row in rows:
  member=tf.getmember(row['path']);b=tf.extractfile(member).read();assert b==data[row['path']] and member.mode==row['mode'] and sha256(b).hexdigest()==row['sha256']
 assert tf.extractfile('MANIFEST.json').read()==encoded
for p,name in paths:assert p.read_bytes()==data[name]
b=archive.read_bytes();receipt={'scope':manifest['scope'],'archive':str(archive),'bytes':len(b),'sha256':sha256(b).hexdigest(),'git_sha':sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'regular_members':len(rows)+1,'original_bytes':sum(r['bytes'] for r in rows),'all_original_bytes_modes_and_sources_read_back':True,'source_manifest_sha256':manifest['source_manifest_sha256'],'full_source_and_cold_gates_pending':True,'whole_stack_closed':False}
(D/'component-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt),flush=True)
