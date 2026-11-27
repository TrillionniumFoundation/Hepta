from pathlib import Path
import json,sys,io,gzip,tarfile
R=Path('/home/qian-qi/hia-native-cold-edge-6f7d-20261127-2ac5');S=R/'source';O=R/'qualified-cold-handoff'
sys.path.insert(0,str(S))
from tools.hia_native_cold_chain import regular,pin,read_json
index=read_json(regular(O/'qualified-cold.generations.json'));captured={};rows=[]
for row in index['generations']:
 p=Path(row['produced_image']);raw=regular(p,1048576)
 assert pin(raw)=={'bytes':row['produced_bytes'],'sha256':row['produced_sha256']}
 captured[row['name']+'.flat']=raw;rows.append({'generation':row['name'],'original_path':str(p),'dev':p.stat().st_dev,'inode':p.stat().st_ino,'nlink':p.stat().st_nlink,**pin(raw)})
assert len({x['original_path'] for x in rows})==3 and len({x['inode'] for x in rows})==3
meta={'schema':'hepta.hia.actual-three-cold-generations.v1','source_head':index['source_head'],'original_report':index['native_report'],'read_each_original_path_independently':True,'generation_files':rows}
captured['GENERATION-READBACK.json']=(json.dumps(meta,indent=2,sort_keys=True)+'\n').encode()
captured['MANIFEST.json']=(json.dumps({n:pin(b) for n,b in sorted(captured.items())},indent=2,sort_keys=True)+'\n').encode()
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as tf:
 for n,b in sorted(captured.items()):
  e=tarfile.TarInfo(n);e.size=len(b);e.mode=0o400;e.mtime=0;tf.addfile(e,io.BytesIO(b))
raw=gzip.compress(buf.getvalue(),mtime=0);p=O/'original-generation-images.tar.gz'
with p.open('xb') as f:f.write(raw)
print(json.dumps({'path':str(p),**pin(raw),'readback':meta},sort_keys=True),flush=True)
