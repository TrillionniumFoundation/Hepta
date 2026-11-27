from pathlib import Path
from hashlib import sha256
import os,sys,json,gzip,io,tarfile,struct
R=Path('/home/qian-qi/hia-native-cold-edge-6f7d-20261127-2ac5');S=R/'source';O=R/'qualified-cold-handoff';H='6f7dfb2defd8852d2fe58e02ff8c5cf78c5e7807'
sys.path.insert(0,str(S));os.chdir(S)
from tools.hia_native_cold_chain import regular,read_json,pin
from tools.hia_native_cold_admission import admit_native_report
from tools.hia_release_contract import validate_release_contract
from tools.hia_selfhost_contract import CONTRACT_PATH
from tools.generate_hia_native_observer import reference_image
assert not O.exists();O.mkdir(mode=0o700)
qraw=regular(R/'chain/qualification.json');q=read_json(qraw)
assert q['source_head']==H and q['whole_cold_qualified'] is True and len(q['phases'])==60 and q['qualification_nodes']==479882
raw=regular(R/'chain/cold/final-cold.json');assert pin(raw)=={k:q['cold'][k] for k in ('bytes','sha256')}
contract=validate_release_contract(S);sources={**contract['source_identity']['files'],CONTRACT_PATH:sha256(regular(S/CONTRACT_PATH)).hexdigest()}
base=R/'chain/cold/qualification/base';compiler=regular(base/'B3.flat',1048576)
admit_native_report(compiler,raw,contract=contract,sources=sources,observer_bytes=reference_image())
report=read_json(raw);original=O/'qualified-cold.json';original.write_bytes(raw)
generations=[]
for name in ('B1','B2','B3'):
 p=base/(name+'.flat');b=regular(p,1048576);assert b==compiler
 generations.append({'name':name,'produced_image':str(p),'produced_bytes':len(b),'produced_sha256':sha256(b).hexdigest()})
index={'schema':'hepta.hia.native-cold-generation-index.v1','source_head':H,'native_report':{'path':str(original),**pin(raw)},'generations':generations,'location_index_only':True,'hosted_qualification_claimed':False}
(O/'qualified-cold.generations.json').write_text(json.dumps(index,indent=2,sort_keys=True)+'\n')
owner=regular(R/'chain/cold/process-owner.receipt',1048576);w=struct.unpack_from('<32Q',owner)
assert w[6:8]==(180,3000000000) and w[9]==0 and w[10]==0 and w[12:16]==(1,1,0,0)
assert w[17]==w[21]==w[24]==0 and w[22]==1 and w[19]-w[4]<=180000000000 and w[23]-w[19]<=3000000000
captured={'final-cold.json':raw,'generation-index.json':(O/'qualified-cold.generations.json').read_bytes(),'B3.flat':compiler,'chain-cold-and-post-snapshot.json':qraw,'cold-process-owner.receipt':owner}
for relative in ('bootstrap-inputs.json','campaign-preflight.json','source-materialization.json','source-materialization-v2.json','fetch-exact.stderr','preparation/report.json','preparation/source-manifest.json','preparation/before-source-pins.json','preparation/after-source-pins.json','preseed/report.json','build/qualification.json','build/toolchain/process-owner.receipt','export/qualification.json','chain/full-cold.resources.jsonl','chain/source-bootstrap/build.receipt','chain/source-bootstrap/process-owner.receipt','full-chain.stdout'):
 captured[relative]=regular(R/relative)
captured['MANIFEST.json']=(json.dumps({n:pin(b) for n,b in sorted(captured.items())},indent=2,sort_keys=True)+'\n').encode()
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as tf:
 for name,b in sorted(captured.items()):
  entry=tarfile.TarInfo(name);entry.size=len(b);entry.mode=0o400;entry.mtime=0;tf.addfile(entry,io.BytesIO(b))
packed=gzip.compress(buf.getvalue(),mtime=0);archive=O/'qualified-cold-handoff.tar.gz';archive.write_bytes(packed)
readback={'schema':'hepta.hia.actual-native-cold-handoff.v1','source_head':H,'whole_cold_qualified':True,'whole_native_delivery_qualified':False,'remaining_release_install_rebuild_active':True,'source_count':len(sources),'phase_count':60,'qualification_nodes':479882,'qualification_ns':report['nested_wall_elapsed_ns'],'cleanup_ns':report['cleanup_wall_elapsed_ns'],'owner_qualification_ns':w[19]-w[4],'owner_cleanup_ns':w[23]-w[19],'all_14_checks_true':all(x is True for x in report['checks'].values()) and len(report['checks'])==14,'report':{'path':str(original),**pin(raw)},'index':{'path':str(O/'qualified-cold.generations.json'),**pin((O/'qualified-cold.generations.json').read_bytes())},'compiler':{'path':str(base/'B3.flat'),**pin(compiler)},'archive':{'path':str(archive),**pin(packed)},'members':len(captured)}
(O/'readback.json').write_text(json.dumps(readback,indent=2,sort_keys=True)+'\n');print(json.dumps(readback,sort_keys=True),flush=True)
