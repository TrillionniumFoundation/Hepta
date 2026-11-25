from pathlib import Path
from hashlib import sha256
import argparse,ctypes as C,json,struct,sys
W=Path(__file__).resolve().parents[1];sys.path.insert(0,str(W))
from tools.qualify_hia_background_optimizer_structure import Flat
p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);args=p.parse_args()
D=args.directory;f=Flat(D/'background_optimizer_json_capture.flat');rows=[]
for wn,on,mode in [(w,64,0)for w in [0,1,8,64,104,127]]+[(128,o,0)for o in [0,1,8,32,63]]+[(128,64,m)for m in [2,3,255,(1<<64)-1]]:
 s=C.create_string_buffer(b'null');o=C.create_string_buffer(256);w=C.create_string_buffer(256)
 C.memset(o,0xdb,256);C.memset(w,0xa5,256);struct.pack_into('<Q',w,16+104,mode);prior=w.raw
 rc=f.entry(s,4,C.addressof(o)+16,on,C.addressof(w)+16,wn)
 assert rc==4294967293 and o.raw==b'\xdb'*256 and w.raw==prior and s.raw==b'null\0',(wn,on,mode,rc)
 rows.append({'workN':wn,'outN':on,'mode':mode,'rc':rc,'atomic':True,'passed':True})
for i,raw in enumerate([b'',b' ',b'null',b'[]',b'{}',b'{"a":1,"a":2}',b'"\\ud800"',b'NaN',b'Infinity',b'-Infinity',b'1e99999',b'\n[1,{"x":[]}]\r\n']):
 s=C.create_string_buffer(raw);o=C.create_string_buffer(96);w=C.create_string_buffer(160)
 C.memset(o,0xdb,len(o));C.memset(w,0xa5,len(w));struct.pack_into('<Q',w,16+104,0);prior=w.raw
 rc=f.entry(s,len(raw),C.addressof(o)+16,64,C.addressof(w)+16,128)
 assert rc==0 and o.raw[:16]+o.raw[-16:]==b'\xdb'*32 and w.raw==prior and s.raw==raw+b'\0'
 h=struct.unpack_from('<8s7Q',o,16);assert h[0]==b'HIANJS01'and h[6]==len(raw)and h[7]==0
 rows.append({'case':'exact-minimum-stat-'+str(i),'input_sha256':sha256(raw).hexdigest(),'stats':list(h[1:]),'passed':True})
report={'passed':True,'whole_background_qualified':False,'count':len(rows),'cases':rows,'flat_sha256':f.sha,'scope':'Exact minima, dispatch refusal and guard/source integrity for the actual production flat. Stats success does not assert JSON admission.'}
(D/'private-controls.json').write_text(json.dumps(report,indent=2)+'\n')
print('CAPTURE_PRIVATE_CONTROLS_PASS',len(rows),flush=True)
