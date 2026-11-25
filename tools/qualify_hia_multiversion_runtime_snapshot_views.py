from pathlib import Path
import importlib.util,sys,ctypes,hashlib,json,struct,time,random,os
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');Q=T/'multiversion-runtime-snapshot-qa'
from tools import qualify_hia_multiversion_runtime_snapshot as h
Q=h.Q;T=h.T
D=Q/'aux-v1';D.mkdir()
n=h.Native(Q/'native-v4/snapshot.flat');p=h.Native(Q/'native-v4/snapshot-packer.flat');rows=[]
body=(Q/'native-v4/snapshot-policy.flat').read_bytes()
def pw(body):return b'HIAMVSPK'+struct.pack('<3Q',len(body),0,0)+body
def pack(body):
 req=pw(body);s=ctypes.create_string_buffer(req);out=ctypes.create_string_buffer(len(body)+175);w=ctypes.create_string_buffer(64)
 assert p.function(s,len(req),out,len(out),w,64)==0
 return out.raw
assert pack(body)==n.raw;rows.append({'case':'native-packer-exact-product'})
# Native constructor failures are atomic.
for label,wire in [('empty',b''),('zero-body',pw(b'')),('oversize',pw(bytes(4194305))),('trailing',pw(b'\xc3')+b'x')]:
 s=ctypes.create_string_buffer(wire);o=ctypes.create_string_buffer(512);ctypes.memset(o,0x75,512);w=ctypes.create_string_buffer(64)
 r=p.function(s,len(wire),o,512,w,64);assert r==4294967293 and o.raw==b'\x75'*512,(label,r)
 rows.append({'case':'packer-'+label})
req=pw(b'\xc3')
for at in [0,8,16,24]:
 z=bytearray(req);struct.pack_into('<Q',z,at,h.U);s=ctypes.create_string_buffer(bytes(z));o=ctypes.create_string_buffer(512);ctypes.memset(o,0x75,512);w=ctypes.create_string_buffer(64)
 assert p.function(s,len(z),o,512,w,64)==4294967293 and o.raw==b'\x75'*512
 rows.append({'case':'packer-header-'+str(at)})
# Same HIA producer at its closed construction maximum, no relaxed limit.
big=bytes([0xC3])*4194304;full=pack(big);assert full[175:]==big and len(full)==4194479;rows.append({'case':'packer-4MiB'})
wire=pw(body);s=ctypes.create_string_buffer(wire);o=ctypes.create_string_buffer(len(n.raw));w=ctypes.create_string_buffer(64)
for cap in [0,1,174,len(n.raw)-1]:
 ctypes.memset(o,0x61,len(o));r=p.function(s,len(wire),o,cap,w,64);assert r==4294967294 and o.raw==b'\x61'*len(o)and struct.unpack_from('<Q',w.raw)[0]==len(n.raw)
 rows.append({'case':'packer-nospace-'+str(cap)})
# The mechanical return adapter preserves a full u64 result and maps statuses.
for value,status in [(0x100000005,0),(h.U-4,0),(0,0xfffffffd),(0,0xfffffffe),(0,0xfffffffc),(0,15)]:
 stub=b'\x48\xb8'+struct.pack('<Q',value)+b'\x49\x89\x00'+b'\xb8'+struct.pack('<I',status)+b'\xc3'
 raw=pack(stub);path=D/('stub-'+str(value)+'-'+str(status)+'.flat');path.write_bytes(raw);probe=h.Native(path)
 s=ctypes.create_string_buffer(128);o=ctypes.create_string_buffer(128);w=ctypes.create_string_buffer(128)
 got=probe.function(s,128,o,128,w,128);expected=value if status==0 else h.U-1 if status==0xfffffffe else h.U-2 if status==0xfffffffc else h.U
 assert got==expected,(status,got,expected);rows.append({'case':'full-u64-return-'+str(value)+'-'+str(status)})
# Exact typed fields at nonaligned but otherwise valid disjoint views.
item=h.pin(bound=True,held=True,attempted=True);wire=h.packet(item.wire);ex=h.jbytes(item.expected)
for off in range(8):
 r,o,w,_=n.run(wire,len(ex),65536,off);assert r==len(ex)and o==ex
 rows.append({'case':'unaligned-'+str(off)})
# ABI checks are entirely before the first policy store.
s=ctypes.create_string_buffer(wire);o=ctypes.create_string_buffer(4096);w=ctypes.create_string_buffer(65536)
sp,op,wp=map(ctypes.addressof,(s,o,w))
baseline=[sp,len(wire),op,4096,wp,65536]
bad=[]
for ptr,size in [(0,1),(2,3),(4,5)]:
 a=baseline.copy();a[ptr]=0;bad.append(('null-'+str(ptr),a))
 a=baseline.copy();a[ptr]=h.U-3;a[size]=9;bad.append(('overflow-'+str(ptr),a))
for ap,bp in [(0,2),(0,4),(2,4)]:
 a=baseline.copy();a[ap]=a[bp];bad.append(('alias-'+str(ap)+'-'+str(bp),a))
for label,args in bad:
 before=(s.raw,o.raw,w.raw);r=n.function(*args);assert r==h.U and before==(s.raw,o.raw,w.raw),(label,r);rows.append({'case':label})
# Adjacent views have no overlap; zero output size may share the W pointer.
storage=ctypes.create_string_buffer(len(wire)+len(ex)+65536)
base=ctypes.addressof(storage);ctypes.memmove(base,wire,len(wire))
r=n.function(base,len(wire),base+len(wire),len(ex),base+len(wire)+len(ex),65536)
assert r==len(ex)and storage.raw[len(wire):len(wire)+len(ex)]==ex;rows.append({'case':'adjacent-valid-views'})
r=n.function(sp,len(wire),wp,0,wp,65536);assert r==h.U-1 and struct.unpack_from('<Q',w.raw)[0]==len(ex);rows.append({'case':'empty-output-work-address'})
(D/'report.json').write_text(json.dumps({'status':'PASS','cases':len(rows),'rows':rows,'flat_sha256':h.sha(n.raw)},indent=2)+'\n');print('SNAPSHOT_AUX_PASS',len(rows),flush=True)
