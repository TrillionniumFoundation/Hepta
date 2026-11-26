"""Actual native Clang Value packer qualification; Python is a QA driver only."""
from pathlib import Path
import ctypes as C,mmap,json,struct,traceback,hashlib
from tools import generate_hia_clang_value_packer as spec
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--build',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
build=args.build;root=args.output;root.mkdir(mode=0o700)
body=[(build/(name+'.component')).read_bytes() for name in spec.ROLES]
flat=(build/'clang_value_packer.flat').read_bytes()
code=mmap.mmap(-1,len(flat),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);code.write(flat)
entry=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(C.addressof(C.c_char.from_buffer(code)))
work=C.create_string_buffer(2048);controls=[]
report=dict(passed=False,controls=controls,original_role_limit=4194304,original_text_limit=16777216,logical_roles=len(body),packer=dict(bytes=len(flat),sha256=hashlib.sha256(flat).hexdigest()))
def save():(root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def frame(body,mode=0):return b'HIACVPP1'+struct.pack('<'+str(len(body)+2)+'Q',len(body),*map(len,body),mode)+b''.join(body)
def run(raw,capacity):
 src=C.create_string_buffer(raw);out=C.create_string_buffer(b'\xa5'*capacity,capacity)
 rc=entry(src,len(raw),out,capacity,work,len(work));return rc,bytes(out)
try:
 wire=frame(body);header=(len(body)+3)*8;mode_at=(len(body)+2)*8
 for mode,name in [(0,'clang-value.o'),(1,'clang-value.flat')]:
  expected=(build/name).read_bytes();rc,data=run(frame(body,mode),len(expected))
  assert rc==len(expected) and data==expected,(mode,rc)
 bad=[('short',wire[:header-1]),('truncated',wire[:-1]),('trailing',wire+b'x')]
 for name,at,value in [('magic',0,0),('count-low',8,len(body)-1),('count-high',8,len(body)+1),('mode',mode_at,2)]+[(role+'-'+kind,16+8*i,value)for i,role in enumerate(spec.ROLES)for kind,value in [('zero',0),('oversize',4194305)]]:
  candidate=bytearray(wire);struct.pack_into('<Q',candidate,at,value);bad.append((name,bytes(candidate)))
 for name,raw in bad:
  rc,data=run(raw,512);assert rc==0xffffffff and data==b'\xa5'*512,(name,hex(rc));controls.append(name)
 huge=frame([bytes(4194304) for _ in spec.ROLES]);rc,data=run(huge,512)
 assert rc==0xffffffff and data==b'\xa5'*512;controls.append('original16MiBtext-bound')
 for mode,name in [(0,'clang-value.o'),(1,'clang-value.flat')]:
  n=(build/name).stat().st_size-1;rc,data=run(frame(body,mode),n)
  assert rc==0xfffffffe and data==b'\xa5'*n;controls.append('short-output-'+str(mode))
 assert len(controls)==82
 report.update(passed=True,native_pack_modes=2,atomic_rejections=True)
except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();raise
finally:save();code.close()
print('CLANG_VALUE_PACKER_PASS',len(controls),flush=True)
