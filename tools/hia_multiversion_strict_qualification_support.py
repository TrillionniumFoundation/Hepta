"""Portable external QA frames; these are never native product dependencies.

The constructor frame and token observer are preserved from the original
qualified clients (f7ca81afdd46e179ee100206fab858b96d609ec223d8a601d44341ba7efa434a, a03aa4bf1db4dd0773211c1b39ee24f29149c6fb26b06bc1722ea983f84fe0a2).
The strict suites replace only the explicit protocol magic and captured policy.
"""
import ctypes as C
import hashlib
import struct
from tools.qualify_hia_multiversion_prepare_process import sealed, NONE
from tools.qualify_hia_multiversion_runtime_generation import scalar_program, rawdoc

get = lambda raw, at: struct.unpack_from('<Q', raw, at)[0]

def inner(op,*,files=(),parent=b'',raw=b'',fn=b'',args=b'',expected=(0,0),token=0,budget=0,measurement=b'',maxlive=8,prove=False,handoff=NONE):
 h=bytearray(256);struct.pack_into('<8sQ',h,0,b'HIAMVEX1',op)
 if op==0:
  struct.pack_into('<6Q',h,16,*[fd for fd,b in files],2000,maxlive,int(prove));h[128:224]=b''.join(hashlib.sha256(b).digest() for fd,b in files)
 else:struct.pack_into('<4Q',h,40,*expected,budget,token)
 struct.pack_into('<Q',h,72,handoff);struct.pack_into('<6Q',h,80,len(raw),len(parent),len(fn),len(args),len(measurement),int(bool(measurement)))
 return bytes(h)+raw+parent+fn+args+measurement

class Token:
 def __init__(self,lib):
  self.w=C.create_string_buffer(512);self.f=lib.hia_mv_future;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32;self.q(0)
 def q(self,op):
  b=struct.pack('<8s7Q',b'HIAMVFQ1',op,0,0,0,0,0,0);s=C.create_string_buffer(b);o=C.create_string_buffer(512)
  rc=self.f(s,len(b),o,len(o),self.w,len(self.w));assert rc==0,(op,rc,o.raw[:80].hex());return o.raw
 @property
 def address(self):return C.addressof(self.w)
