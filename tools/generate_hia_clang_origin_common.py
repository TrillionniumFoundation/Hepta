"""Private FD-relative Clang producer; original HIACLB01 roles stay unchanged."""
from tools import generate_hia_clang_compile_common as base
C=dict(base.C)
C.update(P_REQUEST=int.from_bytes(b'HIACLB02','little'),P_ORIGIN_FD=2088)
def write_module(name,source,entry='advance'):
 base.capture.C.update(C)
 return base.capture.write_module(name,source+'\n'+base.COMMON,entry)
