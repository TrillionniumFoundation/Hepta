"""Fixed native dispatch for logged Clang phases."""
from tools import generate_hia_clang_compile_owner as original
from tools.generate_hia_clang_origin_log_common import write_module
SOURCE=original.SOURCE.replace('    if phase>=20 and phase<60:', '''    if phase>=2500 and phase<2600:
        return 110
    if (phase>=2100 and phase<2300) or (phase>=2600 and phase<2800):
        return 109
    if phase>=2000 and phase<2500:
        return 108
    if phase>=20 and phase<60:''')
if __name__=='__main__':write_module('clang_origin_log_owner',SOURCE)
