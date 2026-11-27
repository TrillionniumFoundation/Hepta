"""Retire the extended owned exception map and every actual Value capability."""
from tools.generate_hia_clang_value_error_common import write_module
from tools.generate_hia_clang_value_cleanup import SOURCE as ORIGINAL
SOURCE=ORIGINAL.replace('while index<40:','while index<64:').replace('while index<4:','while index<7:')
old="""    if index==2:
        return A_FRAME
    return A_PATH_MAP"""
new="""    if index==2:
        return A_FRAME
    if index==3:
        return A_PATH_MAP
    if index==4:
        return A_XMAP
    if index==5:
        return 4008
    return 327552"""
assert SOURCE.count(old)==1
SOURCE=SOURCE.replace(old,new)
if __name__=='__main__':write_module('clang_value_cleanup_error',SOURCE)
