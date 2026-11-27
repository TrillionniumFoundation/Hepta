"""Preserve the native primary error independently from cleanup failure."""
from tools import generate_hia_clang_value_transport as old
from tools.generate_hia_clang_value_error_common import write_module
SOURCE=old.SOURCE
marker="""        if get(w,A_INNER_OUT+8)!=0:
            return a_fail(w,get(w,A_INNER_OUT+8),10000+get(w,A_INNER_OUT+16))"""
replacement="""        if get(w,A_INNER_WORK+824)!=0:
            a_clean_error(w,get(w,A_INNER_WORK+824),get(w,A_INNER_WORK+832))
        if get(w,A_INNER_WORK+16)!=0:
            return a_fail(w,get(w,A_INNER_WORK+16),10000+get(w,A_INNER_WORK+24))
        if get(w,A_INNER_OUT+8)!=0:
            return a_fail(w,get(w,A_INNER_OUT+8),10000+get(w,A_INNER_OUT+16))"""
assert SOURCE.count(marker)==1
SOURCE=SOURCE.replace(marker,replacement)
if __name__=='__main__':write_module('clang_value_transport_error',SOURCE)
