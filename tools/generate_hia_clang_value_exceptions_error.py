"""Canonical protocol errors for actual default path __str__ calls."""
from tools.generate_hia_clang_value_error_common import write_module
from tools import generate_hia_clang_value_exceptions as original
SOURCE=original.SOURCE.replace('put(w,A_ERROR_FRAME,A_V1)','put(w,A_ERROR_FRAME,A_V6)')
old="""            if get(w,A_ERROR_SELECTOR)==125:
                slot=6"""
new="""            if get(w,A_ERROR_SELECTOR)==125:
                slot=6
            elif get(w,A_ERROR_SELECTOR)==1261:
                slot=11"""
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
old="""        if detail==123:
            text_expected(w)"""
new="""        if detail==1261:
            text_str_return(w)
            append_name(w,0)
            text_right_parenthesis(w)
        elif detail==123:
            text_expected(w)"""
assert SOURCE.count(old)==1;SOURCE=SOURCE.replace(old,new)
TEXTS=dict(original.TEXTS,str_return='__str__ returned non-string (type ',right_parenthesis=')')
def source():
 old_source=original.SOURCE;old_texts=original.TEXTS
 original.SOURCE=SOURCE;original.TEXTS=TEXTS
 try:return original.source()
 finally:original.SOURCE=old_source;original.TEXTS=old_texts
if __name__=='__main__':write_module('clang_value_exceptions_error',source())
