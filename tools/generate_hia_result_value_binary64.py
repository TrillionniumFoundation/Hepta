"""Unbounded raw decimal profile for typed value import; identical exact integer rounding."""
from tools.generate_hia_agent_binary64 import source_program as original
from tools.generate_hia_result_value_common import ROOT,document,render_assembly
def source_program():
 s=original()
 s=s.replace('if n == 0 or n > 8388608:','if n == 0:')
 s=s.replace('    exponent = 0\n','    exponent = 0\n    exponent_cap = 18446744073709551615\n    if n <= 18446744073709547519:\n        exponent_cap = n + 4096\n',1)
 old='''                if exponent < 33554432:
                    exponent = exponent * 10 + ch - 48
                    if exponent > 33554432:
                        exponent = 33554432'''
 new='''                if exponent < exponent_cap:
                    digit_value = ch - 48
                    if exponent > (exponent_cap - digit_value) // 10:
                        exponent = exponent_cap
                    else:
                        exponent = exponent * 10 + digit_value'''
 assert old in s;s=s.replace(old,new)
 old='''    order = 67108864 + significant - fraction - 1
    if negative_exponent:
        order = order - exponent
    else:
        order = order + exponent
    if order > 67109172:
        return 4294967292
    if order < 67108540:
        put(o, 0, sign)
        return 8'''
 new='''    order_negative = significant <= fraction
    order_magnitude = 0
    if order_negative:
        order_magnitude = fraction - significant + 1
    else:
        order_magnitude = significant - fraction - 1
    if negative_exponent == order_negative:
        if exponent > 18446744073709551615 - order_magnitude:
            if order_negative:
                put(o, 0, sign)
                return 8
            return 4294967292
        order_magnitude = order_magnitude + exponent
    elif exponent > order_magnitude:
        order_magnitude = exponent - order_magnitude
        order_negative = negative_exponent
    else:
        order_magnitude = order_magnitude - exponent
    if order_negative:
        if order_magnitude > 324:
            put(o, 0, sign)
            return 8
    elif order_magnitude > 308:
        return 4294967292
    order = 67108864 + order_magnitude
    if order_negative:
        order = 67108864 - order_magnitude'''
 assert old in s;s=s.replace(old,new)
 return s
def program():return document(source_program(),'result_value_binary64')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/result_value_binary64.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)
