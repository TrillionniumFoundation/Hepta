"""Author bounded Agent u64/digest identity admission in ordinary HIA Core."""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
MAGIC=int.from_bytes(b'HIAIDP01','little')
RESULT_MAGIC=int.from_bytes(b'HIAIDR01','little')
SOURCE=r'''
def identity_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16:
        return 4294967293
    if read_word(s, 0) != @MAGIC@:
        return 4294967293
    kind = read_word(s, 8)
    if kind == 5:
        return measurement_policy(s, o)
    if kind == 6:
        return cost_totals(s, o)
    if kind == 7:
        return observation_agreement(s, o)
    if kind > 1:
        return context_policy(s, o, kind)
    if length(s) > 80:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    valid = 1
    value = 0
    size = length(s) - 16
    if kind == 0:
        if size == 0 or size > 20:
            valid = 0
        elif size > 1 and byte(s, 16) == 48:
            valid = 0
        index = 0
        while index < size and valid != 0:
            ch = byte(s, 16 + index)
            if ch < 48 or ch > 57:
                valid = 0
            else:
                digit = ch - 48
                if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
                    valid = 0
                else:
                    value = value * 10 + digit
            index = index + 1
    else:
        if size != 64:
            valid = 0
        index = 0
        while index < size and valid != 0:
            ch = byte(s, 16 + index)
            if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
                valid = 0
            index = index + 1
    if valid == 0:
        value = 0
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, valid)
    put(o, 16, value)
    return 24

def context_policy(s:readbuf, o:mutbuf, kind:u64) -> u32:
    decision = 0
    if kind == 2:
        if length(s) != 40:
            return 4294967293
        memory = read_word(s, 16)
        if memory < 67108864 or memory > 4294967296:
            decision = 1
        elif read_word(s, 32) > read_word(s, 24):
            decision = 2
    elif kind == 3:
        if length(s) != 48:
            return 4294967293
        tokens = read_word(s, 24)
        missing = read_word(s, 32)
        complete = read_word(s, 40)
        if missing > 7 or complete > 1 or ((missing & 1) != 0 and tokens != 0):
            return 4294967293
        if tokens > read_word(s, 16):
            decision = 3
        elif complete == 1 and missing != 0:
            decision = 4
    elif kind == 4:
        if length(s) > 524304 or (length(s) & 7) != 0:
            return 4294967293
        offset = 16
        total = 0
        while offset < length(s):
            size = read_word(s, offset)
            if size > 1048576:
                return 4294967293
            total = total + size
            offset = offset + 8
        if total > 33554432:
            decision = 5
    else:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 1)
    put(o, 16, decision)
    return 24

def measurement_policy(s:readbuf, o:mutbuf) -> u32:
    if length(s) != 48:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    before = read_word(s, 16)
    after = read_word(s, 24)
    threshold = read_word(s, 32)
    flags = read_word(s, 40)
    if threshold == 9223372036854775808:
        threshold = 0
    if flags > 31 or threshold > 4607182418800017408:
        return 4294967293
    ratio = 0
    if before != 0 and before != after:
        if before > after:
            ratio = rational_bits(before - after, before)
        else:
            ratio = rational_bits(after - before, before) | 9223372036854775808
    outcome = 6
    if (flags & 1) != 0:
        outcome = 1
    elif (flags & 2) == 0:
        outcome = 2
    elif (flags & 4) == 0 or (flags & 24) == 24:
        outcome = 3
    elif after < before and ratio >= threshold:
        outcome = 4
    elif after > before:
        outcome = 5
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, outcome)
    put(o, 16, ratio)
    return 24

def observation_agreement(s:readbuf, o:mutbuf) -> u32:
    # Header followed by five pairs of length-prefixed fields, in order:
    # status, scalar result, external bytes, first trap, resource ledger.
    # Mode 0 compares a workload declaration, where buffers may be omitted;
    # mode 1 compares two reference executions; mode 2 compares native results.
    if length(s) < 24 or read_word(s, 16) > 2:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    mode = read_word(s, 16)
    offset = 24
    field = 0
    equal = 1
    while field < 5:
        if length(s) - offset < 16:
            return 4294967293
        left = read_word(s, offset)
        right = read_word(s, offset + 8)
        offset = offset + 16
        if left > length(s) - offset:
            return 4294967293
        right_at = offset + left
        if right > length(s) - right_at:
            return 4294967293
        if field < 2 or (field == 2 and (mode != 0 or right != 0)) or mode == 1:
            if left != right:
                equal = 0
            else:
                index = 0
                while index < left and equal != 0:
                    if byte(s, offset + index) != byte(s, right_at + index):
                        equal = 0
                    index = index + 1
        field = field + 1
        offset = right_at + right
    if offset != length(s):
        return 4294967293
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 1)
    put(o, 16, equal)
    return 24

def rational_bits(numerator:u64, denominator:u64) -> u64:
    # A nonzero ratio of two u64 values is always normal in binary64.
    exponent = 1023
    divisor = denominator
    remainder = numerator
    if numerator >= denominator:
        while divisor <= (numerator >> 1):
            divisor = divisor << 1
            exponent = exponent + 1
        remainder = numerator - divisor
    else:
        exponent = exponent - 1
        while remainder < divisor - remainder:
            remainder = remainder + remainder
            exponent = exponent - 1
        remainder = remainder - (divisor - remainder)
    significand = 1
    count = 0
    while count < 52:
        complement = divisor - remainder
        significand = significand << 1
        if remainder >= complement:
            remainder = remainder - complement
            significand = significand | 1
        else:
            remainder = remainder + remainder
        count = count + 1
    complement = divisor - remainder
    if remainder > complement or (remainder == complement and (significand & 1) == 1):
        significand = significand + 1
    if significand == 9007199254740992:
        significand = significand >> 1
        exponent = exponent + 1
    return (exponent << 52) | (significand & 4503599627370495)

def cost_totals(s:readbuf, o:mutbuf) -> u32:
    # Each 16-byte row contains a scope and one unsigned word. Up to
    # 10,000 words per scope require at most 78 bits.
    if length(s) > 160016 or (length(s) & 15) != 0:
        return 4294967293
    if length(o) < 40:
        return 4294967294
    context_low = 0
    context_high = 0
    unscoped_low = 0
    unscoped_high = 0
    offset = 16
    while offset < length(s):
        scope = read_word(s, offset)
        value = read_word(s, offset + 8)
        if scope == 0:
            updated = context_low + value
            if updated < context_low:
                context_high = context_high + 1
            context_low = updated
        elif scope == 1:
            updated = unscoped_low + value
            if updated < unscoped_low:
                unscoped_high = unscoped_high + 1
            unscoped_low = updated
        else:
            return 4294967293
        offset = offset + 16
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, context_low)
    put(o, 16, context_high)
    put(o, 24, unscoped_low)
    put(o, 32, unscoped_high)
    return 40

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    count = 0
    while count < 8:
        value = value | (byte(s, index + count) << (count * 8))
        count = count + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(w, index + count, value >> (count * 8))
        count = count + 1
    return value
'''

def source_program():
    return SOURCE.replace('@MAGIC@',str(MAGIC)).replace('@RESULT_MAGIC@',str(RESULT_MAGIC))

def document():
    nodes=ast.parse(source_program()).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'agent_identity','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/agent_identity.hepta'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)


if __name__=='__main__':main()
