"""Author bounded Agent u64/digest identity admission in ordinary HIA Core."""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_identity_native import (
    ABI_SCALAR_IDS, EXACT_COMPARISON_CHUNK, PROOF_EFFECT_IDS, PROOF_OPCODE_IDS,
)
from hepta.hia_opcodes import WIDTHS
from hepta.hia_optimization import PURE
from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
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
    if kind == 8:
        return record_authority(s, o)
    if kind == 9:
        return wall_window(s, o)
    if kind == 10:
        return claim_eligibility(s, o)
    if kind == 11:
        return finite_function(s, o, w)
    if kind == 12:
        return finite_domain(s, o)
    if kind == 13:
        return exact_comparison(s, o)
    if kind == 14:
        return abi_scalar(s, o)
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
        if equal != 0 and (field < 2 or (field == 2 and (mode != 0 or right != 0)) or mode == 1):
            equal = equal_pair(s, offset, left, right_at, right)
        field = field + 1
        offset = right_at + right
    if offset != length(s):
        return 4294967293
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 1)
    put(o, 16, equal)
    return 24

def record_authority(s:readbuf, o:mutbuf) -> u32:
    # Three exact namespace fields followed by an optional required kind.
    # Missing references and mismatching identity take precedence over kind.
    if length(s) < 24 or read_word(s, 16) > 1:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    offset = 24
    field = 0
    decision = 1 - read_word(s, 16)
    while field < 4:
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
        if decision == 0 and (field < 3 or left != 0):
            if equal_pair(s, offset, left, right_at, right) == 0:
                decision = 1
                if field == 3:
                    decision = 2
        field = field + 1
        offset = right_at + right
    if offset != length(s):
        return 4294967293
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 1)
    put(o, 16, decision)
    return 24

def equal_pair(s:readbuf, left_at:u64, left:u64, right_at:u64, right:u64) -> u64:
    if left != right:
        return 0
    index = 0
    while index < left:
        if byte(s, left_at + index) != byte(s, right_at + index):
            return 0
        index = index + 1
    return 1

def finite_function(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    # Raw observed function shape: block count, entry index, operation
    # count, effect mask, two successors per block, then opcode IDs.
    if length(s) < 48:
        return 4294967293
    if length(o) < 24 or length(w) < 384:
        return 4294967294
    blocks = read_word(s, 16)
    entry = read_word(s, 24)
    operations = read_word(s, 32)
    effects = read_word(s, 40)
    if blocks > 128 or operations > 4096:
        if length(s) != 48:
            return 4294967293
        return finite_function_reply(o, 0)
    op_at = 48 + 2 * blocks
    if length(s) != op_at + operations or entry == 0 or entry > blocks:
        return 4294967293
    index = 48
    while index < op_at:
        if byte(s, index) > blocks:
            return 4294967293
        index = index + 1
    if (effects & @DISALLOWED_EFFECT_MASK@) != 0:
        return finite_function_reply(o, 0)
    index = op_at
    while index < length(s):
        opcode = byte(s, index)
        if opcode > 63 or ((@PURE_OPCODE_MASK@ >> opcode) & 1) == 0:
            return finite_function_reply(o, 0)
        index = index + 1
    return finite_function_reply(o, acyclic_from_entry(s, w, blocks, entry))

def finite_function_reply(o:mutbuf, eligible:u64) -> u32:
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 1)
    put(o, 16, eligible)
    return 24

def acyclic_from_entry(s:readbuf, w:mutbuf, blocks:u64, entry:u64) -> u64:
    # Mark only blocks reachable from the admitted entry, as in the
    # reference verifier. An edge to an active stack node is a cycle.
    index = 0
    while index < blocks:
        store(w, index, 0)
        index = index + 1
    store(w, entry - 1, 1)
    store(w, 128, entry)
    store(w, 256, 0)
    depth = 1
    while depth != 0:
        level = depth - 1
        block = byte(w, 128 + level)
        edge = byte(w, 256 + level)
        if edge == 2:
            store(w, block - 1, 2)
            depth = depth - 1
        else:
            store(w, 256 + level, edge + 1)
            target = byte(s, 48 + 2 * (block - 1) + edge)
            if target != 0:
                state = byte(w, target - 1)
                if state == 1:
                    return 0
                if state == 0:
                    store(w, target - 1, 1)
                    store(w, 128 + depth, target)
                    store(w, 256 + depth, 0)
                    depth = depth + 1
    return 1

def finite_domain(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 32:
        return 4294967293
    if length(o) < 32:
        return 4294967294
    consumed = read_word(s, 16)
    parameters = read_word(s, 24)
    if consumed > 4096:
        return 4294967293
    if parameters > 12:
        if length(s) != 32:
            return 4294967293
        return domain_reply(o, 0, consumed)
    if length(s) != 32 + parameters:
        return 4294967293
    bits = 0
    index = 0
    while index < parameters:
        width = byte(s, 32 + index)
        if width != 1 and width != 8 and width != 16 and width != 32 and width != 64 and width != 255:
            return 4294967293
        bits = bits + width
        index = index + 1
    if bits > 12:
        return domain_reply(o, 0, consumed)
    needed = 1 << bits
    if needed > 4096 - consumed:
        return domain_reply(o, 0, consumed)
    return domain_reply(o, needed, consumed + needed)

def domain_reply(o:mutbuf, needed:u64, total:u64) -> u32:
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 1)
    put(o, 16, needed)
    put(o, 24, total)
    return 32

def wall_window(s:readbuf, o:mutbuf) -> u32:
    if length(s) != 40:
        return 4294967293
    if length(o) < 32:
        return 4294967294
    created = read_word(s, 16)
    now = read_word(s, 24)
    limit = read_word(s, 32)
    remaining = 0
    expired = 0
    high = 0
    if created > now:
        # A backwards wall-clock adjustment extends the current interval.
        remaining = limit + (created - now) // 1000000
        if remaining < limit:
            high = 1
    else:
        elapsed = now - created
        whole = elapsed // 1000000
        fraction = elapsed % 1000000
        if whole > limit or (whole == limit and fraction != 0):
            expired = 1
        else:
            remaining = limit - whole
            if fraction != 0:
                remaining = remaining - 1
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, expired)
    put(o, 16, remaining)
    put(o, 24, high)
    return 32

def claim_eligibility(s:readbuf, o:mutbuf) -> u32:
    # Claim, subject kind, candidate plan flag, check count, checks,
    # then exact pairs for base Core digest, native artifact, and plan.
    if length(s) < 48:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    claim = read_word(s, 16)
    kind = read_word(s, 24)
    planned = read_word(s, 32)
    count = read_word(s, 40)
    if claim > 3 or kind > 2 or planned > 1 or count > 4 or count > length(s) - 48:
        return 4294967293
    proved = 0
    index = 0
    while index < count:
        check = byte(s, 48 + index)
        if check > 7:
            return 4294967293
        if check == claim + 4:
            proved = 1
        index = index + 1
    offset = 48 + count
    field = 0
    matched = 0
    while field < 3:
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
        if equal_pair(s, offset, left, right_at, right) != 0:
            matched = matched | (1 << field)
        field = field + 1
        offset = right_at + right
    if offset != length(s):
        return 4294967293
    # 0 = cannot satisfy, 1 = qualifies, 2 = requires build custody recheck.
    decision = 0
    if proved != 0:
        if claim == 0 or (claim == 1 and (matched & 1) != 0):
            decision = 1
        elif kind == 1 and claim >= 2 and (matched & 2) != 0:
            decision = 2
        elif claim == 2 and kind == 2 and planned != 0 and (matched & 4) != 0:
            decision = 1
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 1)
    put(o, 16, decision)
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

def abi_scalar(s:readbuf, o:mutbuf) -> u32:
    if length(s) != 40:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    role = read_word(s, 16)
    kind = read_word(s, 24)
    word = read_word(s, 32)
    if role == @BOOL_ABI_ROLE@:
        return finite_function_reply(o, choose(kind == 2 and word <= 1, 1, 0))
    if role == @UNIT_ABI_ROLE@:
        return finite_function_reply(o, choose(kind == 1 and word == 0, 1, 0))
    if kind != 3 and kind != 4:
        return finite_function_reply(o, 0)
    spec = scalar_abi_type(role)
    width = spec & 127
    if width == 0:
        return finite_function_reply(o, 0)
    if (spec & 128) != 0:
        boundary = 1 << (width - 1)
        if kind == 4:
            return finite_function_reply(o, choose(word > 0 and word <= boundary, 1, 0))
        return finite_function_reply(o, choose(word < boundary, 1, 0))
    if kind == 4:
        return finite_function_reply(o, 0)
    if width == 64:
        return finite_function_reply(o, 1)
    return finite_function_reply(o, choose(word < (1 << width), 1, 0))

def exact_comparison(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 32:
        return 4294967293
    left = read_word(s, 16)
    right = read_word(s, 24)
    if left > @EXACT_COMPARISON_CHUNK@ or right > @EXACT_COMPARISON_CHUNK@:
        return 4294967293
    right_at = 32 + left
    if length(s) != right_at + right:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    return finite_function_reply(o, equal_pair(s, 32, left, right_at, right))
'''

def source_program():
    pure = sum(1 << PROOF_OPCODE_IDS[opcode] for opcode in PURE)
    disallowed = ((1 << 64) - 1) ^ PROOF_EFFECT_IDS['trap']
    types = ['def scalar_abi_type(role:u64) -> u64:']
    for name, width in WIDTHS.items():
        spec = width | (128 if name.startswith('i') else 0)
        types += [f'    if role == {ABI_SCALAR_IDS[name]}:', f'        return {spec}']
    types.append('    return 0')
    return (SOURCE.replace('@MAGIC@', str(MAGIC)).replace('@RESULT_MAGIC@', str(RESULT_MAGIC))
            .replace('@PURE_OPCODE_MASK@', str(pure))
            .replace('@DISALLOWED_EFFECT_MASK@', str(disallowed))
            .replace('@EXACT_COMPARISON_CHUNK@', str(EXACT_COMPARISON_CHUNK))
            .replace('@BOOL_ABI_ROLE@', str(ABI_SCALAR_IDS['bool']))
            .replace('@UNIT_ABI_ROLE@', str(ABI_SCALAR_IDS['unit'])) + '\n' + '\n'.join(types) + '\n')


def document():
    nodes=ast.parse(source_program()).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=LinkerBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'agent_identity','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/agent_identity.hepta'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)


if __name__=='__main__':main()
