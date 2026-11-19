"""Author bounded Agent u64/digest identity admission in ordinary HIA Core."""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_identity_native import (
    ABI_SCALAR_IDS, EXACT_COMPARISON_CHUNK, PROOF_EFFECT_IDS, PROOF_OPCODE_IDS,
)
from hepta.hia_agent_store import MAX_ARTIFACT_BYTES
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
    if kind == 15:
        return proof_evidence(s, o)
    if kind == 16:
        return cost_receipt(s, o)
    if kind == 17:
        return cost_window(s, o)
    if kind == 18:
        return wide_wall_window(s, o)
    if kind == 19:
        return artifact_input(s, o)
    if kind == 20:
        size = artifact_receipt(s, o, 0)
        if size > length(o):
            return size
        return artifact_receipt(s, o, 1)
    if kind == 21:
        size = context_manifest(s, o, 0)
        if size > length(o):
            return size
        return context_manifest(s, o, 1)
    if kind == 22:
        size = context_receipt(s, o, 0)
        if size > length(o):
            return size
        return context_receipt(s, o, 1)
    if kind == 23:
        return context_id(s, o)
    if kind == 24:
        size = page_receipt(s, o, 0)
        if size > length(o):
            return size
        return page_receipt(s, o, 1)
    if kind == 25:
        size = candidate_receipt(s, o, 0)
        if size > length(o):
            return size
        return candidate_receipt(s, o, 1)
    if kind == 26:
        size = verification_record(s, o, 0)
        if size > length(o):
            return size
        return verification_record(s, o, 1)
    if kind == 27:
        size = verification_result(s, o, 0)
        if size > length(o):
            return size
        return verification_result(s, o, 1)
    if kind == 28:
        size = build_record(s, o, 0)
        if size > length(o):
            return size
        return build_record(s, o, 1)
    if kind == 29:
        size = build_result(s, o, 0)
        if size > length(o):
            return size
        return build_result(s, o, 1)
    if kind == 30:
        return issued_artifact(s, o)
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

def wide_wall_window(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 36:
        return 4294967293
    words = read_word(s, 16)
    if words == 0 or words > (length(s) - 24) // 12 or length(s) != 24 + 12 * words:
        return 4294967293
    width = 4 * words
    if width > 4294967279 or length(o) < 16 + width:
        return 4294967294
    # Each operand has an entire sign-extension limb. This leaves at least
    # 31 spare magnitude bits, enough for the scale and the two signed sums.
    if wall_sign_limb(s, 20 + width) == 0 or wall_sign_limb(s, 20 + 2 * width) == 0 or wall_sign_limb(s, 20 + 3 * width) == 0:
        return 4294967293
    top = wide_wall_delta(s, o, width)
    expired = top >> 31
    at = width
    remainder = 0
    while at != 0:
        at = at - 4
        value = get_wall_limb(o, 16 + at) | (remainder << 32)
        quotient = choose(expired == 0, value // 1000000, 0)
        remainder = value % 1000000
        put_wall_limb(o, 16 + at, quotient)
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, expired)
    return 16 + width

def wide_wall_delta(s:readbuf, o:mutbuf, width:u64) -> u64:
    at = 0
    scale_carry = 0
    sum_carry = 0
    borrow = 0
    digit = 0
    # Work modulo the transport width. Because of the admitted spare limb,
    # the sign bit of the result is the sign of the exact mathematical delta.
    while at < width:
        scaled = read_wall_limb(s, 24 + 2 * width + at) * 1000000 + scale_carry
        scale_carry = scaled >> 32
        summed = read_wall_limb(s, 24 + at) + (scaled & 4294967295) + sum_carry
        sum_carry = summed >> 32
        left = summed & 4294967295
        right = read_wall_limb(s, 24 + width + at) + borrow
        borrow = choose(left < right, 1, 0)
        digit = (left - right) & 4294967295
        put_wall_limb(o, 16 + at, digit)
        at = at + 4
    return digit

def wall_sign_limb(s:readbuf, offset:u64) -> u64:
    word = read_wall_limb(s, offset)
    return choose(word == 0 or word == 4294967295, 1, 0)

def read_wall_limb(s:readbuf, offset:u64) -> u64:
    return byte(s, offset) | (byte(s, offset + 1) << 8) | (byte(s, offset + 2) << 16) | (byte(s, offset + 3) << 24)

def get_wall_limb(o:mutbuf, offset:u64) -> u64:
    return byte(o, offset) | (byte(o, offset + 1) << 8) | (byte(o, offset + 2) << 16) | (byte(o, offset + 3) << 24)

def put_wall_limb(o:mutbuf, offset:u64, word:u64) -> u64:
    store(o, offset, word & 255)
    store(o, offset + 1, (word >> 8) & 255)
    store(o, offset + 2, (word >> 16) & 255)
    store(o, offset + 3, word >> 24)
    return 0

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

def proof_evidence(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 96:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    claim = read_word(s, 16)
    status = read_word(s, 24)
    subject = read_word(s, 32)
    method = read_word(s, 40)
    flags = read_word(s, 48)
    checked = read_word(s, 56)
    required = read_word(s, 64)
    complete = read_word(s, 72)
    bytes_equal = read_word(s, 80)
    object_equal = read_word(s, 88)
    if claim > 4 or status > 4 or subject > 4 or method > 5 or flags > 511:
        return 4294967293
    if complete > 2 or bytes_equal > 2 or object_equal > 2:
        return 4294967293
    matched = proof_text_matches(s)
    if matched > 127:
        return 4294967293
    decision = 0
    if claim == 1:
        if status == 1 and (matched & 3) == 3:
            decision = 1
    elif claim == 2 and (flags & 3) == 3:
        if method == 1:
            if status == 1 and (matched & 28) == 28 and (flags & 4) != 0:
                decision = 2
        elif method == 2:
            if checked <= required and required > 0 and required <= 4096:
                if status == 1 and complete == 2 and checked == required and (flags & 24) == 24 and (matched & 24) == 24:
                    decision = 3
                elif status == 2 and (flags & 32) != 0:
                    decision = 8
                elif status == 3 and complete == 1 and (flags & 32) == 0:
                    decision = 3
        elif method == 3:
            if status == 3:
                decision = 4
        elif (flags & 256) != 0:
            decision = 9
    elif claim == 3:
        if subject == 4:
            decision = 10
        elif subject == 2 and status == 4 and (flags & 64) != 0:
            decision = 6
        elif subject == 3 and status == 1 and method == 4 and (flags & 128) != 0 and (matched & 34) == 34:
            decision = 5
    elif claim == 4 and subject == 4 and method == 5 and (matched & 64) != 0:
        if bytes_equal != 0 and object_equal != 0:
            if status == choose(bytes_equal == 2 and object_equal == 2, 1, 2):
                decision = 7
    return finite_function_reply(o, decision)

def proof_text_matches(s:readbuf) -> u64:
    offset = 96
    field = 0
    matched = 0
    while field < 7:
        if length(s) - offset < 16:
            return 128
        left = read_word(s, offset)
        right = read_word(s, offset + 8)
        offset = offset + 16
        if left == 0 or right == 0 or left > length(s) - offset:
            return 128
        right_at = offset + left
        if right > length(s) - right_at:
            return 128
        if byte(s, offset) == 1 and byte(s, right_at) == 1:
            if equal_pair(s, offset, left, right_at, right) != 0:
                matched = matched | (1 << field)
        field = field + 1
        offset = right_at + right
    if offset != length(s):
        return 128
    return matched

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

def cost_window(s:readbuf, o:mutbuf) -> u32:
    if length(s) != 24 or read_word(s, 16) > 10001:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    observed = read_word(s, 16)
    return finite_function_reply(o, choose(observed > 10000, 10000, observed))

def cost_receipt(s:readbuf, o:mutbuf) -> u32:
    size = cost_receipt_pass(s, o, 0)
    if size > length(o):
        return size
    return cost_receipt_pass(s, o, 1)

def receipt_fragment_size(s:readbuf, at:u64) -> u64:
    if at > length(s) or length(s) - at < 8:
        return 0
    size = read_word(s, at)
    return choose(size <= length(s) - at - 8, size, 0)

def receipt_literal(o:mutbuf, cursor:u64, word:u64, size:u64, emit:u64) -> u64:
    if cursor > length(o) or size > length(o) - cursor:
        return length(o) + 1
    index = 0
    while emit != 0 and index < size:
        store(o, cursor + index, word >> (8 * index))
        index = index + 1
    return cursor + size

def receipt_fragment(s:readbuf, o:mutbuf, at:u64, cursor:u64, size:u64, emit:u64) -> u64:
    if cursor > length(o) or size > length(o) - cursor:
        return length(o) + 1
    index = 0
    while emit != 0 and index < size:
        store(o, cursor + index, byte(s, at + index))
        index = index + 1
    return cursor + size

def artifact_input(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 20:
        return 4294967293
    kind = quad(s, 16)
    if kind == @ARTIFACT_PATH@:
        if length(s) != 28:
            return 4294967293
        limit = read_word(s, 20)
        if limit == 0 or limit > 8388608:
            return 4294967293
        if length(o) < 24:
            return 4294967294
        put(o, 0, @RESULT_MAGIC@)
        put(o, 8, 1)
        put(o, 16, limit)
        return 24
    if kind != @ARTIFACT_UTF8@ or (length(s) - 20) % 4 != 0 or length(s) > 262164:
        return 4294967293
    size = artifact_text(s, o, 0)
    if size > length(o):
        return size
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 0)
    return artifact_text(s, o, 1)

def quad(s:readbuf, at:u64) -> u64:
    return byte(s, at) | (byte(s, at + 1) << 8) | (byte(s, at + 2) << 16) | (byte(s, at + 3) << 24)

def artifact_text(s:readbuf, o:mutbuf, emit:u64) -> u64:
    cursor = 16
    at = 20
    while at < length(s):
        codepoint = quad(s, at)
        if codepoint > 1114111 or (codepoint >= 55296 and codepoint <= 57343):
            return 4294967293
        tail = 128 | (codepoint & 63)
        if codepoint < 128:
            cursor = receipt_literal(o, cursor, codepoint, 1, emit)
        elif codepoint < 2048:
            first = 192 | (codepoint >> 6)
            cursor = receipt_literal(o, cursor, first | (tail << 8), 2, emit)
        elif codepoint < 65536:
            first = 224 | (codepoint >> 12)
            second = 128 | ((codepoint >> 6) & 63)
            cursor = receipt_literal(o, cursor, first | (second << 8) | (tail << 16), 3, emit)
        else:
            first = 240 | (codepoint >> 18)
            second = 128 | ((codepoint >> 12) & 63)
            third = 128 | ((codepoint >> 6) & 63)
            cursor = receipt_literal(o, cursor, first | (second << 8) | (third << 16) | (tail << 24), 4, emit)
        at = at + 4
    if cursor > length(o):
        return 4294967294
    return cursor

def artifact_size_text(o:mutbuf, cursor:u64, size:u64, emit:u64) -> u64:
    rest = size
    divisor = 1
    while rest >= 10:
        rest = rest // 10
        divisor = divisor * 10
    while divisor != 0:
        cursor = receipt_literal(o, cursor, 48 + size // divisor, 1, emit)
        size = size % divisor
        divisor = divisor // 10
    return cursor

def context_id(s:readbuf, o:mutbuf) -> u32:
    if length(s) != 32:
        return 4294967293
    if length(o) < 36:
        return 4294967294
    receipt_literal(o, 0, 762868835, 4, 1)
    return nonce_hex(s, o, 16, 4)

def nonce_hex(s:readbuf, o:mutbuf, start:u64, destination:u64) -> u64:
    index = 0
    while index < 16:
        value = byte(s, start + index)
        high = value >> 4
        low = value & 15
        position = destination + 2 * index
        store(o, position, choose(high < 10, 48 + high, 87 + high))
        store(o, position + 1, choose(low < 10, 48 + low, 87 + low))
        index = index + 1
    return destination + 32

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

def cost_receipt_source():
    """Emit the fixed receipt schema and a bounded captured-fragment ABI."""
    lines = [
        'def cost_receipt_pass(s:readbuf, o:mutbuf, emit:u64) -> u64:',
        '    if length(s) < 32 or length(o) > 8388608:',
        '        return 4294967293',
        '    count = read_word(s, 16)',
        '    complete = read_word(s, 24)',
        '    if count > 10001 or complete > 1:',
        '        return 4294967293',
        '    at = 32',
        '    cursor = 0',
    ]

    def literal(raw, indent='    '):
        for index in range(0, len(raw), 8):
            part = raw[index:index + 8].encode('ascii')
            lines.append(f'{indent}cursor = receipt_literal(o, cursor, '
                         f'{int.from_bytes(part, "little")}, {len(part)}, emit)')

    def boolean(field):
        lines.append(f'    if {field}:')
        literal('true', '        ')
        lines.append('    else:')
        literal('false', '        ')

    def fragment(*, external=False):
        lines.extend(('    size = receipt_fragment_size(s, at)',
                      '    if size == 0:',
                      '        return 4294967293',
                      '    at = at + 8'))
        if external:
            lines.extend(('    if complete == 1:',
                          '        cursor = receipt_fragment(s, o, at, cursor, size, emit)',
                          '    else:'))
            literal('null', '        ')
        else:
            lines.append('    cursor = receipt_fragment(s, o, at, cursor, size, emit)')
        lines.append('    at = at + size')

    literal('{"adoption_wall_ns":null,"context":')
    fragment()
    literal(',"context_tool_wall_ns_before_evaluation":')
    fragment()
    literal(',"entries_truncated":')
    boolean('count > 10000')
    literal(',"evaluation_wall_ns_through_report":')
    fragment()
    literal(',"external_cost_source":"caller-supplied report, independently unmeasured","external_costs":{')
    for prefix, name in (('', 'discovery_wall_ns'), (',', 'model_tokens'), (',', 'model_wall_ns')):
        literal(f'{prefix}"{name}":')
        fragment(external=True)
    literal('},"external_costs_complete":')
    boolean('complete == 1')
    literal(',"failed_attempts_retained":true,"full_search_cost_complete":false,"future_execution_count":')
    fragment()
    literal(',"native_child_wall_ns":')
    fragment()
    literal(',"net_optimization_benefit_proved":false,"schema":"hepta.hia.agent.cost-ledger.v1",'
            '"scope":"observed request prefix; unscoped calls cannot be uniquely attributed and adoption/future/'
            'model cost may be unknown","unattributed_discovery_artifact_read_wall_ns":')
    fragment()
    literal('}')
    lines.extend(('    if at != length(s):', '        return 4294967293',
                  '    if cursor > length(o):', '        return 4294967294', '    return cursor'))
    return '\n'.join(lines) + '\n'


def artifact_receipt_source():
    """Append only the issued reference fragment to a fixed inert receipt."""
    lines = [
        'def artifact_receipt(s:readbuf, o:mutbuf, emit:u64) -> u64:',
        f'    if length(s) < 32 or read_word(s, 16) > {MAX_ARTIFACT_BYTES}:',
        '        return 4294967293',
        '    size = receipt_fragment_size(s, 24)',
        '    if size == 0 or size != length(s) - 32:',
        '        return 4294967293',
        '    cursor = 0',
    ]

    def literal(text):
        for start in range(0, len(text), 8):
            raw = text[start:start + 8].encode('ascii')
            lines.append(f'    cursor = receipt_literal(o, cursor, {int.from_bytes(raw, "little")}, {len(raw)}, emit)')

    literal('{"artifact":')
    lines.append('    cursor = receipt_fragment(s, o, 32, cursor, size, emit)')
    literal(',"byte_length":"')
    lines.append('    cursor = artifact_size_text(o, cursor, read_word(s, 16), emit)')
    literal('","content_admitted_as_program":false,"execution_authority_granted":false}')
    lines.extend(('    if cursor > length(o):', '        return 4294967294', '    return cursor'))
    return '\n'.join(lines) + '\n'


def issued_artifact_source():
    """Encode independent, already-observed nonces and a canonical digest."""
    parts = ('{"id":"a-', '","sha256":"', '","uri":"hia://artifacts/', '"}')
    result_size = sum(map(len, parts)) + 128
    lines = [
        'def issued_artifact(s:readbuf, o:mutbuf) -> u32:',
        '    if length(s) != 112:',
        '        return 4294967293',
        '    at = 16',
        '    while at < 80:',
        '        value = byte(s, at)',
        '        if (value < 48 or value > 57) and (value < 97 or value > 102):',
        '            return 4294967293',
        '        at = at + 1',
        f'    if length(o) < {result_size}:',
        '        return 4294967294',
        '    cursor = 0',
    ]
    for text, field in zip(parts, (
            'nonce_hex(s, o, 80, cursor)', 'receipt_fragment(s, o, 16, cursor, 64, 1)',
            'nonce_hex(s, o, 96, cursor)', None), strict=True):
        for start in range(0, len(text), 8):
            raw = text[start:start + 8].encode('ascii')
            lines.append(f'    cursor = receipt_literal(o, cursor, {int.from_bytes(raw, "little")}, {len(raw)}, 1)')
        if field is not None:
            lines.append(f'    cursor = {field}')
    lines.append('    return cursor')
    return '\n'.join(lines) + '\n'


def receipt_template(name, template):
    """Serialize already-admitted JSON fragments in a fixed HIA schema."""
    lines = [
        f'def {name}(s:readbuf, o:mutbuf, emit:u64) -> u64:',
        '    at = 16',
        '    cursor = 0',
    ]
    chunks = template.split('{}')
    for index, chunk in enumerate(chunks):
        for offset in range(0, len(chunk), 8):
            raw = chunk[offset:offset + 8].encode('ascii')
            lines.append(f'    cursor = receipt_literal(o, cursor, {int.from_bytes(raw, "little")}, {len(raw)}, emit)')
        if index + 1 < len(chunks):
            lines.extend((
                '    size = receipt_fragment_size(s, at)',
                '    if size == 0:',
                '        return 4294967293',
                '    at = at + 8',
                '    cursor = receipt_fragment(s, o, at, cursor, size, emit)',
                '    at = at + size',
            ))
    lines.extend(('    if at != length(s):', '        return 4294967293',
                  '    if cursor > length(o):', '        return 4294967294', '    return cursor'))
    return '\n'.join(lines) + '\n'


CONTEXT_MANIFEST = ('{"baseline_core_sha256":{},"baseline_program":{},"budget":{},"catalog_sha256":{},'
                    '"compiler_profile":{},"context_is_execution_authority":false,"foreign_buffer_exports":{},'
                    '"installation":{},"objective":{},"resource_reservation_held":false,"sampled_at":{},'
                    '"schema":"hepta.hia.agent.context.v1","target_observation":{"cpu_count":{},"machine":{},'
                    '"observation_only":true,"system":{}},"target_profile":{},"workload":{}}')
CONTEXT_RECEIPT = ('{"compiler_profile":{},"context":{},"context_is_execution_authority":false,'
                   '"manifest":{},"resource_reservation_held":false,"sampled_at":{},"target_profile":{}}')
PAGE_RECEIPT = '{"artifact":{},"content":{},"encoding":{},"next_cursor":{}}'
CANDIDATE_RECEIPT = ('{"adopted":false,"base_program":{},"behavior_equivalence_proved":false,'
                     '"candidate":{},"core_admitted":true,"diagnostics":{}}')
VERIFICATION_RECORD = ('{"base_core_sha256":{},"base_program":{},"candidate":{},"candidate_core_sha256":{},'
                       '"checks":{},"context":{},"installation":{},"schema":"hepta.hia.agent.verification.v1",'
                       '"subject":{},"validation_profile":{}}')
VERIFICATION_RESULT = ('{"adopted":false,"candidate":{},"checks":{},"subject":{},"verification_receipt":{}}')
BUILD_RECORD = ('{"backend_profile":{},"candidate":{},"codegen":{},"context":{},"core_sha256":{},'
                '"foreign_buffer_exports":{},"installation":{},"machine_plan":{},"native_artifact":{},'
                '"native_build":{},"object_artifact":{},"object_sha256":{},"output_kind":{},'
                '"schema":"hepta.hia.agent.build.v1","signatures":{},"target_profile":{},"verification_receipts":{}}')
BUILD_RESULT = ('{"adopted":false,"backend_profile":{},"build_receipt":{},"candidate":{},'
                '"codegen_backend":"hia-direct","external_assembler_used":false,"linker_used":{},'
                '"llvm_codegen_used":false,"native_artifact":{},"native_execution_observed":false,"target_profile":{}}')



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
            .replace('@ARTIFACT_PATH@', str(int.from_bytes(b'path', 'little')))
            .replace('@ARTIFACT_UTF8@', str(int.from_bytes(b'utf8', 'little')))
            .replace('@BOOL_ABI_ROLE@', str(ABI_SCALAR_IDS['bool']))
            .replace('@UNIT_ABI_ROLE@', str(ABI_SCALAR_IDS['unit'])) + '\n' + '\n'.join(types) + '\n'
            + cost_receipt_source() + artifact_receipt_source()
            + receipt_template('context_manifest', CONTEXT_MANIFEST)
            + receipt_template('context_receipt', CONTEXT_RECEIPT)
            + receipt_template('page_receipt', PAGE_RECEIPT)
            + receipt_template('candidate_receipt', CANDIDATE_RECEIPT)
            + receipt_template('verification_record', VERIFICATION_RECORD)
            + receipt_template('verification_result', VERIFICATION_RESULT)
            + receipt_template('build_record', BUILD_RECORD)
            + receipt_template('build_result', BUILD_RESULT) + issued_artifact_source())


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
