"""Author the bounded scalar NDU protocol, evaluator and digest chain in HIA.

The compatibility wire is the fixed single-owner profile of the independently
pinned Rust evaluator.  No Rust/Python evaluator is called by the produced image.
Only the separate mechanical syscall adapter performs process I/O.
"""
from __future__ import annotations

import hashlib
import ast
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_sha256 import source_program as sha_program

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/ndu_scalar.hepta'
UPSTREAM = 'd3c2d760eca5065fc966820379c35c6e8d56e855'
WORK_BYTES = 2 << 20
INPUT_BYTES = (1 << 20) + 4096
OUTPUT_BYTES = (1 << 20) + 4096


def be(value, width=4):
    return value.to_bytes(width, 'big')


def sid(value):
    raw = value.encode('ascii')
    return be(len(raw)) + raw


LITERALS = {
    'K_SCHEMA': b'schema', 'K_OBJECTIVE': b'objective_sha256',
    'K_GENERATION': b'generation', 'K_CAP': b'resource_cap_q32',
    'K_CANDIDATES': b'candidates', 'K_ID': b'id', 'K_COST': b'cost_q32',
    'K_UNCERTAINTY': b'uncertainty_q32', 'K_RESOURCE': b'resource_q32',
    'K_HARD': b'hard_violation', 'K_SUPPORT': b'support_sha256',
    'REQUEST_SCHEMA': b'hepta.hia.ndu-request.v1', 'ABSTAIN': b'abstain',
    'STREAM_ARG': b'--stream-v1',
    'PROFILE_PREFIX': b'hepta.ndu.utility-profile.v1' + sid('hia-total-cost-ms-v1')
        + hashlib.sha256(b'total-ms:minimize;search-ms:ceiling').digest()
        + hashlib.sha256(b'nanoseconds-to-ms-q32;nearest-ties-even;no-clipping').digest()
        + be(1) + sid('total-ms') + b'\x01' + be(0) + be(1) + sid('search-ms'),
    'PROFILE_SUFFIX': be(1) + sid('hia-compiler'),
    'POLICY_PREIMAGE': b'hepta.ndu.evaluation-policy.v2' + sid('hia-single-owner-no-shared-cost-v1')
        + be(1) + sid('total-ms') + b'\x03' + be(0)
        + be(1) + sid('search-ms') + b'\x03'
        + be(1) + sid('total-ms') + b'\x01'
        + be(1) + sid('total-ms') + be(0, 8),
    'CONTRIBUTION_DOMAIN': b'hepta.ndu.contribution.v1',
    'ORGAN_ID': sid('hia-compiler'), 'UTILITY_AXIS': be(1) + sid('total-ms'),
    'RESOURCE_AXIS': be(1) + sid('search-ms'),
    'EVALUATION_DOMAIN': b'hepta.ndu.evaluation.v1',
    'V2_DOMAIN': b'hepta.ndu.evaluation.v2',
    'O_ADVICE': b'{"advisory_recommendation":',
    'O_AUTHORITY': b',"authority":"ADVISORY_ONLY","disposition":',
    'D_ABSTAIN': b'"InfeasibleExplicitAbstain"',
    'D_UNIQUE': b'"UniqueParetoRecommendation"',
    'D_TIE': b'"ParetoSetRequiresSlowPath"',
    'O_ENTRY': b',"entry_point":"codex_hepta_ndu::evaluate_candidates_with_policy","evaluation_digest_v2":',
    'O_POLICY': b',"evaluation_policy_digest":', 'O_GENERATION': b',"generation":',
    'O_OBJECTIVE': b',"global_optimality_established":false,"objective_sha256":',
    'O_FRONTIER': b',"pareto_frontier":[',
    'O_REJECTED': b'],"proves_program_safety":false,"rejected":[',
    'O_ID': b'{"id":', 'O_REASONS': b',"reasons":',
    'R_HARD': b'"[HardConstraintViolation]"',
    'R_RESOURCE': b'"[ResourceCeilingExceeded]"',
    'R_BOTH': b'"[HardConstraintViolation, ResourceCeilingExceeded]"',
    'O_REQUEST': b'],"request_sha256":',
    'O_TAIL': b',"schema":"hepta.hia.ndu-response.v1","upstream_commit":"' + UPSTREAM.encode()
        + b'","utility_profile_digest":',
    'NULL': b'null',
    'HELLO_PREFIX': b'{"authority":"ADVISORY_ONLY","entry_point":"codex_hepta_ndu::evaluate_candidates_with_policy",'
        b'"evaluates_each_request":true,"max_frame_json_bytes":1048576,"max_requests":',
    'HELLO_SUFFIX': b',"max_session_bytes":8388608,"result_cache":false,"schema":"hepta.hia.ndu-stream-hello.v1",'
        b'"transport_profile":"hepta.hia.ndu-ranking-persistent-framed.v1","upstream_commit":"' + UPSTREAM.encode() + b'"}',
    'ERROR_PREFIX': b'{"authority":"NONE","error":',
    'ERROR_ONESHOT': b',"schema":"hepta.hia.ndu-error.v1"}\n',
    'ERROR_STREAM': b',"schema":"hepta.hia.ndu-stream-error.v1"}\n',
    'E_JSON': b'"invalid closed scalar JSON request"',
    'E_BYTES': b'"request exceeds byte limit"',
    'E_SCHEMA': b'"invalid schema, candidate count or resource cap"',
    'E_DUPLICATE': b'"duplicate candidate or negative cost"',
    'E_ABSTAIN': b'"baseline abstain candidate is required"',
    'E_INFEASIBLE': b'"abstain candidate is infeasible"',
    'E_DIGEST': b'"invalid lowercase hex or empty digest"',
    'E_STREAM_ARGS': b'"expected --stream-v1 SESSION_HEX MAX_REQUESTS"',
    'E_STREAM_SESSION': b'"invalid stream session or request allowance"',
    'E_STREAM_FRAME': b'"stream frame exceeds byte bounds"',
    'E_STREAM_BUDGET': b'"session byte allowance exhausted"',
    'E_STREAM_SHORT': b'"failed to fill whole buffer"',
    'E_STREAM_SEQUENCE': b'"stream sequence or session mismatch"',
    'E_IO': b'"I/O transport failure"',
}

POLICY = r'''
def ndu(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or length(o) < 1048644 or length(w) != 2097152:
        return 0
    state = get(w, 1536)
    if state == 0:
        return startup(s, o, w)
    if input_word(s, 0) == 2:
        if state == 8:
            return command(o, 3, 2, 0)
        return error_reply(o, w, @E_IO@)
    if state == 7:
        return command(o, 3, 0, 0)
    if state == 8:
        return command(o, 3, 2, 0)
    if state == 1:
        error = evaluate(s, w, 16)
        if error != 0:
            return error_reply(o, w, error)
        put(w, 1536, 7)
        return body_reply(o, w)
    if state == 2:
        if get(w, 1552) > get(w, 1544):
            return command(o, 3, 0, 0)
        put(w, 1536, 3)
        return command(o, 1, 0, 4)
    if state == 3:
        size = length(s) - 16
        if size == 0 and input_word(s, 0) == 1:
            return command(o, 3, 0, 0)
        if size != 4:
            return error_reply(o, w, @E_STREAM_SHORT@)
        size = input_be(s, 16, 4)
        if size < 69 or size > 1048644:
            return error_reply(o, w, @E_STREAM_FRAME@)
        if charge(w, 4 + size) == 0:
            return error_reply(o, w, @E_STREAM_BUDGET@)
        put(w, 1568, size)
        put(w, 1536, 4)
        return command(o, 1, 0, size)
    if state == 4:
        if length(s) - 16 != get(w, 1568):
            return error_reply(o, w, @E_STREAM_SHORT@)
        if input_be(s, 16, 4) != get(w, 1552):
            return error_reply(o, w, @E_STREAM_SEQUENCE@)
        i = 0
        while i < 64:
            if byte(s, 20 + i) != byte(w, 1664 + i):
                return error_reply(o, w, @E_STREAM_SEQUENCE@)
            i = i + 1
        error = evaluate(s, w, 84)
        if error != 0:
            return error_reply(o, w, error)
        put(w, 1536, 2)
        result = frame_reply(o, w, get(w, 1552))
        put(w, 1552, get(w, 1552) + 1)
        return result
    return command(o, 3, 2, 0)

def startup(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    argc = input_word(s, 8)
    if argc == 1:
        put(w, 1584, 0)
        put(w, 1536, 1)
        return command(o, 4, 0, 1048577)
    put(w, 1584, 1)
    if argc != 4 or input_word(s, 0) != 0:
        return error_reply(o, w, @E_STREAM_ARGS@)
    at = 16
    index = 0
    while index < 4:
        if at > length(s) or length(s) - at < 8:
            return error_reply(o, w, @E_STREAM_ARGS@)
        size = input_word(s, at)
        at = at + 8
        if size > length(s) - at:
            return error_reply(o, w, @E_STREAM_ARGS@)
        if index == 1:
            if size != 11:
                return error_reply(o, w, @E_STREAM_ARGS@)
            copy_input(s, w, at, 2304, size)
            if literal_equal(w, 2304, size, @STREAM_ARG@) == 0:
                return error_reply(o, w, @E_STREAM_ARGS@)
        if index == 2:
            if size != 64:
                return error_reply(o, w, @E_STREAM_SESSION@)
            i = 0
            while i < 64:
                c = byte(s, at + i)
                if hex_digit(c) > 15:
                    return error_reply(o, w, @E_STREAM_SESSION@)
                store(w, 1664 + i, c)
                i = i + 1
        if index == 3:
            if size == 0:
                return error_reply(o, w, @E_STREAM_SESSION@)
            value = 0
            i = 0
            if byte(s, at) == 43:
                i = 1
            if i == size:
                return error_reply(o, w, @E_STREAM_SESSION@)
            while i < size:
                c = byte(s, at + i)
                if c < 48 or c > 57 or value > 256:
                    return error_reply(o, w, @E_STREAM_SESSION@)
                value = value * 10 + c - 48
                i = i + 1
            if value < 1 or value > 256:
                return error_reply(o, w, @E_STREAM_SESSION@)
            put(w, 1544, value)
        at = at + size
        index = index + 1
    if at != length(s):
        return error_reply(o, w, @E_STREAM_ARGS@)
    put(w, 1552, 1)
    put(w, 1560, 0)
    put(w, 2176, 1200000)
    output_literal(w, @HELLO_PREFIX@)
    output_decimal(w, get(w, 1544))
    output_literal(w, @HELLO_SUFFIX@)
    put(w, 1536, 2)
    return frame_reply(o, w, 0)

def command(o:mutbuf, action:u64, value:u64, size:u64) -> u32:
    put(o, 0, action)
    put(o, 8, value)
    put(o, 16, size)
    return 32

def charge(w:mutbuf, amount:u64) -> u64:
    total = get(w, 1560)
    if total > 8388608 or amount > 8388608 - total:
        return 0
    put(w, 1560, total + amount)
    return 1

def error_reply(o:mutbuf, w:mutbuf, error:u64) -> u32:
    put(w, 2176, 1200000)
    output_literal(w, @ERROR_PREFIX@)
    output_literal(w, error)
    if get(w, 1584) == 0:
        output_literal(w, @ERROR_ONESHOT@)
    else:
        output_literal(w, @ERROR_STREAM@)
    put(w, 1536, 8)
    size = get(w, 2176) - 1200000
    copy_work(w, o, 1200000, 32, size)
    command(o, 2, 2, size)
    return 32 + size

def body_reply(o:mutbuf, w:mutbuf) -> u32:
    size = get(w, 2176) - 1200000
    copy_work(w, o, 1200000, 32, size)
    command(o, 2, 1, size)
    return 32 + size

def frame_reply(o:mutbuf, w:mutbuf, sequence:u64) -> u32:
    size = get(w, 2176) - 1200000
    if size == 0 or size > 1048576 or charge(w, 72 + size) == 0:
        return error_reply(o, w, @E_STREAM_BUDGET@)
    big(o, 32, 68 + size, 4)
    big(o, 36, sequence, 4)
    copy_work(w, o, 1664, 40, 64)
    copy_work(w, o, 1200000, 104, size)
    command(o, 2, 1, 72 + size)
    return 104 + size

def evaluate(s:readbuf, w:mutbuf, begin:u64) -> u64:
    if begin > length(s) or length(s) - begin > 1048576:
        return @E_BYTES@
    put(w, 2048, begin)
    put(w, 2056, 0)
    put(w, 2064, 0)
    put(w, 2080, begin)
    put(w, 2088, length(s))
    if consume(s, w, 123) == 0:
        return @E_JSON@
    flags = 0
    more = 1
    while more != 0:
        size = read_string(s, w, 2304, 128)
        key = request_key(w, size)
        if key == 0 or (flags & key) != 0 or consume(s, w, 58) == 0:
            return @E_JSON@
        flags = flags | key
        if key == 1:
            size = read_string(s, w, 2304, 128)
            if literal_equal(w, 2304, size, @REQUEST_SCHEMA@) == 0:
                return @E_SCHEMA@
        elif key == 2:
            size = read_string(s, w, 2560, 64)
            if size != 64 or decode_digest(w, 2560, 2656) == 0:
                return @E_DIGEST@
        elif key == 4:
            value = read_integer(s, w, 18446744073709551615)
            if value == 0:
                return @E_SCHEMA@
            put(w, 2072, value)
        elif key == 8:
            put(w, 2096, read_integer(s, w, 9223372036854775807))
        else:
            if read_candidates(s, w) == 0:
                return @E_JSON@
        if get(w, 2056) != 0:
            return @E_JSON@
        c = peek(s, w)
        if c == 125:
            consume(s, w, 125)
            more = 0
        elif consume(s, w, 44) == 0:
            return @E_JSON@
    if flags != 31 or peek(s, w) != 256:
        return @E_JSON@
    count = get(w, 2064)
    if count == 0 or count > 128:
        return @E_SCHEMA@
    sort_rows(w, count)
    i = 0
    abstain = 128
    feasible = 0
    rejected = 0
    minimum = 9223372036854775807
    while i < count:
        row = get(w, 40000 + i * 8)
        if i > 0 and compare_ids(w, row, get(w, 40000 + (i - 1) * 8)) == 1:
            return @E_DUPLICATE@
        at = 4096 + row * 256
        if literal_equal(w, at, get(w, at + 128), @ABSTAIN@) != 0:
            abstain = row
        reasons = get(w, at + 160)
        if get(w, at + 152) > get(w, 2096):
            reasons = reasons | 2
        put(w, at + 232, reasons)
        if reasons == 0:
            feasible = feasible + 1
            cost = get(w, at + 136)
            if cost < minimum:
                minimum = cost
        else:
            rejected = rejected + 1
        i = i + 1
    if abstain == 128:
        return @E_ABSTAIN@
    if get(w, 4096 + abstain * 256 + 232) != 0:
        return @E_INFEASIBLE@
    put(w, 2112, feasible)
    put(w, 2120, rejected)
    put(w, 2152, minimum)
    frontier = 0
    advice = 128
    i = 0
    while i < count:
        row = get(w, 40000 + i * 8)
        at = 4096 + row * 256
        if get(w, at + 232) == 0 and get(w, at + 136) == minimum:
            frontier = frontier + 1
            advice = row
        i = i + 1
    disposition = 2
    if feasible == 1:
        disposition = 0
        advice = abstain
    elif frontier == 1:
        disposition = 1
    else:
        advice = 128
    put(w, 2128, frontier)
    put(w, 2136, disposition)
    put(w, 2144, advice)
    copy_input(s, w, begin, 65536, length(s) - begin)
    hash_at(w, 65536, length(s) - begin, 2800)
    digests(w)
    response_json(w)
    return 0

def read_candidates(s:readbuf, w:mutbuf) -> u64:
    if consume(s, w, 91) == 0:
        return 0
    if peek(s, w) == 93:
        consume(s, w, 93)
        return 1
    count = 0
    more = 1
    while more != 0:
        if count >= 128 or read_candidate(s, w, count) == 0:
            return 0
        count = count + 1
        c = peek(s, w)
        if c == 93:
            consume(s, w, 93)
            more = 0
        elif consume(s, w, 44) == 0:
            return 0
    put(w, 2064, count)
    return 1

def read_candidate(s:readbuf, w:mutbuf, index:u64) -> u64:
    if consume(s, w, 123) == 0:
        return 0
    at = 4096 + index * 256
    flags = 0
    more = 1
    while more != 0:
        size = read_string(s, w, 2304, 128)
        key = candidate_key(w, size)
        if key == 0 or (flags & key) != 0 or consume(s, w, 58) == 0:
            return 0
        flags = flags | key
        if key == 1:
            size = read_string(s, w, at, 128)
            if size == 0 or size > 128:
                return 0
            i = 0
            while i < size:
                c = byte(w, at + i)
                if ((c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122)
                        and c != 46 and c != 95 and c != 45 and c != 58):
                    return 0
                i = i + 1
            put(w, at + 128, size)
        elif key == 2:
            put(w, at + 136, read_integer(s, w, 9223372036854775807))
        elif key == 4:
            put(w, at + 144, read_integer(s, w, 9223372036854775807))
        elif key == 8:
            put(w, at + 152, read_integer(s, w, 9223372036854775807))
        elif key == 16:
            put(w, at + 160, read_boolean(s, w))
        else:
            size = read_string(s, w, 2304, 64)
            if size != 64 or decode_digest(w, 2304, at + 168) == 0:
                return 0
        if get(w, 2056) != 0:
            return 0
        if peek(s, w) == 125:
            consume(s, w, 125)
            more = 0
        elif consume(s, w, 44) == 0:
            return 0
    if flags != 63:
        return 0
    return 1

def request_key(w:mutbuf, size:u64) -> u64:
    if literal_equal(w, 2304, size, @K_SCHEMA@) != 0:
        return 1
    if literal_equal(w, 2304, size, @K_OBJECTIVE@) != 0:
        return 2
    if literal_equal(w, 2304, size, @K_GENERATION@) != 0:
        return 4
    if literal_equal(w, 2304, size, @K_CAP@) != 0:
        return 8
    if literal_equal(w, 2304, size, @K_CANDIDATES@) != 0:
        return 16
    return 0

def candidate_key(w:mutbuf, size:u64) -> u64:
    if literal_equal(w, 2304, size, @K_ID@) != 0:
        return 1
    if literal_equal(w, 2304, size, @K_COST@) != 0:
        return 2
    if literal_equal(w, 2304, size, @K_UNCERTAINTY@) != 0:
        return 4
    if literal_equal(w, 2304, size, @K_RESOURCE@) != 0:
        return 8
    if literal_equal(w, 2304, size, @K_HARD@) != 0:
        return 16
    if literal_equal(w, 2304, size, @K_SUPPORT@) != 0:
        return 32
    return 0

def peek(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 2048)
    end = get(w, 2088)
    while at < end:
        c = byte(s, at)
        if c != 32 and c != 9 and c != 10 and c != 13:
            put(w, 2048, at)
            return c
        at = at + 1
    put(w, 2048, at)
    return 256

def consume(s:readbuf, w:mutbuf, expected:u64) -> u64:
    if peek(s, w) != expected:
        put(w, 2056, 1)
        return 0
    put(w, 2048, get(w, 2048) + 1)
    return 1

def read_string(s:readbuf, w:mutbuf, target:u64, maximum:u64) -> u64:
    if consume(s, w, 34) == 0:
        return 129
    at = get(w, 2048)
    end = get(w, 2088)
    size = 0
    while at < end:
        c = byte(s, at)
        at = at + 1
        if c == 34:
            put(w, 2048, at)
            return size
        if c == 92:
            if at == end:
                put(w, 2056, 1)
                return 129
            c = byte(s, at)
            at = at + 1
            if c == 117:
                if end - at < 4:
                    put(w, 2056, 1)
                    return 129
                value = 0
                i = 0
                while i < 4:
                    h = unicode_hex(byte(s, at + i))
                    if h > 15:
                        put(w, 2056, 1)
                        return 129
                    value = value * 16 + h
                    i = i + 1
                at = at + 4
                c = value
            elif c == 98:
                c = 8
            elif c == 102:
                c = 12
            elif c == 110:
                c = 10
            elif c == 114:
                c = 13
            elif c == 116:
                c = 9
            elif c != 34 and c != 92 and c != 47:
                put(w, 2056, 1)
                return 129
        elif c < 32:
            put(w, 2056, 1)
            return 129
        if c > 127 or size >= maximum:
            put(w, 2056, 1)
            return 129
        store(w, target + size, c)
        size = size + 1
    put(w, 2056, 1)
    return 129

def read_integer(s:readbuf, w:mutbuf, maximum:u64) -> u64:
    c = peek(s, w)
    at = get(w, 2048)
    end = get(w, 2088)
    if c < 48 or c > 57:
        put(w, 2056, 1)
        return 0
    if c == 48:
        put(w, 2048, at + 1)
        return 0
    quotient = 922337203685477580
    remainder = 7
    if maximum == 18446744073709551615:
        quotient = 1844674407370955161
        remainder = 5
    value = 0
    while at < end:
        c = byte(s, at)
        if c < 48 or c > 57:
            put(w, 2048, at)
            return value
        digit = c - 48
        if value > quotient or (value == quotient and digit > remainder):
            put(w, 2056, 1)
            return 0
        value = value * 10 + digit
        at = at + 1
    put(w, 2048, at)
    return value

def read_boolean(s:readbuf, w:mutbuf) -> u64:
    c = peek(s, w)
    at = get(w, 2048)
    end = get(w, 2088)
    if c == 116 and end - at >= 4:
        if byte(s, at + 1) == 114 and byte(s, at + 2) == 117 and byte(s, at + 3) == 101:
            put(w, 2048, at + 4)
            return 1
    if c == 102 and end - at >= 5:
        if byte(s, at + 1) == 97 and byte(s, at + 2) == 108 and byte(s, at + 3) == 115 and byte(s, at + 4) == 101:
            put(w, 2048, at + 5)
            return 0
    put(w, 2056, 1)
    return 0

def hex_digit(c:u64) -> u64:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    return 16

def unicode_hex(c:u64) -> u64:
    if c >= 65 and c <= 70:
        return c - 55
    return hex_digit(c)

def decode_digest(w:mutbuf, source:u64, target:u64) -> u64:
    i = 0
    nonzero = 0
    while i < 32:
        a = hex_digit(byte(w, source + i * 2))
        b = hex_digit(byte(w, source + i * 2 + 1))
        if a > 15 or b > 15:
            return 0
        value = a * 16 + b
        nonzero = nonzero | value
        store(w, target + i, value)
        i = i + 1
    if nonzero == 0:
        return 0
    return 1

def compare_ids(w:mutbuf, left:u64, right:u64) -> u64:
    a = 4096 + left * 256
    b = 4096 + right * 256
    n = get(w, a + 128)
    m = get(w, b + 128)
    i = 0
    while i < n and i < m:
        if byte(w, a + i) < byte(w, b + i):
            return 0
        if byte(w, a + i) > byte(w, b + i):
            return 2
        i = i + 1
    if n < m:
        return 0
    if n > m:
        return 2
    return 1

def sort_rows(w:mutbuf, count:u64) -> u64:
    i = 0
    while i < count:
        j = i
        moving = 1
        while j > 0 and moving != 0:
            previous = get(w, 40000 + (j - 1) * 8)
            if compare_ids(w, i, previous) == 0:
                put(w, 40000 + j * 8, previous)
                j = j - 1
            else:
                moving = 0
        put(w, 40000 + j * 8, i)
        i = i + 1
    return 0

def digests(w:mutbuf) -> u64:
    put(w, 2184, 65536)
    add_literal(w, @PROFILE_PREFIX@)
    add_number(w, get(w, 2096), 8)
    add_literal(w, @PROFILE_SUFFIX@)
    hash_at(w, 65536, get(w, 2184) - 65536, 2832)
    put(w, 2184, 65536)
    add_literal(w, @POLICY_PREIMAGE@)
    hash_at(w, 65536, get(w, 2184) - 65536, 2864)
    i = 0
    count = get(w, 2064)
    while i < count:
        row = get(w, 40000 + i * 8)
        at = 4096 + row * 256
        if get(w, at + 232) == 0:
            put(w, 2184, 65536)
            add_literal(w, @CONTRIBUTION_DOMAIN@)
            add_id(w, row)
            add_literal(w, @ORGAN_ID@)
            add_copy(w, 2656, 32)
            add_number(w, get(w, 2072), 8)
            add_number(w, 0, 1)
            add_axes(w, row)
            add_copy(w, at + 168, 32)
            hash_at(w, 65536, get(w, 2184) - 65536, 2960)
            hash_at(w, 2960, 32, at + 200)
        i = i + 1
    put(w, 2184, 65536)
    add_literal(w, @EVALUATION_DOMAIN@)
    add_copy(w, 2656, 32)
    add_copy(w, 2832, 32)
    add_number(w, 0, 1)
    add_number(w, get(w, 2072), 8)
    add_number(w, get(w, 2136), 1)
    add_number(w, get(w, 2112), 4)
    i = 0
    while i < count:
        row = get(w, 40000 + i * 8)
        if get(w, 4096 + row * 256 + 232) == 0:
            add_candidate(w, row)
        i = i + 1
    add_number(w, get(w, 2120), 4)
    i = 0
    while i < count:
        row = get(w, 40000 + i * 8)
        reasons = get(w, 4096 + row * 256 + 232)
        if reasons != 0:
            add_id(w, row)
            add_number(w, choose(reasons == 3, 2, 1), 4)
            if (reasons & 1) != 0:
                add_number(w, 0, 1)
            if (reasons & 2) != 0:
                add_number(w, 2, 1)
        i = i + 1
    add_number(w, get(w, 2128), 4)
    i = 0
    while i < count:
        row = get(w, 40000 + i * 8)
        at = 4096 + row * 256
        if get(w, at + 232) == 0 and get(w, at + 136) == get(w, 2152):
            add_candidate(w, row)
        i = i + 1
    advice = get(w, 2144)
    if advice == 128:
        add_number(w, 0, 1)
    else:
        add_number(w, 1, 1)
        add_id(w, advice)
    hash_at(w, 65536, get(w, 2184) - 65536, 2896)
    put(w, 2184, 65536)
    add_literal(w, @V2_DOMAIN@)
    add_copy(w, 2896, 32)
    add_copy(w, 2864, 32)
    add_number(w, get(w, 2136), 1)
    hash_at(w, 65536, get(w, 2184) - 65536, 2896)
    return 0

def add_candidate(w:mutbuf, row:u64) -> u64:
    add_id(w, row)
    add_axes(w, row)
    add_copy(w, 4096 + row * 256 + 200, 32)
    add_number(w, 0, 1)
    return 0

def add_axes(w:mutbuf, row:u64) -> u64:
    at = 4096 + row * 256
    add_literal(w, @UTILITY_AXIS@)
    add_number(w, get(w, at + 136), 8)
    add_number(w, 0, 4)
    add_literal(w, @RESOURCE_AXIS@)
    add_number(w, get(w, at + 152), 8)
    add_literal(w, @UTILITY_AXIS@)
    add_number(w, get(w, at + 144), 8)
    return 0

def add_id(w:mutbuf, row:u64) -> u64:
    at = 4096 + row * 256
    size = get(w, at + 128)
    add_number(w, size, 4)
    add_copy(w, at, size)
    return 0

def add_literal(w:mutbuf, which:u64) -> u64:
    put(w, 2184, literal(w, get(w, 2184), which))
    return 0

def add_number(w:mutbuf, value:u64, width:u64) -> u64:
    at = get(w, 2184)
    big(w, at, value, width)
    put(w, 2184, at + width)
    return 0

def add_copy(w:mutbuf, source:u64, size:u64) -> u64:
    at = get(w, 2184)
    copy_same(w, source, at, size)
    put(w, 2184, at + size)
    return 0

def response_json(w:mutbuf) -> u64:
    put(w, 2176, 1200000)
    output_literal(w, @O_ADVICE@)
    advice = get(w, 2144)
    if advice == 128:
        output_literal(w, @NULL@)
    else:
        output_id(w, advice)
    output_literal(w, @O_AUTHORITY@)
    disposition = get(w, 2136)
    if disposition == 0:
        output_literal(w, @D_ABSTAIN@)
    elif disposition == 1:
        output_literal(w, @D_UNIQUE@)
    else:
        output_literal(w, @D_TIE@)
    output_literal(w, @O_ENTRY@)
    output_hex(w, 2896)
    output_literal(w, @O_POLICY@)
    output_hex(w, 2864)
    output_literal(w, @O_GENERATION@)
    output_decimal(w, get(w, 2072))
    output_literal(w, @O_OBJECTIVE@)
    output_hex(w, 2656)
    output_literal(w, @O_FRONTIER@)
    count = get(w, 2064)
    i = 0
    emitted = 0
    while i < count:
        row = get(w, 40000 + i * 8)
        at = 4096 + row * 256
        if get(w, at + 232) == 0 and get(w, at + 136) == get(w, 2152):
            if emitted != 0:
                output_byte(w, 44)
            output_id(w, row)
            emitted = emitted + 1
        i = i + 1
    output_literal(w, @O_REJECTED@)
    i = 0
    emitted = 0
    while i < count:
        row = get(w, 40000 + i * 8)
        reasons = get(w, 4096 + row * 256 + 232)
        if reasons != 0:
            if emitted != 0:
                output_byte(w, 44)
            output_literal(w, @O_ID@)
            output_id(w, row)
            output_literal(w, @O_REASONS@)
            if reasons == 1:
                output_literal(w, @R_HARD@)
            elif reasons == 2:
                output_literal(w, @R_RESOURCE@)
            else:
                output_literal(w, @R_BOTH@)
            output_byte(w, 125)
            emitted = emitted + 1
        i = i + 1
    output_literal(w, @O_REQUEST@)
    output_hex(w, 2800)
    output_literal(w, @O_TAIL@)
    output_hex(w, 2832)
    output_byte(w, 125)
    output_byte(w, 10)
    return 0

def output_literal(w:mutbuf, which:u64) -> u64:
    put(w, 2176, literal(w, get(w, 2176), which))
    return 0

def output_byte(w:mutbuf, value:u64) -> u64:
    at = get(w, 2176)
    store(w, at, value)
    put(w, 2176, at + 1)
    return 0

def output_id(w:mutbuf, row:u64) -> u64:
    at = 4096 + row * 256
    size = get(w, at + 128)
    output_byte(w, 34)
    i = 0
    while i < size:
        output_byte(w, byte(w, at + i))
        i = i + 1
    output_byte(w, 34)
    return 0

def output_hex(w:mutbuf, source:u64) -> u64:
    output_byte(w, 34)
    i = 0
    while i < 32:
        c = byte(w, source + i)
        a = c >> 4
        b = c & 15
        output_byte(w, choose(a < 10, 48 + a, 87 + a))
        output_byte(w, choose(b < 10, 48 + b, 87 + b))
        i = i + 1
    output_byte(w, 34)
    return 0

def output_decimal(w:mutbuf, value:u64) -> u64:
    if value == 0:
        output_byte(w, 48)
        return 0
    i = 0
    while value != 0:
        quotient = divide_ten(value)
        store(w, 3072 + i, 48 + value - quotient * 10)
        value = quotient
        i = i + 1
    while i != 0:
        i = i - 1
        output_byte(w, byte(w, 3072 + i))
    return 0

def divide_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bits = 64
    while bits != 0:
        bits = bits - 1
        remainder = (remainder << 1) | ((value >> bits) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bits)
    return quotient

def input_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (8 * i))
        i = i + 1
    return value

def input_be(s:readbuf, at:u64, width:u64) -> u64:
    value = 0
    i = 0
    while i < width:
        value = (value << 8) | byte(s, at + i)
        i = i + 1
    return value

def big(w:mutbuf, at:u64, value:u64, width:u64) -> u64:
    i = 0
    while i < width:
        store(w, at + i, (value >> (8 * (width - i - 1))) & 255)
        i = i + 1
    return 0

def copy_input(s:readbuf, w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, source + i))
        i = i + 1
    return 0

def copy_work(w:mutbuf, o:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(w, source + i))
        i = i + 1
    return 0

def copy_same(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0
'''


def literal_functions():
    source = 'def literal(w:mutbuf, at:u64, which:u64) -> u64:\n'
    values = list(enumerate(LITERALS.values(), 1))
    groups = [values[i:i + 8] for i in range(0, len(values), 8)]
    for group, entries in enumerate(groups):
        source += f'    if which <= {entries[-1][0]}:\n        return literal_{group}(w, at, which)\n'
    source += '    return at\n'
    for group, entries in enumerate(groups):
        source += f'\ndef literal_{group}(w:mutbuf, at:u64, which:u64) -> u64:\n'
        for index, raw in entries:
            source += f'    if which == {index}:\n'
            for offset in range(0, len(raw), 8):
                chunk = raw[offset:offset + 8]
                if len(chunk) == 8:
                    source += f'        put(w, at + {offset}, {int.from_bytes(chunk, "little")})\n'
                else:
                    for j, byte in enumerate(chunk):
                        source += f'        store(w, at + {offset+j}, {byte})\n'
            source += f'        return at + {len(raw)}\n'
        source += '    return at\n'
    source += '\ndef literal_equal(w:mutbuf, at:u64, size:u64, which:u64) -> u64:\n'
    for index, (name, raw) in enumerate(LITERALS.items(), 1):
        if not (name.startswith('K_') or name in {'REQUEST_SCHEMA', 'ABSTAIN', 'STREAM_ARG'}):
            continue
        source += f'    if which == {index}:\n        if size != {len(raw)}:\n            return 0\n'
        for at in range(0, len(raw), 8):
            chunk = raw[at:at + 8]
            if len(chunk) == 8:
                predicate = f'get(w, at + {at}) != {int.from_bytes(chunk, "little")}'
            else:
                predicate = ' or '.join(f'byte(w, at + {at+j}) != {byte}' for j, byte in enumerate(chunk))
            source += f'        if {predicate}:\n            return 0\n'
        source += '        return 1\n'
    return source + '    return 0\n'


def hash_functions():
    source = sha_program(word_memory=True)
    source = source.replace('def sha256(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        'def hash_at(w:mutbuf, start:u64, size:u64, target:u64) -> u64:')
    source = source.replace('    if length(s) > 8388608 or length(o) < 32 or length(w) < 1088:\n        return 4294967293\n', '')
    source = source.replace('length(s)', 'size')
    source = source.replace('padded_byte(s, block + i * 4 + j, padded)', 'padded_byte(w, start, size, block + i * 4 + j, padded)')
    source = source.replace('store(o, i * 4 + j,', 'store(w, target + i * 4 + j,')
    source = source.replace('def padded_byte(s:readbuf, index:u64, total:u64) -> u64:',
        'def padded_byte(w:mutbuf, start:u64, size:u64, index:u64, total:u64) -> u64:')
    source = source.replace('return byte(s, index)', 'return byte(w, start + index)')
    return source


def authoring_source():
    source = POLICY
    for index, name in enumerate(LITERALS, 1):
        source = source.replace('@' + name + '@', str(index))
    if '@' in source:
        raise ValueError('unbound NDU authoring constant')
    return source + literal_functions() + hash_functions()


def render():
    class WordBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and node.func.id == 'word_store':
                args = [self.expr(value) for value in node.args]
                return self.op('buffer.store.u64.le', [args[0], self.cast(args[1], 'usize'), args[2]])
            return super().expr(node)

    nodes = ast.parse(authoring_source()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = WordBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return render_assembly(compact_authoring_cfg({
        'schema': 'hepta.hia.program.v9', 'module': 'ndu_scalar', 'functions': functions}))


if __name__ == '__main__':
    path = ROOT / SOURCE
    path.write_text(render(), encoding='utf-8')
    print(path.name, path.stat().st_size)
