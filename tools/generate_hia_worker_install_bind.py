"""Author HIA Worker installation profile and entry configuration byte owners.

This authoring tool is not invoked by an installation. The generated HIA
program validates its closed framing and hashes all supplied image bytes.
"""
from pathlib import Path
from hashlib import sha256
import ast
import copy
import json
import argparse
from tools.generate_hia_sha256_stream import source_program
from tools.generate_hia_sha256 import INITIAL, ROUND
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from hepta.hia_agent_assembly import render_assembly

ROOT = Path(__file__).resolve().parents[1]
PROFILE_IMAGES = (
    ('store_sha256', 'hia-agent-store', 16777216),
    ('artifact_sha256', 'hia-artifact', 1048576),
    ('capture_sha256', 'hia-agent-artifact-capture', 1048576),
    ('edit_query_sha256', 'hia-prepare-edit-query', 4194304),
    ('assembly_import_sha256', 'hia-import-assembly', 4194304),
    ('json_admission_sha256', 'hia-nominal-constructor', 8388608),
    ('terminal_sha256', 'hia-worker-terminal', 1048576),
    ('worker_data_sha256', 'hia-worker-data', 1048576),
    ('evaluate_case_sha256', 'hia-agent-worker-evaluate-case', 1048576),
    ('evaluate_request_sha256', 'hia-agent-worker-evaluate-request', 1048576),
    ('initializer_sha256', 'hia-agent-store-init', 1048576),
)
REFERENCES = (
    ('reference', 'reference/hia-reference-wire'),
    ('owned_reference', 'reference/hia-owned-reference-wire'),
    ('direct_call', 'reference/hia-direct-call'),
    ('read_page', 'agent-read-page/hia-agent-read-page'),
    ('journal', 'agent-journal/hia-agent-journal'),
    ('store_unique', 'agent-store-transport/hia-agent-store-unique'),
    ('journal_cost', 'store/@PACKAGE@/hia-agent-journal-cost'),
)

SOURCE = r'''def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 2097152 or length(o) < 33554432:
        return 17
    phase = get(w, 0)
    mode = get(w, 16)
    if phase == 0 and mode == 0:
        if length(s) != 21 or uint(s, 0) != 1 or uint(s, 8) != 5 or uintn(s, 16, 5) != 431315580258:
            return 16
        put(w, 16, 1)
        return 0
    if phase == 2 and mode == 3:
        return 3
    if phase != 1 or mode != 1 or framing(s, w) == 0:
        return 16
    constants(w)
    put(w, 256, 0)
    selected = uint(s, 8)
    ok = 0
    if selected == 1:
        ok = profile(s, o, w)
    elif selected == 3:
        ok = configuration(s, o, w)
    elif selected == 5:
        ok = capsule(s, o, w)
    elif selected == 6:
        ok = discovery_request(s, o, w)
    elif selected == 7:
        ok = capsule_manifest(s, o, w)
    elif selected == 8:
        ok = installation_result(s, o, w)
    elif selected == 4:
        if uint(s, 24) == 1 and extent(w, 0) == 128:
            ok = identity(s, o, w, piece(w, 0))
    if ok == 0 or get(w, 256) == 0 or get(w, 256) > choose(selected == 5, 2097152, 1048576):
        return 16
    put(w, 0, 1)
    put(w, 16, 3)
    put(w, 88, get(w, 256))
    return 0

def framing(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 40 or length(s) > 67108864 or uint(s, 0) != MAGIC:
        return 0
    selected = uint(s, 8)
    if selected == 5 or selected == 7:
        if uint(s, 16) < 1 or uint(s, 16) > 6:
            return 0
    elif uint(s, 16) != 0:
        return 0
    count = uint(s, 24)
    if count == 0 or count > 256:
        return 0
    at = 32
    i = 0
    while i < count:
        if at > length(s) or length(s) - at < 8:
            return 0
        n = uint(s, at)
        if n > length(s) - at - 8:
            return 0
        put(w, 8192 + i * 16, at + 8)
        put(w, 8200 + i * 16, n)
        at = at + 8 + n
        i = i + 1
    return choose(at == length(s), 1, 0)

def profile(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if uint(s, 24) != 20 or extent(w, 0) != 32 or extent(w, 1) < 2 or extent(w, 1) > 1048576:
        return 0
    i = 2
    while i < 20:
        if extent(w, i) < 176 or extent(w, i) > image_limit(i) or uintn(s, piece(w, i), 4) != 1179403647:
            return 0
        i = i + 1
    copy(s, o, 16777216, piece(w, 0), 32)
    i = 1
    while i < 20:
        digest(s, o, w, piece(w, i), extent(w, i), 16777216 + i * 32)
        i = i + 1
    return profile_template(o, w)

def configuration(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if uint(s, 24) != 6 or extent(w, 0) == 0 or extent(w, 0) > 1048576 or extent(w, 1) < 40 or extent(w, 1) > 2097152:
        return 0
    if extent(w, 2) < 176 or extent(w, 2) > 1048576 or uintn(s, piece(w, 2), 4) != 1179403647 or extent(w, 3) != 128 or extent(w, 5) != 32:
        return 0
    if roots(s, w, piece(w, 4), extent(w, 4)) == 0:
        return 0
    digest(s, o, w, piece(w, 0), extent(w, 0), 16777216)
    if same(s, o, piece(w, 3) + 96, 16777216, 32) == 0:
        return 0
    digest(s, o, w, piece(w, 1), extent(w, 1), 16777248)
    put(o, 0, CONFIG_MAGIC)
    put(w, 256, 104)
    put(w, 264, 0)
    section(o, w)
    literal(o, w, LIT_PROFILE)
    close_section(o, w)
    section(o, w)
    emit(s, o, w, piece(w, 0), extent(w, 0))
    close_section(o, w)
    section(o, w)
    literal(o, w, LIT_STORE)
    hex_input(s, o, w, piece(w, 5), 32)
    output_byte(o, w, 0)
    close_section(o, w)
    section(o, w)
    literal(o, w, LIT_CAPSULE)
    hex_output(o, w, 16777248, 32)
    output_byte(o, w, 0)
    close_section(o, w)
    section(o, w)
    emit(s, o, w, piece(w, 2), extent(w, 2))
    close_section(o, w)
    section(o, w)
    identity(s, o, w, piece(w, 3))
    output_byte(o, w, 10)
    close_section(o, w)
    section(o, w)
    bound_tail(s, o, w)
    close_section(o, w)
    section(o, w)
    literal(o, w, LIT_PREFIX)
    close_section(o, w)
    section(o, w)
    literal(o, w, LIT_STATE)
    close_section(o, w)
    section(o, w)
    put(o, get(w, 256), 50)
    put(w, 256, get(w, 256) + 8)
    literal(o, w, LIT_MANIFEST_PAIR)
    suffix(s, o, w)
    close_section(o, w)
    section(o, w)
    literal(o, w, LIT_MANIFEST)
    close_section(o, w)
    put(o, 8, get(w, 256))
    return choose(get(w, 264) == 11, 1, 0)

def bound_tail(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    start = get(w, 256)
    put(w, 280, start)
    put(w, 256, start + 8)
    literal(o, w, LIT_EXPECT_WORKER)
    hex_input(s, o, w, piece(w, 3) + 64, 32)
    output_byte(o, w, 0)
    literal(o, w, LIT_EXPECT_BACKEND)
    hex_input(s, o, w, piece(w, 3) + 32, 32)
    output_byte(o, w, 0)
    literal(o, w, LIT_EXPECT_CATALOG)
    hex_input(s, o, w, piece(w, 3), 32)
    output_byte(o, w, 0)
    at = piece(w, 4) + 8
    i = 0
    while i < get(w, 304):
        literal(o, w, LIT_ARTIFACT_ROOT)
        emit(s, o, w, at + 8, uint(s, at))
        output_byte(o, w, 0)
        at = at + 8 + uint(s, at)
        i = i + 1
    literal(o, w, LIT_HELPERS)
    put(o, get(w, 280), get(w, 256) - get(w, 280) - 8)
    suffix(s, o, w)
    return literal(o, w, LIT_REQUEST)

def suffix(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    literal(o, w, LIT_EXPECT_HELPERS)
    hex_input(s, o, w, piece(w, 3) + 96, 32)
    return output_byte(o, w, 0)

def roots(s:readbuf, w:mutbuf, at:u64, n:u64) -> u64:
    if n < 8 or uint(s, at) > 32:
        return 0
    end = at + n
    count = uint(s, at)
    put(w, 304, count)
    at = at + 8
    i = 0
    while i < count:
        if end - at < 9:
            return 0
        size = uint(s, at)
        if size == 0 or size > 4095 or size > end - at - 8 or byte(s, at + 8) != 47:
            return 0
        j = 0
        while j < size:
            if byte(s, at + 8 + j) == 0:
                return 0
            j = j + 1
        at = at + 8 + size
        i = i + 1
    return choose(at == end, 1, 0)

def identity(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    literal(o, w, LIT_ID_BACKEND)
    hex_input(s, o, w, at + 32, 32)
    literal(o, w, LIT_ID_CATALOG)
    hex_input(s, o, w, at, 32)
    literal(o, w, LIT_ID_HELPERS)
    hex_input(s, o, w, at + 96, 32)
    literal(o, w, LIT_ID_WORKER)
    hex_input(s, o, w, at + 64, 32)
    return literal(o, w, LIT_ID_END)

def section(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, 256)
    put(o, 16 + get(w, 264) * 8, at)
    put(w, 272, at)
    put(w, 256, at + 8)
    put(w, 264, get(w, 264) + 1)
    return 0

def close_section(o:mutbuf, w:mutbuf) -> u64:
    return put(o, get(w, 272), get(w, 256) - get(w, 272) - 8)

def piece(w:mutbuf, i:u64) -> u64:
    return get(w, 8192 + i * 16)

def extent(w:mutbuf, i:u64) -> u64:
    return get(w, 8200 + i * 16)

def emit(s:readbuf, o:mutbuf, w:mutbuf, at:u64, n:u64) -> u64:
    copy(s, o, get(w, 256), at, n)
    put(w, 256, get(w, 256) + n)
    return 1

def literal(o:mutbuf, w:mutbuf, index:u64) -> u64:
    at = literal_offset(index)
    n = literal_size(index)
    i = 0
    while i < n:
        output_byte(o, w, byte(w, at + i))
        i = i + 1
    return 1

def hex_input(s:readbuf, o:mutbuf, w:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
        value = byte(s, at + i)
        output_byte(o, w, hex_digit(value >> 4))
        output_byte(o, w, hex_digit(value & 15))
        i = i + 1
    return 1

def hex_output(o:mutbuf, w:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
        value = byte(o, at + i)
        output_byte(o, w, hex_digit(value >> 4))
        output_byte(o, w, hex_digit(value & 15))
        i = i + 1
    return 1

def output_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    store(o, get(w, 256), value)
    put(w, 256, get(w, 256) + 1)
    return 1

def hex_digit(n:u64) -> u64:
    return choose(n < 10, 48 + n, 87 + n)

def same(s:readbuf, o:mutbuf, a:u64, b:u64, n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s, a + i) != byte(o, b + i):
            return 0
        i = i + 1
    return 1

def copy(s:readbuf, o:mutbuf, at:u64, source:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, at + i, byte(s, source + i))
        i = i + 1
    return 0

def uint(s:readbuf, at:u64) -> u64:
    return uintn(s, at, 8)

def uintn(s:readbuf, at:u64, n:u64) -> u64:
    value = 0
    i = 0
    while i < n:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''

CAPSULE_SOURCE = 'def capsule(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n    kind = uint(s, 16)\n    if uint(s, 24) != 7 or extent(w, 0) != 128 or extent(w, 1) == 0 or extent(w, 1) > 1048576:\n        return 0\n    if roots(s, w, piece(w, 2), extent(w, 2)) == 0 or role_rows(s, w, kind) == 0:\n        return 0\n    if kind == 1 and (get(w, 304) != 0 or extent(w, 3) != 0 or extent(w, 4) != 0 or extent(w, 5) != 0):\n        return 0\n    if kind == 2 and (extent(w, 3) != 0 or extent(w, 5) != 0):\n        return 0\n    if kind > 1 and documents(s, w) == 0:\n        return 0\n    if kind > 2:\n        if equal_literal(s, w, piece(w, 3), extent(w, 3), LIT_COMPAT) == 0 or discovery_response(s, w) == 0:\n            return 0\n    digest(s, o, w, piece(w, 1), extent(w, 1), 16777216)\n    if same(s, o, piece(w, 0), 16777216, 32) == 0:\n        return 0\n    roots_digest(s, o, w, 2)\n    put(w, 256, 2162688)\n    identity(s, o, w, piece(w, 0))\n    put(w, 392, get(w, 256) - 2162688)\n    put(w, 256, choose(kind == 1, 40, 56))\n    put(o, 0, capsule_magic(kind))\n    put(o, 8, 1)\n    put(o, 16, role_count(kind))\n    emit(s, o, w, piece(w, 6), extent(w, 6))\n    put(w, 336, get(w, 256))\n    capsule_dossier(s, o, w, kind)\n    put(o, 24, get(w, 256) - get(w, 336))\n    if kind == 1:\n        put(o, 32, 0)\n        return 1\n    put(w, 344, get(w, 256))\n    bootstrap_config(s, o, w)\n    put(o, 32, get(w, 256) - get(w, 344))\n    put(o, 40, extent(w, 4))\n    emit(s, o, w, piece(w, 4), extent(w, 4))\n    put(w, 344, get(w, 256))\n    if kind > 2:\n        artifact_config(s, o, w)\n    put(o, 48, get(w, 256) - get(w, 344))\n    return 1\n\ndef role_rows(s:readbuf, w:mutbuf, kind:u64) -> u64:\n    count = role_count(kind)\n    if extent(w, 6) != count * 48:\n        return 0\n    i = 0\n    while i < count:\n        at = piece(w, 6) + i * 48\n        if uint(s, at) != i + 1 or uint(s, at + 8) < 64 or uint(s, at + 8) > 8388608:\n            return 0\n        i = i + 1\n    return 1\n\ndef capsule_dossier(s:readbuf, o:mutbuf, w:mutbuf, kind:u64) -> u64:\n    at = get(w, 256)\n    put(o, at, DOSSIER_MAGIC)\n    put(o, at + 8, 4300)\n    put(o, at + 16, 1)\n    put(o, at + 24, extent(w, 1))\n    put(o, at + 32, get(w, 392))\n    put(o, at + 40, get(w, 392))\n    put(o, at + 48, 0)\n    put(w, 256, at + 56)\n    hex_input(s, o, w, piece(w, 0), 128)\n    emit(s, o, w, piece(w, 1), extent(w, 1))\n    emit_output(o, w, 2162688, get(w, 392))\n    emit_output(o, w, 2162688, get(w, 392))\n    if kind > 2:\n        proof_trust(s, o, w, kind)\n    return 1\n\ndef proof_trust(s:readbuf, o:mutbuf, w:mutbuf, kind:u64) -> u64:\n    put(w, 376, get(w, 256))\n    put(w, 256, 2228224)\n    literal(o, w, LIT_SELECTION_PREFIX)\n    hex_input(s, o, w, piece(w, 0) + 96, 32)\n    literal(o, w, LIT_SELECTION_SUFFIX)\n    digest_mut(o, w, 2228224, get(w, 256) - 2228224, 16777312)\n    put(w, 256, get(w, 376))\n    put(o, get(w, 256), TRUST_MAGIC)\n    put(o, get(w, 256) + 8, extent(w, 3))\n    put(w, 256, get(w, 256) + 16)\n    output_byte(o, w, 34)\n    hex_output(o, w, 16777312, 32)\n    output_byte(o, w, 34)\n    emit(s, o, w, piece(w, 3), extent(w, 3))\n    while get(w, 256) < get(w, 376) + 224:\n        output_byte(o, w, 0)\n    output_byte(o, w, 91)\n    output_byte(o, w, 34)\n    hex_input(s, o, w, piece(w, 6) + checker_ordinal(kind, 0) * 48 + 16, 32)\n    literal(o, w, LIT_PIN_SEPARATOR)\n    hex_input(s, o, w, piece(w, 6) + checker_ordinal(kind, 1) * 48 + 16, 32)\n    output_byte(o, w, 34)\n    return output_byte(o, w, 93)\n\ndef bootstrap_config(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n    at = get(w, 256)\n    put(o, at, BOOTSTRAP_MAGIC)\n    put(o, at + 8, 0)\n    put(o, at + 16, get(w, 392))\n    put(o, at + 24, choose(get(w, 304) < 10, 1, 2))\n    put(o, at + 32, 0)\n    put(o, at + 40, 0)\n    put(w, 256, at + 48)\n    hex_input(s, o, w, piece(w, 0), 32)\n    hex_output(o, w, 16777280, 32)\n    emit_output(o, w, 2162688, get(w, 392))\n    return small_decimal(o, w, get(w, 304))\n\ndef artifact_config(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n    digest(s, o, w, piece(w, 5) + 40, extent(w, 5) - 40, 16777344)\n    put(w, 376, get(w, 256))\n    put(w, 256, 2228224)\n    literal(o, w, LIT_ARTIFACT_PREFIX)\n    hex_output(o, w, 16777344, 32)\n    literal(o, w, LIT_ID_END)\n    put(w, 400, get(w, 256) - 2228224)\n    put(w, 256, get(w, 376))\n    put(o, get(w, 256), ARTIFACT_MAGIC)\n    put(w, 256, get(w, 256) + 8)\n    hex_output(o, w, 16777344, 32)\n    put(o, get(w, 256), get(w, 400))\n    put(o, get(w, 256) + 8, get(w, 304))\n    put(w, 256, get(w, 256) + 16)\n    emit_output(o, w, 2228224, get(w, 400))\n    return emit(s, o, w, piece(w, 2) + 8, extent(w, 2) - 8)\n\ndef documents(s:readbuf, w:mutbuf) -> u64:\n    at = piece(w, 4)\n    end = at + extent(w, 4)\n    if extent(w, 4) < 16 or uint(s, at) != RESOURCE_MAGIC or uint(s, at + 8) != 10:\n        return 0\n    at = at + 16\n    i = 0\n    while i < 10:\n        if at > end or end - at < 16:\n            return 0\n        nn = uint(s, at)\n        size = uint(s, at + 8)\n        if nn > 255 or size > 1048576 or nn + size > end - at - 16:\n            return 0\n        if equal_literal(s, w, at + 16, nn, document_literal(i)) == 0:\n            return 0\n        at = at + 16 + nn + size\n        i = i + 1\n    return choose(at == end, 1, 0)\n\ndef discovery_response(s:readbuf, w:mutbuf) -> u64:\n    at = piece(w, 5)\n    n = extent(w, 5)\n    if n <= 40 or n > 65576:\n        return 0\n    if uint(s, at) != n - 8 or uint(s, at + 8) != PROFILE_VERSION or uint(s, at + 16) != 0 or uint(s, at + 24) != 0 or uint(s, at + 32) != n - 40:\n        return 0\n    return 1\n\ndef discovery_request(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n    if uint(s, 24) != 2 or extent(w, 0) != 128 or roots(s, w, piece(w, 1), extent(w, 1)) == 0:\n        return 0\n    roots_digest(s, o, w, 1)\n    put(w, 256, 72)\n    identity(s, o, w, piece(w, 0))\n    put(w, 392, get(w, 256) - 72)\n    hex_input(s, o, w, piece(w, 0), 32)\n    small_decimal(o, w, get(w, 304))\n    hex_output(o, w, 16777280, 32)\n    put(o, 0, PROFILE_MAGIC)\n    put(o, 8, 4)\n    put(o, 16, get(w, 392))\n    put(o, 24, 64)\n    put(o, 32, choose(get(w, 304) < 10, 1, 2))\n    put(o, 40, 64)\n    put(o, 48, 0)\n    put(o, 56, 0)\n    put(o, 64, 0)\n    return 1\n\ndef roots_digest(s:readbuf, o:mutbuf, w:mutbuf, index:u64) -> u64:\n    put(w, 256, 2097152)\n    output_byte(o, w, 91)\n    at = piece(w, index) + 8\n    i = 0\n    while i < get(w, 304):\n        if i != 0:\n            output_byte(o, w, 44)\n        output_byte(o, w, 34)\n        json_bytes(s, o, w, at + 8, uint(s, at))\n        output_byte(o, w, 34)\n        at = at + 8 + uint(s, at)\n        i = i + 1\n    output_byte(o, w, 93)\n    return digest_mut(o, w, 2097152, get(w, 256) - 2097152, 16777280)\n\ndef json_bytes(s:readbuf, o:mutbuf, w:mutbuf, at:u64, n:u64) -> u64:\n    i = 0\n    while i < n:\n        ch = byte(s, at + i)\n        if ch == 34 or ch == 92:\n            output_byte(o, w, 92)\n            output_byte(o, w, ch)\n        elif ch < 32:\n            output_byte(o, w, 92)\n            escaped = 0\n            if ch == 8:\n                escaped = 98\n            elif ch == 9:\n                escaped = 116\n            elif ch == 10:\n                escaped = 110\n            elif ch == 12:\n                escaped = 102\n            elif ch == 13:\n                escaped = 114\n            if escaped != 0:\n                output_byte(o, w, escaped)\n            else:\n                output_byte(o, w, 117)\n                output_byte(o, w, 48)\n                output_byte(o, w, 48)\n                output_byte(o, w, hex_digit(ch >> 4))\n                output_byte(o, w, hex_digit(ch & 15))\n        else:\n            output_byte(o, w, ch)\n        i = i + 1\n    return 1\n\ndef small_decimal(o:mutbuf, w:mutbuf, value:u64) -> u64:\n    if value >= 10:\n        digit = choose(value >= 30, 3, choose(value >= 20, 2, 1))\n        output_byte(o, w, 48 + digit)\n        value = value - digit * 10\n    return output_byte(o, w, 48 + value)\n\ndef emit_output(o:mutbuf, w:mutbuf, at:u64, n:u64) -> u64:\n    i = 0\n    while i < n:\n        output_byte(o, w, byte(o, at + i))\n        i = i + 1\n    return 1\n\ndef equal_literal(s:readbuf, w:mutbuf, at:u64, n:u64, index:u64) -> u64:\n    if n != literal_size(index):\n        return 0\n    other = literal_offset(index)\n    i = 0\n    while i < n:\n        if byte(s, at + i) != byte(w, other + i):\n            return 0\n        i = i + 1\n    return 1\n\ndef capsule_manifest(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n    if uint(s, 24) != 3 or extent(w, 0) < 40 or extent(w, 0) > 2097152 or extent(w, 1) < 176 or extent(w, 1) > 1048576 or extent(w, 2) != 32:\n        return 0\n    if uintn(s, piece(w, 1), 4) != 1179403647:\n        return 0\n    digest(s, o, w, piece(w, 0), extent(w, 0), 16777216)\n    digest(s, o, w, piece(w, 1), extent(w, 1), 16777248)\n    copy(s, o, 16777280, piece(w, 2), 32)\n    return manifest_template(o, w, uint(s, 16))\n'

RESULT_SOURCE = 'def installation_result(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n    if uint(s, 24) != 12 or extent(w, 0) == 0 or extent(w, 0) > 4095 or byte(s, piece(w, 0)) != 47 or extent(w, 1) != 32:\n        return 0\n    if extent(w, 2) < 2 or extent(w, 2) > 1048576 or extent(w, 3) < 176 or extent(w, 3) > 2097152:\n        return 0\n    if uintn(s, piece(w, 3), 4) != 1179403647 or extent(w, 10) != 96 or extent(w, 11) != 8 or uint(s, piece(w, 11)) > 1:\n        return 0\n    at = piece(w, 10)\n    if uint(s, at) != CONTROLLER_RECEIPT_MAGIC or uint(s, at + 8) != 26 or uint(s, at + 16) != 20 or uint(s, at + 88) != 0:\n        return 0\n    i = 2\n    while i < 10:\n        if extent(w, i) < 2 or extent(w, i) > choose(i == 3, 2097152, 1048576):\n            return 0\n        digest(s, o, w, piece(w, i), extent(w, i), 16777216 + (i - 2) * 32)\n        i = i + 1\n    return result_template(s, o, w)\n\ndef result_path(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n    at = piece(w, 0)\n    n = extent(w, 0)\n    i = 0\n    while i < n:\n        ch = byte(s, at + i)\n        if ch == 0:\n            return 0\n        if ch < 127:\n            json_bytes(s, o, w, at + i, 1)\n            i = i + 1\n        elif ch == 127:\n            result_unicode(o, w, ch)\n            i = i + 1\n        else:\n            extra = 0\n            value = 0\n            if ch >= 194 and ch <= 223:\n                extra = 1\n                value = ch & 31\n            elif ch >= 224 and ch <= 239:\n                extra = 2\n                value = ch & 15\n            elif ch >= 240 and ch <= 244:\n                extra = 3\n                value = ch & 7\n            if extra == 0 or extra >= n - i:\n                return 0\n            second = byte(s, at + i + 1)\n            if (ch == 224 and second < 160) or (ch == 237 and second > 159) or (ch == 240 and second < 144) or (ch == 244 and second > 143):\n                return 0\n            j = 1\n            while j <= extra:\n                c = byte(s, at + i + j)\n                if c < 128 or c > 191:\n                    return 0\n                value = (value << 6) | (c & 63)\n                j = j + 1\n            if value <= 65535:\n                result_unicode(o, w, value)\n            else:\n                value = value - 65536\n                result_unicode(o, w, 55296 + (value >> 10))\n                result_unicode(o, w, 56320 + (value & 1023))\n            i = i + extra + 1\n    return 1\n\ndef result_unicode(o:mutbuf, w:mutbuf, value:u64) -> u64:\n    output_byte(o, w, 92)\n    output_byte(o, w, 117)\n    output_byte(o, w, hex_digit((value >> 12) & 15))\n    output_byte(o, w, hex_digit((value >> 8) & 15))\n    output_byte(o, w, hex_digit((value >> 4) & 15))\n    return output_byte(o, w, hex_digit(value & 15))\n'

def sha_functions():
    nodes = [n for n in ast.parse(source_program()).body if n.name != 'stream']
    names = {n.name: 'sha_' + n.name for n in nodes}
    class Rename(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            node = copy.deepcopy(node)
            node.name = names[node.name]
            return self.generic_visit(node)
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name):
                name = node.func.id
                if name in ('byte', 'store', 'word_load') and isinstance(node.args[0], ast.Name) and node.args[0].id == 'w':
                    node.args[1] = ast.BinOp(left=ast.Constant(value=4096), op=ast.Add(), right=node.args[1])
                if name in names:
                    node.func.id = names[name]
            return node
    text = '\n' + '\n\n'.join(ast.unparse(ast.fix_missing_locations(Rename().visit(n))) for n in nodes) + '\n'
    text += '\ndef digest(s:readbuf, o:mutbuf, w:mutbuf, start:u64, count:u64, out:u64) -> u64:\n'
    for i, value in enumerate(ROUND):
        text += f'    sha_put(w, {i * 8}, {value})\n'
    for i, value in enumerate(INITIAL):
        text += f'    sha_put(w, {1024 + i * 8}, {value})\n'
    text += '''    used = 0
    i = 0
    while i < count:
        store(w, 5208 + used, byte(s, start + i))
        used = used + 1
        if used == 64:
            sha_compress(w)
            used = 0
        i = i + 1
    store(w, 5208 + used, 128)
    used = used + 1
    while used != 56:
        if used == 64:
            sha_compress(w)
            used = 0
        else:
            store(w, 5208 + used, 0)
            used = used + 1
    bits = count << 3
    i = 0
    while i < 8:
        store(w, 5264 + i, (bits >> ((7 - i) * 8)) & 255)
        i = i + 1
    sha_compress(w)
    i = 0
    while i < 8:
        value = sha_get(w, 1024 + i * 8)
        j = 0
        while j < 4:
            store(o, out + i * 4 + j, (value >> ((3 - j) * 8)) & 255)
            j = j + 1
        i = i + 1
    return 0
'''
    mutable = text[text.index('\ndef digest('):].replace('digest(s:readbuf, o:mutbuf', 'digest_mut(o:mutbuf', 1).replace('byte(s, start + i)', 'byte(o, start + i)')
    return text + mutable

def policy_source():
    constants = []
    replacements = {'MAGIC': int.from_bytes(b'HIAWIB01', 'little'), 'CONFIG_MAGIC': int.from_bytes(b'HIAWEC01', 'little')}
    def literal(raw, name=None):
        if isinstance(raw, str): raw = raw.encode()
        index = len(constants)
        constants.append(raw)
        if name: replacements[name] = index
        return index
    for name, raw in {
        'LIT_PROFILE': b'worker.json\0', 'LIT_STORE': b'store/',
        'LIT_CAPSULE': b'evaluate-full-worker-capsule.bin\0',
        'LIT_PREFIX': b'-B\0-E\0-s\0-m\0hepta.hia_agent_worker\0',
        'LIT_STATE': b'--state-root\0',
        'LIT_MANIFEST_PAIR': b'--installation-manifest\0--native-helpers-manifest\0',
        'LIT_MANIFEST': b'--installation-manifest\0',
        'LIT_EXPECT_WORKER': b'--expected-worker-sha256\0',
        'LIT_EXPECT_BACKEND': b'--expected-backend-sha256\0',
        'LIT_EXPECT_CATALOG': b'--expected-catalog-sha256\0',
        'LIT_EXPECT_HELPERS': b'--expected-native-helpers-sha256\0',
        'LIT_HELPERS': b'--native-helpers-manifest\0',
        'LIT_ARTIFACT_ROOT': b'--artifact-root\0',
        'LIT_REQUEST': b'--request-json-stdin\0',
        'LIT_ID_BACKEND': b'{"backend_sha256":"',
        'LIT_ID_CATALOG': b'","catalog_sha256":"',
        'LIT_ID_HELPERS': b'","native_helpers_sha256":"',
        'LIT_ID_WORKER': b'","worker_sha256":"',
        'LIT_ID_END': b'"}',
        'LIT_COMPAT': b'{"implementation":"CPython","version":"3.14.4"}',
        'LIT_SELECTION_PREFIX': b'{"native_helpers_sha256":"',
        'LIT_SELECTION_SUFFIX': b'","schema":"hepta.hia.agent.proof-native-selection.v1"}',
        'LIT_ARTIFACT_PREFIX': b'{"id":"hia-artifact-v1","sha256":"',
        'LIT_PIN_SEPARATOR': b'","',
    }.items(): literal(raw, name)
    profile = {'schema':'hepta.hia.native-helpers.v24','target':'linux-x86_64-lp64','abi':'hia-byte-six-argument-v1',
               'base_bundle':'schedulers.json','base_bundle_sha256':'@1@','release_path':'store/@0@'}
    for index, (field, _, _) in enumerate(PROFILE_IMAGES, 2): profile[field] = f'@{index}@'
    for index, (name, path) in enumerate(REFERENCES, 13):
        profile[name + '_path'] = path.replace('@PACKAGE@', '@0@')
        profile[name + '_sha256'] = f'@{index}@'
    raw = (json.dumps(profile, indent=2, sort_keys=True) + '\n').encode()
    import re
    body = '\ndef profile_template(o:mutbuf, w:mutbuf) -> u64:\n'
    at = 0
    for match in re.finditer(rb'@(\d+)@', raw):
        body += f'    literal(o, w, {literal(raw[at:match.start()])})\n'
        body += f'    hex_output(o, w, {16777216 + int(match[1]) * 32}, 32)\n'
        at = match.end()
    body += f'    literal(o, w, {literal(raw[at:])})\n    return 1\n'
    body += '\ndef image_limit(index:u64) -> u64:\n'
    for index, (_, _, limit) in enumerate(PROFILE_IMAGES, 2): body += f'    if index == {index}:\n        return {limit}\n'
    body += '    return 1048576\n'
    from tools.generate_hia_read_capsule import ROLES as READ_ROLES
    from tools.generate_hia_readonly_worker_capsule import ROLES as READONLY_ROLES, NATIVE_ROLES, replay_inventory, PROOF_TRUST_CHECKERS
    from tools.generate_hia_worker_evaluate_launcher import inventory
    from tools.generate_hia_discovery_bootstrap_plan import BOOTSTRAP_FILES
    from hepta.hia_schema import PRIMITIVE_PROFILES
    inventories = (READ_ROLES, READONLY_ROLES, NATIVE_ROLES, replay_inventory(), replay_inventory(intake=True), inventory())
    body += '\ndef role_count(kind:u64) -> u64:\n'
    for i, rows in enumerate(inventories,1):body += f'    if kind == {i}:\n        return {len(rows)}\n'
    body += '    return 0\n\ndef checker_ordinal(kind:u64, index:u64) -> u64:\n'
    for i, rows in enumerate(inventories[2:],3):
        body += f'    if kind == {i}:\n        return choose(index == 0, {rows.index(PROOF_TRUST_CHECKERS[0])}, {rows.index(PROOF_TRUST_CHECKERS[1])})\n'
    body += '    return 0\n\ndef capsule_magic(kind:u64) -> u64:\n'
    body += f'    return choose(kind == 1, {int.from_bytes(b"HIARCP01","little")}, choose(kind == 2, {int.from_bytes(b"HIADCP01","little")}, {int.from_bytes(b"HIANCP01","little")}))\n'
    body += '\ndef document_literal(index:u64) -> u64:\n'
    for i, (_, filename) in enumerate(BOOTSTRAP_FILES):body += f'    if index == {i}:\n        return {literal(filename)}\n'
    body += '    return 0\n\ndef manifest_template(o:mutbuf, w:mutbuf, kind:u64) -> u64:\n'
    for i, kind in enumerate(('read','readonly','native','evaluate-replay','evaluate-intake','evaluate-full'),1):
        body += f'    if kind == {i}:\n        return manifest_template_{i}(o, w)\n'
    body += '    return 0\n'
    for i, kind in enumerate(('read','readonly','native','evaluate-replay','evaluate-intake','evaluate-full'),1):
        record={'schema':'hepta.hia.'+kind+'-worker.v1','launcher':'store/@2@/hia-agent-'+kind+'-launcher','launcher_sha256':'@1@','release':'store/@2@','capsule':kind+'-worker-capsule.bin','capsule_sha256':'@0@'}
        raw=(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode();at=0
        body += f'\ndef manifest_template_{i}(o:mutbuf, w:mutbuf) -> u64:\n'
        for match in re.finditer(rb'@(\d+)@',raw):
            body += f'    literal(o, w, {literal(raw[at:match.start()])})\n    hex_output(o, w, {16777216+int(match[1])*32}, 32)\n';at=match.end()
        body += f'    literal(o, w, {literal(raw[at:])})\n    return 1\n'
    replacements.update({key:int.from_bytes(value,'little') for key,value in {'DOSSIER_MAGIC':b'HIARWD01','TRUST_MAGIC':b'HIAPTK02','BOOTSTRAP_MAGIC':b'HIADBQ01','ARTIFACT_MAGIC':b'HIARAC01','RESOURCE_MAGIC':b'HIADBF01','PROFILE_MAGIC':b'HIADISPF'}.items()})
    replacements['PROFILE_VERSION']=len(PRIMITIVE_PROFILES)+1+4
    replacements['CONTROLLER_RECEIPT_MAGIC']=int.from_bytes(b'HIACTO01','little')
    body += '\ndef result_template(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n'
    result_fields=[('native_helpers_manifest','path','/worker.json'),('native_helpers_sha256','digest',0),('package_sha256','package',0),('production_activated','false',0),('python_executable','path','/hia-agent-worker'),('native_worker_executable_sha256','digest',1)]
    for index,kind in enumerate(('read','readonly','native','evaluate-replay','evaluate-intake','evaluate-full')):
        label=kind.replace('-','_');result_fields.extend(((f'native_{label}_worker_manifest','path','/'+kind+'-worker.json'),(f'native_{label}_worker_sha256','digest',index+2)))
    result_fields.extend((('hia_controller_manifest','controller',0),('hia_controller_sha256','controller_pin',0)))
    def emit_result_field(key,kind,value,first=False,indent='    '):
        prefix=('{' if first else ', ')+json.dumps(key)+': '
        if kind=='false':return indent+f'literal(o, w, {literal(prefix+"false")})\n'
        code=indent+f'literal(o, w, {literal(prefix+chr(34))})\n'
        if kind in ('path','controller'):
            code+=indent+'if result_path(s, o, w) == 0:\n'+indent+'    return 0\n'
            if kind=='path':code+=indent+f'literal(o, w, {literal(value)})\n'
            else:code+=indent+f'literal(o, w, {literal("/controller/")})\n'+indent+'hex_input(s, o, w, piece(w, 10) + 24, 32)\n'+indent+f'literal(o, w, {literal("/hia-controller.json")})\n'
        elif kind=='digest':code+=indent+f'hex_output(o, w, {16777216+value*32}, 32)\n'
        elif kind=='package':code+=indent+'hex_input(s, o, w, piece(w, 1), 32)\n'
        else:code+=indent+'hex_input(s, o, w, piece(w, 10) + 56, 32)\n'
        return code+indent+'output_byte(o, w, 34)\n'
    for index,(key,kind,value) in enumerate(result_fields):
        body+=emit_result_field(key,kind,value,index==0)
        if index==5:
            body+='    if uint(s, piece(w, 11)) == 1:\n'+emit_result_field('runtime_config','path','/runtime-config.json',indent='        ')
    body+='    output_byte(o, w, 125)\n    output_byte(o, w, 10)\n    return 1\n'

    init = '\ndef constants(w:mutbuf) -> u64:\n'
    offsets = []
    at = 131072
    for raw in constants:
        offsets.append(at)
        for offset in range(0, len(raw), 8):
            chunk = raw[offset:offset+8]
            if len(chunk) == 8: init += f'    put(w, {at+offset}, {int.from_bytes(chunk,"little")})\n'
            else:
                for j, value in enumerate(chunk): init += f'    store(w, {at+offset+j}, {value})\n'
        at += (len(raw)+7)&~7
    init += '    return 0\n\ndef literal_offset(index:u64) -> u64:\n'
    for i, offset in enumerate(offsets): init += f'    if index == {i}:\n        return {offset}\n'
    init += '    return 0\n\ndef literal_size(index:u64) -> u64:\n'
    for i, raw in enumerate(constants): init += f'    if index == {i}:\n        return {len(raw)}\n'
    init += '    return 0\n'
    source = SOURCE + CAPSULE_SOURCE + RESULT_SOURCE + body + init + sha_functions()
    for name, value in sorted(replacements.items(), key=lambda item: -len(item[0])):
        source = source.replace(name, str(value))
    # The bound prefix consists of exactly these two NUL-terminated vectors.
    source = source.replace('put(o, get(w, 256), 50)', f'put(o, get(w, 256), {len(b"--installation-manifest\0--native-helpers-manifest\0")})')
    tree = ast.parse(source)
    node = next(n for n in tree.body if n.name == 'constants')
    statements = [ast.get_source_segment(source, n) for n in node.body[:-1]]
    chunks = [statements[i:i+128] for i in range(0, len(statements), 128)]
    replacement = 'def constants(w:mutbuf) -> u64:\n' + ''.join(f'    constants_part_{i}(w)\n' for i in range(len(chunks))) + '    return 0'
    source = source.replace(ast.get_source_segment(source, node), replacement, 1)
    for i, chunk in enumerate(chunks):
        source += f'\ndef constants_part_{i}(w:mutbuf) -> u64:\n' + ''.join('    '+line+'\n' for line in chunk) + '    return 0\n'
    return source

def render():
    nodes = ast.parse(policy_source()).body
    names = {n.name: f'f{i}' for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(a) for a in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    doc = compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':'source_worker_install_bind','functions':functions})
    text = render_assembly(doc)
    return text, {'functions':len(doc['functions']),'maximum_block_parameters':max(len(b['params']) for f in doc['functions'] for b in f['blocks']), 'source_bytes':len(text.encode()),'sha256':sha256(text.encode()).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    text, record = render()
    path = ROOT / 'examples/hia_bootstrap/source_worker_install_bind.hepta'
    if args.check:
        if path.read_text() != text: raise SystemExit('Worker install binding source differs from its author')
    else: path.write_text(text)
    print(json.dumps(record, sort_keys=True))

if __name__ == '__main__': main()
