"""Author the native provider's byte-preserving Worker request encoder.

The transport supplies canonical JSON fragments after schema, catalog and host
policy checks. HIA owns the envelope, hashes and durable job key. It must not
parse and reprint numbers: the existing transport's exact bytes are stored
as part of the durable job identity.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_worker_request import WorkerRequestBuilder, worker_hash_program


SOURCE_PATH = 'examples/hia_bootstrap/worker_prepare.hepta'
INPUT_MAGIC = b'HIAWPR01'
OUTPUT_MAGIC = b'HIAWPO01'
JOB_INPUT_MAGIC = b'HIAJID01'
JOB_OUTPUT_MAGIC = b'HIAJDO01'
REUSE_INPUT_MAGIC = b'HIAJRE01'
REUSE_OUTPUT_MAGIC = b'HIAJRO01'
SCOPE_INPUT_MAGIC = b'HIASCO01'
SCOPE_OUTPUT_MAGIC = b'HIASCR01'
TRANSITION_INPUT_MAGIC = b'HIAJTR01'
TRANSITION_OUTPUT_MAGIC = b'HIAJTO01'
HTTP_AUTH_INPUT = b'HIAHAT01'
HTTP_AUTH_OUTPUT = b'HIAHAO01'

SOURCE = '''
def prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    n = length(s)
    if n < 8 or n > 8388608 or length(w) < 4432:
        return 4294967293
    magic = word_load(s, 0)
    if magic == JOB_INPUT_MAGIC:
        return job_identity(s, o, w)
    if magic == REUSE_INPUT_MAGIC:
        return job_reuse(s, o)
    if magic == SCOPE_INPUT_MAGIC:
        return session_scope(s, o)
    if magic == TRANSITION_INPUT_MAGIC:
        return durable_transition(s, o)
    if magic == HTTP_AUTH_INPUT:
        return http_auth(s, o, w)
    if n < 112 or magic != INPUT_MAGIC:
        return 4294967293
    if length(o) < 524552:
        return 4294967294
    start = 112
    field = 0
    while field < 5:
        size = word_load(s, 8 + field * 8)
        if size > 524288 or size > n - start:
            return 4294967293
        if field < 3:
            if size < 2:
                return 4294967293
            if byte(s, start) != 123 or byte(s, start + size - 1) != 125:
                return 4294967293
        elif field == 3 or size != 0:
            if size < 2:
                return 4294967293
            if byte(s, start) != 34 or byte(s, start + size - 1) != 34:
                return 4294967293
        word_store(w, 256 + field * 16, start)
        word_store(w, 264 + field * 16, size)
        start = start + size
        field = field + 1
    if start != n:
        return 4294967293
    index = 48
    while index < 112:
        value = byte(s, index)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return 4294967293
        index = index + 1
    # Bound both the final envelope and the temporary key preimage.
    size = word_load(w, 296) + word_load(w, 312)
    if size > MAX_FRAGMENTS or word_load(w, 312) + word_load(w, 328) > 524288:
        return 4294967294
    count = append_field(s, o, w, 0, 0)
    if digest(o, w, count, 0) == 0:
        return 4294967293
    count = append_field(s, o, w, 0, 1)
    if digest(o, w, count, 64) == 0:
        return 4294967293
    count = envelope_prefix(s, o, w, 0)
    count = envelope_tail(s, o, w, count)
    if digest(o, w, count, 128) == 0:
        return 4294967293
    if word_load(w, 328) == 0:
        count = readonly_start(o, 0)
        count = saved(w, o, count, 128, 64)
        count = readonly_tool(o, count)
    else:
        count = mutation_start(o, 0)
        count = append_field(s, o, w, count, 4)
        count = mutation_tool(o, count)
    count = append_field(s, o, w, count, 3)
    count = close(o, count)
    if digest(o, w, count, 192) == 0:
        return 4294967293
    count = envelope_prefix(s, o, w, 264)
    count = request_member(o, count)
    count = saved(w, o, count, 128, 64)
    count = envelope_tail(s, o, w, count)
    store(o, count, 10)
    word_store(o, 0, OUTPUT_MAGIC)
    saved(w, o, 8, 0, 256)
    return count + 1

def job_identity(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    n = length(s)
    if n < 10:
        return 4294967293
    if byte(s, 8) != 123 or byte(s, n - 1) != 125:
        return 4294967293
    count = n - 8
    if length(o) < count or length(o) < 72:
        return 4294967294
    external(s, o, 0, 8, count)
    if digest(o, w, count, 0) == 0:
        return 4294967293
    word_store(o, 0, JOB_OUTPUT_MAGIC)
    return saved(w, o, 8, 0, 64)

def envelope_prefix(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    at = arguments_member(o, at)
    at = append_field(s, o, w, at, 2)
    at = catalog_member(o, at)
    at = external(s, o, at, 48, 64)
    at = profile_member(o, at)
    return saved(w, o, at, 64, 64)

def envelope_tail(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    at = schema_and_tool(o, at)
    at = append_field(s, o, w, at, 3)
    return close(o, at)

def append_field(s:readbuf, o:mutbuf, w:mutbuf, at:u64, field:u64) -> u64:
    record = 256 + field * 16
    return external(s, o, at, word_load(w, record), word_load(w, record + 8))

def external(s:readbuf, o:mutbuf, at:u64, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, byte(s, start + i))
        i = i + 1
    return at + size

def saved(w:mutbuf, o:mutbuf, at:u64, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, byte(w, start + i))
        i = i + 1
    return at + size

def append_word(o:mutbuf, at:u64, word:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, (word >> (i * 8)) & 255)
        i = i + 1
    return at + size

def digest(o:mutbuf, w:mutbuf, size:u64, at:u64) -> u64:
    if widen(hash_sha256(o, w, size)) != 32:
        return 0
    start = length(w) - 4096 + 1088
    i = 0
    while i < 32:
        value = byte(w, start + i)
        store(w, at + 2 * i, hex(value >> 4))
        store(w, at + 2 * i + 1, hex(value & 15))
        i = i + 1
    return 1

def widen(value:u32) -> u64:
    return value

def hex(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def job_reuse(s:readbuf, o:mutbuf) -> u64:
    n = length(s)
    if n < 88 or n > 152:
        return 4294967293
    fingerprint = word_load(s, 8)
    present = word_load(s, 16)
    if present > 1 or (present == 0 and n != 88):
        return 4294967293
    if length(o) < 16:
        return 4294967294
    prefix = 0
    equal = 1
    index = 0
    while index < 64:
        value = byte(s, 24 + index)
        digit = 0
        if value >= 48 and value <= 57:
            digit = value - 48
        elif value >= 97 and value <= 102:
            digit = value - 87
        else:
            return 4294967293
        if index < 16:
            prefix = prefix * 16 + digit
        if n == 152 and byte(s, 88 + index) != value:
            equal = 0
        index = index + 1
    decision = 1
    if present == 0:
        decision = 2
    elif n == 152 and equal != 0 and fingerprint == prefix:
        decision = 0
    word_store(o, 0, REUSE_OUTPUT_MAGIC)
    word_store(o, 8, decision)
    return 16

def http_auth(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    n = length(s)
    if n < 104 or n > 4168:
        return 4294967293
    count = n - 72
    if length(o) < count:
        return 4294967294
    external(s, o, 0, 72, count)
    if digest(o, w, count, 0) == 0:
        return 4294967293
    # Compare every digest byte, including the last. The candidate header
    # length is public. Never return the candidate bytes or either digest.
    difference = 0
    index = 0
    while index < 64:
        difference = difference | (byte(s, 8 + index) ^ byte(w, index))
        index = index + 1
    word_store(o, 0, HTTP_AUTH_OUTPUT)
    word_store(o, 8, choose(difference == 0, 1, 0))
    return 16

def session_scope(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 160:
        return 4294967293
    if length(o) < 16:
        return 4294967294
    transport = word_load(s, 8)
    candidate_size = word_load(s, 16)
    prior_kind = word_load(s, 24)
    if transport > 1 or prior_kind > 2:
        return 4294967293
    if prior_kind != 0 and scope_digest(s, 96) == 0:
        return 4294967293
    # HTTP uses only verified middleware evidence. The stdio fallback is
    # never interpreted as a credential, even if every digest byte agrees.
    decision = 0
    if candidate_size != 64 or scope_digest(s, 32) == 0:
        if transport == 1:
            decision = 1
        else:
            decision = 2
    elif prior_kind != 0:
        different = prior_kind ^ (transport + 1)
        index = 0
        while index < 64:
            different = different | (byte(s, 32 + index) ^ byte(s, 96 + index))
            index = index + 1
        if different != 0:
            decision = 3
    word_store(o, 0, SCOPE_OUTPUT_MAGIC)
    word_store(o, 8, decision)
    return 16

def scope_digest(s:readbuf, at:u64) -> u64:
    index = 0
    while index < 64:
        value = byte(s, at + index)
        if value < 48 or (value > 57 and value < 97) or value > 102:
            return 0
        index = index + 1
    return 1

def durable_transition(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 80:
        return 4294967293
    if length(o) < 16:
        return 4294967294
    flags = word_load(s, 8)
    size = word_load(s, 16)
    if flags > 7 or size > 56:
        return 4294967293
    first = word_load(s, 24)
    # Unknown state or incomplete outcomes remain serialized.
    # Only an already confirmed launch releases the lane for observation.
    decision = 0
    if size == 8 and first == LAUNCHED_WORD:
        decision = 1
    elif flags == 7:
        # All three authorities are required: caller route permits
        # reconciliation, and the bound owner is isolated system jobctl.
        if size == 7 and first & 0x00ffffffffffffff == PENDING_WORD:
            decision = 2
        elif size == 13 and first == FAILED_HEAD and word_load(s, 32) & 0x000000ffffffffff == FAILED_TAIL:
            decision = 2
    word_store(o, 0, TRANSITION_OUTPUT_MAGIC)
    word_store(o, 8, decision)
    return 16
'''

LITERALS = {
    'arguments_member': '{"arguments":',
    'catalog_member': ',"catalog_sha256":"',
    'profile_member': '","profile_sha256":"',
    'request_member': '","request_sha256":"',
    'schema_and_tool': '","schema":"hia-agent-worker-request-v1","tool":',
    'close': '}',
    'readonly_start': '{"readonly_request_sha256":"',
    'readonly_tool': '","tool":',
    'mutation_start': '{"key":',
    'mutation_tool': ',"tool":',
}


def source_program():
    envelope_fields = ('arguments_member', 'catalog_member', 'profile_member',
                       'request_member', 'schema_and_tool', 'close')
    fixed_bytes = sum(len(LITERALS[field]) for field in envelope_fields) + 3 * 64 + 1
    source = (SOURCE.replace('JOB_INPUT_MAGIC', str(int.from_bytes(JOB_INPUT_MAGIC, 'little')))
              .replace('JOB_OUTPUT_MAGIC', str(int.from_bytes(JOB_OUTPUT_MAGIC, 'little')))
              .replace('REUSE_INPUT_MAGIC', str(int.from_bytes(REUSE_INPUT_MAGIC, 'little')))
              .replace('REUSE_OUTPUT_MAGIC', str(int.from_bytes(REUSE_OUTPUT_MAGIC, 'little')))
              .replace('SCOPE_INPUT_MAGIC', str(int.from_bytes(SCOPE_INPUT_MAGIC, 'little')))
              .replace('SCOPE_OUTPUT_MAGIC', str(int.from_bytes(SCOPE_OUTPUT_MAGIC, 'little')))
              .replace('TRANSITION_INPUT_MAGIC', str(int.from_bytes(TRANSITION_INPUT_MAGIC, 'little')))
              .replace('TRANSITION_OUTPUT_MAGIC', str(int.from_bytes(TRANSITION_OUTPUT_MAGIC, 'little')))
              .replace('HTTP_AUTH_INPUT', str(int.from_bytes(HTTP_AUTH_INPUT, 'little')))
              .replace('HTTP_AUTH_OUTPUT', str(int.from_bytes(HTTP_AUTH_OUTPUT, 'little')))
              .replace('LAUNCHED_WORD', str(int.from_bytes(b'launched', 'little')))
              .replace('PENDING_WORD', str(int.from_bytes(b'pending', 'little')))
              .replace('FAILED_HEAD', str(int.from_bytes(b'launch_f', 'little')))
              .replace('FAILED_TAIL', str(int.from_bytes(b'ailed', 'little')))
              .replace('INPUT_MAGIC', str(int.from_bytes(INPUT_MAGIC, 'little')))
              .replace('OUTPUT_MAGIC', str(int.from_bytes(OUTPUT_MAGIC, 'little')))
              .replace('MAX_FRAGMENTS', str(524288 - fixed_bytes)))
    for name, literal in LITERALS.items():
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        raw = literal.encode('ascii')
        for start in range(0, len(raw), 8):
            part = raw[start:start + 8]
            source += f'    at = append_word(o, at, {int.from_bytes(part, "little")}, {len(part)})\n'
        source += '    return at\n'
    return source + worker_hash_program()


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: f'f{i}' for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = WorkerRequestBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9',
                                 'module': 'worker_prepare', 'functions': functions})


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
