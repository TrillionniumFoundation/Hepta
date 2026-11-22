"""Author the descriptor-ready projection of a schema-admitted Emit request."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_candidate_request import POLICY as CANDIDATE
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_inspection_request import POLICY as INSPECTION

SOURCE = Path('examples/hia_bootstrap/worker_emit_request.hepta')
FIELDS = ('catalog_sha256', 'backend_profile', 'context', 'candidate', 'verification_receipts',
          'output_kind', 'codegen', 'kind', 'lowering_profile', 'plan_profile', 'plan',
          'verification_receipt')

POLICY = r'''
# The capsule supplies the installed catalog digest. Business effect order
# is backend, Context, candidate, ordered receipts, then the specific codegen.
def emit_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 32768 or length(o) < 32768 or length(w) < 65536:
        return INVALID
    if length(s) >= 8:
        tag = input_word(s, 0)
        if tag == WINDOW or tag == LAUNCH_WINDOW:
            return emit_window(s, o, tag == LAUNCH_WINDOW)
    put(o, 48, 4096)
    put(o, 56, 32)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    arity = get(w, 96)
    if arity != 2 and arity != 3:
        return INVALID
    pinned = 64 + get(w, 88) * 72
    arguments = 64 + get(w, pinned + 16) * 72
    if digest_text(w, pinned, False) == False or get(w, arguments) != 6:
        return INVALID
    catalog = lookup(w, arguments, K_catalog_sha256)
    if digest_text(w, catalog, True) == False:
        return INVALID
    if arity == 3:
        marker = 64 + get(w, arguments + 16) * 72
        if get(w, marker) != 0:
            return INVALID
        at = copy_value(s, w, o, catalog, 24)
        end = copy_value(s, w, o, pinned, at)
        put(o, 0, at - 24)
        put(o, 8, end - at)
        put(o, 16, 0)
        return end
    if equal_span(s, w, pinned, catalog) == False:
        return CATALOG_MISMATCH
    return emit_arguments(s, o, w, arguments)

def emit_arguments(s:readbuf, o:mutbuf, w:mutbuf, args:u64) -> u64:
    backend = lookup(w, args, K_backend_profile)
    context = lookup(w, args, K_context)
    candidate = lookup(w, args, K_candidate)
    receipts = lookup(w, args, K_verification_receipts)
    codegen = lookup(w, args, K_codegen)
    output = lookup(w, args, K_output_kind)
    if object_node(w, backend) == False or object_node(w, context) == False:
        return INVALID
    if object_node(w, candidate) == False or object_node(w, codegen) == False:
        return INVALID
    if receipts == NONE or get(w, receipts) != 5 or get(w, receipts + 32) > 16:
        return INVALID
    output_kind = 1
    if shared_kind(w, output):
        output_kind = 2
    elif object_kind(w, output) == False:
        return INVALID
    put(o, 0, REQUEST)
    put(o, 8, output_kind)
    put(o, 24, get(w, receipts + 32))
    at = fragment(s, w, o, backend, 32)
    at = fragment(s, w, o, context, at)
    at = fragment(s, w, o, candidate, at)
    at = fragment(s, w, o, receipts, at)
    value = get(w, receipts + 24)
    index = 0
    while index < get(w, receipts + 32):
        receipt = 64 + value * 72
        if object_node(w, receipt) == False:
            return INVALID
        at = fragment(s, w, o, receipt, at)
        value = get(w, receipt + 16)
        index = index + 1
    at = fragment(s, w, o, codegen, at)
    return emit_codegen(s, o, w, codegen, at)

def emit_codegen(s:readbuf, o:mutbuf, w:mutbuf, codegen:u64, at:u64) -> u64:
    kind = lookup(w, codegen, K_kind)
    if canonical_kind(w, kind):
        profile = lookup(w, codegen, K_lowering_profile)
        if object_node(w, profile) == False:
            return INVALID
        put(o, 16, 1)
        return fragment(s, w, o, profile, at)
    if plan_kind(w, kind) == False:
        return INVALID
    profile = lookup(w, codegen, K_plan_profile)
    plan = lookup(w, codegen, K_plan)
    receipt = lookup(w, codegen, K_verification_receipt)
    if object_node(w, profile) == False or object_node(w, plan) == False or object_node(w, receipt) == False:
        return INVALID
    put(o, 16, 2)
    at = fragment(s, w, o, profile, at)
    at = fragment(s, w, o, plan, at)
    return fragment(s, w, o, receipt, at)

def object_node(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 6

# Exact native Context lookup observation plus a live clock sample.
# Admission rejects strictly after the deadline; launch additionally requires
# a whole millisecond. Report only the bounded duration usable by the child.
def emit_window(s:readbuf, o:mutbuf, launch:bool) -> u64:
    context_at = choose(launch, 40, 32)
    row = context_at + 121
    created_at = row + 208
    if length(s) <= created_at or length(s) > created_at + 20:
        return INVALID
    stage = input_word(s, 8)
    total = input_word(s, 16)
    now = input_word(s, 24)
    if stage < 1 or stage > 2 or (launch and stage != 2) or total == 0 or total > 86400000:
        return INVALID
    if valid_context_id(s, context_at + 7) == False or input_word(s, row) != CONTEXT_ROW or input_word(s, row + 8) != 0:
        return INVALID
    if match_context_digest(s, context_at + 55, row + 85) == False:
        return INVALID
    count = input_word(s, row + 24)
    if count != length(s) - created_at or (count > 1 and byte(s, created_at) == 48):
        return INVALID
    created = 0
    index = created_at
    while index < length(s):
        digit = byte(s, index)
        if digit < 48 or digit > 57:
            return INVALID
        if created > 1844674407370955161 or (created == 1844674407370955161 and digit > 53):
            return INVALID
        created = created * 10 + (digit - 48)
        index = index + 1
    extent = remaining_window(o, stage, total * 1000000, created, now)
    if launch == False:
        return extent
    return launch_permit(o, input_word(s, 32))

def match_context_digest(s:readbuf, context_digest:u64, digest:u64) -> bool:
    index = 0
    while index < 64:
        ch = byte(s, context_digest + index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        if ch != byte(s, digest + index):
            return False
        index = index + 1
    return True

def remaining_window(o:mutbuf, stage:u64, total:u64, created:u64, now:u64) -> u64:
    maximum = 3600000000000
    remaining = 0
    expired = False
    if created > now:
        future = created - now
        remaining = choose(total < maximum, total, maximum) + choose(future < maximum, future, maximum)
    else:
        spent = now - created
        expired = spent > total
        if expired == False:
            remaining = total - spent
    millis = whole_milliseconds(remaining)
    refused = expired or (stage == 2 and millis == 0)
    put(o, 0, WINDOW_RESULT)
    put(o, 8, choose(refused, 1, 0))
    put(o, 16, millis)
    return 24

def whole_milliseconds(nanos:u64) -> u64:
    lower = 0
    upper = 3600001
    while lower + 1 < upper:
        middle = (lower + upper) >> 1
        before_deadline = middle * 1000000 <= nanos
        lower = choose(before_deadline, middle, lower)
        upper = choose(before_deadline, upper, middle)
    return lower

def launch_permit(o:mutbuf, sampled:u64) -> u64:
    duration = get(o, 16) * 1000000
    if sampled == 0 or sampled > 18446744073709551615 - duration:
        return INVALID
    put(o, 0, LAUNCH_PERMIT)
    put(o, 24, sampled)
    put(o, 32, sampled + duration)
    return 40
'''


def program():
    constants = {f'K_{name}': index for index, name in enumerate(FIELDS, 1)}
    constants.update(REQUEST=int.from_bytes(b'HIAERQ01', 'little'), NONE=(1 << 64) - 1,
                     INVALID=4294967293, CATALOG_MISMATCH=4294967286,
                     WINDOW=int.from_bytes(b'HIAEMW01', 'little'),
                     WINDOW_RESULT=int.from_bytes(b'HIAEMW02', 'little'),
                     LAUNCH_WINDOW=int.from_bytes(b'HIAEMW03', 'little'),
                     LAUNCH_PERMIT=int.from_bytes(b'HIAEMW04', 'little'),
                     CONTEXT_ROW=int.from_bytes(b'HIACTO02', 'little'))
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda match: str(constants[match[0]]), POLICY)
    choices = {f'{name}_kind': name for name in ('object', 'shared', 'canonical')}
    choices['plan_kind'] = 'agent_plan'
    return '\n'.join((
        policy,
        *(function(CONTEXT, name).replace('NONE', str(constants['NONE']))
          for name in ('equal_span', 'digest_text', 'fragment', 'copy_value')),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(constants['NONE'])),
        function(CANDIDATE, 'valid_context_id').replace('CONTEXT_PREFIX', str(int.from_bytes(b'ctx-', 'little'))),
        function(INSPECTION, 'input_word'),
        comparison_table('key_id', FIELDS),
        *(literal_match(name, value) for name, value in choices.items()),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
