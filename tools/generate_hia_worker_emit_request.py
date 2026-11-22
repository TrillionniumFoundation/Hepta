"""Author the descriptor-ready projection of a schema-admitted Emit request."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function

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
'''


def program():
    constants = {f'K_{name}': index for index, name in enumerate(FIELDS, 1)}
    constants.update(REQUEST=int.from_bytes(b'HIAERQ01', 'little'), NONE=(1 << 64) - 1,
                     INVALID=4294967293, CATALOG_MISMATCH=4294967286)
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda match: str(constants[match[0]]), POLICY)
    choices = {f'{name}_kind': name for name in ('object', 'shared', 'canonical')}
    choices['plan_kind'] = 'agent_plan'
    return '\n'.join((
        policy,
        *(function(CONTEXT, name).replace('NONE', str(constants['NONE']))
          for name in ('equal_span', 'digest_text', 'fragment', 'copy_value')),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(constants['NONE'])),
        comparison_table('key_id', FIELDS),
        *(literal_match(name, value) for name, value in choices.items()),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
