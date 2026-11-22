"""Retain the checked native build report without process-local paths."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as authority_policy
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_inspection_effect import function

from tools.generate_hia_worker_proof_scope import split_key_table

SOURCE = Path('examples/hia_bootstrap/worker_retained_build.hepta')
REPORT_FIELDS = (
    'artifact_bytes', 'artifact_sha256', 'binary_inventory', 'build_host', 'claims', 'core_sha256',
    'exports', 'external_abi', 'flags', 'foreign_buffer_exports', 'function_frames',
    'implementation_sha256', 'implicit_profitability_optimizer_used', 'input_sha256', 'kind',
    'machine_plan_sha256', 'machine_text_bytes', 'machine_text_sha256', 'object_sha256', 'ok',
    'parent_death_guarded_linker', 'profile', 'runtime_assumptions', 'schema', 'status',
    'supported_core_schemas', 'supported_opcodes', 'target', 'toolchain',
)
FORBIDDEN = ('assembler_used', 'external_linker_used', 'c_codegen_used', 'llvm_codegen_used',
             'llvm_ir_used', 'rust_codegen_used', 'rust_reference_required', 'source_ast_required',
             'native_execution_qualified', 'whole_language_soundness_proved', 'fallback_used')
EXTRA = ('commands', 'machine_proof', 'object_artifact', 'output')
FIELDS = tuple(sorted((*REPORT_FIELDS, *EXTRA)))
KEYS = (*FIELDS, *FORBIDDEN, 'direct_machine_code', 'standalone_core_reverified', 'sha256',
        'self_hosted', 'foreign_buffer_entrypoints_exposed')

POLICY = r'''
# Accept a process report, or the explicit in-memory HIA report protocol
# [reference, report, 1], after independent object/final-image custody.
def retained_build(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 176 or length(s) > 1048576 or length(w) < 65536 or length(o) < 2048:
        return INVALID
    put(o, 48, 32768)
    put(o, 56, 64)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    arity = get(w, 96)
    if arity != 2 and arity != 3:
        return INVALID
    retained = 64 + get(w, 88) * 72
    report = 64 + get(w, retained + 16) * 72
    if get(w, retained) != 6 or get(w, retained + 64) != 176 or get(w, report) != 6:
        return INVALID
    memory = arity == 3
    if memory:
        mode = 64 + get(w, report + 16) * 72
        if get(w, mode) != 3 or get(w, mode + 32) != 1 or byte(s, get(w, mode + 24)) != 49:
            return INVALID
    if artifact_reference(s, get(w, retained + 56)) == False or validate_report(s, w, retained, report, memory) == False:
        return INVALID
    store(o, 0, 123)
    cursor = 1
    key = 1
    while key <= FIELD_COUNT:
        if key != K_output:
            node = lookup(w, report, key)
            if key == K_object_artifact:
                node = retained
            if key == K_commands or node != NONE:
                if cursor != 1:
                    if cursor >= length(o):
                        return INVALID
                    store(o, cursor, 44)
                    cursor = cursor + 1
                cursor = emit_key(o, cursor, key)
                if cursor > length(o):
                    return INVALID
                if key == K_commands:
                    if length(o) - cursor < 2:
                        return INVALID
                    store(o, cursor, 91)
                    store(o, cursor + 1, 93)
                    cursor = cursor + 2
                else:
                    cursor = compact_value(s, w, o, node, cursor)
                if cursor >= length(o):
                    return INVALID
        key = key + 1
    store(o, cursor, 125)
    return cursor + 1

def validate_report(s:readbuf, w:mutbuf, retained:u64, report:u64, memory:bool) -> bool:
    count = get(w, report + 32)
    proof = lookup(w, report, K_machine_proof)
    if count != REPORT_COUNT + choose(proof == NONE, 0, 1) + choose(memory, 0, 1):
        return False
    if proof != NONE and get(w, proof) != 6:
        return False
    if lookup(w, report, K_commands) != NONE or lookup(w, report, K_object_artifact) != NONE:
        return False
    path = lookup(w, report, K_output)
    digest = lookup(w, report, K_object_sha256)
    observed = lookup(w, retained, K_sha256)
    if memory:
        if path != NONE or memory_claims(w, lookup(w, report, K_claims)) == False:
            return False
    elif path == NONE or get(w, path) != 4:
        return False
    if digest_text(w, digest, False) == False:
        return False
    if observed == NONE or equal_span(s, w, observed, digest) == False:
        return False
    field = 1
    while field <= FIELD_COUNT:
        optional = field == K_commands or field == K_object_artifact or field == K_machine_proof or (memory and field == K_output)
        if optional == False and lookup(w, report, field) == NONE:
            return False
        field = field + 1
    return claims(w, report)

def memory_claims(w:mutbuf, claims:u64) -> bool:
    if claims == NONE or get(w, claims) != 6:
        return False
    native = lookup(w, claims, K_self_hosted)
    borrowed = lookup(w, claims, K_foreign_buffer_entrypoints_exposed)
    return native != NONE and borrowed != NONE and get(w, native) == 2 and get(w, borrowed) == 2

def claims(w:mutbuf, report:u64) -> bool:
    observed = lookup(w, report, K_claims)
    if observed == NONE or get(w, observed) != 6:
        return False
    begin = FIRST_FLAG
    while begin <= LAST_FLAG:
        node = lookup(w, observed, begin)
        if node == NONE or get(w, node) != 1:
            return False
        begin = begin + 1
    direct = lookup(w, observed, K_direct_machine_code)
    verified = lookup(w, observed, K_standalone_core_reverified)
    return direct != NONE and verified != NONE and get(w, direct) == 2 and get(w, verified) == 2

def compact_value(s:readbuf, w:mutbuf, o:mutbuf, node:u64, target:u64) -> u64:
    at = get(w, node + 56)
    size = get(w, node + 64)
    tag = get(w, node)
    if tag <= 3:
        at = get(w, node + 24)
        size = get(w, node + 32)
    end = at + size
    in_string = False
    escaped = False
    while at < end:
        digit = byte(s, at)
        at = at + 1
        if in_string or digit > 32:
            if target >= length(o):
                return INVALID
            store(o, target, digit)
            target = target + 1
        if escaped:
            escaped = False
        elif in_string and digit == 92:
            escaped = True
        elif digit == 34:
            in_string = in_string == False
    return target
'''


def emitted_keys():
    wire = [f'"{key}":'.encode() for key in FIELDS]
    dispatch = ['def emit_key(o:mutbuf, at:u64, key:u64) -> u64:']
    literals = []
    for field, raw in enumerate(wire, 1):
        dispatch.extend((f'    if key == {field}:', f'        return key_{field}(o, at)'))
        lines = [f'def key_{field}(o:mutbuf, at:u64) -> u64:',
                  f'    if at > length(o) or length(o) - at < {len(raw)}:',
                  '        return 4294967293']
        lines.extend(f'    store(o, at + {offset}, {byte})' for offset, byte in enumerate(raw))
        lines.append(f'    return at + {len(raw)}')
        literals.append('\n'.join(lines))
    dispatch.append('    return 4294967293')
    return '\n'.join(('\n'.join(dispatch), *literals))


def program():
    names = {f'K_{name}': index for index, name in enumerate(KEYS, 1)}
    names.update(INVALID=4294967293, NONE=(1 << 64)-1, FIELD_COUNT=len(FIELDS),
                 REPORT_COUNT=len(REPORT_FIELDS), FIRST_FLAG=len(FIELDS)+1, LAST_FLAG=len(FIELDS)+len(FORBIDDEN))
    policy = re.sub(r'\b('+'|'.join(names)+r')\b', lambda m: str(names[m[0]]), POLICY)
    authority = authority_policy()
    return '\n'.join((policy, emitted_keys(), split_key_table(FIELDS, KEYS[len(FIELDS):]),
                      WIRE_HELPERS.split('\ndef signed_id',1)[0].replace('NONE', str(names['NONE'])),
                      *(function(CONTEXT, name).replace('NONE', str(names['NONE']))
                        for name in ('equal_span', 'digest_text')),
                      *(function(authority, name) for name in
                        ('artifact_reference', 'artifact_start', 'artifact_digest', 'artifact_uri', 'valid_hex')),
                      json_decoder(wire_spans=True)))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
