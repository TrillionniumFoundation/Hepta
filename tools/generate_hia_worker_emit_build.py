"""Author the evidence comparison at the native Worker Emit boundary."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match

SOURCE = Path('examples/hia_bootstrap/worker_emit_build_observation.hepta')
BINDINGS = ('core_sha256', 'input_sha256', 'object_sha256', 'artifact_sha256', 'artifact_bytes',
            'kind', 'foreign_buffer_exports', 'machine_plan_sha256', 'implementation_sha256')
KEYS = (*BINDINGS, 'schema', 'status', 'ok', 'claims', 'direct_machine_code', 'fallback_used',
        'standalone_core_reverified')

POLICY = r'''
# A sealed canonical array [independent physical facts, native build report].
# The report does not supply any of the expected digests, length or ABI facts.
# A supplied proof stays part of the report for its separate proof consumer.
def emit_build_observation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 5 or length(s) > 8388608 or length(o) < 64 or length(w) < 65536:
        return INVALID
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 2:
        return INVALID
    facts = 64 + get(w, 88) * 72
    report = 64 + get(w, facts + 16) * 72
    if get(w, facts) != 6 or get(w, report) != 6 or get(w, facts + 32) != BINDING_COUNT:
        return INVALID
    field = 1
    while field <= BINDING_COUNT:
        observed = lookup(w, report, field)
        expected = lookup(w, facts, field)
        if observed == NONE or expected == NONE:
            return INVALID
        if value_matches(s, w, expected, observed) == False:
            return response(o, field)
        field = field + 1
    if successful_build(w, report) == False:
        return response(o, BINDING_COUNT + 1)
    return response(o, 0)

def successful_build(w:mutbuf, report:u64) -> bool:
    if report_schema(w, lookup(w, report, K_schema)) == False:
        return False
    if result_status(w, lookup(w, report, K_status)) == False:
        return False
    if boolean_value(w, lookup(w, report, K_ok), True) == False:
        return False
    claims = lookup(w, report, K_claims)
    if claims == NONE or get(w, claims) != 6:
        return False
    return boolean_value(w, lookup(w, claims, K_direct_machine_code), True) and boolean_value(w, lookup(w, claims, K_fallback_used), False) and boolean_value(w, lookup(w, claims, K_standalone_core_reverified), True)

def boolean_value(w:mutbuf, node:u64, expected:bool) -> bool:
    if node == NONE:
        return False
    return get(w, node) == choose(expected, 2, 1)

def value_matches(s:readbuf, w:mutbuf, left:u64, right:u64) -> bool:
    kind = get(w, left)
    if kind != get(w, right):
        return False
    if kind == 0:
        return True
    return equal_span(s, w, left, right)

def response(o:mutbuf, code:u64) -> u64:
    put(o, 0, RESULT)
    put(o, 8, code)
    return 16
'''


def program():
    words = {f'K_{name}': ordinal for ordinal, name in enumerate(KEYS, 1)}
    words.update(BINDING_COUNT=len(BINDINGS), RESULT=int.from_bytes(b'HIABOR01', 'little'),
                 INVALID=4294967293, NONE=(1 << 64) - 1)
    policy=re.sub(r'\b('+'|'.join(words)+r')\b', lambda m: str(words[m[0]]), POLICY)
    return '\n'.join((
        policy, function(CONTEXT, 'equal_span'),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(words['NONE'])),
        comparison_table('key_id', KEYS), literal_match('report_schema', 'hepta.hia.program.direct-native.v1'),
        literal_match('result_status', 'native_emitted_not_executed'), json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
