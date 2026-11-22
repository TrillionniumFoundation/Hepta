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
MEASUREMENTS = ('binary_inventory', 'exports', 'function_frames', 'machine_text_bytes',
                'machine_text_sha256', 'toolchain')
BORROWED_CLAIMS = ('self_hosted', 'foreign_buffer_entrypoints_exposed', 'backend_refinement_proved',
                   'native_execution_qualified', 'external_linker_used')
KEYS = (*BINDINGS, 'schema', 'status', 'ok', 'claims', 'direct_machine_code', 'fallback_used',
        'standalone_core_reverified', *MEASUREMENTS, *BORROWED_CLAIMS)

POLICY = r'''
# A sealed canonical array [independent physical facts, native build report].
# For a borrowed entry, append the independently observed ABI, frames, text
# length/hash and linker identity in measurement order to this envelope.
# The report does not supply any of the expected digests, length or ABI facts.
# A supplied proof stays part of the report for its separate proof consumer.
def emit_build_observation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 5 or length(s) > 8388608 or length(o) < 64 or length(w) < 65536:
        return INVALID
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    fields = get(w, 96)
    if fields != 2 and fields != 3:
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
    foreign = lookup(w, facts, K_foreign_buffer_exports)
    if get(w, foreign) != 5:
        return INVALID
    if get(w, foreign + 32) == 0:
        if fields != 2:
            return INVALID
    else:
        if fields != 3 or borrowed_claims(w, lookup(w, report, K_claims)) == False:
            return response(o, BINDING_COUNT + 1)
        return observed_measurements(s, o, w, report)
    return response(o, 0)

def observed_measurements(s:readbuf, o:mutbuf, w:mutbuf, report:u64) -> u64:
    envelope = 64 + get(w, report + 16) * 72
    if get(w, envelope) != 5 or get(w, envelope + 32) != MEASUREMENT_COUNT:
        return INVALID
    physical = 64 + get(w, envelope + 24) * 72
    field = FIRST_MEASUREMENT
    while field < FIRST_MEASUREMENT + MEASUREMENT_COUNT:
        observed = lookup(w, report, field)
        if observed == NONE:
            return INVALID
        if value_matches(s, w, physical, observed) == False:
            return response(o, field - FIRST_MEASUREMENT + BINDING_COUNT + 2)
        physical = 64 + get(w, physical + 16) * 72
        field = field + 1
    return response(o, 0)

def borrowed_claims(w:mutbuf, claims:u64) -> bool:
    return boolean_value(w, lookup(w, claims, K_self_hosted), True) and boolean_value(w, lookup(w, claims, K_foreign_buffer_entrypoints_exposed), True) and boolean_value(w, lookup(w, claims, K_backend_refinement_proved), False) and boolean_value(w, lookup(w, claims, K_native_execution_qualified), False) and boolean_value(w, lookup(w, claims, K_external_linker_used), False)

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
    if kind < 3:
        return True
    if kind == 3 or kind == 7:
        width = get(w, left + 32)
        if width != get(w, right + 32):
            return False
        return same_input_bytes(s, get(w, left + 24), get(w, right + 24), width)
    return equal_span(s, w, left, right)

def same_input_bytes(s:readbuf, a:u64, b:u64, count:u64) -> bool:
    index = 0
    while index < count:
        if byte(s, a + index) != byte(s, b + index):
            return False
        index = index + 1
    return True

def response(o:mutbuf, code:u64) -> u64:
    put(o, 0, RESULT)
    put(o, 8, code)
    return 16
'''


def program():
    words = {f'K_{name}': ordinal for ordinal, name in enumerate(KEYS, 1)}
    words.update(BINDING_COUNT=len(BINDINGS), RESULT=int.from_bytes(b'HIABOR01', 'little'),
                 INVALID=4294967293, NONE=(1 << 64) - 1, MEASUREMENT_COUNT=len(MEASUREMENTS),
                 FIRST_MEASUREMENT=KEYS.index(MEASUREMENTS[0]) + 1)
    policy=re.sub(r'\b('+'|'.join(words)+r')\b', lambda m: str(words[m[0]]), POLICY)
    return '\n'.join((
        policy, function(CONTEXT, 'equal_span'),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(words['NONE'])),
        comparison_table('key_id', KEYS), literal_match('report_schema', 'hepta.hia.program.direct-native.v1'),
        literal_match('result_status', 'native_emitted_not_executed'), json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
