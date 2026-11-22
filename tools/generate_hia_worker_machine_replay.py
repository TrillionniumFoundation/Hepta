"""Bind a retained machine claim to independent HIA proof of its physical ELF."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import SAT, UNSAT
from hepta.hia_proof_contract import SAFE_CORE_METHOD, SAFE_CORE_SERVICE_PROFILE
from hepta.hia_safe_core import ARTIFACT_OBLIGATIONS, ARTIFACT_PROFILE, SCHEMA
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_safe_core_obligation import RESPONSE_MAGIC as OBLIGATION_REPLY
from tools.generate_hia_supplied_safe_core_proof import (
    FILE_LIMIT, OUTPUT_LIMIT, RECEIPT_HEAD, RECEIPT_MAGIC, REQUEST_MAGIC,
)
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_build_custody import POLICY as CUSTODY
from tools.generate_hia_worker_finite_reference import INVALID, NONE, enum_reader, key_reader
from tools.generate_hia_worker_inspection_effect import function
from tools.hia_retained_proof_method import MACHINE_VERDICT

SOURCE = Path('examples/hia_bootstrap/worker_machine_replay.hepta')
MACHINE_ANCHOR = int.from_bytes(b'HIAMAP01', 'little')
PHASES = ('HIAMRQ01', 'HIAMRV01')
FIELDS = (
    'method', 'profile', 'service_profile', 'outcome', 'deadline_met', 'counterexample', 'artifact_binding',
    'validation', 'candidate_core_sha256', 'input_sha256', 'native_artifact', 'build_receipt', 'object_artifact',
    'object_sha256', 'final_image_sha256', 'output_kind', 'entry_symbols', 'foreign_buffer_exports', 'schema',
    'validation_mode', 'subject', 'function', 'core_sha256', 'entry_symbol', 'image_binding',
    'linked_text_sha256', 'linked_text_file_offset', 'backend_implementation_sha256',
    'source_identity', 'solver', 'ok', 'complete', 'status', 'obligations', 'queries',
    'name', 'expected', 'result', 'query_file', 'query_sha256', 'sha256', 'artifact',
)
ANCHOR_HEAD = 416
ANCHOR_BYTES = ANCHOR_HEAD + len(ARTIFACT_OBLIGATIONS) * 176

POLICY = r'''
def machine_replay(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < ANCHOR_BYTES:
        return BAD
    tag = input_word(s, 0)
    if tag == REQUEST:
        return request_header(s, o)
    if tag == FINISH:
        return proved_machine(s, o)
    return retained_evidence(s, o, w)

# Physical Store descriptors are attached by the relay, not by the receipt.
def request_header(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 40:
        return BAD
    budget = input_word(s, 8)
    core = input_word(s, 16)
    obj = input_word(s, 24)
    final = input_word(s, 32)
    if budget < 100 or budget > 60000 or core == 0 or core > FILE_MAX:
        return BAD
    if obj < 64 or obj > FILE_MAX or final < 64 or final > FILE_MAX:
        return BAD
    put(o, 0, PROVER_REQUEST)
    put(o, 8, 0)
    put(o, 16, budget)
    put(o, 24, core)
    put(o, 32, obj)
    put(o, 40, final)
    return 48

# The three reference arguments came from the authorized retained subject and
# native-build custody, not from the evidence being checked.
def retained_evidence(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) > FILE_MAX or length(w) < 65536:
        return BAD
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 4:
        return BAD
    evidence = child(w, 64)
    if kind(w, evidence) != 6 or proof_method(w, lookup(w, evidence, K_method)) == NONE:
        return BAD
    if artifact_profile(w, lookup(w, evidence, K_profile)) == NONE or service_profile(w, lookup(w, evidence, K_service_profile)) == NONE:
        return BAD
    if proved_label(w, lookup(w, evidence, K_outcome)) == NONE or true_field(w, evidence, K_deadline_met) == False:
        return BAD
    if lookup(w, evidence, K_counterexample) != NONE:
        return BAD
    native = next(w, evidence)
    build = next(w, native)
    obj = next(w, build)
    binding = lookup(w, evidence, K_artifact_binding)
    if kind(w, binding) != 6 or shared_kind(w, lookup(w, binding, K_output_kind)) == NONE:
        return BAD
    if field_is(s, w, binding, K_native_artifact, native) == False or field_is(s, w, binding, K_build_receipt, build) == False or field_is(s, w, binding, K_object_artifact, obj) == False:
        return BAD
    entry = lookup(w, binding, K_entry_symbols)
    if empty_array(w, lookup(w, binding, K_foreign_buffer_exports)) == False or kind(w, entry) != 5 or get(w, entry + 32) != 1:
        return BAD
    symbol = child(w, entry)
    if kind(w, symbol) != 4:
        return BAD
    size = get(w, symbol + 32)
    if size == 0 or size > 256:
        return BAD
    checked = lookup(w, evidence, K_validation)
    image = lookup(w, checked, K_image_binding)
    if bind_validation(s, w, evidence, binding, checked, symbol) == False:
        return BAD
    if field_is(s, w, binding, K_object_sha256, lookup(w, obj, K_sha256)) == False or field_is(s, w, binding, K_final_image_sha256, lookup(w, native, K_sha256)) == False:
        return BAD
    if fix_digests(s, o, w, binding, image) == False:
        return BAD
    offset = decimal(s, w, lookup(w, image, K_linked_text_file_offset))
    if offset > FILE_MAX or retained_queries(s, o, w, evidence, checked) == False:
        return BAD
    put(o, 0, ANCHOR)
    put(o, 8, 0)
    put(o, 16, offset)
    put(o, 24, size)
    cursor = get(w, symbol + 24)
    index = 0
    while index < 256:
        value = 0
        if index < size:
            value = byte(w, cursor + index)
        store(o, 160 + index, value)
        index = index + 1
    return ANCHOR_BYTES

def bind_validation(s:readbuf, w:mutbuf, evidence:u64, binding:u64, checked:u64, entry:u64) -> bool:
    if kind(w, checked) != 6 or validation_schema(w, lookup(w, checked, K_schema)) == NONE:
        return False
    if artifact_profile(w, lookup(w, checked, K_profile)) == NONE or supplied_mode(w, lookup(w, checked, K_validation_mode)) == NONE:
        return False
    if checked_label(w, lookup(w, checked, K_status)) == NONE:
        return False
    if true_field(w, checked, K_ok) == False or true_field(w, checked, K_complete) == False:
        return False
    if empty_array(w, lookup(w, checked, K_foreign_buffer_exports)) == False or kind(w, lookup(w, checked, K_backend_implementation_sha256)) != 0:
        return False
    if field_is(s, w, checked, K_function, entry) == False or field_is(s, w, checked, K_source_identity, lookup(w, evidence, K_source_identity)) == False or field_is(s, w, checked, K_solver, lookup(w, evidence, K_solver)) == False:
        return False
    core = lookup(w, binding, K_candidate_core_sha256)
    source = lookup(w, binding, K_input_sha256)
    obj = lookup(w, binding, K_object_sha256)
    final = lookup(w, binding, K_final_image_sha256)
    subject = lookup(w, checked, K_subject)
    image = lookup(w, checked, K_image_binding)
    if field_is(s, w, checked, K_core_sha256, core) == False or field_is(s, w, checked, K_input_sha256, source) == False:
        return False
    if field_is(s, w, subject, K_entry_symbol, entry) == False or field_is(s, w, image, K_entry_symbol, entry) == False:
        return False
    if field_is(s, w, subject, K_object_sha256, obj) == False or field_is(s, w, image, K_object_sha256, obj) == False:
        return False
    if field_is(s, w, subject, K_final_image_sha256, final) == False or field_is(s, w, image, K_final_image_sha256, final) == False:
        return False
    return field_is(s, w, subject, K_core_sha256, core) and field_is(s, w, subject, K_input_sha256, source) and empty_array(w, lookup(w, subject, K_foreign_buffer_exports))

def fix_digests(s:readbuf, o:mutbuf, w:mutbuf, binding:u64, image:u64) -> bool:
    core = lookup(w, binding, K_candidate_core_sha256)
    if field_is(s, w, binding, K_input_sha256, core) == False:
        return False
    return write_digest(o, w, core, 32) and write_digest(o, w, lookup(w, binding, K_object_sha256), 64) and write_digest(o, w, lookup(w, binding, K_final_image_sha256), 96) and write_digest(o, w, lookup(w, image, K_linked_text_sha256), 128)

def write_digest(o:mutbuf, w:mutbuf, node:u64, dest:u64) -> bool:
    if kind(w, node) != 4 or get(w, node + 32) != 64:
        return False
    src = get(w, node + 24)
    index = 0
    while index < 32:
        hi = hex_digit(byte(w, src + index * 2))
        lo = hex_digit(byte(w, src + index * 2 + 1))
        if hi > 15 or lo > 15:
            return False
        store(o, dest + index, (hi << 4) | lo)
        index = index + 1
    return True

def hex_digit(c:u64) -> u64:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    return 16

def retained_queries(s:readbuf, o:mutbuf, w:mutbuf, evidence:u64, checked:u64) -> bool:
    queries = lookup(w, evidence, K_queries)
    obligations = lookup(w, checked, K_obligations)
    if kind(w, queries) != 5 or get(w, queries + 32) != 5 or kind(w, obligations) != 5 or get(w, obligations + 32) != 5:
        return False
    query = child(w, queries)
    row = child(w, obligations)
    index = 0
    while index < 5:
        if query_matches(s, o, w, index, query, row) == False:
            return False
        query = next(w, query)
        row = next(w, row)
        index = index + 1
    return True

def query_matches(s:readbuf, o:mutbuf, w:mutbuf, index:u64, query:u64, row:u64) -> bool:
    name = lookup(w, query, K_name)
    if obligation_label(w, lookup(w, row, K_name)) != index or obligation_file(w, name) != index:
        return False
    expected = result_label(w, lookup(w, row, K_expected))
    if expected != choose(index == 0, SAT, UNSAT) or result_label(w, lookup(w, row, K_result)) != expected:
        return False
    if field_is(s, w, row, K_query_file, name) == False:
        return False
    digest = lookup(w, query, K_sha256)
    artifact = lookup(w, query, K_artifact)
    if kind(w, artifact) != 6 or get(w, artifact + 64) != 176 or write_digest(o, w, digest, 160) == False:
        return False
    if field_is(s, w, row, K_query_sha256, digest) == False or field_is(s, w, artifact, K_sha256, digest) == False:
        return False
    copy_reference(s, o, get(w, artifact + 56), ANCHOR_HEAD + index * 176)
    return True

def field_is(s:readbuf, w:mutbuf, parent:u64, field:u64, expected:u64) -> bool:
    value = lookup(w, parent, field)
    if value == NONE or expected == NONE:
        return False
    size = get(w, value + 64)
    if size != get(w, expected + 64):
        return False
    return same_bytes(s, get(w, value + 56), get(w, expected + 56), size)

def true_field(w:mutbuf, row:u64, key:u64) -> bool:
    return kind(w, lookup(w, row, key)) == 2

def empty_array(w:mutbuf, node:u64) -> bool:
    return kind(w, node) == 5 and get(w, node + 32) == 0

def decimal(s:readbuf, w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 3 or get(w, node + 32) > 8:
        return NONE
    first = get(w, node + 24)
    end = first + get(w, node + 32)
    value = 0
    while first < end:
        digit = byte(s, first) - 48
        if digit > 9:
            return NONE
        value = value * 10 + digit
        first = first + 1
    return value

def proved_machine(s:readbuf, o:mutbuf) -> u64:
    at = 16 + ANCHOR_HEAD
    if length(s) < at + PROVER_HEAD or input_word(s, 16) != ANCHOR or input_word(s, 24) != 0:
        return BAD
    if input_word(s, 8) != length(s) - at or length(s) - at > PROVER_MAX:
        return BAD
    if input_word(s, at) != PROVER_REPLY or input_word(s, at + 8) != 1 or input_word(s, at + 40) != 5:
        return BAD
    profile = input_word(s, at + 16)
    if profile == 0 or profile > 6 or input_word(s, at + 24) > 6 or input_word(s, at + 32) == 0 or input_word(s, at + 32) > 1024:
        return BAD
    if input_word(s, at + 48) != input_word(s, 32) or input_word(s, at + 56) == 0 or input_word(s, at + 72) != 0:
        return BAD
    size = input_word(s, 40)
    if size == 0 or size > 256 or input_word(s, at + 64) != size:
        return BAD
    if same_bytes(s, 48, at + 80, 128) == False or same_bytes(s, 176, at + 208, 256) == False:
        return BAD
    cursor = at + PROVER_HEAD
    index = 0
    while index < 5:
        if length(s) - cursor < 88:
            return BAD
        n = input_word(s, cursor)
        if n < 120 or n > length(s) - cursor - 8:
            return BAD
        if input_word(s, cursor + 8) != OBLIGATION or input_word(s, cursor + 16) != index:
            return BAD
        if input_word(s, cursor + 24) != choose(index == 0, SAT, UNSAT):
            return BAD
        cursor = cursor + 8 + n
        index = index + 1
    if cursor != length(s):
        return BAD
    put(o, 0, COMPLETE)
    put(o, 8, 0)
    put(o, 16, 1)
    return 24

def same_bytes(s:readbuf, a:u64, b:u64, size:u64) -> bool:
    index = 0
    while index < size:
        if byte(s, a + index) != byte(s, b + index):
            return False
        index = index + 1
    return True
'''


def program():
    constants = dict(
        BAD=INVALID, NONE=NONE, REQUEST=int.from_bytes(PHASES[0].encode(), 'little'),
        FINISH=int.from_bytes(PHASES[1].encode(), 'little'), PROVER_REQUEST=REQUEST_MAGIC,
        ANCHOR=MACHINE_ANCHOR, ANCHOR_BYTES=ANCHOR_BYTES, ANCHOR_HEAD=ANCHOR_HEAD,
        PROVER_REPLY=RECEIPT_MAGIC, PROVER_HEAD=RECEIPT_HEAD, PROVER_MAX=OUTPUT_LIMIT,
        OBLIGATION=OBLIGATION_REPLY, COMPLETE=MACHINE_VERDICT, FILE_MAX=FILE_LIMIT, SAT=SAT, UNSAT=UNSAT,
    )
    constants.update({f'K_{name}': index for index, name in enumerate(FIELDS, 1)})
    policies = (POLICY, function(CUSTODY, 'copy_reference'))
    source = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda found: str(constants[found[0]]), '\n'.join(policies))
    names = [name for name, _ in ARTIFACT_OBLIGATIONS]
    enums = (
        ('proof_method', ((SAFE_CORE_METHOD, 1),)), ('artifact_profile', ((ARTIFACT_PROFILE, 1),)),
        ('service_profile', ((SAFE_CORE_SERVICE_PROFILE, 1),)), ('proved_label', (('proved', 1),)),
        ('validation_schema', ((SCHEMA, 1),)), ('checked_label', (('smt_validated', 1),)),
        ('supplied_mode', (('independent_supplied_bytes', 1),)), ('shared_kind', (('shared', 1),)),
        ('result_label', (('sat', SAT), ('unsat', UNSAT))), ('obligation_label', ((name, n) for n, name in enumerate(names))),
        ('obligation_file', ((f'{n:02d}-{name}.smt2', n) for n, name in enumerate(names))),
    )
    enums = [enum_reader(role, members) for role, members in enums]
    helpers = r'''
def kind(w:mutbuf, node:u64) -> u64:
    if node == NONE:
        return NONE
    return get(w, node)

def child(w:mutbuf, node:u64) -> u64:
    return 64 + get(w, node + 24) * 72

def next(w:mutbuf, node:u64) -> u64:
    index = get(w, node + 16)
    if index == NONE:
        return NONE
    return 64 + index * 72
'''.replace('NONE', str(NONE))
    return '\n'.join((source, helpers, key_reader(FIELDS), *enums,
                      WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(NONE)).replace(
                          '    children =', f'    if kind(w, parent) != 6:\n        return {NONE}\n    children =', 1),
                      function(authority(), 'input_word'), json_decoder(wire_spans=True)))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
