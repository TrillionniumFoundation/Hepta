"""Author the native Adoption gate for sealed evaluation and objective records."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import (
    ADOPTION_RECORD, ADOPTION_RESULT, receipt_template, source_program as identity_source,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as artifact_authority
from tools.generate_hia_worker_build_custody import POLICY as BUILD_CUSTODY
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_emit_verification import POLICY as VERIFICATION, key_table, literal_match
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_rollback import POLICY as ROLLBACK, RELEASE, SLOT_POLICY
from tools.generate_hia_store_transport import POLICY as STORE_TRANSPORT

SOURCE = Path('examples/hia_bootstrap/worker_adopt_authority.hepta')
FIELDS = (
    'schema', 'installation', 'context', 'candidate_artifact', 'baseline_artifact',
    'baseline_core_sha256', 'build_receipt', 'measurements', 'full_cost_ledger',
    'report_complete', 'planned_workload_complete', 'termination_confirmed',
    'outcome', 'allow_unchanged', 'require_net_benefit',
    'catalog_sha256', 'request_key', 'target_slot', 'expected_current', 'generation', 'epoch',
    'evaluation_receipt', 'verification_receipts', 'subject', 'kind', 'native_artifact',
)

POLICY = r'''
# A verified Store read must precede this gate. Its output references the
# sealed input; a successful comparison does not authorize a slot update.
def adopt_authority(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 4 or length(s) > 8388608 or length(o) < 4096 or length(w) < 65536:
        return INVALID
    if length(s) >= 8:
        tag = input_word(s, 0)
        if tag == SLOT_PLAN:
            return adopt_sequence(s, o)
        if tag == SLOT_EXPECTED:
            return expected_current(s, o)
        if tag == SLOT_WRITE:
            return adopt_store_frame(s, o)
        if tag == SLOT_RECEIPT:
            return render_adoption(s, o)
        if tag == ADOPT_INDEX_REQUEST:
            return adopt_request_index(s, o)
    put(o, 48, 65536)
    put(o, 56, 48)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    first = 64 + get(w, 88) * 72
    count = get(w, 96)
    if count == 4:
        return bind_evaluation(s, o, w, first)
    if count == 3:
        if is_object(w, first):
            return project_proof_build(s, o, w, first)
        return project_journal_catalog(s, o, w, first)
    if count == 2:
        if get(w, first) == 4:
            return request_projection(s, o, w, first, next(w, first))
        return admit_evaluation(o, w, first, next(w, first))
    if count == 1:
        return admit_benefit(o, w, first)
    return INVALID

def project_journal_catalog(s:readbuf, o:mutbuf, w:mutbuf, pinned:u64) -> u64:
    args = next(w, pinned)
    if digest_text(w, pinned, False) == False or is_object(w, args) == False or get(w, next(w, args)) != 0:
        return INVALID
    catalog = lookup(w, args, K_catalog_sha256)
    if digest_text(w, catalog, True) == False:
        return INVALID
    at = copy_value(s, w, o, catalog, 24)
    end = copy_value(s, w, o, pinned, at)
    put(o, 0, at - 24)
    put(o, 8, end - at)
    put(o, 16, 0)
    return end

def project_proof_build(s:readbuf, o:mutbuf, w:mutbuf, receipt:u64) -> u64:
    candidate = next(w, receipt)
    if exact_reference(s, w, candidate) == False or get(w, next(w, candidate)) != 0:
        return INVALID
    subject = lookup(w, receipt, K_subject)
    if (is_object(w, subject) == False or native_subject(w, lookup(w, subject, K_kind)) == False
            or matches_field(s, w, subject, K_native_artifact, candidate) == False):
        return INVALID
    build = lookup(w, subject, K_build_receipt)
    if exact_reference(s, w, build) == False:
        return INVALID
    put(o, 0, ADOPT_PROOF_BUILD)
    return copy_value(s, w, o, build, 8)

def request_projection(s:readbuf, o:mutbuf, w:mutbuf, pinned:u64, args:u64) -> u64:
    if is_object(w, args) == False or get(w, args + 32) != 8:
        return INVALID
    catalog = lookup(w, args, K_catalog_sha256)
    if digest_text(w, pinned, False) == False or digest_text(w, catalog, True) == False:
        return INVALID
    if equal_span(s, w, pinned, catalog) == False:
        return CATALOG_MISMATCH
    context = lookup(w, args, K_context)
    candidate = lookup(w, args, K_candidate_artifact)
    evaluation = lookup(w, args, K_evaluation_receipt)
    receipts = lookup(w, args, K_verification_receipts)
    current = lookup(w, args, K_expected_current)
    key = lookup(w, args, K_request_key)
    slot = lookup(w, args, K_target_slot)
    if is_object(w, context) == False or is_object(w, candidate) == False or is_object(w, evaluation) == False:
        return INVALID
    if is_object(w, current) == False or get(w, current + 32) != 2:
        return INVALID
    generation = lookup(w, current, K_generation)
    epoch = lookup(w, current, K_epoch)
    if allowed_text(w, key, 192) == False or allowed_text(w, slot, 192) == False:
        return INVALID
    if allowed_text(w, generation, 20) == False or allowed_text(w, epoch, 20) == False:
        return INVALID
    if receipts == NONE or get(w, receipts) != 5:
        return INVALID
    count = get(w, receipts + 32)
    if count == 0 or count > 16 or length(o) < length(s) * 2 + 256:
        return INVALID
    put(o, 0, ADOPT_REQUEST)
    put(o, 8, count)
    at = fragment(s, w, o, context, 16)
    at = fragment(s, w, o, candidate, at)
    at = fragment(s, w, o, evaluation, at)
    at = fragment(s, w, o, slot, at)
    at = fragment(s, w, o, generation, at)
    at = fragment(s, w, o, epoch, at)
    at = fragment(s, w, o, key, at)
    at = fragment(s, w, o, receipts, at)
    entry = 64 + get(w, receipts + 24) * 72
    index = 0
    while index < count:
        if is_object(w, entry) == False:
            return INVALID
        at = fragment(s, w, o, entry, at)
        entry = next(w, entry)
        index = index + 1
    return at

# The projection, not the public request, supplies the descriptor ranges.
# Return offsets into the sealed projection without moving fragment bytes.
def adopt_request_index(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 24 or input_word(s, 8) != ADOPT_REQUEST:
        return INVALID
    receipts = input_word(s, 16)
    if receipts < 1 or receipts > 16:
        return INVALID
    count = 8 + receipts
    at = 24
    index = 0
    while index < count:
        if at > length(s) or length(s) - at < 10:
            return INVALID
        width = input_word(s, at)
        value = at + 8
        if width < 2 or width > length(s) - value:
            return INVALID
        put(o, 24 + 16 * index, value - 8)
        put(o, 32 + 16 * index, width)
        at = value + width
        index = index + 1
    if at != length(s):
        return INVALID
    put(o, 0, ADOPT_INDEX_RESULT)
    put(o, 8, receipts)
    put(o, 16, count)
    return 24 + 16 * count

def bind_evaluation(s:readbuf, o:mutbuf, w:mutbuf, installed:u64) -> u64:
    context = next(w, installed)
    candidate = next(w, context)
    evaluation = next(w, candidate)
    if is_object(w, installed) == False or is_object(w, context) == False or exact_reference(s, w, candidate) == False:
        return INVALID
    if is_object(w, evaluation) == False or evaluation_schema(w, lookup(w, evaluation, K_schema)) == False:
        return INVALID
    if matches_field(s, w, evaluation, K_context, context) == False or matches_field(s, w, evaluation, K_candidate_artifact, candidate) == False or matches_field(s, w, evaluation, K_installation, installed) == False:
        return refusal(o, 1)
    baseline_core = lookup(w, evaluation, K_baseline_core_sha256)
    if digest_text(w, baseline_core, False) == False:
        return INVALID
    put(o, 0, RESULT)
    put(o, 8, 0)
    at = span(w, o, baseline_core, 16)
    at = reference_span(s, o, w, evaluation, K_build_receipt, at)
    at = reference_span(s, o, w, evaluation, K_measurements, at)
    at = reference_span(s, o, w, evaluation, K_full_cost_ledger, at)
    return reference_span(s, o, w, evaluation, K_baseline_artifact, at)

def reference_span(s:readbuf, o:mutbuf, w:mutbuf, record:u64, key:u64, at:u64) -> u64:
    if at == INVALID:
        return INVALID
    node = lookup(w, record, key)
    if exact_reference(s, w, node) == False:
        return INVALID
    return span(w, o, node, at)

def admitted_flag(w:mutbuf, record:u64, key:u64) -> bool:
    node = lookup(w, record, key)
    return node != NONE and get(w, node) == TRUE_NODE

def admit_evaluation(o:mutbuf, w:mutbuf, evaluation:u64, objective:u64) -> u64:
    if is_object(w, evaluation) == False or is_object(w, objective) == False:
        return INVALID
    if admitted_flag(w, evaluation, K_report_complete) == False or admitted_flag(w, evaluation, K_planned_workload_complete) == False or admitted_flag(w, evaluation, K_termination_confirmed) == False:
        return refusal(o, 2)
    allow = lookup(w, objective, K_allow_unchanged)
    if allow == NONE or (get(w, allow) != FALSE_NODE and get(w, allow) != TRUE_NODE):
        return INVALID
    outcome = lookup(w, evaluation, K_outcome)
    accepted = outcome_improved(w, outcome) or (get(w, allow) == TRUE_NODE and outcome_unchanged(w, outcome))
    return refusal(o, choose(accepted, 0, 2))

def admit_benefit(o:mutbuf, w:mutbuf, objective:u64) -> u64:
    if is_object(w, objective) == False:
        return INVALID
    node = lookup(w, objective, K_require_net_benefit)
    if node == NONE or get(w, node) == FALSE_NODE:
        return refusal(o, 0)
    if get(w, node) != TRUE_NODE:
        return INVALID
    return refusal(o, 3)

# Schema admission bounds the decimal tokens but does not prove u64 range.
# Like the reference operation, check generation before checking epoch.
def expected_current(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 26 or length(s) > 64:
        return INVALID
    generation = input_word(s, 8)
    epoch = input_word(s, 16)
    if generation == 0 or generation > 20 or epoch == 0 or epoch > 20 or length(s) != 24 + generation + epoch:
        return INVALID
    if canonical_timestamp(s, 24, generation) == False:
        return refusal(o, 8)
    if canonical_timestamp(s, 24 + generation, epoch) == False:
        return refusal(o, 9)
    put(o, 0, SLOT_EXPECTED_VALUES)
    put(o, 8, number(s, 24, generation))
    put(o, 16, number(s, 24 + generation, epoch))
    return 24

# This scope is after the context, proof, workload and exact ABI comparisons.
# These Store facts must belong to the same exclusive transaction as the write.
def adopt_sequence(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 64 and length(s) != 320:
        return INVALID
    present = input_word(s, 8)
    current = input_word(s, 32)
    epoch = input_word(s, 40)
    maximum = input_word(s, 48)
    count = input_word(s, 56)
    if present == 0:
        if length(s) != 64 or (current | epoch | maximum | count) != 0:
            return INVALID
    elif present != 1 or length(s) != 320 or count == 0 or maximum < current:
        return INVALID
    if current != input_word(s, 16) or epoch != input_word(s, 24):
        return refusal(o, 4)
    if present == 1:
        if valid_hex(s, 64, 256) == False:
            return INVALID
        if bytes_equal(s, 64, 128, 64) == False:
            return refusal(o, 5)
        if bytes_equal(s, 192, 256, 64) == False:
            return refusal(o, 6)
    if maximum == 18446744073709551615 or epoch == 18446744073709551615:
        return refusal(o, 7)
    put(o, 0, SLOT_ADVANCE)
    put(o, 8, maximum + 1)
    put(o, 16, epoch + 1)
    return 24

def adopt_store_frame(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 33:
        return INVALID
    operation = input_word(s, 8)
    width = input_word(s, 16)
    generation = input_word(s, 24)
    if width == 0 or width > 192 or width > length(s) - 32:
        return INVALID
    if slot_name(s, 32, width) == False:
        return INVALID
    payload = 32 + width
    if operation == 7:
        if generation != 0 or length(s) != payload + 100:
            return INVALID
        if context_id(s, payload) == False or valid_hex(s, payload + 36, 64) == False:
            return INVALID
        return create_slot(s, o, width, payload)
    if operation != 8 or length(s) != payload + 176 or artifact_reference(s, payload) == False:
        return INVALID
    return record_slot_version(s, o, width, payload, generation)

def insert_header(o:mutbuf, ordinal:u64, fields:u64) -> u64:
    put(o, 0, INSERT_TAG)
    put(o, 8, 1)
    put(o, 16, ordinal)
    put(o, 24, 0)
    return put(o, 32, fields)

def create_slot(s:readbuf, o:mutbuf, width:u64, payload:u64) -> u64:
    insert_header(o, 7, 5)
    context = copy_input(s, o, 32, 160, width)
    generation = copy_input(s, o, payload, context, 36)
    store(o, generation, 48)
    store(o, generation + 1, 48)
    slot_cell(o, 40, 160, width)
    slot_cell(o, 64, context, 36)
    slot_cell(o, 88, generation, 1)
    slot_cell(o, 112, generation + 1, 1)
    slot_cell(o, 136, generation + 2, 64)
    return copy_input(s, o, payload + 36, generation + 2, 64)

def record_slot_version(s:readbuf, o:mutbuf, width:u64, payload:u64, generation:u64) -> u64:
    insert_header(o, 8, 3)
    value = copy_input(s, o, 32, 112, width)
    artifact = decimal(o, value, generation)
    slot_cell(o, 40, 112, width)
    slot_cell(o, 64, value, artifact - value)
    slot_cell(o, 88, artifact, 176)
    return copy_input(s, o, payload, artifact, 176)

def render_adoption(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 16:
        return INVALID
    kind = input_word(s, 8)
    if kind == 1:
        size = adoption_record(s, o, 0)
        if size <= length(o):
            return adoption_record(s, o, 1)
        return size
    if kind == 2:
        size = adoption_result(s, o, 0)
        if size <= length(o):
            return adoption_result(s, o, 1)
        return size
    return INVALID
'''


def source_program():
    constants = {f'K_{name}': index for index, name in enumerate(FIELDS, 1)}
    constants.update(RESULT=int.from_bytes(b'HIAADR01', 'little'), NONE=(1 << 64) - 1,
                     INVALID=4294967293, CATALOG_MISMATCH=4294967286, FALSE_NODE=1, TRUE_NODE=2)
    constants.update({name: int.from_bytes(tag, 'little') for name, tag in {
        'SLOT_PLAN': b'HIAADS01', 'SLOT_ADVANCE': b'HIAADA01',
        'SLOT_EXPECTED': b'HIAADU01', 'SLOT_EXPECTED_VALUES': b'HIAADU02',
        'SLOT_WRITE': b'HIAADW01', 'INSERT_TAG': b'HIAINS01',
        'SLOT_RECEIPT': b'HIAADP01', 'ADOPT_REQUEST': b'HIAADQ01',
        'ADOPT_INDEX_REQUEST': b'HIAADI01', 'ADOPT_INDEX_RESULT': b'HIAADI02',
        'ADOPT_PROOF_BUILD': b'HIAADBR1',
    }.items()})
    source = '\n'.join((
        POLICY,
        *(function(VERIFICATION, name) for name in ('next', 'is_object', 'matches_field', 'span', 'refusal')),
        literal_match('native_subject', 'native_artifact'),
        *(function(CONTEXT, name) for name in ('equal_span', 'digest_text', 'copy_value', 'fragment')),
        function(ROLLBACK, 'allowed_text'),
        function(ROLLBACK, 'number'),
        function(BUILD_CUSTODY, 'exact_reference'),
        function(STORE_TRANSPORT, 'slot_name'),
        function(STORE_TRANSPORT, 'context_id'),
        function(STORE_TRANSPORT, 'canonical_timestamp'),
        function(SLOT_POLICY, 'slot_cell'),
        function(RELEASE, 'decimal'),
        function(RELEASE, 'divide10'),
        receipt_template('adoption_record', ADOPTION_RECORD),
        receipt_template('adoption_result', ADOPTION_RESULT),
        *(function(identity_source(), name).replace('read_word(', 'input_word(')
          for name in ('receipt_fragment_size', 'receipt_literal', 'receipt_fragment')),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0],
        key_table(FIELDS),
        literal_match('evaluation_schema', 'hepta.hia.agent.evaluation.v1'),
        literal_match('outcome_improved', 'improved'),
        literal_match('outcome_unchanged', 'unchanged'),
        *(function(artifact_authority(), name)
          for name in ('artifact_reference', 'artifact_start', 'artifact_digest', 'artifact_uri',
                       'valid_hex', 'input_word', 'copy_input')),
        function(artifact_authority(), 'matches').replace('def matches(', 'def bytes_equal('),
    ))
    return re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), source) + '\n' + json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
