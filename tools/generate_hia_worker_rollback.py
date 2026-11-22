"""Author HIA projection, ordered slot decisions and canonical Rollback receipts."""
import json
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import (
    ROLLBACK_RECORD, ROLLBACK_RESULT, receipt_template, source_program as identity_source,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_artifact import kind_width_source, kind_match_source
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_store_transport import POLICY as STORE
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_inspection_effect import function, literal as packed_literal
from tools.generate_hia_worker_inspection_request import POLICY as INSPECTION

SOURCE = Path('examples/hia_bootstrap/worker_rollback.hepta')
KEYS = ('catalog_sha256', 'context', 'target_slot', 'expected_current',
        'generation', 'epoch', 'retained_generation', 'reason')
TAGS = {'REQUEST': b'HIARLQ01', 'DECISION': b'HIARLD01',
        'ANSWER': b'HIARLA01', 'RECEIPT': b'HIARLR01', 'STORE_QUERY': b'HIARLS01',
        'STORE_OBSERVE': b'HIARLO01', 'STORE_ROW': b'HIARLB01', 'COUNT': b'HIASTLC1',
        'QUERY': b'HIAQPA01', 'UPDATE': b'HIAUPB01', 'GENERATION': b'HIARLF01',
        'PUBLIC_ERROR': b'HIARLE01', 'FORMAT_COUNT': b'HIARLN01', 'DOCUMENT_OBSERVE': b'HIARLP01',
        'DOCUMENT_RESULT': b'HIARLP02', 'DOCUMENT_RECEIPT': b'HIADOC01', 'OUTCOME_REQUEST': b'HIARLT01', 'OUTCOME': b'HIAIND01'}
SNAPSHOT = ('{"active_artifact":{},"context":{},"current":{},"in_flight_leases":{},'
            '"snapshot_is_adoption_authority":false,"target_slot":{}}')
STALE = 'slot changed; read the retained current snapshot and choose a fresh conditional request'
POLICY = r'''
def rollback_worker(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 32768 or length(o) < 32768 or length(w) < 262144:
        return INVALID
    if length(s) >= 16:
        tag = input_word(s, 0)
        if tag == DECISION:
            return rollback_decision(s, o)
        if tag == RECEIPT:
            return rollback_receipt(s, o)
        if tag == STORE_QUERY:
            return slot_parameters(s, o)
        if tag == STORE_OBSERVE:
            return slot_observation(s, o)
        if tag == GENERATION:
            return generation_json(s, o)
        if tag == FORMAT_COUNT and length(s) == 16:
            put(o, 0, FORMAT_COUNT)
            return decimal(o, 8, input_word(s, 8))
        if tag == PUBLIC_ERROR:
            return rollback_error(s, o)
        if tag == DOCUMENT_OBSERVE:
            return observe_document(s, o)
        if tag == OUTCOME_REQUEST:
            return rollback_outcome(s, o)
    return rollback_project(s, o, w)

def rollback_project(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
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
        last = 64 + get(w, arguments + 16) * 72
        if get(w, last) != 0:
            return INVALID
        current = copy_value(s, w, o, catalog, 24)
        end = copy_value(s, w, o, pinned, current)
        put(o, 0, current - 24)
        put(o, 8, end - current)
        put(o, 16, 0)
        return end
    if equal_span(s, w, pinned, catalog) == False:
        return CATALOG_MISMATCH
    return rollback_arguments(s, o, w, arguments)

def rollback_arguments(s:readbuf, o:mutbuf, w:mutbuf, arguments:u64) -> u64:
    context = lookup(w, arguments, K_context)
    slot = lookup(w, arguments, K_target_slot)
    current = lookup(w, arguments, K_expected_current)
    retained = lookup(w, arguments, K_retained_generation)
    reason = lookup(w, arguments, K_reason)
    if context == NONE or get(w, context) != 6 or current == NONE or get(w, current) != 6:
        return INVALID
    generation = lookup(w, current, K_generation)
    epoch = lookup(w, current, K_epoch)
    if allowed_text(w, slot, 192) == False or allowed_text(w, reason, 8192) == False:
        return INVALID
    if allowed_text(w, retained, 20) == False or allowed_text(w, generation, 20) == False or allowed_text(w, epoch, 20) == False:
        return INVALID
    put(o, 0, REQUEST)
    at = fragment(s, w, o, context, 8)
    at = fragment(s, w, o, slot, at)
    at = fragment(s, w, o, retained, at)
    at = fragment(s, w, o, generation, at)
    at = fragment(s, w, o, epoch, at)
    return fragment(s, w, o, reason, at)

def allowed_text(w:mutbuf, node:u64, extent:u64) -> bool:
    return node != NONE and get(w, node) == 4 and get(w, node + 32) > 0 and get(w, node + 32) <= extent

# These three calls match the legacy effect order: canonical range, expected
# current state, then retained object and ABI. A corrupted transport is not a
# public rejection and may not be interpreted as a status.
def rollback_decision(s:readbuf, o:mutbuf) -> u64:
    kind = input_word(s, 8)
    if kind == 1:
        return rollback_ranges(s, o)
    if kind == 2:
        return rollback_snapshot(s, o)
    if kind == 3:
        return rollback_retained(s, o)
    return INVALID

def rollback_ranges(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 43 or length(s) > 100:
        return INVALID
    first = input_word(s, 16)
    second = input_word(s, 24)
    third = input_word(s, 32)
    if first < 1 or first > 20 or second < 1 or second > 20 or third < 1 or third > 20:
        return INVALID
    if length(s) != 40 + first + second + third:
        return INVALID
    if canonical_timestamp(s, 40, first) == False:
        return answer(o, 1, 0, 0, 0)
    if canonical_timestamp(s, 40 + first, second) == False:
        return answer(o, 2, 0, 0, 0)
    if canonical_timestamp(s, 40 + first + second, third) == False:
        return answer(o, 3, 0, 0, 0)
    return answer(o, 0, number(s, 40, first), number(s, 40 + first, second),
                  number(s, 40 + first + second, third))

def number(s:readbuf, at:u64, size:u64) -> u64:
    cursor = 0
    result = 0
    while cursor < size:
        result = result * 10 + byte(s, at + cursor) - 48
        cursor = cursor + 1
    return result

def rollback_snapshot(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 56:
        return INVALID
    present = input_word(s, 16)
    expected_generation = input_word(s, 24)
    expected_epoch = input_word(s, 32)
    generation = input_word(s, 40)
    epoch = input_word(s, 48)
    if present > 1 or (present == 0 and (generation != 0 or epoch != 0)):
        return INVALID
    if generation != expected_generation or epoch != expected_epoch:
        return answer(o, 4, generation, epoch, 0)
    if present == 0:
        return answer(o, 5, 0, 0, 0)
    return answer(o, 0, generation, epoch, 0)

def rollback_retained(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 32:
        return INVALID
    present = input_word(s, 16)
    epoch = input_word(s, 24)
    if present == 0 and length(s) == 32:
        return answer(o, 6, 0, 0, 0)
    if present != 1 or length(s) != 160:
        return INVALID
    if valid_hex(s, 32, 64) == False or valid_hex(s, 96, 64) == False:
        return INVALID
    index = 0
    while index < 64:
        if byte(s, 32 + index) != byte(s, 96 + index):
            return answer(o, 7, 0, 0, 0)
        index = index + 1
    if epoch == 18446744073709551615:
        return answer(o, 8, 0, 0, 0)
    return answer(o, 0, epoch + 1, 0, 0)

def answer(o:mutbuf, status:u64, x:u64, y:u64, z:u64) -> u64:
    put(o, 0, ANSWER)
    put(o, 8, status)
    put(o, 16, x)
    put(o, 24, y)
    put(o, 32, z)
    return 40

def rollback_receipt(s:readbuf, o:mutbuf) -> u64:
    kind = input_word(s, 8)
    if kind == 1:
        size = rollback_record(s, o, 0)
        if size <= length(o):
            return rollback_record(s, o, 1)
        return size
    if kind == 2:
        size = rollback_result(s, o, 0)
        if size <= length(o):
            return rollback_result(s, o, 1)
        return size
    if kind == 3:
        size = rollback_snapshot_json(s, o, 0)
        if size <= length(o):
            return rollback_snapshot_json(s, o, 1)
        return size
    return INVALID
'''


SLOT_POLICY = r'''
# Fixed observations are carried in the same Store transaction as the eventual
# publication. The transport has no SQL-shaped fallback for Rollback.
def slot_parameters(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 41 or length(s) > 268:
        return INVALID
    mode = input_word(s, 8)
    generation = input_word(s, 16)
    epoch = input_word(s, 24)
    size = input_word(s, 32)
    if size < 1 or size > 192 or mode < 1 or mode > 3:
        return INVALID
    start = choose(mode == 3, 76, 40)
    if length(s) != start + size or slot_name(s, start, size) == False:
        return INVALID
    if mode == 3:
        if context_id(s, 40) == False:
            return INVALID
        return move_parameters(s, o, generation, epoch, size)
    if epoch != 0 or (mode == 1 and generation != 0):
        return INVALID
    payload = choose(mode == 1, 56, 80)
    end = copy_input(s, o, 40, payload, size)
    put(o, 0, QUERY)
    put(o, 8, 1)
    put(o, 16, mode)
    slot_cell(o, 32, payload, size)
    if mode == 2:
        last = decimal(o, end, generation)
        slot_cell(o, 56, end, last - end)
        end = last
    put(o, 24, end)
    return end

def move_parameters(s:readbuf, o:mutbuf, generation:u64, epoch:u64, size:u64) -> u64:
    after_generation = decimal(o, 136, generation)
    after_epoch = decimal(o, after_generation, epoch)
    after_context = copy_input(s, o, 40, after_epoch, 36)
    end = copy_input(s, o, 76, after_context, size)
    put(o, 0, UPDATE)
    put(o, 8, 1)
    put(o, 16, 2)
    put(o, 24, 0)
    put(o, 32, 4)
    slot_cell(o, 40, 136, after_generation - 136)
    slot_cell(o, 64, after_generation, after_epoch - after_generation)
    slot_cell(o, 88, after_epoch, 36)
    slot_cell(o, 112, after_context, size)
    return end

def slot_cell(o:mutbuf, at:u64, offset:u64, size:u64) -> u64:
    put(o, at, 3)
    put(o, at + 8, offset)
    put(o, at + 16, size)
    return at + 24

# Correlate the Store settlement and the exact queried primary-key fields.
def slot_observation(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 104 or length(s) > 808:
        return INVALID
    extent = input_word(s, 8)
    kind = input_word(s, 32)
    slot = input_word(s, 40)
    generation = input_word(s, 48)
    if kind < 1 or kind > 3 or extent > 512 or slot > 192:
        return INVALID
    row = 56 + slot
    if length(s) != row + extent + 48 or unique_summary(s, row + extent, extent) == False:
        return INVALID
    if kind == 3:
        if slot != 0 or generation != 0 or extent != 16 or input_word(s, row) != COUNT:
            return INVALID
        return copy_input(s, o, row, 0, 16)
    if slot_name(s, 56, slot) == False:
        return INVALID
    if kind == 2:
        return projected_version(s, o, row, extent, slot, generation)
    if generation != 0:
        return INVALID
    return projected_slot(s, o, row, extent, slot)

def projected_slot(s:readbuf, o:mutbuf, row:u64, extent:u64, slot:u64) -> u64:
    put(o, 0, STORE_ROW)
    put(o, 8, choose(extent == 0, 0, 1))
    if extent == 0:
        return 16
    if extent < 254 + slot or row_header(s, row, 7, 5) == False:
        return INVALID
    if row_text(s, row + 32, 152, slot) == False or matches(s, row + 152, 56, slot) == False:
        return INVALID
    context = 152 + slot
    if row_text(s, row + 56, context, 36) == False or context_id(s, row + context) == False:
        return INVALID
    start = context + 36
    gen = input_word(s, row + 96)
    epoch = input_word(s, row + 120)
    if gen < 1 or gen > 20 or epoch < 1 or epoch > 20 or extent != start + gen + epoch + 64:
        return INVALID
    if row_text(s, row + 80, start, gen) == False or row_text(s, row + 104, start + gen, epoch) == False:
        return INVALID
    if row_text(s, row + 128, start + gen + epoch, 64) == False:
        return INVALID
    if canonical_timestamp(s, row + start, gen) == False or canonical_timestamp(s, row + start + gen, epoch) == False:
        return INVALID
    if valid_hex(s, row + start + gen + epoch, 64) == False:
        return INVALID
    put(o, 16, number(s, row + start, gen))
    put(o, 24, number(s, row + start + gen, epoch))
    copy_input(s, o, row + context, 32, 36)
    return copy_input(s, o, row + start + gen + epoch, 68, 64)

def projected_version(s:readbuf, o:mutbuf, row:u64, extent:u64, slot:u64, generation:u64) -> u64:
    put(o, 0, STORE_ROW)
    put(o, 8, choose(extent == 0, 0, 1))
    if extent == 0:
        return 16
    if extent < 281 + slot or row_header(s, row, 8, 3) == False:
        return INVALID
    width = input_word(s, row + 72)
    start = 104 + slot
    artifact = start + width
    if width < 1 or width > 20 or extent != artifact + 176:
        return INVALID
    if row_text(s, row + 32, 104, slot) == False or matches(s, row + 104, 56, slot) == False:
        return INVALID
    if row_text(s, row + 56, start, width) == False or canonical_timestamp(s, row + start, width) == False:
        return INVALID
    if number(s, row + start, width) != generation:
        return INVALID
    if row_text(s, row + 80, artifact, 176) == False or artifact_reference(s, row + artifact) == False:
        return INVALID
    return copy_input(s, o, row + artifact, 16, 176)

def generation_json(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 24:
        return INVALID
    at = epoch_open(o, 0)
    at = decimal(o, at, input_word(s, 16))
    at = generation_open(o, at)
    at = decimal(o, at, input_word(s, 8))
    return generation_close(o, at)

def rollback_error(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 16:
        return INVALID
    code = input_word(s, 8)
    if code == 4:
        if length(s) != 216 or input_word(s, 16) != DOCUMENT_RECEIPT:
            return INVALID
        if input_word(s, 24) != 176 or input_word(s, 32) != 0 or artifact_reference(s, 40) == False:
            return INVALID
        stale_open(o, 0)
        at = copy_input(s, o, 40, STALE_OPEN_SIZE, 176)
        return stale_close(o, at)
    if length(s) != 16:
        return INVALID
    return static_error(o, code)

# An exact content-key query may find a receipt published by an earlier
# equivalent effect. Never issue a new public reference for that same row.
def observe_document(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 216 or length(s) > 1024:
        return INVALID
    extent = input_word(s, 8)
    kind = input_word(s, 32)
    if kind != 10 and kind != 11:
        return INVALID
    if length(s) != 216 + extent or unique_summary(s, 168 + extent, extent) == False:
        return INVALID
    if valid_hex(s, 40, 128) == False:
        return INVALID
    put(o, 0, DOCUMENT_RESULT)
    put(o, 8, choose(extent == 0, 0, 1))
    if extent == 0:
        return 16
    name = document_kind_width(kind)
    row = 168
    if extent != 388 + name or row_header(s, row, 1, 6) == False:
        return INVALID
    if row_text(s, row + 32, 176, 34) == False or row_text(s, row + 56, 210, 64) == False:
        return INVALID
    if row_text(s, row + 80, 274, 48) == False or row_text(s, row + 104, 322, name) == False:
        return INVALID
    if row_text(s, row + 128, 322 + name, 2) == False or row_text(s, row + 152, 324 + name, 64) == False:
        return INVALID
    if matches(s, row + 210, 40, 64) == False or matches(s, row + 324 + name, 104, 64) == False:
        return INVALID
    if document_kind_matches(s, row + 322, kind) == False:
        return INVALID
    if byte(s, row + 322 + name) != 123 or byte(s, row + 323 + name) != 125:
        return INVALID
    if byte(s, row + 176) != 97 or byte(s, row + 177) != 45 or valid_hex(s, row + 178, 32) == False:
        return INVALID
    if native_uri(s, row + 274) == False or valid_hex(s, row + 290, 32) == False:
        return INVALID
    at = ref_open(o, 16)
    at = copy_input(s, o, row + 176, at, 34)
    at = ref_sha(o, at)
    at = copy_input(s, o, row + 210, at, 64)
    at = ref_uri(o, at)
    at = copy_input(s, o, row + 274, at, 48)
    return generation_close(o, at)

def rollback_outcome(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 34:
        return INVALID
    status = input_word(s, 8)
    context = input_word(s, 16)
    extent = input_word(s, 24)
    if (status != 1 and status != 2) or (context != 0 and context != 36) or extent < 2:
        return INVALID
    if length(s) != 32 + context + extent or (context == 36 and context_id(s, 32) == False):
        return INVALID
    if status == 1 and context != 36:
        return INVALID
    if byte(s, 32 + context) != 123 or byte(s, length(s) - 1) != 125:
        return INVALID
    put(o, 0, OUTCOME)
    put(o, 8, status)
    put(o, 16, context)
    put(o, 24, extent)
    at = 0
    while at < 36:
        store(o, 32 + at, 0)
        at = at + 1
    copy_input(s, o, 32, 32, context)
    return copy_input(s, o, 32 + context, 68, extent)
'''


def literal(name, text):
    return packed_literal(name, text.encode('ascii')).replace('state_put(', 'put(')


def errors():
    cases = {
        1: ('E_HIA_RANGE', 'retained_generation must be a canonical u64 decimal string', 'admission'),
        2: ('E_HIA_RANGE', 'generation must be a canonical u64 decimal string', 'admission'),
        3: ('E_HIA_RANGE', 'epoch must be a canonical u64 decimal string', 'admission'),
        5: ('E_HIA_SLOT', 'slot has no retained generation', 'adoption'),
        6: ('E_HIA_GENERATION', 'requested generation is not retained', 'adoption'),
        7: ('E_HIA_ABI', 'retained generation is not ABI compatible', 'adoption'),
        8: ('E_HIA_GENERATION_EXHAUSTED', 'u64 epoch space is exhausted', 'adoption'),
        9: ('E_HIA_RECEIPT_BINDING', 'native artifact belongs to a different context or implementation', 'admission'),
        10: ('E_HIA_RECEIPT_BINDING', "native artifact's admitted Core identity differs", 'admission'),
        11: ('E_HIA_ARTIFACT_IDENTITY', 'artifact reference was not issued in this runtime namespace', 'admission'),
        12: ('E_HIA_ARTIFACT_AUTHORITY', 'input bytes cannot impersonate a retained native', 'admission'),
        13: ('E_HIA_CONTEXT_IDENTITY', 'context is not a retained server record', 'context'),
        14: ('E_HIA_CONTEXT_STALE', 'context binds a different installed implementation', 'context'),
        16: ('E_HIA_ARTIFACT_AUTHORITY', 'input bytes cannot impersonate a retained context', 'admission'),
    }
    dispatch = ['def static_error(o:mutbuf, code:u64) -> u64:']
    code = []
    for status,(name,message,phase) in cases.items():
        body = json.dumps({'code':name,'message':message,'phase':phase,'details_artifact':None,
                           'retry_action':'correct_input'}, sort_keys=True, separators=(',', ':'))
        dispatch.extend((f'    if code == {status}:', f'        return error_{status}(o, 0)'))
        code.append(literal(f'error_{status}', body))
    dispatch.append('    return 4294967293')
    return '\n'.join((*code, '\n'.join(dispatch)))


def native_uri():
    prefix = 'hia://artifacts/'.encode('ascii')
    checks = ' and '.join(f'byte(s, at + {offset}) == {value}' for offset,value in enumerate(prefix))
    return 'def native_uri(s:readbuf, at:u64) -> bool:\n    return ' + checks


def program():
    keys = {f'K_{key}': index for index, key in enumerate(KEYS, 1)}
    constants = {name: int.from_bytes(value, 'little') for name, value in TAGS.items()}
    stale_open = '{"code":"E_HIA_GENERATION_STALE","details_artifact":'
    constants.update(keys, STALE_OPEN_SIZE=len(stale_open), INVALID=4294967293, CATALOG_MISMATCH=4294967286, NONE=(1 << 64) - 1)
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda match: str(constants[match[0]]), POLICY + SLOT_POLICY)
    identity = identity_source()
    artifact = authority()
    return '\n'.join((
        policy, function(INSPECTION, 'input_word'),
        *(function(CONTEXT, name) for name in ('equal_span', 'fragment', 'copy_value')),
        function(CONTEXT.replace('NONE', str(constants['NONE'])), 'digest_text'),
        function(WIRE_HELPERS.replace('NONE', str(constants['NONE'])), 'lookup'),
        function(WIRE_HELPERS, 'match_word'),
        comparison_table('key_id', KEYS),
        *(function(STORE, name).replace('read_word(', 'input_word(')
          for name in ('canonical_timestamp', 'valid_hex', 'lower_hex')),
        receipt_template('rollback_record', ROLLBACK_RECORD),
        receipt_template('rollback_result', ROLLBACK_RESULT),
        *(function(identity, name).replace('read_word(', 'input_word(')
          for name in ('receipt_fragment_size', 'receipt_literal', 'receipt_fragment')),
        receipt_template('rollback_snapshot_json', SNAPSHOT),
        *(function(STORE, name).replace('read_word(', 'input_word(') for name in ('slot_name', 'context_id')),
        *(function(artifact, name) for name in ('copy_input', 'unique_summary', 'row_header', 'row_text',
                'artifact_reference', 'artifact_start', 'artifact_digest', 'artifact_uri', 'matches')),
        function(RELEASE, 'decimal'), function(RELEASE, 'divide10'),
        literal('epoch_open', '{"epoch":"'), literal('generation_open', '","generation":"'),
        literal('generation_close', '"}'), literal('stale_open', stale_open),
        literal('stale_close', ',"message":"' + STALE +
            '","phase":"adoption","retry_action":"refresh_context"}'),
        literal('ref_open', '{"id":"'), literal('ref_sha', '","sha256":"'),
        literal('ref_uri', '","uri":"'), native_uri(),
        kind_width_source(), kind_match_source(),
        errors(), json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
