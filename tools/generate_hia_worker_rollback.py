"""Author HIA projection, ordered slot decisions and canonical Rollback receipts."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import (
    ROLLBACK_RECORD, ROLLBACK_RESULT, receipt_template, source_program as identity_source,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_store_transport import POLICY as STORE
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_inspection_request import POLICY as INSPECTION

SOURCE = Path('examples/hia_bootstrap/worker_rollback.hepta')
KEYS = ('catalog_sha256', 'context', 'target_slot', 'expected_current',
        'generation', 'epoch', 'retained_generation', 'reason')
TAGS = {'REQUEST': b'HIARLQ01', 'DECISION': b'HIARLD01',
        'ANSWER': b'HIARLA01', 'RECEIPT': b'HIARLR01'}
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
    return INVALID
'''


def program():
    keys = {f'K_{key}': index for index, key in enumerate(KEYS, 1)}
    constants = {name: int.from_bytes(value, 'little') for name, value in TAGS.items()}
    constants.update(keys, INVALID=4294967293, CATALOG_MISMATCH=4294967286, NONE=(1 << 64) - 1)
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda match: str(constants[match[0]]), POLICY)
    identity = identity_source()
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
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
