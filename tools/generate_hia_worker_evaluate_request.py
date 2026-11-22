"""Project a schema-admitted Evaluate request into sealed custody spans."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as artifact_authority
from tools.generate_hia_worker_build_custody import POLICY as BUILD_CUSTODY
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_emit_verification import POLICY as VERIFICATION, key_table
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_rollback import POLICY as ROLLBACK
from tools.generate_hia_worker_verify_request import POLICY as VERIFY

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_request.hepta')
FIELDS = ('catalog_sha256', 'context', 'request_key', 'baseline_artifact', 'candidate_artifact',
          'build_receipt', 'verification_receipts', 'id', 'sha256')

POLICY = r'''
# [installed catalog, admitted arguments, null] projects the Journal's
# comparison. [catalog, arguments] indexes custody in the same sealed input;
# it does not admit executable bytes or establish a proof of any claim.
def evaluate_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 72 or length(s) > 32768 or length(o) < 368 or length(w) < 65536:
        return INVALID
    put(o, 48, 4096)
    put(o, 56, 32)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    pinned = 64 + get(w, 88) * 72
    args = next(w, pinned)
    if get(w, 96) == 3:
        marker = next(w, args)
        if marker != NONE and get(w, marker) == 0:
            return journal_catalog(s, o, w, pinned, args)
        return INVALID
    if get(w, 96) != 2 or is_object(w, args) == False or get(w, args + 32) != 7:
        return INVALID
    catalog = lookup(w, args, K_catalog_sha256)
    if digest_text(w, pinned, False) == False or digest_text(w, catalog, True) == False:
        return INVALID
    if equal_span(s, w, pinned, catalog) == False:
        return CATALOG_MISMATCH
    return custody_request(s, o, w, args)

def custody_request(s:readbuf, o:mutbuf, w:mutbuf, args:u64) -> u64:
    context = lookup(w, args, K_context)
    request = lookup(w, args, K_request_key)
    if context_reference(s, w, context) == False or allowed_text(w, request, 192) == False:
        return INVALID
    baseline = lookup(w, args, K_baseline_artifact)
    candidate = lookup(w, args, K_candidate_artifact)
    build = lookup(w, args, K_build_receipt)
    if (exact_reference(s, w, baseline) == False or exact_reference(s, w, candidate) == False
            or exact_reference(s, w, build) == False):
        return INVALID
    receipts = lookup(w, args, K_verification_receipts)
    if receipts == NONE or get(w, receipts) != 5:
        return INVALID
    count = get(w, receipts + 32)
    if count < 1 or count > 16:
        return INVALID
    put(o, 0, REQUEST)
    put(o, 8, count)
    span(w, o, context, 16)
    span(w, o, baseline, 32)
    span(w, o, candidate, 48)
    span(w, o, build, 64)
    span(w, o, request, 80)
    span(w, o, receipts, 96)
    receipt = 64 + get(w, receipts + 24) * 72
    index = 0
    while index < count:
        if exact_reference(s, w, receipt) == False:
            return INVALID
        span(w, o, receipt, 112 + 16 * index)
        receipt = next(w, receipt)
        index = index + 1
    return 112 + 16 * count

def context_reference(s:readbuf, w:mutbuf, node:u64) -> bool:
    if is_object(w, node) == False or get(w, node + 32) != 2:
        return False
    reference = lookup(w, node, K_id)
    if reference == NONE or get(w, reference) != 4 or get(w, reference + 32) != 36:
        return False
    at = get(w, reference + 56) + 1
    if byte(s, at) != 99 or byte(s, at + 1) != 116 or byte(s, at + 2) != 120 or byte(s, at + 3) != 45:
        return False
    return valid_hex(s, at + 4, 32) and digest_text(w, lookup(w, node, K_sha256), False)
'''


def source_program():
    constants = {f'K_{name}': index for index, name in enumerate(FIELDS, 1)}
    constants.update(INVALID=4294967293, CATALOG_MISMATCH=4294967286, NONE=(1 << 64) - 1,
                     REQUEST=int.from_bytes(b'HIAEVQ01', 'little'))
    artifact = artifact_authority()
    body = '\n'.join((
        POLICY, function(VERIFY, 'journal_catalog'), function(BUILD_CUSTODY, 'exact_reference'),
        *(function(VERIFICATION, name) for name in ('next', 'is_object', 'span')),
        *(function(CONTEXT, name) for name in ('equal_span', 'digest_text', 'copy_value')),
        function(ROLLBACK, 'allowed_text'),
        *(function(artifact, name) for name in ('artifact_reference', 'artifact_start', 'artifact_digest',
                                              'artifact_uri', 'valid_hex', 'input_word')),
        function(artifact, 'matches').replace('def matches(', 'def bytes_equal('),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0], key_table(FIELDS),
    ))
    return re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), body) + '\n' + json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
