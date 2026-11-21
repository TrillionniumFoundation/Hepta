"""Author HIA admission of retained native artifact metadata and exact bindings."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_native_artifact.hepta')
FIELDS = ('installation', 'context', 'candidate', 'core_sha256', 'foreign_buffer_exports', 'signatures')
TAGS = {
    'OBSERVE': b'HIAARN01', 'ARTIFACT': b'HIAARN02', 'METADATA': b'HIAANM01',
    'COMPARE': b'HIAABC01', 'MATCH': b'HIAABR01',
}
POLICY = r'''
# The observation is the immutable public reference plus the exact Store row
# and unique-query settlement. Return offsets into that same sealed frame.
def native_artifact(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > INPUT_LIMIT or length(o) < 4194304 or length(w) < WORKSPACE:
        return INVALID
    if length(s) >= 8:
        tag = input_word(s, 0)
        if tag == OBSERVE:
            return observe_native(s, o)
        if tag == COMPARE:
            return compare_native(s, o)
    return project_metadata(s, o, w)

def observe_native(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 256:
        return INVALID
    extent = input_word(s, 8)
    if extent != length(s) - 256 or unique_summary(s, 208 + extent, extent) == False:
        return INVALID
    if artifact_reference(s, 32) == False:
        return INVALID
    if extent == 0:
        return MISSING
    row = 208
    if extent < 389 or row_header(s, row, 1, 6) == False:
        return INVALID
    if row_text(s, row + 32, 176, 34) == False or row_text(s, row + 56, 210, 64) == False:
        return INVALID
    if row_text(s, row + 80, 274, 48) == False:
        return INVALID
    width = input_word(s, row + 120)
    if width == 0 or width > 128 or extent < 388 + width:
        return INVALID
    if row_text(s, row + 104, 322, width) == False:
        return INVALID
    start = 322 + width
    amount = extent - 386 - width
    if row_text(s, row + 128, start, amount) == False or row_text(s, row + 152, start + amount, 64) == False:
        return INVALID
    if valid_hex(s, row + extent - 64, 64) == False:
        return INVALID
    if matches(s, row + 176, 39, 34) == False or matches(s, row + 210, 85, 64) == False or matches(s, row + 274, 158, 48) == False:
        return MISSING
    if width != 6 or input_word(s, row + 322) & 281474976710655 != NATIVE:
        return KIND
    put(o, 0, ARTIFACT)
    copy_input(s, o, 85, 8, 64)
    put(o, 72, row + start)
    put(o, 80, amount)
    return 88

def project_metadata(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 6:
        return INVALID
    installation = lookup(w, 64, K_installation)
    context = lookup(w, 64, K_context)
    core = lookup(w, 64, K_candidate)
    sha = lookup(w, 64, K_core_sha256)
    exports = lookup(w, 64, K_foreign_buffer_exports)
    signatures = lookup(w, 64, K_signatures)
    if metadata_object(w, installation) == False or metadata_object(w, context) == False:
        return INVALID
    if metadata_object(w, core) == False or metadata_object(w, signatures) == False:
        return INVALID
    if digest_text(w, sha, False) == False or get(w, sha + 64) != 66:
        return INVALID
    if exports != NONE and get(w, exports) != 5:
        return INVALID
    put(o, 0, METADATA)
    put(o, 8, 6)
    projection(w, o, installation, 16)
    projection(w, o, context, 32)
    projection(w, o, core, 48)
    put(o, 64, get(w, sha + 56) + 1)
    put(o, 72, 64)
    projection(w, o, exports, 80)
    projection(w, o, signatures, 96)
    return 112

def metadata_object(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 6

def projection(w:mutbuf, o:mutbuf, node:u64, offset:u64) -> u64:
    if node == NONE:
        put(o, offset, 0)
        put(o, offset + 8, 0)
    else:
        put(o, offset, get(w, node + 56))
        put(o, offset + 8, get(w, node + 64))
    return 0

# Both spans are canonical bytes from pinned owners, not an authorization
# claim from the caller. This rejects prefix or cross-field substitution.
def compare_native(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 24:
        return INVALID
    left = input_word(s, 8)
    right = input_word(s, 16)
    if left == 0 or right == 0 or left > length(s) - 24 or right != length(s) - 24 - left:
        return INVALID
    equal = left == right
    if equal:
        equal = matches(s, 24, 24 + left, left)
    put(o, 0, MATCH)
    put(o, 8, choose(equal, 1, 0))
    return 16
'''


def program():
    constants = {name: int.from_bytes(value, 'little') for name, value in TAGS.items()}
    constants.update({f'K_{key}': index for index, key in enumerate(FIELDS, 1)})
    constants.update(NATIVE=int.from_bytes(b'native', 'little'), NONE=(1 << 64) - 1,
                     INPUT_LIMIT=(8 << 20) + 1024, WORKSPACE=64 + 262144 * 72 + (8 << 20),
                     INVALID=4294967293, MISSING=4294967288, KIND=4294967287)
    body = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), POLICY)
    authority_source = authority()
    return '\n'.join((
        body,
        *(function(authority_source, name) for name in
          ('input_word', 'unique_summary', 'artifact_reference', 'artifact_start',
           'artifact_digest', 'artifact_uri', 'valid_hex', 'matches',
           'row_header', 'row_text', 'copy_input')),
        function(CONTEXT.replace('NONE', str(constants['NONE'])), 'digest_text'),
        function(WIRE_HELPERS.replace('NONE', str(constants['NONE'])), 'lookup'),
        function(WIRE_HELPERS, 'match_word'),
        comparison_table('key_id', FIELDS),
        decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
