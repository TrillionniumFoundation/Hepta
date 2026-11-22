"""Author the native immutable-input profile binding and artifact result."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_effect import source_program as document_effect
from tools.generate_hia_describe_bind import METADATA_FIELDS
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE_POLICY

SOURCE = 'examples/hia_bootstrap/worker_artifact_authority.hepta'

# These are read roles, not immutable publication kind ordinals.
TYPED_READ_KINDS = (
    (12, 'evaluation_receipt', b'evaluation-receipt'),
    (13, 'measurements', b'measurements'),
    (14, 'cost_ledger', b'cost-ledger'),
    (15, 'machine_certificate', b'machine-validation-certificate'),
)

POLICY = r'''
def artifact_authority(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < 512:
        return 4294967293
    mode = input_word(s, 0)
    if mode == PROFILE_QUERY:
        if length(s) != 72 or valid_hex(s, 8, 64) == False:
            return 4294967293
        return profile_query(s, o)
    if mode == PROFILE_OBSERVE:
        return profile_observation(s, o)
    if mode == ARTIFACT_OBSERVE:
        return artifact_observation(s, o)
    if mode == CONTEXT_PROFILE_QUERY:
        if length(s) != 80 or valid_hex(s, 16, 64) == False or context_profile_width(input_word(s, 8)) == 0:
            return 4294967293
        return contextual_profile_query(s, o)
    if mode == CONTEXT_PROFILE_OBSERVE:
        return contextual_profile_observation(s, o)
    if mode == CONTEXT_PROFILE_ADMIT:
        return contextual_profile_admission(s, o)
    if mode == RETAINED_QUERY:
        return retained_query(s, o)
    if mode == CONTEXT_RETAINED_QUERY:
        return contextual_retained_query(s, o)
    if mode == CONTEXT_MANIFEST_REF:
        return contextual_manifest_reference(s, o)
    if mode == RETAINED_OBSERVE:
        return retained_observation(s, o)
    if mode == INPUT_RESULT:
        return receipt(s, o)
    return 4294967293

def profile_query(s:readbuf, o:mutbuf) -> u64:
    query_header(o, 0, 2, 159)
    query_field(o, 32, 80, 15)
    query_field(o, 56, 95, 64)
    put(o, 80, PROFILE_HEAD)
    put(o, 88, PROFILE_END)
    return copy_input(s, o, 8, 95, 64)

def profile_observation(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 144 or valid_hex(s, 32, 64) == False:
        return 4294967293
    size = input_word(s, 8)
    if size != length(s) - 144 or unique_summary(s, 96 + size, size) == False:
        return 4294967293
    return profile_lookup_binding(s, o, 3, 32, size)

def contextual_profile_observation(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 152 or valid_hex(s, 40, 64) == False:
        return 4294967293
    kind = input_word(s, 32)
    size = input_word(s, 8)
    if context_profile_width(kind) == 0 or size != length(s) - 152 or unique_summary(s, 104 + size, size) == False:
        return 4294967293
    return profile_lookup_binding(s, o, kind, 40, size)

def contextual_profile_query(s:readbuf, o:mutbuf) -> u64:
    kind = input_word(s, 8)
    width = context_profile_width(kind)
    query_header(o, 0, 2, 144 + width)
    query_field(o, 32, 80, width)
    query_field(o, 56, 80 + width, 64)
    write_profile_name(o, 80, kind)
    return copy_input(s, o, 16, 80 + width, 64)

# Pinned profile identities are generated from the installation, not from the
# request or a potentially stale retained Store row. The public schema has
# already admitted the canonical reference before this equality check.
def contextual_profile_admission(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 82 or valid_hex(s, 16, 64) == False:
        return 4294967293
    role = input_word(s, 8)
    width = context_profile_width(role)
    if width == 0:
        return 4294967293
    if length(s) != 165 + width:
        return 4294967286
    if reference_begin(s, 80) == False or selected_profile(s, 87, role) == False:
        return 4294967286
    digest = 87 + width
    if artifact_digest(s, digest) == False or matches(s, digest + 12, 16, 64) == False:
        return 4294967286
    if byte(s, digest + 76) != 34 or byte(s, digest + 77) != 125:
        return 4294967286
    return contextual_profile_query(s, o)

def context_profile_width(role:u64) -> u64:
    if role == 3:
        return 0
    return profile_width(role)

def profile_lookup_binding(s:readbuf, o:mutbuf, kind:u64, pin:u64, size:u64) -> u64:
    if size == 0:
        return 4294967289
    width = profile_width(kind)
    row = pin + 64
    if size != 344 + width or row_header(s, row, 2, 3) == False:
        return 4294967293
    if row_text(s, row + 32, 104, width) == False or row_text(s, row + 56, 104 + width, 64) == False:
        return 4294967293
    start = row + 168 + width
    if row_text(s, row + 80, 168 + width, 176) == False or artifact_reference(s, start) == False:
        return 4294967293
    if matches(s, row + 104 + width, pin, 64) == False or matches(s, start + 53, pin, 64) == False:
        return 4294967293
    if selected_profile(s, row + 104, kind) == False:
        return 4294967293
    put(o, 0, PROFILE_REF)
    put(o, 8, 176)
    copy_input(s, o, start, 16, 176)
    query_header(o, 192, 1, 90)
    query_field(o, 224, 56, 34)
    return copy_input(s, o, start + 7, 248, 34)

def retained_query(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 192 or input_word(s, 8) > RETAINED_KIND_LIMIT or artifact_reference(s, 16) == False:
        return 4294967293
    return retained_parameters(s, o)

def contextual_retained_query(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 18 or input_word(s, 8) != 0:
        return 4294967293
    if length(s) != 192 or artifact_reference(s, 16) == False:
        return 4294967288
    return retained_parameters(s, o)

def retained_parameters(s:readbuf, o:mutbuf) -> u64:
    query_header(o, 0, 1, 90)
    query_field(o, 32, 56, 34)
    return copy_input(s, o, 23, 56, 34)

def contextual_manifest_reference(s:readbuf, o:mutbuf) -> u64:
    if length(s) < CONTEXT_METADATA_FIELDS + 184 or length(s) > 32776:
        return 4294967293
    if input_word(s, 8) != CONTEXT_METADATA or input_word(s, 32) != 66 or input_word(s, 40) != 0 or input_word(s, 48) != 176:
        return 4294967293
    artifact = input_word(s, 16)
    backend = input_word(s, 24)
    if artifact != 100 or backend != 99:
        return 4294967293
    at = 8 + CONTEXT_METADATA_FIELDS + artifact + backend + 66
    if at + 176 > length(s) or artifact_reference(s, at) == False:
        return 4294967293
    return copy_input(s, o, at, 0, 176)

def artifact_observation(s:readbuf, o:mutbuf) -> u64:
    # The artifact profile route keeps its original seal and reply shape.
    if length(s) < 256:
        return 4294967293
    size = input_word(s, 8)
    if size != length(s) - 256 or unique_summary(s, 208 + size, size) == False:
        return 4294967293
    return retain_binding(s, o, 32, size, 2, PROFILE_READ)

def retained_observation(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 264 or input_word(s, 32) > RETAINED_KIND_LIMIT:
        return 4294967293
    size = input_word(s, 8)
    if size != length(s) - 264 or unique_summary(s, 216 + size, size) == False:
        return 4294967293
    return retain_binding(s, o, 40, size, input_word(s, 32), RETAINED_READ)

def retain_binding(s:readbuf, o:mutbuf, ref:u64, size:u64, kind:u64, outcome:u64) -> u64:
    if artifact_reference(s, ref) == False:
        return 4294967293
    if size == 0:
        return 4294967288
    row = ref + 176
    if size < 389 or row_header(s, row, 1, 6) == False:
        return 4294967293
    if row_text(s, row + 32, 176, 34) == False or row_text(s, row + 56, 210, 64) == False:
        return 4294967293
    if row_text(s, row + 80, 274, 48) == False:
        return 4294967293
    width = input_word(s, row + 120)
    if width == 0 or width > 128 or size < 388 + width or row_text(s, row + 104, 322, width) == False:
        return 4294967293
    metadata = size - 386 - width
    if row_text(s, row + 128, 322 + width, metadata) == False:
        return 4294967293
    if row_text(s, row + 152, 322 + width + metadata, 64) == False:
        return 4294967293
    if valid_hex(s, row + size - 64, 64) == False:
        return 4294967293
    if requested_kind(s, row + 322, width, kind) == False:
        return 4294967287
    if matches(s, row + 176, ref + 7, 34) == False or matches(s, row + 210, ref + 53, 64) == False or matches(s, row + 274, ref + 126, 48) == False:
        return 4294967288
    if kind < 5:
        put(o, 0, outcome)
        return copy_input(s, o, ref + 53, 8, 64)
    # Offsets refer to the original sealed Store row, not to a new lookup.
    put(o, 0, BUILD_READ)
    copy_input(s, o, ref + 53, 8, 64)
    put(o, 72, 322 + width)
    put(o, 80, metadata)
    return 88

def requested_kind(s:readbuf, at:u64, size:u64, kind:u64) -> bool:
    if kind == 0:
        return True
    if kind == 1:
        return size == 5 and input_text(s, at)
    if kind == 2:
        return size == 7 and profile_text(s, at)
    if kind == 3:
        return size == 7 and context_text(s, at)
    if kind == 4:
        return size == 4 and program_text(s, at)
    if kind == 5:
        return size == 13 and build_receipt_text(s, at)
    if kind == 6:
        return size == 12 and build_object_text(s, at)
    if kind == 7:
        return size == 6 and native_text(s, at)
    if kind == 8:
        return size == 20 and verification_receipt_text(s, at)
    if kind == 9:
        return size == 24 and verification_assumptions_text(s, at)
    if kind == 10:
        return size == 21 and verification_evidence_text(s, at)
    if kind == 11:
        return size == 24 and machine_query_text(s, at)
RETAINED_ADOPT_DISPATCH
    return False

def unique_summary(s:readbuf, at:u64, size:u64) -> bool:
    if input_word(s, at) != 5 or input_word(s, at + 8) != size or input_word(s, at + 24) != 0:
        return False
    if input_word(s, at + 16) != choose(size == 0, 0, 1):
        return False
    return input_word(s, at + 32) == input_word(s, 16) and input_word(s, at + 40) == input_word(s, 24)

def row_header(s:readbuf, at:u64, table:u64, count:u64) -> bool:
    return input_word(s, at) == ROW and input_word(s, at + 8) == 1 and input_word(s, at + 16) == table and input_word(s, at + 24) == count

def row_text(s:readbuf, at:u64, offset:u64, size:u64) -> bool:
    return input_word(s, at) == 3 and input_word(s, at + 8) == offset and input_word(s, at + 16) == size

def artifact_reference(s:readbuf, at:u64) -> bool:
    if artifact_start(s, at) == False or artifact_digest(s, at + 41) == False or artifact_uri(s, at + 117) == False:
        return False
    if valid_hex(s, at + 9, 32) == False or valid_hex(s, at + 53, 64) == False:
        return False
    return valid_hex(s, at + 142, 32) and byte(s, at + 174) == 34 and byte(s, at + 175) == 125

def matches(s:readbuf, left:u64, right:u64, count:u64) -> bool:
    index = 0
    while index < count:
        if byte(s, left + index) != byte(s, right + index):
            return False
        index = index + 1
    return True

def query_header(o:mutbuf, at:u64, count:u64, size:u64) -> u64:
    put(o, at, QUERY)
    put(o, at + 8, 1)
    put(o, at + 16, count)
    return put(o, at + 24, size)

def query_field(o:mutbuf, at:u64, offset:u64, size:u64) -> u64:
    put(o, at, 3)
    put(o, at + 8, offset)
    return put(o, at + 16, size)

def receipt(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 216 or input_word(s, 16) != DOCUMENT or input_word(s, 24) != 176 or input_word(s, 32) != 0:
        return 4294967293
    size = input_word(s, 8)
    if size > 8388608 or artifact_reference(s, 40) == False:
        return 4294967293
    at = result_open(o, 0)
    at = copy_input(s, o, 40, at, 176)
    at = result_size(o, at)
    at = decimal(o, at, size)
    return result_end(o, at)
'''


def source_program():
    tags = {
        'PROFILE_QUERY': b'HIARPF01', 'PROFILE_OBSERVE': b'HIARPF02',
        'ARTIFACT_OBSERVE': b'HIARPF03', 'INPUT_RESULT': b'HIARPF04',
        'PROFILE_REF': b'HIARPO01', 'PROFILE_READ': b'HIARPO02',
        'RETAINED_QUERY': b'HIARFG01', 'RETAINED_OBSERVE': b'HIARFG02',
        'RETAINED_READ': b'HIARFO02', 'CONTEXT_PROFILE_QUERY': b'HIARFP01',
        'BUILD_READ': b'HIABRD01',
        'CONTEXT_PROFILE_OBSERVE': b'HIARFP02', 'CONTEXT_PROFILE_ADMIT': b'HIARFP03',
        'CONTEXT_RETAINED_QUERY': b'HIARFG03',
        'CONTEXT_MANIFEST_REF': b'HIARFM01', 'CONTEXT_METADATA': b'HIADMT01',
        'QUERY': b'HIAQPA01', 'ROW': b'HIAROW01', 'DOCUMENT': b'HIADOC01',
        'PROFILE_HEAD': b'hia-arti', 'PROFILE_END': b'fact-v1',
    }
    program = re.sub(r'\b(' + '|'.join(tags) + r')\b',
                     lambda match: str(int.from_bytes(tags[match.group()], 'little')), POLICY)
    program = program.replace('CONTEXT_METADATA_FIELDS', str(METADATA_FIELDS))
    program = program.replace('RETAINED_KIND_LIMIT', str(TYPED_READ_KINDS[-1][0]))
    program = program.replace('RETAINED_ADOPT_DISPATCH', '\n'.join(
        f'    if kind == {kind}:\n        return size == {len(raw)} and {name}_text(s, at)'
        for kind, name, raw in TYPED_READ_KINDS
    ))
    shared = document_effect()
    for name in ('copy_input', 'valid_hex', 'input_word', 'state_put', 'profile_text', 'input_text'):
        definition = '\ndef ' + name + '('
        start = shared.index(definition)
        end = shared.find('\ndef ', start + len(definition))
        program += shared[start:end if end != -1 else len(shared)] + '\n'
    program += RELEASE_POLICY[RELEASE_POLICY.index('\ndef decimal('):RELEASE_POLICY.index('\ndef hex(')]
    program = program.replace('state_put(', 'put(')
    for name, raw in (
        ('artifact_start', b'{"id":"a-'), ('reference_begin', b'{"id":"'),
        ('artifact_digest', b'","sha256":"'),
        ('artifact_uri', b'","uri":"hia://artifacts/'),
        ('context_text', b'context'), ('program_text', b'core'),
        ('build_receipt_text', b'build-receipt'), ('build_object_text', b'build-object'),
        ('native_text', b'native'),
        ('verification_receipt_text', b'verification-receipt'),
        ('verification_assumptions_text', b'verification-assumptions'),
        ('verification_evidence_text', b'verification-evidence'),
        ('machine_query_text', b'machine-validation-query'),
        *((name + '_text', raw) for _, name, raw in TYPED_READ_KINDS),
        *((name + '_profile', b'hia-' + name.encode('ascii') + b'-v1') for name in PROFILE_PORTS),
    ):
        program += f'\ndef {name}(s:readbuf, at:u64) -> bool:\n'
        program += '    return ' + ' and '.join(
            f'byte(s, at + {offset}) == {byte}' for offset, byte in enumerate(raw)) + '\n'
    for name, raw in (
        *((name + '_name', b'hia-' + name.encode('ascii') + b'-v1') for name in PROFILE_PORTS),
        ('result_open', b'{"artifact":'), ('result_size', b',"byte_length":"'),
        ('result_end', b'","content_admitted_as_program":false,"execution_authority_granted":false}'),
    ):
        program += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        for offset, byte in enumerate(raw):
            program += f'    store(o, at + {offset}, {byte})\n'
        program += f'    return at + {len(raw)}\n'
    return program + profile_ports()


PROFILE_PORTS = ('compiler', 'target', 'artifact', 'backend', 'lowering', 'plan', 'validation')


def profile_ports():
    functions = (
        ('profile_width(role:u64) -> u64', 'role', lambda name: str(len('hia-' + name + '-v1')), '0'),
        ('selected_profile(s:readbuf, at:u64, kind:u64) -> bool', 'kind',
         lambda name: name + '_profile(s, at)', 'False'),
        ('write_profile_name(o:mutbuf, at:u64, kind:u64) -> u64', 'kind',
         lambda name: name + '_name(o, at)', '0'),
    )
    source = []
    for declaration, selector, result, default in functions:
        source.append(f'\ndef {declaration}:')
        for ordinal, name in enumerate(PROFILE_PORTS, 1):
            source.extend((f'    if {selector} == {ordinal}:', f'        return {result(name)}'))
        source.append(f'    return {default}')
    return '\n'.join(source) + '\n'


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'worker_artifact_authority')),
                            encoding='utf-8')
