"""Author the native authority for the installed read-only Worker routes."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_read_capsule import DOSSIER_MAGIC, MAX_ROLE_BYTES, ROLES as READ_ROLES
from tools.generate_hia_sha256 import source_program as sha256_program

SOURCE = 'examples/hia_bootstrap/worker_readonly_capsule.hepta'
MANIFEST_MAGIC = b'HIADCP01'
BOOTSTRAP_MAGIC = b'HIADBQ01'
RESOURCES_MAGIC = b'HIADBF01'
DESCRIBE_ROLES = (
    'hia-worker-admit', 'hia-worker-journal-call', 'hia-agent-worker-arguments',
    'hia-agent-mcp-input-schema', 'hia-agent-journal-read-workflow', 'hia-agent-journal',
    'hia-agent-read-carrier', 'hia-agent-store', 'hia-agent-store-ready',
    'hia-agent-discovery-effect', 'hia-agent-describe-request', 'hia-agent-discovery',
    'hia-agent-describe-bind', 'hia-artifact', 'hia-agent-store-unique',
    'hia-worker-response', 'hia-agent-mcp-response-schema', 'hia-agent-journal-cost',
    'hia-worker-terminal', 'hia-agent-discovery-carrier', 'hia-agent-discovery-artifact',
    'hia-agent-describe-answer',
)
BOOTSTRAP_ROLES = (
    'hia-agent-discovery-bootstrap-plan', 'hia-agent-discovery',
    'hia-agent-discovery-bootstrap-assemble', 'hia-agent-discovery-carrier',
    'hia-agent-store-init', 'hia-agent-store', 'hia-agent-store-ready', 'hia-agent-store-unique',
    'hia-artifact', 'hia-agent-discovery-artifact', 'hia-agent-discovery-effect',
)
DESCRIBE_OWNER = 'hia-agent-describe-worker-carrier'
BOOTSTRAP_OWNER = 'hia-agent-discovery-bootstrap-carrier'
ROLES = tuple(dict.fromkeys((*READ_ROLES, *DESCRIBE_ROLES, *BOOTSTRAP_ROLES, DESCRIBE_OWNER, BOOTSTRAP_OWNER)))
CAPSULE_MAX = 4 << 20
HEADER_BYTES = 56
ROW_BYTES = 48
DOSSIER_HEADER = 312
DOSSIER_OFFSET = HEADER_BYTES + len(ROLES) * ROW_BYTES

POLICY = r'''
def authenticate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 88 or length(w) < 1088:
        return 0
    extent = get(o, 80)
    if extent < 2 or extent > ROLE_LIMIT or length(s) != extent:
        return 0
    operation = get(o, 64)
    role = get(o, 72)
    if operation == 3:
        if role != 0:
            return 0
        return route(s)
    if operation == 1:
        if role != 0 or manifest_shape(s) == False:
            return 0
    elif operation == 2:
        if role == 0 or role > ROLE_COUNT or extent < 64:
            return 0
        if capsule_word(s, 0) & 4294967295 != 1179403647:
            return 0
        if byte(s, 4) != 2 or byte(s, 5) != 1 or byte(s, 18) != 62 or byte(s, 19) != 0:
            return 0
    else:
        return 0
    if widen(sha256(s, o, w)) != 32:
        return 0
    at = 0
    while at < 32:
        if byte(o, at) != byte(o, at + 32):
            return 0
        at = at + 1
    return 1

def manifest_shape(s:readbuf) -> bool:
    if length(s) <= DOSSIER_OFFSET + DOSSIER_HEADER or length(s) > CAPSULE_MAX:
        return False
    if capsule_word(s, 0) != MANIFEST or capsule_word(s, 8) != 1:
        return False
    if capsule_word(s, 16) != ROLE_COUNT or capsule_word(s, 48) != 0:
        return False
    dossier = capsule_word(s, 24)
    config = capsule_word(s, 32)
    documents = capsule_word(s, 40)
    if dossier <= DOSSIER_HEADER or dossier > length(s) - DOSSIER_OFFSET:
        return False
    after = DOSSIER_OFFSET + dossier
    if config < 179 or config > 4274 or config > length(s) - after:
        return False
    if documents < 16 or documents != length(s) - after - config:
        return False
    pack = after + config
    if capsule_word(s, pack) != RESOURCES or capsule_word(s, pack + 8) != 10:
        return False
    if dossier_shape(s, dossier, after, config) == False:
        return False
    index = 0
    while index < ROLE_COUNT:
        row = HEADER_BYTES + index * ROW_BYTES
        extent = capsule_word(s, row + 8)
        if capsule_word(s, row) != index + 1 or extent < 64 or extent > ROLE_LIMIT:
            return False
        index = index + 1
    return True

def dossier_shape(s:readbuf, dossier:u64, config_at:u64, config_size:u64) -> bool:
    at = DOSSIER_OFFSET
    if capsule_word(s, at) != DOSSIER or capsule_word(s, at + 48) != 0:
        return False
    if capsule_word(s, at + 16) != 1:
        return False
    digits = capsule_word(s, at + 8)
    if digits > 2147483647 or (digits != 0 and digits < 640):
        return False
    catalog = capsule_word(s, at + 24)
    actual = capsule_word(s, at + 32)
    selected = capsule_word(s, at + 40)
    remaining = dossier - DOSSIER_HEADER
    if catalog == 0 or actual < 2 or actual > 4096 or selected != actual or catalog > remaining:
        return False
    if actual > remaining - catalog or selected != remaining - catalog - actual:
        return False
    if capsule_word(s, config_at) != BOOTSTRAP or capsule_word(s, config_at + 8) != 0:
        return False
    if capsule_word(s, config_at + 16) != actual:
        return False
    root_digits = capsule_word(s, config_at + 24)
    if root_digits < 1 or root_digits > 2 or config_size != 176 + actual + root_digits:
        return False
    if capsule_word(s, config_at + 32) != 0 or capsule_word(s, config_at + 40) != 0:
        return False
    identities = at + DOSSIER_HEADER + catalog
    if byte(s, identities) != 123 or byte(s, identities + actual - 1) != 125:
        return False
    return same_range(s, at + 56, config_at + 48, 64) and same_range(s, identities, identities + actual, actual) and same_range(s, identities, config_at + 176, actual)

def same_range(s:readbuf, a:u64, b:u64, count:u64) -> bool:
    index = 0
    while index < count:
        if byte(s, a + index) != byte(s, b + index):
            return False
        index = index + 1
    return True

def capsule_word(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value

def widen(value:u32) -> u64:
    return value
'''


def routing():
    # Only the response of the pinned admit process enters this mode. Its
    # canonical serialization guarantees sorted keys and an unescaped tool.
    source = '\ndef route(s:readbuf) -> u32:\n    if byte(s, 0) != 123:\n        return 0\n'
    schema = b',"schema":"hia-agent-worker-request-v1","tool":"'
    methods = ((1, b'hia_read'), (2, b'hia_describe'))
    for result, method in methods:
        suffix = schema + method + b'"}'
        source += f'    if length(s) > {len(suffix)} and match_{result}(s, length(s) - {len(suffix)}):\n'
        source += f'        return {result}\n'
    source += '    return 0\n'
    for result, method in methods:
        suffix = schema + method + b'"}'
        source += f'\ndef match_{result}(s:readbuf, at:u64) -> bool:\n    return '
        source += ' and '.join(f'byte(s, at + {i}) == {value}' for i, value in enumerate(suffix))
        source += '\n'
    return source


def source_program():
    tags = {'MANIFEST': MANIFEST_MAGIC, 'DOSSIER': DOSSIER_MAGIC,
            'BOOTSTRAP': BOOTSTRAP_MAGIC, 'RESOURCES': RESOURCES_MAGIC}
    constants = {name: int.from_bytes(raw, 'little') for name, raw in tags.items()}
    constants.update(CAPSULE_MAX=CAPSULE_MAX, HEADER_BYTES=HEADER_BYTES, ROW_BYTES=ROW_BYTES,
                     DOSSIER_HEADER=DOSSIER_HEADER, DOSSIER_OFFSET=DOSSIER_OFFSET,
                     ROLE_COUNT=len(ROLES), ROLE_LIMIT=MAX_ROLE_BYTES)
    source = POLICY
    for name, value in constants.items():
        source = re.sub(rf'\b{name}\b', str(value), source)
    return source + routing() + '\n' + sha256_program()


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'worker_readonly_capsule')),
                            encoding='utf-8')
