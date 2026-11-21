"""Author HIA authentication of one retained-read Worker capability set.

The caller supplies the administrator-selected SHA-256 in the read-only
portion of the output ABI. Bytes are captured and sealed before this policy;
neither untrusted request JSON nor a filesystem path selects a capability.
"""
from __future__ import annotations

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_stdio import ROOT, document
from tools.generate_hia_sha256 import source_program as sha256_program

SOURCE = 'examples/hia_bootstrap/worker_read_capsule.hepta'
# The order is the private descriptor ABI, not a search path.
ROLES = (
    'hia-worker-admit', 'hia-worker-journal-call', 'hia-agent-worker-arguments',
    'hia-agent-mcp-input-schema', 'hia-agent-journal-read-workflow', 'hia-agent-journal',
    'hia-agent-read-carrier', 'hia-agent-store', 'hia-agent-store-ready',
    'hia-agent-read-effect', 'hia-agent-read-request', 'hia-agent-read-page', 'hia-worker-data',
    'hia-artifact', 'hia-agent-store-unique', 'hia-worker-response',
    'hia-agent-mcp-response-schema', 'hia-agent-journal-cost', 'hia-worker-terminal',
)
MANIFEST_MAGIC = b'HIARCP01'
DOSSIER_MAGIC = b'HIARWD01'
ELF_MAGIC = 0x464c457f
MAX_ROLE_BYTES = 8 << 20
HEADER_BYTES = 40
ROW_BYTES = 48
DOSSIER_OFFSET = HEADER_BYTES + len(ROLES) * ROW_BYTES
DOSSIER_HEADER = 312


def source_program():
    source = f"""
def authenticate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 88 or length(w) < 1088:
        return 0
    extent = get(o, 80)
    if extent < 2 or extent > {MAX_ROLE_BYTES} or length(s) != extent:
        return 0
    operation = get(o, 64)
    role = get(o, 72)
    if operation == 1:
        if role != 0 or manifest_shape(s) == False:
            return 0
    elif operation == 2:
        if role == 0 or role > {len(ROLES)} or extent < 64:
            return 0
        if capsule_word(s, 0) & 4294967295 != {ELF_MAGIC}:
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
    at = {DOSSIER_OFFSET}
    if length(s) < at + {DOSSIER_HEADER} or length(s) > 1048576:
        return False
    if capsule_word(s, 0) != {int.from_bytes(MANIFEST_MAGIC, 'little')}:
        return False
    if capsule_word(s, 8) != 1 or capsule_word(s, 16) != {len(ROLES)}:
        return False
    if capsule_word(s, 24) != length(s) - at or capsule_word(s, 32) != 0:
        return False
    if capsule_word(s, at) != {int.from_bytes(DOSSIER_MAGIC, 'little')} or capsule_word(s, at + 48) != 0:
        return False
    if capsule_word(s, at + 16) > 1:
        return False
    digits = capsule_word(s, at + 8)
    if digits > 2147483647 or (digits != 0 and digits < 640):
        return False
    catalog = capsule_word(s, at + 24)
    actual = capsule_word(s, at + 32)
    selected = capsule_word(s, at + 40)
    remaining = length(s) - at - {DOSSIER_HEADER}
    if catalog == 0 or actual == 0 or selected == 0 or catalog > remaining:
        return False
    if actual > remaining - catalog or selected != remaining - catalog - actual:
        return False
    index = 0
    while index < {len(ROLES)}:
        row = {HEADER_BYTES} + index * {ROW_BYTES}
        extent = capsule_word(s, row + 8)
        if capsule_word(s, row) != index + 1 or extent < 64 or extent > {MAX_ROLE_BYTES}:
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
"""
    return source + '\n' + sha256_program()


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render_assembly(document(source_program(), 'worker_read_capsule')),
                               encoding='utf-8')
