"""Author the fixed startup discovery-role plan for a private Store instance."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_discovery_native import DISCOVERY_RESOURCE_NAMES, PROFILE_NAMES, VERSIONS
from tools.generate_hia_artifact_publication import document

SOURCE = 'examples/hia_bootstrap/discovery_bootstrap_plan.hepta'
BOOTSTRAP_FILES = (
    ('assembly_grammar', 'HIA_AGENT_ASSEMBLY.md'),
    ('core_language', 'HIA_PROGRAM.md'),
    ('machine_plan_guide', 'HIA_AGENT_MACHINE_PLANS.md'),
    ('proof_contract_guide', 'HIA_AGENT_PROOF_RESULTS.md'),
    ('machine_validation_guide', 'HIA_SAFE_CORE_MACHINE_VALIDATION.md'),
    ('buffer_lifecycle_guide', 'HIA_AGENT_BUFFER_LIFECYCLE.md'),
    ('macro_policy_guide', 'HIA_AGENT_MACRO_POLICY.md'),
    ('byte_bootstrap_guide', 'HIA_DIRECT_BYTE_BOOTSTRAP.md'),
    ('self_hosting_core_guide', 'HIA_SELF_HOSTING_CORE.md'),
    ('self_hosting_core_support', 'HIA_SELFHOST_CORE_SUPPORT.json'),
)
FIRST_REGISTRY = len(PROFILE_NAMES)
FIRST_RESOURCE = FIRST_REGISTRY + 1
FIRST_FILE = FIRST_RESOURCE + len(DISCOVERY_RESOURCE_NAMES)
MACRO = FIRST_FILE + len(BOOTSTRAP_FILES)

POLICY = r'''
def bootstrap_plan(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 179 or length(o) < 8192 or word(s, 0) != REQUEST:
        return 4294967293
    slot = word(s, 8)
    identities = word(s, 16)
    digits = word(s, 24)
    if slot > MACRO or identities < 2 or identities > 4096 or digits == 0 or digits > 2:
        return 4294967293
    if word(s, 32) != 0 or word(s, 40) != 0 or length(s) != 176 + identities + digits:
        return 4294967293
    if hex_pin(s, 48) == False or hex_pin(s, 112) == False:
        return 4294967293
    if root_count(s, 176 + identities, digits) == False:
        return 4294967293
    put(o, 0, PLAN)
    put(o, 8, 1)
    put(o, 16, 0)
    if slot < FIRST_REGISTRY:
        put(o, 16, FIRST_PROFILE + slot)
        return profile_packet(s, o, slot + 1, identities, digits, False)
    if slot == FIRST_REGISTRY:
        put(o, 24, 8)
        put(o, 32, REGISTRY)
        return 40
    if slot < FIRST_FILE:
        put(o, 24, 16)
        put(o, 32, RESOURCE)
        put(o, 40, slot - FIRST_RESOURCE + 1)
        return 48
    if slot == MACRO:
        return profile_packet(s, o, MACRO_ROLE, identities, digits, True)
    put(o, 8, 2)
    return document_name(o, slot)

def profile_packet(s:readbuf, o:mutbuf, role:u64, identities:u64, digits:u64, macro:bool) -> u64:
    put(o, 32, PROFILE)
    put(o, 40, role)
    put(o, 48, identities)
    index = 56
    while index < 104:
        put(o, index, 0)
        index = index + 8
    out = copy(s, o, 176, 104, identities)
    if macro == False:
        put(o, 56, 64)
        put(o, 64, digits)
        put(o, 72, 64)
        out = copy(s, o, 48, out, 64)
        out = copy(s, o, 176 + identities, out, digits)
        out = copy(s, o, 112, out, 64)
    put(o, 24, out - 32)
    return out

def root_count(s:readbuf, at:u64, digits:u64) -> bool:
    first = byte(s, at)
    if first < 48 or first > 57:
        return False
    if digits == 1:
        return True
    last = byte(s, at + 1)
    if first == 48 or last < 48 or last > 57:
        return False
    return (first - 48) * 10 + last - 48 <= 32

def hex_pin(s:readbuf, at:u64) -> bool:
    end = at + 64
    while at < end:
        value = byte(s, at)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return False
        at = at + 1
    return True

def copy(s:readbuf, o:mutbuf, at:u64, out:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, out + i, byte(s, at + i))
        i = i + 1
    return out + size

def word(s:readbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, value >> (i * 8) & 255)
        i = i + 1
    return 0
'''


def source_program():
    tags = {'REQUEST': b'HIADBQ01', 'PLAN': b'HIADBP01', 'REGISTRY': b'HIADISRG',
            'RESOURCE': b'HIADISRS', 'PROFILE': b'HIADISPF'}
    constants = {name: int.from_bytes(raw, 'little') for name, raw in tags.items()}
    constants.update(FIRST_REGISTRY=FIRST_REGISTRY, FIRST_RESOURCE=FIRST_RESOURCE, FIRST_FILE=FIRST_FILE,
                     MACRO=MACRO, FIRST_PROFILE=len(VERSIONS) + 1, MACRO_ROLE=len(PROFILE_NAMES) + 2)
    source = POLICY
    for name, value in constants.items():
        source = re.sub(rf'\b{name}\b', str(value), source)
    source += '\ndef document_name(o:mutbuf, slot:u64) -> u64:\n'
    for slot, (name, _) in enumerate(BOOTSTRAP_FILES, FIRST_FILE):
        source += f'    if slot == {slot}:\n        return file_{name}(o)\n'
    source += '    return 4294967293\n'
    for name, filename in BOOTSTRAP_FILES:
        raw = filename.encode('ascii')
        source += f'\ndef file_{name}(o:mutbuf) -> u64:\n    put(o, 24, {len(raw)})\n'
        for index, value in enumerate(raw):
            source += f'    store(o, {32 + index}, {value})\n'
        source += f'    return {32 + len(raw)}\n'
    return source


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'discovery_bootstrap_plan')),
                            encoding='utf-8')
