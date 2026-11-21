"""Author the manifest and Worker metadata from durable discovery receipts."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_discovery_native import DISCOVERY_RESOURCE_NAMES, PROFILE_NAMES, RESOURCE_ROLES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_bootstrap_plan import BOOTSTRAP_FILES

SOURCE = 'examples/hia_bootstrap/discovery_bootstrap_assemble.hepta'
RESOURCES = ('schema_registry', *DISCOVERY_RESOURCE_NAMES, *(name for name, _ in BOOTSTRAP_FILES), 'macro_policy')
MANIFEST_SLOT = len(PROFILE_NAMES) + len(RESOURCES)

POLICY = r'''
def discovery_bootstrap_assemble(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 90 or length(o) < 32768 or length(w) < SLOT_COUNT * 24:
        return 4294967293
    operation = word(s, 0)
    if operation != MANIFEST_REQUEST and operation != METADATA_REQUEST:
        return 4294967293
    count = choose(operation == MANIFEST_REQUEST, MANIFEST_SLOT, SLOT_COUNT)
    identities = word(s, 8)
    if word(s, 16) != 0 or identities < 2 or identities > 4096 or identities > length(s) - 88:
        return 4294967293
    if valid_hex(s, 24, 64) == False or byte(s, 88) != 123 or byte(s, 87 + identities) != 125:
        return 4294967293
    at = 88 + identities
    slot = 0
    while slot < count:
        if at > length(s) or length(s) - at < 272:
            return 4294967293
        if word(s, at) != slot:
            return 4294967293
        receipt = at + 72
        if word(s, receipt) != DOCUMENT or word(s, receipt + 8) != 176:
            return 4294967293
        size = word(s, receipt + 16)
        ref = receipt + 24
        profile = ref + 176
        if valid_reference(s, ref) == False or same_digest(s, at + 8, ref + 53) == False:
            return 4294967293
        if slot < PROFILE_COUNT:
            name = profile_name_length(slot)
            if size != name + 85 or size > length(s) - profile:
                return 4294967293
            if starts_id(s, profile) == False or profile_name_matches(s, profile + 7, slot) == False:
                return 4294967293
            tail = profile + 7 + name
            if starts_sha(s, tail) == False or same_digest(s, ref + 53, tail + 12) == False:
                return 4294967293
            if byte(s, profile + size - 2) != 34 or byte(s, profile + size - 1) != 125:
                return 4294967293
        elif size != 0:
            return 4294967293
        put(w, slot * 24, ref)
        put(w, slot * 24 + 8, profile)
        put(w, slot * 24 + 16, size)
        at = profile + size
        slot = slot + 1
    if at != length(s):
        return 4294967293
    if operation == MANIFEST_REQUEST:
        return manifest_packet(s, o, w, identities)
    return metadata_packet(s, o, w)

def valid_reference(s:readbuf, at:u64) -> bool:
    if starts_id(s, at) == False or byte(s, at + 7) != 97 or byte(s, at + 8) != 45:
        return False
    if starts_sha(s, at + 41) == False or starts_uri(s, at + 117) == False:
        return False
    if byte(s, at + 174) != 34 or byte(s, at + 175) != 125:
        return False
    return valid_hex(s, at + 9, 32) and valid_hex(s, at + 53, 64) and valid_hex(s, at + 142, 32)

def valid_hex(s:readbuf, at:u64, size:u64) -> bool:
    end = at + size
    while at < end:
        value = byte(s, at)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return False
        at = at + 1
    return True

def same_digest(s:readbuf, a:u64, b:u64) -> bool:
    at = 0
    while at < 64:
        if word(s, a + at) != word(s, b + at):
            return False
        at = at + 8
    return True

def manifest_packet(s:readbuf, o:mutbuf, w:mutbuf, identities:u64) -> u64:
    put(o, 0, PROFILE_REQUEST)
    put(o, 8, PROFILE_COUNT + 1)
    put(o, 16, identities)
    put(o, 24, 64)
    put(o, 32, 0)
    put(o, 40, 0)
    out = copy_value(s, o, 88, 72, identities)
    out = copy_value(s, o, 24, out, 64)
    past_profiles = profile_map(s, o, w, out)
    put(o, 48, past_profiles - out)
    past_artifacts = profile_artifact_map(s, o, w, past_profiles)
    put(o, 56, past_artifacts - past_profiles)
    end = resource_map(s, o, w, past_artifacts)
    put(o, 64, end - past_artifacts)
    return end

def append_ref(s:readbuf, o:mutbuf, w:mutbuf, out:u64, slot:u64) -> u64:
    return copy_value(s, o, work_word(w, slot * 24), out, 176)

def append_profile(s:readbuf, o:mutbuf, w:mutbuf, out:u64, slot:u64) -> u64:
    return copy_value(s, o, work_word(w, slot * 24 + 8), out, work_word(w, slot * 24 + 16))

def ref_field(s:readbuf, o:mutbuf, w:mutbuf, out:u64, slot:u64, field:u64) -> u64:
    put(o, 8 + field * 8, 176)
    return append_ref(s, o, w, out, slot)

def profile_field(s:readbuf, o:mutbuf, w:mutbuf, out:u64, slot:u64, field:u64) -> u64:
    put(o, 8 + field * 8, work_word(w, slot * 24 + 16))
    return append_profile(s, o, w, out, slot)

def copy_value(s:readbuf, o:mutbuf, at:u64, out:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, out + i, byte(s, at + i))
        i = i + 1
    return out + count

def word(s:readbuf, at:u64) -> u64:
    count = 0
    value = 0
    while count < 8:
        value = value | (byte(s, at + count) << (count * 8))
        count = count + 1
    return value

def work_word(w:mutbuf, at:u64) -> u64:
    count = 0
    value = 0
    while count < 8:
        value = value | (byte(w, at + count) << (count * 8))
        count = count + 1
    return value

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, value >> (i * 8) & 255)
        i = i + 1
    return 0
'''


def match(name, value):
    clauses = (f'byte(s, at + {index}) == {byte}' for index, byte in enumerate(value))
    return f'\ndef {name}(s:readbuf, at:u64) -> bool:\n    return ' + ' and '.join(clauses) + '\n'


def mapping(name, names, append):
    source = f'\ndef {name}(s:readbuf, o:mutbuf, w:mutbuf, out:u64) -> u64:\n'
    for index, (key, slot) in enumerate(sorted(names.items())):
        prefix = ('{' if index == 0 else ',') + '"' + key + '":'
        for offset, byte in enumerate(prefix.encode('ascii')):
            source += f'    store(o, out + {offset}, {byte})\n'
        source += f'    out = {append}(s, o, w, out + {len(prefix)}, {slot})\n'
    return source + '    store(o, out, 125)\n    return out + 1\n'


def metadata(profiles, resources):
    fields = len(RESOURCE_ROLES) + 5
    source = f'\ndef metadata_packet(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n'
    source += f'    put(o, 0, {int.from_bytes(b"HIADMT01", "little")})\n'
    source += f'    out = {8 + fields * 8}\n'
    for field, name in enumerate(('artifact', 'backend')):
        source += f'    out = profile_field(s, o, w, out, {profiles[name]}, {field})\n'
    source += ('    put(o, 24, 66)\n    store(o, out, 34)\n'
               '    out = copy_value(s, o, 24, out + 1, 64)\n    store(o, out, 34)\n'
               '    out = out + 1\n    put(o, 32, 0)\n')
    source += f'    out = ref_field(s, o, w, out, {MANIFEST_SLOT}, 4)\n'
    for field, (collection, name) in enumerate(RESOURCE_ROLES, 5):
        if collection is None:
            source += f'    put(o, {8 + field * 8}, 0)\n'
            continue
        slot = (MANIFEST_SLOT if collection == 'manifest'
                else profiles[name] if collection == 'profile_artifacts' else resources[name])
        source += f'    out = ref_field(s, o, w, out, {slot}, {field})\n'
    return source + '    return out\n'


def source_program():
    tags = {'MANIFEST_REQUEST': b'HIADBM01', 'METADATA_REQUEST': b'HIADBT01',
            'PROFILE_REQUEST': b'HIADISPF', 'DOCUMENT': b'HIADOC01'}
    constants = {name: int.from_bytes(value, 'little') for name, value in tags.items()}
    constants.update(MANIFEST_SLOT=MANIFEST_SLOT, SLOT_COUNT=MANIFEST_SLOT + 1,
                     PROFILE_COUNT=len(PROFILE_NAMES))
    source = POLICY
    for name, value in constants.items():
        source = re.sub(rf'\b{name}\b', str(value), source)
    for name, value in (('starts_id', b'{"id":"'), ('starts_sha', b'","sha256":"'),
                        ('starts_uri', b'","uri":"hia://artifacts/')):
        source += match(name, value)
    profiles = dict(zip(PROFILE_NAMES, range(len(PROFILE_NAMES)), strict=True))
    resources = {name: slot for slot, name in enumerate(RESOURCES, len(profiles))}
    lengths = '\ndef profile_name_length(slot:u64) -> u64:\n'
    checks = '\ndef profile_name_matches(s:readbuf, at:u64, slot:u64) -> bool:\n'
    for name, slot in profiles.items():
        value = f'hia-{name}-v1'.encode('ascii')
        source += match('name_' + name, value)
        lengths += f'    if slot == {slot}:\n        return {len(value)}\n'
        checks += f'    if slot == {slot}:\n        return name_{name}(s, at)\n'
    source += lengths + '    return 0\n' + checks + '    return False\n'
    source += mapping('profile_map', profiles, 'append_profile')
    source += mapping('profile_artifact_map', profiles, 'append_ref')
    source += mapping('resource_map', resources, 'append_ref')
    return source + metadata(profiles, resources)


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'discovery_bootstrap_assemble')),
                            encoding='utf-8')
