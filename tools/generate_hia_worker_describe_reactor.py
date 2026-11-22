"""Author the live native Describe worker's custody and continuation controls.

The descriptor transport supplies observed fd properties and exact retained
bytes. The HIA reactor decides which trusted role may run and which slices
may be used, without granting any request authority over executable fds.
"""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_readonly_worker_capsule import DESCRIBE_ROLES, DOSSIER_HEADER
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_describe_reactor.hepta')
CONTROLS = {
    'ENTRY': b'HIADRI01',
    'ROUTE': b'HIADRJ01',
    'EFFECT': b'HIADRE01',
    'TERMINAL': b'HIADRT01',
    'ADMITTED': b'HIADRA01',
    'JOURNAL': b'HIADRQ01',
    'RECIPE': b'HIADRZ01',
    'PUBLICATION': b'HIADRU01',
    'DOSSIER': b'HIARWD01',
    'JOURNAL_REPLY': b'HIAJWO01',
    'ADMIT_HEADER': b'HIAWRA01',
}
BAD = 0xfffffffd
COUNT = len(DESCRIBE_ROLES)
ENTRY_HEAD = 64
DESCRIPTOR_BYTES = 40

POLICY = r'''
def describe_reactor(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < 368:
        return BAD
    phase = input_word(s, 0)
    if phase == ENTRY:
        return admit_entry(s, o)
    if phase == ROUTE:
        return journal_continuation(s, o)
    if phase == EFFECT:
        return discovery_recipe(s, o)
    if phase == TERMINAL:
        return terminal_publication(s, o)
    return BAD

# [tag, request size, dossier size, metadata size, dossier fd, metadata fd,
#  dossier seals, metadata seals, original dossier header,
#  repeated fd, F_GET_SEALS, S_IFMT mode, byte length, ELF magic].
# The descriptor snapshots refer to actual opened fds, not request numbers.
def admit_entry(s:readbuf, o:mutbuf) -> u64:
    if length(s) != ENTRY_BYTES:
        return BAD
    n = input_word(s, 8)
    dossier = input_word(s, 16)
    metadata = input_word(s, 24)
    dossier_fd = input_word(s, 32)
    metadata_fd = input_word(s, 40)
    if n < 2 or n > MAX_INPUT or dossier < DOSSIER_HEAD or dossier > 1048576:
        return BAD
    if metadata < 224 or metadata > 32768 or valid_fd(dossier_fd) == False or valid_fd(metadata_fd) == False:
        return BAD
    if dossier_fd == metadata_fd or input_word(s, 48) != 15 or input_word(s, 56) != 15:
        return BAD
    if dossier_identity(s, dossier) == False or trusted_descriptors(s, dossier_fd, metadata_fd) == False:
        return BAD
    put(o, 0, ADMITTED)
    put(o, 8, 0)
    put(o, 16, n)
    put(o, 24, DOSSIER_HEAD)
    put(o, 32, input_word(s, ENTRY_HEAD + 24))
    put(o, 40, input_word(s, ENTRY_HEAD + 32))
    put(o, 48, input_word(s, ENTRY_HEAD + 40))
    put(o, 56, input_word(s, ENTRY_HEAD + 8))
    put(o, 64, input_word(s, ENTRY_HEAD + 16))
    put(o, 72, ADMIT_HEADER)
    put(o, 80, input_word(s, ENTRY_HEAD + 8))
    copy_span(s, o, ENTRY_HEAD + 56, 88, 256)
    return 344

def valid_fd(fd:u64) -> bool:
    return fd >= 3 and fd <= 2147483647

def dossier_identity(s:readbuf, size:u64) -> bool:
    p = ENTRY_HEAD
    if input_word(s, p) != DOSSIER or input_word(s, p + 48) != 0:
        return False
    digits = input_word(s, p + 8)
    helpers = input_word(s, p + 16)
    if (digits != 0 and digits < 640) or digits > 2147483647 or helpers > 1:
        return False
    catalog = input_word(s, p + 24)
    current = input_word(s, p + 32)
    pinned = input_word(s, p + 40)
    if catalog == 0 or current == 0 or pinned == 0 or catalog > size or current > size or pinned > size:
        return False
    if DOSSIER_HEAD + catalog + current + pinned != size:
        return False
    index = 0
    while index < 256:
        value = byte(s, p + 56 + index)
        if helpers == 1 or index < 192:
            if is_hex(value) == False:
                return False
        elif value != 0:
            return False
        index = index + 1
    return True

def is_hex(v:u64) -> bool:
    return (v >= 48 and v <= 57) or (v >= 97 and v <= 102)

def trusted_descriptors(s:readbuf, dossier:u64, metadata:u64) -> bool:
    start = ENTRY_HEAD + DOSSIER_HEAD
    index = 0
    while index < ROLE_COUNT:
        at = start + DESCRIPTOR_BYTES * index
        fd = input_word(s, at)
        if valid_fd(fd) == False or fd == dossier or fd == metadata:
            return False
        if input_word(s, at + 8) != 15 or input_word(s, at + 16) != 32768 or input_word(s, at + 24) < 64:
            return False
        if input_word(s, at + 24) > 16777216 or input_word(s, at + 32) != ELF_MAGIC:
            return False
        previous = 0
        while previous < index:
            if input_word(s, start + DESCRIPTOR_BYTES * previous) == fd:
                return False
            previous = previous + 1
        index = index + 1
    return True

# Trusted Journal observation is not a free-standing instruction. Its
# echoed stage must match the one this process actually issued, and the
# allowed predecessor/next-stage relation is checked before effects.
# [tag, issued stage, raw journal reply extent, HIAJWO01 row].
def journal_continuation(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 88 or input_word(s, 24) != JOURNAL_REPLY:
        return BAD
    stage = input_word(s, 8)
    size = input_word(s, 16)
    if size > MAX_INPUT or input_word(s, 32) != stage:
        return BAD
    choice = input_word(s, 40)
    status = input_word(s, 48)
    body = input_word(s, 56)
    body_n = input_word(s, 64)
    state = input_word(s, 72)
    state_n = input_word(s, 80)
    if body > size or body_n > size - body or state > size or state_n > size - state:
        return BAD
    if state_n != 0 and state_n != 512:
        return BAD
    if stage_edge(stage, choice, status, body_n) == False:
        return BAD
    put(o, 0, JOURNAL)
    put(o, 8, 0)
    copy_span(s, o, 32, 16, 56)
    return 72

def stage_edge(stage:u64, choice:u64, status:u64, size:u64) -> bool:
    if stage == 9:
        return choice == 0
    if stage == 0:
        return choice == 11
    if stage == 11:
        return choice == 12
    if stage == 12:
        return choice == 5
    if stage == 5:
        return choice == 16
    if stage == 13 or stage == 14:
        return choice == 17 and size <= 192
    if stage == 8:
        return choice == 18 and (status == 1 or status == 2)
    return False

# [tag, raw HIA discovery result], either an eight-byte refusal or the
# original length, fixed recipe header and exact language authority bytes.
# Returned offsets are relative to the original discovery stdout (sans tag).
def discovery_recipe(s:readbuf, o:mutbuf) -> u64:
    extent = length(s) - 8
    if extent < 8:
        return BAD
    first = input_word(s, 8)
    put(o, 0, RECIPE)
    if first >= 4294967000:
        if extent != 8:
            return BAD
        put(o, 8, 1)
        put(o, 16, first)
        put(o, 24, 0)
        put(o, 32, 0)
        return 40
    if first != extent - 8 or first <= 32 or first > 65568:
        return BAD
    version = input_word(s, 16)
    if version < 1 or version > 9:
        return BAD
    put(o, 8, 0)
    put(o, 16, version)
    put(o, 24, 40)
    put(o, 32, first - 32)
    return 40

# The public report is released only after Journal terminal status agrees
# with the effect outcome and the independently owned cost slot committed.
# Input includes byte count and actual observed last byte, not a trust flag.
def terminal_publication(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 56:
        return BAD
    expected = input_word(s, 8)
    journal = input_word(s, 16)
    cost = input_word(s, 24)
    size = input_word(s, 32)
    end = input_word(s, 40)
    if expected < 1 or expected > 2 or journal != expected or cost != 1:
        return BAD
    if size < 3 or size > MAX_INPUT + 1 or end != 10 or input_word(s, 48) != 0:
        return BAD
    put(o, 0, PUBLICATION)
    put(o, 8, 0)
    put(o, 16, size)
    return 24

def copy_span(s:readbuf, o:mutbuf, src:u64, dst:u64, extent:u64) -> u64:
    p = 0
    while p < extent:
        store(o, dst + p, byte(s, src + p))
        p = p + 1
    return p
'''


def program():
    constants = {name: int.from_bytes(tag, 'little') for name, tag in CONTROLS.items()}
    constants.update(BAD=BAD, MAX_INPUT=8 << 20, ROLE_COUNT=COUNT, ENTRY_HEAD=ENTRY_HEAD,
                     DESCRIPTOR_BYTES=DESCRIPTOR_BYTES, DOSSIER_HEAD=DOSSIER_HEADER,
                     ELF_MAGIC=int.from_bytes(b'\x7fELF', 'little'),
                     ENTRY_BYTES=ENTRY_HEAD + DOSSIER_HEADER + COUNT * DESCRIPTOR_BYTES)
    source = re.sub(r'\b(' + '|'.join(constants) + r')\b', lambda found: str(constants[found[0]]), POLICY)
    return '\n'.join((source, function(authority(), 'input_word'),
                      *(function(RELEASE_WRITER, name) for name in ('put', 'write'))))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
