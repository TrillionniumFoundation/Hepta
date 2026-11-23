"""Author the installed Worker launcher, sharing the exact capsule authority."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_read_capsule import ROLES as READ_ROLES
from tools.generate_hia_readonly_worker_capsule import (
    ADOPT_OWNER, ADOPT_ROLES,
    ARTIFACT_OWNER, ARTIFACT_ROLES, BOOTSTRAP_OWNER, BOOTSTRAP_ROLES,
    CANDIDATE_OWNER, CANDIDATE_ROLES, CONTEXT_OWNER, CONTEXT_ROLES, DESCRIBE_OWNER, DESCRIBE_ROLES,
    EMIT_OWNER, EMIT_ROLES, INSPECTION_OWNER, INSPECTION_ROLES, NATIVE_ROLES, PROOF_TRUST_BYTES,
    ROLLBACK_OWNER, ROLLBACK_ROLES, VERIFY_OWNER, VERIFY_ROLES,
    POLICY as CAPSULE_POLICY,
)
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE, flow_source
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_sha256 import source_program as sha256_program

SOURCE = Path('examples/hia_bootstrap/worker_launcher_flow.hepta')

ROUTES = (
    ('hia-agent-read-carrier', '--worker-read', READ_ROLES),
    (DESCRIBE_OWNER, '--worker-describe', DESCRIBE_ROLES),
    (ARTIFACT_OWNER, '--worker-artifact', ARTIFACT_ROLES),
    (CONTEXT_OWNER, '--worker-context', CONTEXT_ROLES),
    (INSPECTION_OWNER, '--worker-inspection', INSPECTION_ROLES),
    (CANDIDATE_OWNER, '--worker-candidate', CANDIDATE_ROLES),
    (ROLLBACK_OWNER, '--worker-rollback', ROLLBACK_ROLES),
    (EMIT_OWNER, '--worker-emit', EMIT_ROLES),
    (ADOPT_OWNER, '--worker-adopt', ADOPT_ROLES),
    (VERIFY_OWNER, '--worker-verify', VERIFY_ROLES),
)

POLICY = r'''
def launcher(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 2048 or length(w) != 4096:
        return BAD
    state = get(w, 0)
    if state == 0:
        return begin_launch(s, o, w)
    if length(s) < 64 or capsule_word(s, 0) != OBSERVATION or capsule_word(s, 8) != get(w, 8):
        return BAD
    op = get(w, 16)
    if capsule_word(s, 16) != op or capsule_word(s, 24) != 0:
        return BAD
    bytes = capsule_word(s, 40)
    offset = choose(op == READ, capsule_word(s, 48), 0)
    captured = capsule_word(s, 56)
    if bytes > MAX_REQUEST + 1 or offset > bytes or captured > bytes - offset or captured != length(s) - 64:
        return BAD
    if op == READ and (capsule_word(s, 32) != get(w, 72) or offset != get(w, 80) or captured != get(w, 88)):
        return BAD
    if state <= RELEASE_DIRECTORY:
        return bind_capsule(s, o, w, state)
    if state <= ROLE_AUTHORIZED:
        return bind_role(s, o, w, state)
    if state <= PART_MADE:
        return bind_parts(s, o, w, state)
    return dispatch(s, o, w, state)

def begin_launch(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 73 or capsule_word(s, 0) != ENTRY:
        return BAD
    if byte(s, 8) != 47:
        return BAD
    i = 0
    while i < 32:
        first = hex_digit(byte(s, 9 + 2 * i))
        next = hex_digit(byte(s, 10 + 2 * i))
        if first > 15 or next > 15:
            return BAD
        store(w, PIN + i, 16 * first + next)
        i = i + 1
    put(o, 144, 0)
    put(o, 152, MAX_CAPSULE)
    return issue(o, w, CAPSULE_CAPTURED, SNAPSHOT, 0, 0, 0, 0)

def hex_digit(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    return 16

def bound_fd(s:readbuf) -> bool:
    fd = capsule_word(s, 32)
    return fd >= 3 and fd <= 2147483647

def bind_capsule(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == CAPSULE_CAPTURED:
        size = capsule_word(s, 40)
        if bound_fd(s) == False or size < BODY_OFFSET + 312 or size > MAX_CAPSULE:
            return BAD
        fd = capsule_word(s, 32)
        put(w, CAPSULE_FD, fd)
        put(w, CAPSULE_BYTES, size)
        return ask_authority(o, w, CAPSULE_AUTHORIZED, 1, 0, fd, size)
    if state == CAPSULE_AUTHORIZED:
        if auth_result(s) != 1:
            return BAD
        return read_span(o, w, CAPSULE_HEADER, get(w, CAPSULE_FD), 24, 32)
    if state == CAPSULE_HEADER:
        start = BODY_OFFSET
        i = 0
        while i < 4:
            extent = capsule_word(s, 64 + i * 8)
            if extent == 0 or extent > get(w, CAPSULE_BYTES) - start:
                return BAD
            if i == 0:
                if extent <= PROOF_TRUST_BYTES + 312:
                    return BAD
                put(w, PART_TABLE + 104, start + extent - PROOF_TRUST_BYTES)
                put(w, PART_TABLE + 112, PROOF_TRUST_BYTES)
            put(w, PART_TABLE + i * 24 + 8, start)
            put(w, PART_TABLE + i * 24 + 16, extent - choose(i == 0, PROOF_TRUST_BYTES, 0))
            start = start + extent
            i = i + 1
        if start != get(w, CAPSULE_BYTES):
            return BAD
        return issue(o, w, RELEASE_DIRECTORY, OPEN_RELEASE, 0, 0, 0, 0)
    if length(s) != 88 or bound_fd(s) == False or capsule_word(s, 64) != capsule_word(s, 72):
        return BAD
    mode = capsule_word(s, 80)
    if (mode & 61440) != 16384 or (mode & 18) != 0:
        return BAD
    put(w, RELEASE_FD, capsule_word(s, 32))
    return next_role(o, w)

def next_role(o:mutbuf, w:mutbuf) -> u64:
    role = get(w, ROLE_INDEX)
    if role == ROLE_COUNT:
        return next_part(o, w)
    return read_span(o, w, ROLE_ROW, get(w, CAPSULE_FD), 56 + role * 48, 48)

def bind_role(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    role = get(w, ROLE_INDEX)
    if state == ROLE_ROW:
        extent = capsule_word(s, 72)
        if capsule_word(s, 64) != role + 1 or extent < 64 or extent > MAX_REQUEST:
            return BAD
        copy_span(s, w, 80, PIN, 32)
        put(w, ROLE_BYTES, extent)
        put(o, 144, get(w, RELEASE_FD))
        put(o, 152, MAX_REQUEST)
        width = role_name(o, HEADER, role)
        if width == 0:
            return BAD
        return issue(o, w, ROLE_CAPTURED, SNAPSHOT, 0, 0, 0, width)
    if state == ROLE_CAPTURED:
        extent = get(w, ROLE_BYTES)
        if bound_fd(s) == False or capsule_word(s, 40) != extent:
            return BAD
        fd = capsule_word(s, 32)
        put(w, ROLE_TABLE + role * 8, fd)
        return ask_authority(o, w, ROLE_AUTHORIZED, 2, role + 1, fd, extent)
    if auth_result(s) != 1:
        return BAD
    put(w, ROLE_INDEX, role + 1)
    return next_role(o, w)

def ask_authority(o:mutbuf, w:mutbuf, state:u64, mode:u64, role:u64, fd:u64, size:u64) -> u64:
    zero(o, HEADER, 32)
    copy_private(w, o, PIN, HEADER + 32, 32)
    put(o, HEADER + 64, mode)
    put(o, HEADER + 72, role)
    put(o, HEADER + 80, size)
    put(o, 144, fd)
    return issue(o, w, state, AUTHORIZE, 0, 0, 0, 88)

def auth_result(s:readbuf) -> u64:
    if length(s) != 72 or capsule_word(s, 40) != 8:
        return 0
    return capsule_word(s, 64)

def next_part(o:mutbuf, w:mutbuf) -> u64:
    index = get(w, PART_INDEX)
    if index == 5:
        put(o, 152, REQUEST_LEASE)
        return issue(o, w, INPUT_CAPTURED, CAPTURE_INPUT, 0, 0, 0, 0)
    row = PART_TABLE + 24 * index
    fragment(o, 0, get(w, CAPSULE_FD), get(w, row + 8), get(w, row + 16))
    return issue(o, w, PART_MADE, MAKE, 0, 0, 1, 0)

def bind_parts(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    index = get(w, PART_INDEX)
    row = PART_TABLE + 24 * index
    if state != PART_MADE or bound_fd(s) == False or capsule_word(s, 40) != get(w, row + 16):
        return BAD
    put(w, row, capsule_word(s, 32))
    put(w, PART_INDEX, index + 1)
    if index != 0:
        return next_part(o, w)
    return read_span(o, w, DOSSIER_PINS, get(w, row), 0, 120)

def dispatch(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = capsule_word(s, 40)
    fd = capsule_word(s, 32)
    if state == DOSSIER_PINS:
        put(w, DIGITS, capsule_word(s, 72))
        copy_span(s, w, 120, CATALOG, 64)
        return next_part(o, w)
    if state == INPUT_CAPTURED:
        if bound_fd(s) == False or size < 2 or size > MAX_REQUEST:
            return BAD
        put(w, REQUEST_FD, fd)
        put(w, REQUEST_BYTES, size)
        put(o, HEADER, ADMISSION)
        put(o, HEADER + 8, get(w, DIGITS))
        copy_private(w, o, CATALOG, HEADER + 16, 64)
        fragment(o, 0, fd, 0, size)
        child_name(o, ADMIT)
        return issue(o, w, REQUEST_ADMITTED, RUN, role_fd(w, ADMIT), 0, 1, 80)
    if state == REQUEST_ADMITTED:
        if bound_fd(s) == False or size < 2 or size > MAX_REQUEST:
            return BAD
        return ask_authority(o, w, ROUTE_BOUND, 3, 0, fd, size)
    if state == ROUTE_BOUND:
        route = auth_result(s)
        if route < 1 or route > NATIVE_ROUTE_COUNT:
            return BAD
        put(w, ROUTE, route)
        return launch_bootstrap(o, w)
    if state == BOOTSTRAPPED:
        if bound_fd(s) == False or size < 224 or size > 32768 or capsule_word(s, 48) != 15:
            return BAD
        put(w, DISCOVERY_META, fd)
        return launch_worker(o, w, get(w, ROUTE))
    if state == WORKER_DONE:
        if bound_fd(s) == False or size < 3 or size > MAX_REQUEST + 1 or capsule_word(s, 48) != 15:
            return BAD
        fragment(o, 0, fd, 0, size)
        return issue(o, w, PUBLISHED, PUBLISH, 0, 0, 1, 0)
    if state == PUBLISHED and length(s) == 64:
        return issue(o, w, PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD

def role_fd(w:mutbuf, role:u64) -> u64:
    return get(w, ROLE_TABLE + role * 8)

def child_name(o:mutbuf, role:u64) -> u64:
    put(o, 168, 384)
    return role_name(o, 384, role)

def launch_bootstrap(o:mutbuf, w:mutbuf) -> u64:
    argv(o, 0, INPUT_ARG, 1)
    argv(o, 1, INPUT_ARG, 2)
    argv(o, 2, FD_ARG, get(w, PART_TABLE + 48))
    count = append_roles(o, w, BOOTSTRAP_ROUTE, 3)
    fragment(o, 0, get(w, PART_TABLE + 24), 0, get(w, PART_TABLE + 40))
    child_name(o, BOOTSTRAP)
    return issue(o, w, BOOTSTRAPPED, RUN, role_fd(w, BOOTSTRAP), count, 1, 0)

def launch_worker(o:mutbuf, w:mutbuf, route:u64) -> u64:
    mode = route_mode(o, route)
    owner = route_owner(route)
    if mode == 0 or owner >= ROLE_COUNT:
        return BAD
    if route == EMIT_ROUTE and length(o) < 1024 + 16 * EMIT_ARG_COUNT:
        return BAD
    if route == ADOPT_ROUTE and length(o) < 1024 + 16 * ADOPT_ARG_COUNT:
        return BAD
    if route == VERIFY_ROUTE and length(o) < 1024 + 16 * VERIFY_ARG_COUNT:
        return BAD
    argv(o, 0, LITERAL_ARG, 448)
    argv(o, 1, INPUT_ARG, 1)
    argv(o, 2, INPUT_ARG, 2)
    argv(o, 3, FD_ARG, get(w, PART_TABLE))
    count = 4
    if route != 1:
        metadata = choose(route == 3, get(w, PART_TABLE + 72), get(w, DISCOVERY_META))
        argv(o, count, FD_ARG, metadata)
        count = count + 1
    if route == EMIT_ROUTE or route == ADOPT_ROUTE or route == VERIFY_ROUTE:
        argv(o, count + PROOF_ROLE, FD_ARG, get(w, PART_TABLE + 96))
    count = append_roles(o, w, route, count)
    child_name(o, owner)
    fragment(o, 0, get(w, REQUEST_FD), 0, get(w, REQUEST_BYTES))
    return issue(o, w, WORKER_DONE, RUN, role_fd(w, owner), count, 1, 0)

def argv(o:mutbuf, index:u64, kind:u64, value:u64) -> u64:
    at = 1024 + 16 * index
    put(o, at, kind)
    put(o, at + 8, value)
    return 0

def zero(o:mutbuf, offset:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, offset + i, 0)
        i = i + 1
    return 0
'''


def emit_literal(raw, offset):
    data = raw + b'\0'
    return ''.join(f'        put(o, {offset} + {cursor}, {int.from_bytes(data[cursor:cursor + 8], "little")})\n'
                   for cursor in range(0, len(data), 8)) + f'        return {len(data)}\n'


def route_tables():
    # Keep the role index tied to the single existing capsule inventory.
    index = dict(zip(NATIVE_ROLES, range(len(NATIVE_ROLES)), strict=True))
    names = '\ndef role_name(o:mutbuf, offset:u64, role:u64) -> u64:\n'
    for part in range(0, len(NATIVE_ROLES), 12):
        names += f'    if role < {part + 12}:\n        return role_name_{part}(o, offset, role)\n'
    names += '    return 0\n'
    for part in range(0, len(NATIVE_ROLES), 12):
        names += f'\ndef role_name_{part}(o:mutbuf, offset:u64, role:u64) -> u64:\n'
        for name in NATIVE_ROLES[part:part + 12]:
            names += f'    if role == {index[name]}:\n' + emit_literal(name.encode(), 'offset')
        names += '    return 0\n'
    mode = '\ndef route_mode(o:mutbuf, route:u64) -> u64:\n'
    owner = '\ndef route_owner(route:u64) -> u64:\n'
    roles = '\ndef append_roles(o:mutbuf, w:mutbuf, route:u64, count:u64) -> u64:\n'
    children = ''
    for route, (name, option, inventory) in enumerate((*ROUTES, (BOOTSTRAP_OWNER, '', BOOTSTRAP_ROLES)), 1):
        if option:
            mode += f'    if route == {route}:\n' + emit_literal(option.encode(), 448)
            owner += f'    if route == {route}:\n        return {index[name]}\n'
        roles += f'    if route == {route}:\n        return append_roles_{route}(o, w, count)\n'
        children += f'\ndef append_roles_{route}(o:mutbuf, w:mutbuf, count:u64) -> u64:\n'
        proof_route = name in (EMIT_OWNER, ADOPT_OWNER, VERIFY_OWNER)
        for ordinal, role in enumerate(inventory):
            position = ordinal + int(proof_route and ordinal >= len(EMIT_ROLES))
            children += f'    argv(o, count + {position}, 4, role_fd(w, {index[role]}))\n'
        children += f'    return count + {len(inventory) + int(proof_route)}\n'
    return (names + mode + '    return 0\n' + owner + f'    return {len(NATIVE_ROLES)}\n'
            + roles + '    return 0\n' + children)


def program():
    words = {'ENTRY': b'HIALEN02', 'OBSERVATION': b'HIADFO01', 'COMMAND': b'HIADFC01',
             'ADMISSION': b'HIAWRA01'}
    constants = {name: int.from_bytes(raw, 'little') for name, raw in words.items()}
    states = ('CAPSULE_CAPTURED', 'CAPSULE_AUTHORIZED', 'CAPSULE_HEADER', 'RELEASE_DIRECTORY',
              'ROLE_ROW', 'ROLE_CAPTURED', 'ROLE_AUTHORIZED', 'PART_MADE', 'DOSSIER_PINS',
              'INPUT_CAPTURED', 'REQUEST_ADMITTED', 'ROUTE_BOUND', 'BOOTSTRAPPED',
              'WORKER_DONE', 'PUBLISHED')
    fields = ('CAPSULE_FD', 'CAPSULE_BYTES', 'RELEASE_FD', 'ROLE_INDEX', 'ROLE_BYTES',
              'PART_INDEX', 'DIGITS', 'REQUEST_FD', 'REQUEST_BYTES', 'ROUTE', 'DISCOVERY_META')
    constants.update({name: index for index, name in enumerate(states, 1)})
    constants.update({name: 96 + 8 * index for index, name in enumerate(fields)})
    constants.update(BAD=0xfffffffd, ROLE_COUNT=len(NATIVE_ROLES),
                     BODY_OFFSET=56 + 48 * len(NATIVE_ROLES), MAX_CAPSULE=4 << 20, MAX_REQUEST=8 << 20,
                     PIN=192, CATALOG=224, PART_TABLE=288, ROLE_TABLE=512, HEADER=512,
                     RUN=1, READ=2, PUBLISH=3, FINISHED=5, MAKE=11, OPEN_RELEASE=18,
                     SNAPSHOT=19, AUTHORIZE=20, CAPTURE_INPUT=21, DEFAULT_CHILD_LEASE=120_000_000_000,
                     REQUEST_LEASE=60_000_000_000,
                     INPUT_ARG=1, LITERAL_ARG=2, FD_ARG=4, BOOTSTRAP_ROUTE=len(ROUTES) + 1,
                     NATIVE_ROUTE_COUNT=len(ROUTES), EMIT_ROUTE=8, ADOPT_ROUTE=9, VERIFY_ROUTE=10,
                     PROOF_ROLE=len(EMIT_ROLES), VERIFY_ARG_COUNT=6 + len(VERIFY_ROLES),
                     EMIT_ARG_COUNT=6 + len(EMIT_ROLES), ADOPT_ARG_COUNT=6 + len(ADOPT_ROLES),
                     PROOF_TRUST_BYTES=PROOF_TRUST_BYTES,
                     BOOTSTRAP=NATIVE_ROLES.index(BOOTSTRAP_OWNER), ADMIT=NATIVE_ROLES.index('hia-worker-admit'))
    tables = route_tables()
    issue = function(DESCRIBE, 'issue').replace('seq > 160', 'seq > 512').replace(
        '    put(o, 152, choose(op == RUN, DEFAULT_CHILD_LEASE, 0))',
        '    if op == RUN:\n        put(o, 152, choose(next == REQUEST_ADMITTED, 30000000000, DEFAULT_CHILD_LEASE))').replace(
        '    return HEADER + local', '    return choose(args == 0, HEADER + local, 1024 + args * 16)')
    copy = function(DESCRIBE, 'copy_private')
    copy_span = '''def copy_span(s:readbuf, o:mutbuf, offset:u64, target:u64, width:u64) -> u64:
    i = 0
    while i < width:
        store(o, target + i, byte(s, offset + i))
        i = i + 1
    return i
'''
    memory = sha256_program()
    controls = (tables, issue, copy, copy_span, function(DESCRIBE, 'fragment'),
                function(DESCRIBE, 'read_span'), function(CAPSULE_POLICY, 'capsule_word'),
                function(memory, 'get'), function(memory, 'put'))
    return flow_source(POLICY, controls, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
