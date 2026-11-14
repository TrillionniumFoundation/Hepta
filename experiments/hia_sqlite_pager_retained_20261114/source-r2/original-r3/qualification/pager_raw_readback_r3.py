"""Closed-process raw audit and semantic join for the same four Pager scenarios.

Standard-library evidence decoding only. No import of HIA code, native load,
SQLite engine, compiler, SQL, file provider, or product re-execution.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import pager_common_r1 as common

from pager_audit_stream_r3 import (
    canonical, inspect_parts, require, PHYSICAL, PART, INDEX_RESERVE,
)
from pager_ipc_session_r2 import (
    NATIVE_PROFILE, C_PROFILE, EVENT_MAGIC, OUTPUT_MAGIC,
    C_COMMAND_MAGIC, C_OUTPUT_MAGIC, NATIVE_RAW_MAX, NATIVE_RECORD_MAX,
    C_COMMAND_RAW, ENV,
)

CASE_IDS = ('sqlite34600_wal_readmark_isolation', 'sqlite34600_readlock0_reset',
            'sqlite35302_wal_readmark_isolation', 'sqlite35302_readlock0_reset')


def words(raw):
    require(len(raw) % 8 == 0, 'word array extent')
    return struct.unpack('<%dQ' % (len(raw)//8), raw)


def w(raw, offset):
    return struct.unpack_from('<Q', raw, offset)[0]


def expected_commands(case_id, label):
    profile = 34600 if case_id.startswith('sqlite34600_') else 35302
    if label == 'writer':
        return [(1, 0), (2, 4096), (7, 0x42), (10, 0)]
    if label == 'checkpointer':
        values = [(1, 0)]
        if case_id.endswith('readlock0_reset'):
            values.append((8, 1))
        return values + [(8, 0), (8, 1), (8, 2), (8, 3), (10, 0)]
    if label in ('reference-a', 'reference-b'):
        return [(1, 0), (3, 0), (4, 1), (4, 2), (5, 0), (6, 0), (10, 0)]
    if label == 'old-reader':
        return [(1, profile), (3, 1), (3, 2), (3, 2), (3, 2), (4, 0)]
    require(label == 'new-reader', 'fixed process label')
    return [(1, profile), (3, 2), (3, 2), (4, 0)]



C_SOURCE_BYTES = 11376
C_SOURCE_SHA256 = '760580a618260e647a04a4188a15d8acb6e1cdd66ecdb34b3af8c0cca53eab82'
U64_MAX = (1 << 64) - 1
PAGE_SIZE = 4096
LABELS = ('writer', 'checkpointer', 'reference-a', 'reference-b',
          'old-reader', 'new-reader')


def exact(actual, expected, label):
    require(canonical(actual) == canonical(expected), label)


def finite_schedule(case_id):
    """The existing four scenarios' exact synchronous IPC schedule, not new cases."""
    rows = []
    def spawn(label):
        rows.extend([['spawn_intent', label], ['spawn_ack', label]])
    def command(label, op, arg=0):
        rows.append(['command', label, op, arg])
    def waited(label):
        rows.append(['child_waitpid', label])
    def close_c(label):
        command(label, 10)
        waited(label)
    def reference_begin(label):
        spawn(label)
        command(label, 1)
        command(label, 3)
    def reference_complete(label):
        command(label, 4, 1)
        command(label, 4, 2)
        command(label, 5)
        command(label, 6)
        close_c(label)
    spawn('writer')
    spawn('checkpointer')
    command('writer', 1)
    command('writer', 2, PAGE_SIZE)
    command('checkpointer', 1)
    if case_id.endswith('readlock0_reset'):
        command('checkpointer', 8, 1)
    reference_begin('reference-a')
    spawn('old-reader')
    command('old-reader', 1, 34600 if case_id.startswith('sqlite34600_') else 35302)
    reference_complete('reference-a')
    command('old-reader', 3, 1)
    command('old-reader', 3, 2)
    command('writer', 7, 0x42)
    command('old-reader', 3, 2)
    reference_begin('reference-b')
    spawn('new-reader')
    command('new-reader', 1, 34600 if case_id.startswith('sqlite34600_') else 35302)
    reference_complete('reference-b')
    command('new-reader', 3, 2)
    command('checkpointer', 8, 0)
    command('old-reader', 3, 2)
    command('old-reader', 4)
    waited('old-reader')
    command('checkpointer', 8, 1)
    command('checkpointer', 8, 2)
    command('new-reader', 3, 2)
    command('new-reader', 4)
    waited('new-reader')
    command('checkpointer', 8, 3)
    close_c('writer')
    close_c('checkpointer')
    return [[case_id] + row for row in rows]


def recorded_native_mapping(output, name, item, configuration):
    """Closed-only parse of the complete already-written maps and observation."""
    root = Path(output)/item['case']/name
    jp, raw = common.read(root/'native-load.json', 1 << 20)
    observation = json.loads(raw)
    require(common.wire(observation) == raw, 'canonical complete recorded native mapping')
    mp, maps_raw = common.read(root/'native-load.maps.original', 1 << 20)
    layout = configuration['hia_elf_layout']
    executable = configuration['hia_elf']
    require(type(observation['pid']) is int
            and observation['pid'] == item['ack']['pid'] == item['wait']['pid']
            and observation['schema'] == 'hia.sqlite-pager.spawn-elf-map.v1'
            and observation['entry'] == layout['entry']
            and observation['no_interpreter_or_host_library'] is True
            and observation['before_first_client_command'] is True,
            'recorded native PID/entry bound to actual spawn and wait')
    exact(observation['elf'], executable, 'recorded native whole executable pin')
    exact(layout['actual'], executable, 'ELF layout actual whole executable pin')
    exact(observation['maps'], mp, 'recorded whole maps original pin')
    rows, previous = [], 0
    for line in maps_raw.decode('ascii').splitlines():
        fields = line.split(None, 5)
        require(len(fields) in (5, 6), 'complete maps row')
        start, end = (int(x, 16) for x in fields[0].split('-'))
        permissions = fields[1]
        offset = int(fields[2], 16)
        major, minor = (int(x, 16) for x in fields[3].split(':'))
        inode = int(fields[4])
        path = fields[5] if len(fields) == 6 else ''
        require(previous <= start < end and start % 4096 == 0
                and end % 4096 == 0 and len(permissions) == 4, 'recorded maps geometry')
        previous = end
        row = {'start': start, 'end': end, 'permissions': permissions,
               'offset': offset, 'name': path, 'inode': inode,
               'device': [major, minor], 'line': line}
        if path.startswith('/'):
            require(path == executable['path'] and inode == executable['identity'][1]
                    and (major, minor) == (os.major(executable['identity'][0]),
                                           os.minor(executable['identity'][0])),
                    'recorded mapping uses the exact executable inode only')
        elif 'x' in permissions:
            require(offset == 0 and inode == 0 and major == minor == 0
                    and ((path == '[vdso]' and permissions == 'r-xp')
                         or (path == '[vsyscall]' and permissions == '--xp')),
                    'no recorded unbound executable mapping')
        rows.append(row)
    exact(rows, observation['rows'], 'all recorded maps rows independently parsed')
    owned = [row for row in rows if row['name'] == executable['path']]
    used = set()
    for kind, flags, offset, address, physical, size, memsize, alignment in layout['program_headers']:
        if kind != 1 or size == 0:
            continue
        first, last = address & -4096, (address+size+4095) & -4096
        cursor = first
        permissions = ('r' if flags & 4 else '-')+('w' if flags & 2 else '-')+(
            'x' if flags & 1 else '-')+'p'
        for index, row in enumerate(owned):
            if row['end'] <= first or row['start'] >= last:
                continue
            require(row['start'] == cursor and row['end'] <= last
                    and row['permissions'] == permissions
                    and row['offset'] == offset+(row['start']-address),
                    'recorded complete PT_LOAD offset/permission/coverage')
            cursor = row['end']
            used.add(index)
        require(cursor == last, 'recorded whole PT_LOAD coverage')
    require(used and used == set(range(len(owned))), 'no extra recorded inode aliases')
    item['mapping_observation'] = observation
    return {'observation': jp, 'maps': mp, 'pid': observation['pid'],
            'all_rows_and_PT_LOADs_reparsed': True}


def read_journal(root, token):
    root = Path(root)
    names = set()
    def onerror(error):
        raise error
    for parent, directories, files in os.walk(root, onerror=onerror, followlinks=False):
        require(Path(parent) == root and not directories, 'IPC unexpected directory')
        for name in files:
            info = (root/name).lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    'IPC nonregular/aliased file')
            names.add(name)
    require(names == {'INDEX.json', 'IPC.jsonl'}, 'IPC complete namespace')
    raw = (root/'INDEX.json').read_bytes()
    require(len(raw) <= INDEX_RESERVE, 'IPC index extent')
    index = json.loads(raw)
    require(canonical(index) == raw and
            index['schema'] == 'hia.sqlite-pager.finite-ipc.v1' and
            index['status'] == 'CLOSED' and
            index['physical_budget_token'] == token, 'IPC fixed index')
    require(type(index['rows']) is int and type(index['bytes']) is int,
            'IPC exact count types')
    digest = hashlib.sha256()
    count, rows = 0, []
    with (root/'IPC.jsonl').open('rb') as stream:
        while True:
            line = stream.readline(1024*1024+1)
            if not line:
                break
            require(len(line) <= 1024*1024 and line.endswith(b'\n'), 'IPC row extent/EOF')
            count += len(line)
            require(count + len(raw) <= PART, 'IPC original file bound')
            digest.update(line)
            value = json.loads(line)
            require(canonical(value) == line and
                    type(value['ordinal']) is int and
                    value['ordinal'] == len(rows)+1, 'IPC canonical ordinal')
            rows.append(value)
    require(count == index['bytes'] and digest.hexdigest() == index['sha256']
            and len(rows) == index['rows'], 'IPC complete bytes and rows')
    return rows, count+len(raw)


def collect_commands(rows, configuration, output):
    processes, expected_actions, actions, assertions = {}, [], [], []
    for case_id in CASE_IDS:
        expected_actions.extend(finite_schedule(case_id))
        for label in LABELS:
            name = case_id+'-'+label
            processes[name] = {
                'case': case_id, 'label': label, 'commands': [],
                'profile': NATIVE_PROFILE if label.endswith('reader') else C_PROFILE,
                'nonce': configuration['session_nonces'][name],
                'spawn': None, 'ack': None, 'wait': None,
            }
    require(set(configuration['session_nonces']) == set(processes)
            and all(type(p['nonce']) is int and 0 < p['nonce'] < 2**64
                    for p in processes.values())
            and len({p['nonce'] for p in processes.values()}) == 24,
            '24 exact independent process nonces')
    allowed = {'spawn_intent', 'spawn_ack', 'command', 'reply', 'state', 'snapshot',
               'payload', 'child_waitpid', 'assertion'}
    active_command = None
    for row in rows:
        kind = row['kind']
        require(kind in allowed, 'unexpected/failed IPC row')
        if kind == 'assertion':
            # Keep the producer's assertion record for completeness. It is NOT
            # an oracle: all scenario facts are recomputed from raw fields below.
            require(active_command is None and type(row['passed']) is bool
                    and row['case'] in CASE_IDS and type(row['label']) is str,
                    'typed assertion observation outside partial reply')
            assertions.append(row)
            continue
        require(row['process'] in processes, 'unexpected IPC process')
        item = processes[row['process']]
        identity = [item['case'], kind, item['label']]
        if kind in ('spawn_intent', 'spawn_ack'):
            require(active_command is None and type(row['nonce']) is int
                    and row['nonce'] == item['nonce'] and row['profile'] == item['profile'],
                    'exact spawn nonce/profile outside partial command')
            if kind == 'spawn_intent':
                require(item['spawn'] is None and item['ack'] is None
                        and item['wait'] is None, 'unique ordered spawn intent')
                if item['profile'] == NATIVE_PROFILE:
                    supplied = configuration['hia_elf']
                    argv = [supplied['path'], 'probe.db']
                else:
                    version = '3.46.0' if item['case'].startswith('sqlite34600_') else '3.53.2'
                    supplied = configuration['sqlite_runtimes'][version]
                    role = 'r' if item['label'].startswith('reference-') else 'w'
                    argv = [supplied['path'],
                            str(Path(output)/item['case']/'database'/'probe.db'), role]
                exact(row['executable'],
                      {key: supplied[key] for key in ('path', 'bytes', 'sha256')},
                      'spawn uses the exact current supplied executable')
                exact(row['argv'], argv, 'complete fixed child argv')
                exact(row['env'], ENV, 'complete fixed child environment')
                item['spawn'] = row
            else:
                require(item['spawn'] is not None and item['ack'] is None
                        and item['wait'] is None and type(row['pid']) is int
                        and row['pid'] > 0, 'unique actual spawn acknowledgement')
                for other in processes.values():
                    require(other['ack'] is None or other['wait'] is not None
                            or other['ack']['pid'] != row['pid'],
                            'PID cannot alias another currently-live fixed child')
                if item['profile'] == NATIVE_PROFILE:
                    bounds = {'max_raw_bytes': NATIVE_RAW_MAX,
                              'max_records': NATIVE_RECORD_MAX}
                else:
                    count = len(expected_commands(item['case'], item['label']))
                    bounds = {'max_raw_bytes': count*C_COMMAND_RAW, 'max_records': count*6}
                exact(row['bounds'], bounds, 'spawn exact unchanged audit bounds')
                item['ack'] = row
            actions.append(identity)
            continue
        if kind == 'child_waitpid':
            require(active_command is None and item['wait'] is None
                    and item['ack'] is not None and type(row['pid']) is int
                    and row['pid'] == item['ack']['pid']
                    and type(row['raw_status']) is int and row['raw_status'] == 0
                    and type(row['exit_code']) is int and row['exit_code'] == 0
                    and row['unexpected_reply'] == ''
                    and row['collector_alive'] is False and row['collector_error'] is None,
                    'same spawned child naturally waited, no unread reply/collector failure')
            require(item['commands']
                    and item['commands'][-1]['next_field'] == 'complete',
                    'wait follows a whole final reply')
            item['wait'] = row
            actions.append(identity)
            continue
        require(item['spawn'] is not None and item['ack'] is not None
                and item['wait'] is None, 'IPC outside actual child lifecycle')
        require(type(row['command']) is int and type(row['nonce']) is int
                and row['nonce'] == item['nonce'] and type(row['operation']) is int,
                'IPC exact command/nonce/op types')
        if kind == 'command':
            require(active_command is None and row['command'] == len(item['commands'])+1,
                    'one whole synchronous command at a time')
            raw = bytes.fromhex(row['bytes'])
            require(raw.hex() == row['bytes'] and len(raw) == 128, 'whole canonical command')
            ordinal = len(item['commands'])+1
            expected = expected_commands(item['case'], item['label'])
            require(ordinal <= len(expected), 'no extra fixed command')
            operation, argument = expected[ordinal-1]
            require(row['operation'] == operation, 'row operation equals fixed command')
            if item['profile'] == NATIVE_PROFILE:
                frame = [EVENT_MAGIC, 2, item['nonce'], operation, 0, 0, 0, 0,
                         argument, 0, 0, 0, 0, 0, 0, 0]
            else:
                frame = [C_COMMAND_MAGIC, 2, item['nonce'], ordinal,
                         operation, argument]+[0]*10
            require(raw == struct.pack('<16Q', *frame), 'frozen whole command frame')
            item['commands'].append({'raw': raw, 'next_field': 'reply',
                                     'ordinal': row['ordinal'],
                                     'operation': operation, 'argument': argument})
            active_command = (row['process'], ordinal)
            actions.append(identity+[operation, argument])
        else:
            require(item['commands'] and row['command'] == len(item['commands'])
                    and active_command == (row['process'], row['command']),
                    'reply belongs to the one actual in-flight command')
            command = item['commands'][-1]
            require(row['operation'] == command['operation']
                    and kind == command['next_field'], 'whole reply op/field order')
            body = bytes.fromhex(row['bytes'])
            require(body.hex() == row['bytes'], 'canonical complete reply bytes')
            command[kind] = body
            command[kind+'_ordinal'] = row['ordinal']
            if kind == 'reply':
                require(len(body) == 128, 'whole reply')
                command['next_field'] = 'state' if item['profile'] == NATIVE_PROFILE else 'snapshot'
            elif kind in ('state', 'snapshot'):
                require(len(body) == (1024 if kind == 'state' else 48),
                        'whole diagnostic/header')
                command['next_field'] = 'payload'
            else:
                require(len(body) <= 65536, 'whole active IPC payload bound')
                command['next_field'] = 'complete'
                active_command = None
    require(active_command is None, 'no partial global IPC command at EOF')
    exact(actions, expected_actions, 'entire original four-case spawn/command/wait schedule')
    for name, item in processes.items():
        require(item['spawn'] is not None and item['ack'] is not None
                and item['wait'] is not None
                and len(item['commands']) == len(expected_commands(item['case'], item['label']))
                and all(c['next_field'] == 'complete' for c in item['commands']),
                'complete fixed process lifecycle and command population')
        item['assertions'] = [row for row in assertions if row['case'] == item['case']]
    require(sum(len(p['commands']) for p in processes.values()
                if p['profile'] == C_PROFILE) == 98, 'all original C commands')
    require(sum(len(p['commands']) for p in processes.values()
                if p['profile'] == NATIVE_PROFILE) == 40, 'all native client commands')
    return processes


class CJoin:
    def __init__(self, item):
        self.item, self.group, self.command_count = item, [], 0

    def consume(self, ordinal, info, body):
        pattern = (30, 31, 32, 33, 34, 35)
        require(info[0] == pattern[len(self.group)], 'C complete PRE/POST order')
        require(info[3] == self.command_count+1, 'C raw command sequence')
        self.group.append((info, body))
        if len(self.group) != 6:
            return
        require(self.command_count < len(self.item['commands']), 'extra C command')
        expected = self.item['commands'][self.command_count]
        body = [row[1] for row in self.group]
        require(body[0] == expected['raw'], 'C raw command complete bytes')
        require(body[1] == b'\xa5'*65536 and body[2] == bytes(128),
                'C complete PRE spans')
        require(body[3] == expected['reply'] and body[5] == expected['snapshot'],
                'C raw reply and full header precede projection')
        output_words = words(body[3])
        require(output_words[:5] == (C_OUTPUT_MAGIC, 2, self.item['nonce'],
                                    self.command_count+1, expected['operation']),
                'raw C complete nonce/sequence/operation identity')
        count = output_words[6]
        require(count <= 65536 and body[4][:count] == expected['payload'],
                'C entire actual active result')
        require(body[4][count:] == b'\xa5'*(65536-count), 'C full untouched tail')
        raw = output_words[5] & 0xffffffff
        require(all(row[0][2] == raw for row in self.group[3:]),
                'C raw rc on every complete POST')
        self.command_count += 1
        self.group.clear()

    def finish(self):
        require(not self.group and self.command_count == len(self.item['commands']),
                'C full EOF command population')
        return {'C_commands': self.command_count, 'records': self.command_count*6}


class NativeJoin:
    def __init__(self, item):
        self.item, self.group = item, []
        self.state = bytes(73728)
        self.request = bytes(128)
        self.io = bytes(65664)
        self.context = None
        self.pending = None
        self.os_event = None
        self.release_generation = None
        self.client = 0
        self.hia_calls, self.os_calls, self.releases = 0, 0, 0
        self.closed = False
        self.owned_fds, self.opened_fds, self.closed_fds = {}, {}, {}
        self.owned_maps, self.owned_locks = {}, {}
        self.cleanup_receipts = []

    def consume(self, ordinal, info, body):
        require(not self.closed, 'record after terminal HIA CLOSE')
        if not self.group:
            expected = 20 if self.pending is not None else 10
            require(info[0] == expected, 'HIA/OS effect sequence')
        pattern = (20, 22, 23, 21, 25) if (self.group and self.group[0][0][0] == 20) or info[0] == 20 else (10, 13, 14, 11, 12)
        require(info[0] == pattern[len(self.group)], 'whole raw group order')
        self.group.append((info, body))
        if len(self.group) != 5:
            return
        if pattern[0] == 20:
            self.os_group()
        else:
            self.hia_group()
        self.group.clear()


    def transport_ownership(self, req, receipt, before, after):
        """Reconcile only this Pager's OS-owned handles/maps/locks, never fd3/pipes."""
        op, resource, a, b, c = req[4:9]
        raw = receipt[5]
        sequence = req[3]
        require(words(after[:32]) ==
                (int.from_bytes(b'PGOSCTX2', 'little'), 2, self.item['nonce'], 3)
                and w(after, 56) == sequence,
                'transport nonce/borrowed directory/sequence unchanged')
        if op == 1 and raw < 1 << 63:
            require(resource in (0, 1, 2) and resource not in self.opened_fds
                    and resource not in self.owned_fds
                    and w(before, 32+8*resource) == U64_MAX,
                    'one original successful open of each actually-owned file')
            self.opened_fds[resource] = raw
            self.owned_fds[resource] = raw
        elif op == 9:
            require(raw == 0 and resource in self.owned_fds
                    and w(before, 32+8*resource) == self.owned_fds[resource],
                    'clean HIA CLOSE requires a real successful owned-fd close')
            self.closed_fds[resource] = self.owned_fds.pop(resource)
        if op == 5 and raw < 1 << 63:
            slot = b
            require(resource == 2 and slot in (0, 1) and slot not in self.owned_maps,
                    'one current mapping per original slot')
            self.owned_maps[slot] = (raw, 32768, a)
        elif op == 8:
            slot = a
            require(raw == 0 and resource == 2 and slot in self.owned_maps,
                    'clean HIA CLOSE requires an actual successful owned munmap')
            address, length, region = self.owned_maps.pop(slot)
            base = 64 if slot == 0 else 128
            require(w(before, base) == address and w(before, base+8) == length,
                    'unmap refers to the exact prior actual mapping')
        if op == 4 and raw == 0:
            key = (resource, b, c)
            if a == 2:
                require(key in self.owned_locks, 'unlock consumes an actual successful lock')
                del self.owned_locks[key]
            else:
                require(a in (0, 1) and key not in self.owned_locks,
                        'lock acquisition has no unconsumed alias')
                self.owned_locks[key] = a
        owned = sum(1 << member for member in self.owned_fds)
        require(w(after, 80) == owned
                and w(after, 192) == sum(1 << member for member in self.opened_fds) and
                all(w(after, 32+8*member) ==
                    self.owned_fds.get(member, U64_MAX) for member in (0, 1, 2)),
                'all three actual fd slots equal the independently folded live set')
        require(w(after, 88) == sum(1 << slot for slot in self.owned_maps),
                'actual map ledger equals independently folded live set')
        for slot, base in ((0, 64), (1, 128)):
            mapping = self.owned_maps.get(slot)
            require(words(after[base:base+16]) ==
                    ((mapping[0], mapping[1]) if mapping else (0, 0)),
                    'all actual mapping address/length slots')
            if slot == 1:
                require(w(after, 144) == (mapping[2] if mapping else 0),
                        'actual index mapping region')
        masks = {152: 0, 160: 0, 168: 0}
        for (member, start, length), mode in self.owned_locks.items():
            if member == 0:
                require(mode == 0 and (start, length) in
                        ((1073741824, 1), (1073741826, 510)),
                        'only the original shared database lock regions')
                masks[168] |= 1 << (0 if start == 1073741824 else 1)
            else:
                require(member == 2 and length == 1 and 120 <= start <= 128
                        and start != 121, 'only original selected SHM lock bytes')
                masks[160 if mode == 0 else 152] |= 1 << (start-120)
        require(all(w(after, offset) == mask for offset, mask in masks.items()),
                'actual OS lock ledgers equal successful raw fcntl history')
        if op in (8, 9) or (op == 4 and a == 2):
            require(raw == 0, 'finite clean cleanup has no suppressed syscall error')
            self.cleanup_receipts.append({
                'sequence': sequence, 'operation': op, 'resource': resource,
                'arguments': [a, b, c], 'raw_syscall_return_u64': raw,
                'context_before_sha256': hashlib.sha256(before).hexdigest(),
                'context_after_sha256': hashlib.sha256(after).hexdigest()})

    def terminal_transport(self):
        require(self.context is not None and not self.owned_fds
                and not self.owned_maps and not self.owned_locks
                and self.opened_fds == self.closed_fds,
                'HIA CLOSED only after every actually acquired OS resource is released')
        require(words(self.context[:32]) ==
                (int.from_bytes(b'PGOSCTX2', 'little'), 2, self.item['nonce'], 3)
                and words(self.context[32:56]) == (U64_MAX,)*3
                and all(w(self.context, at) == 0
                        for at in (64, 72, 80, 88, 128, 136, 144, 152, 160, 168)),
                'terminal OS context has no Pager-owned fd/map/lock before process exit')
        return {'context_sha256': hashlib.sha256(self.context).hexdigest(),
                'fd_slots': [U64_MAX]*3, 'owned_fd_bits': 0, 'map_bits': 0,
                'SHM_exclusive_bits': 0, 'SHM_shared_bits': 0, 'DB_lock_bits': 0,
                'borrowed_directory_fd': 3,
                'stdio_audit_pipes_and_startup_mapping_are_not_Pager_owned': True}


    def os_group(self):
        g = self.group
        seq = w(self.state, 24)
        require(all(row[0][3] == seq for row in g), 'OS sequence on every raw record')
        require(g[0][1] == self.pending and g[0][1] == self.request,
                'OS consumes exactly the emitted complete HIA request')
        require(g[1][1] == self.io, 'whole OS IO continuity')
        if self.context is None:
            initial = g[2][1]
            require(w(initial, 0) == int.from_bytes(b'PGOSCTX2', 'little') and
                    w(initial, 8) == 2 and w(initial, 16) == self.item['nonce'] and
                    w(initial, 24) == 3 and
                    words(initial[32:56]) == (2**64-1,)*3 and
                    initial[56:256] == bytes(200), 'fresh fixed native context')
            names = (b'probe.db\0', b'probe.db-wal\0', b'probe.db-shm\0')
            for index, name in enumerate(names):
                at = 256+256*index
                require(initial[at:at+len(name)] == name and
                        initial[at+len(name):at+256] == bytes(256-len(name)),
                        'exact held-directory sibling name')
            require(initial[1024:] == bytes(3072), 'fresh context reserved region')
        else:
            require(g[2][1] == self.context, 'whole OS context continuity')
        require(g[3][0][2] == 0 and g[4][0][2] == 0, 'native transport raw u32')
        self.io, self.context = g[3][1], g[4][1]
        receipt = words(self.io[:128])
        req = words(self.request)
        require(receipt[:5] == (int.from_bytes(b'HIAPGIO2', 'little'), 2,
                                self.item['nonce'], req[3], req[4]) and
                receipt[6] <= 65536 and receipt[7:] == (0,)*9,
                'full original syscall receipt envelope')
        self.transport_ownership(req, receipt, g[2][1], self.context)
        event = [EVENT_MAGIC, 2, self.item['nonce'], 2,
                 receipt[3], receipt[4], receipt[5], receipt[6]] + [0]*8
        self.os_event = struct.pack('<16Q', *event)+self.io[128:128+receipt[6]]
        self.pending = None
        self.os_calls += 1

    def hia_group(self):
        g = self.group
        event, before_o, before_w, after_o, after_w = [row[1] for row in g]
        require(before_o == self.request and before_w == self.state,
                'complete HIA mutable-span continuity')
        require(all(row[0][3] == w(before_w, 24) for row in g[:3]) and
                all(row[0][3] == w(after_w, 24) for row in g[3:]),
                'HIA before/after raw sequence identity')
        ev = words(event[:128])
        client_response = None
        if self.os_event is not None:
            require(event == self.os_event, 'all receipt bytes transferred unchanged into HIA')
            self.os_event = None
        elif self.release_generation is not None:
            expected = [EVENT_MAGIC, 2, self.item['nonce'], 5, 0, 0, 0, 0,
                        self.release_generation, 0, 0, 0, 0, 0, 0, 0]
            require(event == struct.pack('<16Q', *expected),
                    'exact PAGE release after completed caller transfer')
            self.release_generation = None
            self.releases += 1
        else:
            require(self.client < len(self.item['commands']), 'extra client event')
            command = self.item['commands'][self.client]
            require(event == command['raw'], 'whole original client event')
            self.client += 1
        status = g[3][0][2]
        require(g[4][0][2] == status, 'raw HIA return retained on both POST spans')
        self.state, self.request = after_w, after_o
        self.hia_calls += 1
        require(ev[3] != 5 or status == 128,
                'original automatic PAGE release is immediate READY with no OS effect')
        if status == 1:
            req = words(after_o)
            require(req[:4] == (int.from_bytes(b'HIAPGOS2', 'little'), 2,
                                self.item['nonce'], w(after_w, 24)) and
                    req[9:] == (0,)*7 and w(after_w, 32) == req[4],
                    'one complete pending OS effect')
            self.pending = after_o
            return
        require(status in (128, 129, 130), 'finite successful HIA domain')
        require(words(after_o)[:4] == (OUTPUT_MAGIC, 2, self.item['nonce'], status),
                'HIA result envelope')
        if ev[3] == 5:
            require(status == 128 and w(after_w, 8) == 200,
                    'internal release returns READY without extra client response')
            command = self.item['commands'][self.client-1]
            require(self.context == command['native_context'],
                    'automatic release preserves actual held OS resources')
            command['automatic_release_without_OS'] = True
            return
        require(self.client > 0, 'HIA outcome without client command')
        command = self.item['commands'][self.client-1]
        require(after_o == command['reply'] and after_w[:1024] == command['state'],
                'complete published native reply/diagnostic equals raw HIA POST')
        size = w(after_w, 128) if status == 129 else 0
        require(command['payload'] == after_w[4096:4096+size],
                'all native page bytes match pre-release held span')
        require(self.context is not None, 'native successful reply has actual OS history')
        command['native_context'] = self.context
        if status == 129:
            self.release_generation = w(after_w, 280)
        if status == 130:
            require(w(after_w, 96) == 0 and w(after_w, 104) == 0,
                    'HIA terminal zero resource and lock ownership')
            self.item['terminal_transport'] = self.terminal_transport()
            self.closed = True

    def finish(self):
        require(not self.group and self.pending is None and self.os_event is None and
                self.release_generation is None and self.closed and
                self.client == len(self.item['commands']), 'native exact complete EOF')
        require(self.os_calls <= 75 and self.hia_calls == self.os_calls+self.client+self.releases,
                'native finite HIA/OS denominator')
        require(self.client+self.releases <= 16, 'frozen non-OS call ceiling')
        return {'HIA_returns': self.hia_calls, 'OS_returns': self.os_calls,
                'client_commands': self.client, 'automatic_releases': self.releases,
                'terminal_transport': self.item['terminal_transport'],
                'cleanup_raw_receipts': self.cleanup_receipts,
                'owned_fd_acquisitions': len(self.opened_fds),
                'owned_fd_closes': len(self.closed_fds)}



def _native_result(command, expected_status, nonce):
    out = words(command['reply'])
    state = command['state']
    require(out[:4] == (OUTPUT_MAGIC, 2, nonce, expected_status)
            and out[4:7] == (0, 0, 0)
            and all(w(state, at) == 0 for at in (368, 376, 392)),
            'actual native status and first/cleanup error ledgers')
    require(out[9] == PAGE_SIZE and out[10] == 2, 'actual native snapshot geometry')
    require('native_context' in command, 'native reply joined to actual OS context')
    if expected_status == 129:
        require(len(command['payload']) == PAGE_SIZE
                and command.get('automatic_release_without_OS') is True,
                'whole page transfer followed by recorded immediate non-OS release')
    else:
        require(command['payload'] == b'', 'no undeclared non-PAGE result bytes')
    return out


def _held_reader(command, slot):
    context = command['native_context']
    require(type(slot) is int and 0 <= slot <= 4
            and w(command['state'], 160) == slot
            and w(context, 80) & (1 << 0)
            and w(context, 80) & (1 << 2)
            and w(context, 160) & (1 << 8)
            and w(context, 160) & (1 << (3+slot))
            and w(context, 168) & (1 << 1),
            'actual OS context retains DB shared/DMS/selected reader lock')


def _reference_pages(item, expected_byte):
    commands = item['commands']
    started = commands[1]
    start = words(started['reply'])
    require(start[7] == 1 and start[9] == PAGE_SIZE and start[10] == 2
            and start[11] > 0 and start[13] <= 4,
            'original C reference has an actual selected WAL snapshot')
    pages = {}
    for command, pgno in zip(commands[2:4], (1, 2)):
        out = words(command['reply'])
        require(out[7] == 1 and command['snapshot'] == started['snapshot']
                and len(command['payload']) == PAGE_SIZE,
                'both whole C pages belong to the same original snapshot')
        pages[pgno] = command['payload']
    expected_rows = (struct.pack('<QQ', 1, 64) + bytes([expected_byte])*64
                     + struct.pack('<QQ', 2, 64) + bytes(64))
    require(commands[4]['payload'] == expected_rows,
            'original SQL returned the complete two expected rows')
    ended, closed = commands[5], commands[6]
    require(words(ended['reply'])[7] == 0 and words(ended['reply'])[13] == U64_MAX
            and ended['payload'] == b'',
            'C END succeeded and original readLock is actually released')
    close = words(closed['reply'])
    require(close[7] == 0 and close[9:13] == (0, 0, 0, 0)
            and close[13] == U64_MAX and closed['snapshot'] == bytes(48)
            and closed['payload'] == b''
            and closed['payload_ordinal'] < item['wait']['ordinal'],
            'C CLOSE zero DB snapshot and natural wait follow the whole END')
    return started, pages


def _bind_case_results(processes, cases):
    require(type(cases) is list and [case['id'] for case in cases] == list(CASE_IDS),
            'all original scenario records in original order')
    for index, case in enumerate(cases):
        case_id = CASE_IDS[index]
        require(case['version'] == ('3.46.0' if index < 2 else '3.53.2')
                and case['mode'] == ('wal' if index % 2 == 0 else 'db')
                and case['status'] == 'SCENARIO_COMMANDS_COMPLETE_PENDING_RAW_AUDIT'
                and type(case['C_commands']) is int
                and case['C_commands'] == (24 if index % 2 == 0 else 25)
                and type(case['HIA_client_commands']) is int
                and case['HIA_client_commands'] == 10,
                'original per-case identity/status/population')
        labels = ('reference-a', 'reference-b', 'old-reader', 'new-reader',
                  'writer', 'checkpointer')
        children = []
        for label in labels:
            item = processes[case_id+'-'+label]
            children.append({
                'process': case_id+'-'+label, 'pid': item['ack']['pid'],
                'exit_code': 0, 'commands': len(item['commands']),
                'audit': item['wait']['capture']})
        exact(case['children'], children, 'all SCENARIOS children bind original spawn/wait/capture')
        exact(case['native_mappings'],
              [processes[case_id+'-'+label]['mapping_observation']
               for label in ('old-reader', 'new-reader')],
              'SCENARIOS maps bind the actual journal PIDs and whole mapping originals')
        recorded_assertions = processes[case_id+'-writer']['assertions']
        exact(case['assertions'], [row['label'] for row in recorded_assertions],
              'all original producer assertion labels preserved')
        # This is a consistency check only. The independent facts below do not
        # accept a passed Boolean as proof of any syscall, snapshot or lock.
        require(all(row['passed'] is True for row in recorded_assertions),
                'producer did not report a failed assertion')


def recompute_scenarios(processes, cases):
    _bind_case_results(processes, cases)
    source_path = Path(__file__).resolve().parent/'sqlite_reference_process_r1.c'
    source_pin, source_body = common.read(source_path, C_SOURCE_BYTES)
    require(len(source_body) == C_SOURCE_BYTES
            and source_pin['sha256'] == C_SOURCE_SHA256,
            'exact unchanged C source for explicit COMMIT/autocommit inference')
    results = []
    for case_id in CASE_IDS:
        items = {label: processes[case_id+'-'+label] for label in LABELS}
        is_db = case_id.endswith('readlock0_reset')
        engine = 3046000 if case_id.startswith('sqlite34600_') else 3053002
        for label in ('writer', 'checkpointer', 'reference-a', 'reference-b'):
            item = items[label]
            for ordinal, command in enumerate(item['commands'], 1):
                out = words(command['reply'])
                expected_rc = 5 if label == 'checkpointer' and (
                    command['operation'], command['argument']) == (8, 2) else 0
                require(out[:5] == (C_OUTPUT_MAGIC, 2, item['nonce'], ordinal,
                                    command['operation'])
                        and out[5] == expected_rc and out[6] == len(command['payload'])
                        and out[8] == engine and out[14:] == (0, 0),
                        'complete original C identity, expected actual rc and extent')
                if label in ('writer', 'checkpointer'):
                    require(out[7] == 0 and out[13] == U64_MAX,
                            'writer/checkpointer have no original active WAL read lock')
        a_start, a_pages = _reference_pages(items['reference-a'], 0)
        b_start, b_pages = _reference_pages(items['reference-b'], 0x42)
        old, new = items['old-reader'], items['new-reader']
        old_start, new_start = old['commands'][0], new['commands'][0]
        old_out = _native_result(old_start, 128, old['nonce'])
        new_out = _native_result(new_start, 128, new['nonce'])
        for native, ref in ((old_start, a_start), (new_start, b_start)):
            require(native['state'][512:560] == ref['snapshot']
                    and words(native['reply'])[9:12] == words(ref['reply'])[9:12],
                    'all 48 snapshot-header bytes and page/endmark geometry match original C')
        old_slot, new_slot = w(old_start['state'], 160), w(new_start['state'], 160)
        require((old_slot == 0 if is_db else 1 <= old_slot <= 4)
                and 1 <= new_slot <= 4, 'actual original old/new reader-lock branch')
        _held_reader(old_start, old_slot)
        _held_reader(new_start, new_slot)
        if is_db:
            require(old_start['state'][544:552] != new_start['state'][544:552],
                    'original WAL salt reset while old READ_LOCK0 remained held')
        else:
            require(new_out[11] > old_out[11], 'new committed endmark advances')
        require(a_pages[2] != b_pages[2], 'real writer changed the whole original table page')
        for item, pages, slot in ((old, a_pages, old_slot), (new, b_pages, new_slot)):
            for command in item['commands'][1:-1]:
                out = _native_result(command, 129, item['nonce'])
                pgno = command['argument']
                require(out[13] == pgno and command['payload'] == pages[pgno],
                        'every complete HIA PAGE equals its original C snapshot page')
                _held_reader(command, slot)
                if item is old and is_db:
                    require(out[14] == 0 and w(command['state'], 240) == 0,
                            'old READ_LOCK0 PAGE uses DB without WAL fallback')
            closed = item['commands'][-1]
            out = _native_result(closed, 130, item['nonce'])
            require(out[7:9] == (0, 0) and item['terminal_transport'] is not None
                    and closed['payload_ordinal'] < item['wait']['ordinal'],
                    'native real owned resources released before reply and wait')
        cp = items['checkpointer']
        check = [command for command in cp['commands'] if command['operation'] == 8]
        counter_rows = []
        for command in check:
            require(len(command['payload']) == 16, 'whole checkpoint counter pair')
            nlog, done = struct.unpack('<2q', command['payload'])
            counter_rows.append({'mode': command['argument'],
                                 'raw_rc': words(command['reply'])[5],
                                 'nLog': nlog, 'nCkpt': done,
                                 'command_ordinal': command['ordinal']})
        if is_db:
            prepare, passive, full, restart, truncate = counter_rows
            require(prepare['nLog'] > 0 and prepare['nCkpt'] == prepare['nLog']
                    and prepare['nLog'] == old_out[11],
                    'fully backfilled original A before READ_LOCK0')
        else:
            passive, full, restart, truncate = counter_rows
        require(passive['nLog'] == new_out[11], 'PASSIVE observed the real new endmark')
        if is_db:
            require(passive['nCkpt'] == 0, 'held READ_LOCK0 prevented new DB backfill')
        else:
            require(0 <= passive['nCkpt'] <= old_out[11] < passive['nLog'],
                    'held older WAL reader prevented checkpoint crossing its endmark')
        require(full['nLog'] == full['nCkpt'] == new_out[11],
                'FULL reaches B only after old HIA reader closes')
        require(restart['raw_rc'] == 5 and
                restart['nLog'] == restart['nCkpt'] == new_out[11],
                'RESTART is BUSY with complete backfill and the new HIA reader still held')
        require(truncate['raw_rc'] == 0 and truncate['nLog'] == truncate['nCkpt'] == 0,
                'TRUNCATE succeeds only after the final HIA close')
        for label in ('reference-a', 'reference-b'):
            require(items[label]['wait']['ordinal'] < passive['command_ordinal'],
                    'both original reference END/CLOSE/wait precede constrained checkpoint')
        require(items['reference-a']['wait']['ordinal'] <
                items['writer']['commands'][2]['ordinal'],
                'A reference is closed before the real B writer commits')
        require(old['wait']['ordinal'] < full['command_ordinal'] <
                restart['command_ordinal'] < new['commands'][-1]['ordinal']
                and new['wait']['ordinal'] < truncate['command_ordinal'],
                'actual old/new wait/held-checkpoint/reset order')
        results.append({
            'id': case_id, 'checkpoint_original_counters': counter_rows,
            'old_snapshot_sha256': hashlib.sha256(a_start['snapshot']).hexdigest(),
            'new_snapshot_sha256': hashlib.sha256(b_start['snapshot']).hexdigest(),
            'old_mxFrame': old_out[11], 'new_mxFrame': new_out[11],
            'old_reader_slot': old_slot, 'new_reader_slot': new_slot,
            'whole_C_pages': {label: {str(pg): hashlib.sha256(raw).hexdigest()
                                      for pg, raw in pages.items()}
                              for label, pages in (('A', a_pages), ('B', b_pages))},
            'writer_and_checkpointer_readLock_observed': -1,
            'autocommit_is_direct_flag_sampling': False,
            'autocommit_basis': 'exact C op2 uses completed implicit statements; '
                               'op7 finalizes UPDATE then successful COMMIT; '
                               'op8 finalizes its read-only schema query and checks '
                               'autocommit and main transaction NONE before checkpoint; '
                               'op1/8/10 introduce no SQL BEGIN; original rc0 '
                               'and readLock=-1 are checked from complete replies',
            'reference_END_CLOSE_wait_before_checkpoint': True,
            'native_OS_resources_empty_before_process_exit': True,
            'assertion_passed_used_as_semantic_oracle': False})
    return {'schema': 'hia.sqlite-pager.independent-finite-schedule.v1',
            'cases': results, 'C_source': source_pin,
            'C_commands': 98, 'native_client_commands': 40,
            'automatic_page_releases': 24,
            'whole_SQLite_or_AgentStore_qualification': False}


def inspect_all(output, configuration, *, scenarios):
    output = Path(output)
    rows, physical = read_journal(output/'ipc', configuration['trace_budget_token'])
    processes = collect_commands(rows, configuration, output)
    results = {}
    for name, item in processes.items():
        if item['profile'] == NATIVE_PROFILE:
            join = NativeJoin(item)
            raw_limit, record_limit = NATIVE_RAW_MAX, NATIVE_RECORD_MAX
        else:
            join = CJoin(item)
            raw_limit = len(item['commands'])*C_COMMAND_RAW
            record_limit = len(item['commands'])*6
        root = output/item['case']/name/'audit'
        result = inspect_parts(root, nonce=item['nonce'], max_raw_bytes=raw_limit,
                               max_records=record_limit, consume_record=join.consume,
                               profile=item['profile'])
        index = json.loads((root/'INDEX.json').read_bytes())
        require(index['physical_budget_token'] == configuration['trace_budget_token'],
                'same physical aggregate token across every native/C stream')
        require(canonical(index) == canonical(item['wait']['capture']),
                'closed collector/child canonical identity')
        physical += result['physical_bytes']
        require(physical <= PHYSICAL, 'original shared 256MiB including every INDEX')
        results[name] = dict(result, **join.finish())
        if item['profile'] == NATIVE_PROFILE:
            results[name]['recorded_native_mapping'] = recorded_native_mapping(
                output, name, item, configuration)
    require(len(results) == 24, 'all eight native and sixteen C process streams')
    require(sum(x.get('C_commands', 0) for x in results.values()) == 98,
            'all 98 complete original C commands')
    require(sum(x.get('client_commands', 0) for x in results.values()) == 40 and
            sum(x.get('automatic_releases', 0) for x in results.values()) == 24,
            'all native client/loan-release calls')
    scenario_facts = recompute_scenarios(processes, scenarios)
    return {'schema': 'hia.sqlite-pager.closed-raw-join.v2',
            'status': 'ALL_FINITE_RAW_STREAMS_JOINED',
            'physical_trace_bytes': physical, 'processes': results,
            'scenario_facts_recomputed': scenario_facts,
            'assertion_passed_used_as_semantic_oracle': False,
            'whole_SQLite_or_AgentStore_qualification': False}
