"""Complete fixed-buffer native entry traces, chunked without per-call files.

Each entry has two 960-byte records. PRE and POST each carry all three actual
buffers (256/128/512), an indexed 32-byte header and a SHA256 of the header and
buffers. Chunk records are never truncated to meet a transport budget. The
reader below rechecks every record; absence of the final index is not PASS.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import time

from common import require, pin, read_file, save, wire

HEADER = struct.Struct('<8sQQQ')
FRAME = struct.Struct('<16Q')
RECORD_BYTES = 960
ENTRY_BYTES = 2 * RECORD_BYTES
CHUNK_BYTES = ((8 << 20) // ENTRY_BYTES) * ENTRY_BYTES
MAX_ENTRIES = 132096
REFUSAL = 0xfffffffd
MAGIC = int.from_bytes(b'HIACMP01', 'little')


class NativeTrace:
    def __init__(self, directory, image):
        require(isinstance(image._entry, ctypes._CFuncPtr), 'finite controls require a real native entry')
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self._native = image._entry
        self.image_sha256 = image.image_sha256
        self.admitted_source_sha256 = image.admitted_source_sha256
        self.entry_count = 0
        self.case = None
        self.cases = []
        self.chunks = []
        self.stream = None
        self.bytes = 0
        self.chunk_start = 0
        self.chunk_digest = None
        self.all_digest = sha256()
        self.status_counts = {}
        self.return_elapsed_ns = 0
        self.closed = False
        self.pending_entry = None

    def begin_case(self, name, metadata=None, reference=None):
        require(not self.closed and self.pending_entry is None and self.case is None,
                'trace case permission is unavailable')
        self.case = {'case_id': len(self.cases) + 1, 'name': name,
                     'first_entry': self.entry_count, 'entry_count': 0,
                     'status_counts': {}, 'metadata': metadata or {}, 'complete': False}
        self._reference = reference
        self.cases.append(self.case)

    def end_case(self, extra=None):
        require(self.case is not None and self.pending_entry is None, 'trace case has incomplete entry')
        if self._reference is not None:
            require(self.case['entry_count'] == len(self._reference), 'native/VM entry count differs')
        self.case.update(extra or {})
        self.case['complete'] = True
        result = self.case
        self.case = None
        self._reference = None
        return result

    def _close_chunk(self):
        if self.stream is None:
            return
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        actual = pin(self.chunk_path, CHUNK_BYTES)
        require(actual['size'] == self.bytes and actual['sha256'] == self.chunk_digest.hexdigest(),
                'native trace chunk readback differs')
        self.chunks.append({'path': self.chunk_path.name, 'offset': self.chunk_start,
                            'length': actual['size'], 'sha256': actual['sha256']})
        self.chunk_start += self.bytes
        self.stream = None

    def _open_chunk(self):
        self.chunk_path = self.directory / ('entries-%04d.bin' % len(self.chunks))
        fd = os.open(self.chunk_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.stream = os.fdopen(fd, 'wb', buffering=1 << 20)
        self.bytes = 0
        self.chunk_digest = sha256()

    def _record(self, header, source, output, workspace):
        body = header + source + output + workspace
        require(len(body) == RECORD_BYTES - 32, 'native trace buffer extent differs')
        raw = body + sha256(body).digest()
        self.stream.write(raw)
        self.bytes += len(raw)
        self.chunk_digest.update(raw)
        self.all_digest.update(raw)

    def _entry(self, source, size, output, output_size, workspace, workspace_size):
        require((size, output_size, workspace_size) == (256, 128, 512), 'numeric native buffer ABI differs')
        require(not self.closed and self.case is not None and self.pending_entry is None,
                'numeric native trace is not ready for an entry')
        require(self.entry_count < MAX_ENTRIES, 'finite control trace exceeded its fixed corpus allowance')
        if self.stream is None or self.bytes + ENTRY_BYTES > CHUNK_BYTES:
            self._close_chunk()
            self._open_chunk()
        index = self.entry_count
        packet = ctypes.string_at(source, 256)
        before_output = ctypes.string_at(output, 128)
        before_workspace = ctypes.string_at(workspace, 512)
        self._record(HEADER.pack(b'CMPPRE01', index, self.case['case_id'], 0),
                     packet, before_output, before_workspace)
        self.pending_entry = index
        started = time.monotonic_ns()
        returned = self._native(source, size, output, output_size, workspace, workspace_size)
        elapsed = time.monotonic_ns() - started
        after_input = ctypes.string_at(source, 256)
        after_output = ctypes.string_at(output, 128)
        after_workspace = ctypes.string_at(workspace, 512)
        self._record(HEADER.pack(b'CMPPOST1', index, returned, elapsed),
                     after_input, after_output, after_workspace)
        self.entry_count += 1
        self.pending_entry = None
        self.case['entry_count'] += 1
        status_key = str(returned)
        self.status_counts[status_key] = self.status_counts.get(status_key, 0) + 1
        counts = self.case['status_counts']
        counts[status_key] = counts.get(status_key, 0) + 1
        self.return_elapsed_ns += elapsed
        require(after_input == packet, 'native numeric owner wrote the readonly input buffer')
        if self._reference is not None:
            position = self.case['entry_count'] - 1
            require(position < len(self._reference), 'native made more entries than the VM reference')
            actual = {'status': returned, 'input_sha256': sha256(packet).hexdigest(),
                      'output_sha256': sha256(after_output).hexdigest()}
            require(actual == self._reference[position], 'actual native/VM buffer return differs')
        return returned

    def raw_entry(self, packet, state=None):
        require(type(packet) is bytes and len(packet) == 256, 'raw numeric packet differs')
        original = bytes(512) if state is None else bytes(state)
        require(len(original) == 512, 'raw numeric workspace differs')
        source = ctypes.create_string_buffer(packet, 256)
        output = ctypes.create_string_buffer(128)
        workspace = ctypes.create_string_buffer(original, 512)
        status = self._entry(source, 256, output, 128, workspace, 512)
        return status, output.raw, workspace.raw

    def close(self):
        if self.closed:
            return
        self._close_chunk()
        self.closed = True
        index = {'schema': 'hepta.hia.numeric-native-full-buffer-trace.v1',
                 'image_sha256': self.image_sha256, 'source_sha256': self.admitted_source_sha256,
                 'buffer_bytes': [256, 128, 512], 'record_bytes': RECORD_BYTES,
                 'entry_bytes': ENTRY_BYTES, 'chunk_bound': CHUNK_BYTES,
                 'entry_count': self.entry_count, 'status_counts': self.status_counts,
                 'native_elapsed_ns': self.return_elapsed_ns,
                 'pending_entry': self.pending_entry,
                 'stream_closed': True, 'all_cases_complete': all(row['complete'] for row in self.cases),
                 'raw_bytes': self.chunk_start, 'raw_sha256': self.all_digest.hexdigest(),
                 'chunks': self.chunks, 'cases': self.cases}
        save(self.directory / 'INDEX.json', index)


def audit_trace(directory, image_sha, source_sha, vm_reference_path):
    """Re-read every actual record; no trust in a child aggregate alone."""
    directory = Path(directory)
    raw_index, index_pin = read_file(directory / 'INDEX.json', 1 << 20)
    index = json.loads(raw_index)
    require(index['schema'] == 'hepta.hia.numeric-native-full-buffer-trace.v1'
            and index['image_sha256'] == image_sha and index['source_sha256'] == source_sha
            and index['buffer_bytes'] == [256, 128, 512]
            and index['record_bytes'] == RECORD_BYTES and index['entry_bytes'] == ENTRY_BYTES
            and index['chunk_bound'] == CHUNK_BYTES
            and index['stream_closed'] is True and index['pending_entry'] is None
            and index['all_cases_complete'] is True, 'native trace is incomplete or bound elsewhere')
    require(type(index['cases']) is list and len(index['cases']) == 185
            and all(type(row) is dict and type(row.get('case_id')) is int
                    and row['case_id'] == position for position, row in enumerate(index['cases'], 1)),
            'original trace case list is not the exact ordered unique185 population')
    cases = {row['case_id']: row for row in index['cases']}
    require(list(cases) == list(range(1, len(cases) + 1)), 'trace cases are not complete and unique')
    expected_files = {'INDEX.json', *(row['path'] for row in index['chunks'])}
    require({p.name for p in directory.iterdir()} == expected_files, 'trace directory membership differs')
    seen = {key: {'count': 0, 'status': {}, 'first': None, 'last_request': None} for key in cases}
    reference_raw, _ = read_file(Path(vm_reference_path), 262144)
    reference = json.loads(reference_raw)
    require(reference['case_count'] == 172 and len(reference['cases']) == 172,
            'frozen source/VM reference population differs')
    pair_positions = [row['metadata']['VM_pair_index'] for row in cases.values()
                      if 'VM_pair_index' in row['metadata']]
    require(pair_positions == list(range(172)), 'native trace does not contain the complete ordered VM matrix')
    large_rows = [row for row in cases.values() if row['metadata'].get('full_large_low_limb')]
    require(len(large_rows) == 1 and large_rows[0]['metadata']['words'] == (8 << 20) // 4 + 1,
            'fixed complete large traversal case is absent or changed')
    operands = {}
    for row in cases.values():
        metadata = row['metadata']
        if 'VM_pair_index' not in metadata and not metadata.get('full_large_low_limb'):
            continue
        for name in ('left', 'right'):
            item = metadata[name]
            require(item['path'].startswith('operands/') and '/' not in item['path'][9:]
                    and '..' not in item['path'], 'operand path is outside the fixed collection')
            if item['path'] not in operands:
                value, actual = read_file(directory.parent / item['path'], 10 << 20)
                require((actual['size'], actual['sha256']) == (item['size'], item['sha256']),
                        'complete operand bytes differ')
                operands[item['path']] = value
            value = operands[item['path']]
            description, descriptor = item['description'], item['descriptor']
            if description['kind'] == 'int':
                minimal = value.rstrip(b'\0')
                bits = (len(minimal) - 1) * 8 + minimal[-1].bit_length() if minimal else 0
                require(description['sign'] in (0, 1)
                        and description['bits'] == bits
                        and description['magnitude_sha256'] == sha256(minimal).hexdigest()
                        and descriptor == [2, (bits + 31) // 32,
                            (description['sign'] << 6) | (((bits - 1) & 31) + 1 if bits else 0)]
                        and len(value) == descriptor[1] * 4,
                        'integer operand bytes do not match their stored exact descriptor')
            elif description['kind'] == 'bool':
                require(type(description['value']) is bool
                        and value == bytes((int(description['value']),))
                        and descriptor == [1, 0, int(description['value'])], 'boolean representation differs')
            else:
                require(description['kind'] == 'float' and len(value) == 8
                        and value.hex() == description['bits']
                        and descriptor == [3, 0, int.from_bytes(value, 'little')], 'binary64 representation differs')
        if 'VM_pair_index' in metadata:
            expected = reference['cases'][metadata['VM_pair_index']]
            require(metadata['operation'] == expected['operation']
                    and metadata['left']['description'] == expected['left']
                    and metadata['right']['description'] == expected['right']
                    and metadata['expected_relation'] == expected['expected_relation']
                    and metadata['expected_predicate'] == expected['expected_predicate'],
                    'native case operands or oracle metadata differ from the frozen matrix')
        else:
            words = (8 << 20) // 4 + 1
            left = operands[metadata['left']['path']]
            right = operands[metadata['right']['path']]
            require(metadata['operation'] == 3 and metadata['expected_relation'] == 0
                    and metadata['expected_predicate'] is True
                    and metadata['summary_shortcut_allowed'] is False
                    and metadata['left']['descriptor'] == metadata['right']['descriptor'] == [2, words, 1]
                    and len(left) == len(right) == words * 4
                    and left[:4] == struct.pack('<I', 0x12345678)
                    and right[:4] == struct.pack('<I', 0x12345679)
                    and left[-4:] == right[-4:] == b'\x01\0\0\0'
                    and left.count(b'\0', 4, len(left) - 4) == len(left) - 8
                    and right[4:] == left[4:], 'complete large fixture differs from its frozen two operands')
    combined = sha256()
    offset = count = 0
    status_counts = {}
    elapsed_total = 0
    for chunk_index, row in enumerate(index['chunks']):
        require(row['path'] == 'entries-%04d.bin' % chunk_index and row['offset'] == offset,
                'trace chunk sequence has a gap or duplicate')
        raw, actual = read_file(directory / row['path'], CHUNK_BYTES)
        require((actual['size'], actual['sha256']) == (row['length'], row['sha256'])
                and len(raw) % ENTRY_BYTES == 0, 'trace chunk bytes or complete entry pairing differs')
        combined.update(raw)
        for start in range(0, len(raw), ENTRY_BYTES):
            pre = raw[start:start + RECORD_BYTES]
            post = raw[start + RECORD_BYTES:start + ENTRY_BYTES]
            require(sha256(pre[:-32]).digest() == pre[-32:]
                    and sha256(post[:-32]).digest() == post[-32:], 'native trace record hash differs')
            pre_tag, pre_index, case_id, reserved = HEADER.unpack_from(pre)
            post_tag, post_index, status, elapsed = HEADER.unpack_from(post)
            require(pre_tag == b'CMPPRE01' and post_tag == b'CMPPOST1'
                    and pre_index == post_index == count and reserved == 0 and case_id in cases
                    and status in (0, 1, REFUSAL), 'native trace entry header differs')
            require(pre[32:288] == post[32:288], 'native input changed in the recorded actual buffers')
            observed = seen[case_id]
            if observed['first'] is None:
                observed['first'] = count
            require(count == observed['first'] + observed['count'], 'case entries are interleaved')
            observed['count'] += 1
            observed['status'][str(status)] = observed['status'].get(str(status), 0) + 1
            status_counts[str(status)] = status_counts.get(str(status), 0) + 1
            elapsed_total += elapsed
            metadata = cases[case_id]['metadata']
            if 'VM_pair_index' in metadata:
                expected = reference['cases'][metadata['VM_pair_index']]['actual_entry_calls']
                ordinal = observed['count'] - 1
                require(ordinal < len(expected) and {
                    'status': status, 'input_sha256': sha256(pre[32:288]).hexdigest(),
                    'output_sha256': sha256(post[288:416]).hexdigest()} == expected[ordinal],
                    'independent actual native/VM packet and output equality failed')
            if 'VM_pair_index' in metadata or metadata.get('full_large_low_limb'):
                packet = pre[32:288]
                incoming = FRAME.unpack_from(packet)
                if observed['count'] == 1:
                    require(pre[288:416] == bytes(128) and pre[416:928] == bytes(512),
                            'numeric invocation did not begin with fresh private buffers')
                    expected_init = (MAGIC, 0, 0, metadata['operation'],
                                     *metadata['left']['descriptor'], *metadata['right']['descriptor'], *([0] * 6))
                    require(incoming == expected_init and packet[128:] == bytes(128),
                            'actual INIT differs from complete stored operand summaries')
                else:
                    require(pre[288:416] == observed['previous_output']
                            and pre[416:928] == observed['previous_workspace'],
                            'numeric continuation buffers do not match the previous native return')
                    require(incoming[0] == MAGIC and incoming[1] == 1 and incoming[3] in (0, 1)
                            and 1 <= incoming[5] <= 32 and not any(incoming[6:]),
                            'valid numeric case contains a malformed ACK')
                    item = metadata[('left', 'right')[incoming[3]]]
                    value = operands[item['path']]
                    start_byte, length = incoming[4] * 4, incoming[5] * 4
                    require(item['descriptor'][0] == 2 and start_byte + length <= len(value)
                            and packet[128:128 + length] == value[start_byte:start_byte + length]
                            and packet[128 + length:] == bytes(128 - length),
                            'actual numeric ACK differs from the full operand bytes')
                observed['previous_output'] = post[288:416]
                observed['previous_workspace'] = post[416:928]
            if cases[case_id]['metadata'].get('full_large_low_limb'):
                incoming = FRAME.unpack_from(pre, 32)
                outgoing = FRAME.unpack_from(post, 288)
                if count == observed['first']:
                    require(incoming[0] == MAGIC and incoming[1] == incoming[2] == 0,
                            'large traversal does not begin at INIT')
                else:
                    last = observed['last_request']
                    require(last is not None and incoming[:6] == (MAGIC, 1, *last),
                            'large traversal ACK does not consume the preceding request')
                if status == 1:
                    require(outgoing[0] == MAGIC and outgoing[2] == 1
                            and outgoing[1] == observed['count'], 'large traversal request sequence differs')
                    sequence, side, limb_start, limb_count = outgoing[1], outgoing[3], outgoing[4], outgoing[5]
                    expected_window = (sequence - 1) // 2
                    words = cases[case_id]['metadata']['words']
                    remaining = words - expected_window * 32
                    require(side == (sequence - 1) % 2 and limb_count == min(32, remaining)
                            and limb_start == remaining - limb_count, 'large traversal skipped or repeated a window')
                    observed['last_request'] = (sequence, side, limb_start, limb_count)
                else:
                    require(status == 0 and outgoing[:4] == (MAGIC, observed['count'] - 1, 0, 1),
                            'large lowest-limb distinction did not return LT/true')
                    observed['last_request'] = None
            count += 1
        offset += len(raw)
    require(count == index['entry_count'] and offset == index['raw_bytes']
            and combined.hexdigest() == index['raw_sha256']
            and status_counts == index['status_counts'] and elapsed_total == index['native_elapsed_ns'],
            'trace aggregate differs from complete original buffers')
    for case_id, row in cases.items():
        actual = seen[case_id]
        require(row['complete'] is True and row['entry_count'] == actual['count']
                and row['status_counts'] == actual['status']
                and (row['first_entry'] == actual['first'] if actual['count'] else True),
                'trace case accounting differs')
        if row['metadata'].get('full_large_low_limb'):
            windows = 2 * ((row['metadata']['words'] + 31) // 32)
            require(actual['count'] == windows + 1 and actual['status'] == {'0': 1, '1': windows},
                    'large traversal did not consume both complete operands')
        if 'VM_pair_index' in row['metadata']:
            require(actual['count'] == len(reference['cases'][row['metadata']['VM_pair_index']]['actual_entry_calls']),
                    'native trace omitted a VM reference entry')
    return {'schema': 'hepta.hia.numeric-native-full-buffer-audit.v1', 'status': 'FULL_TRACE_READBACK_PASS',
            'index': index_pin, 'entry_count': count, 'actual_window_requests': status_counts.get('1', 0),
            'status_counts': status_counts, 'raw_bytes': offset, 'raw_sha256': combined.hexdigest(),
            'case_count': len(cases), 'image_sha256': image_sha, 'source_sha256': source_sha,
            'matched_original_VM_pairs': 172, 'complete_large_traversal_cases': 1,
            'native_elapsed_ns': elapsed_total}
