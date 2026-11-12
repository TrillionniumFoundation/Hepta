"""Mechanical actual-image test driver; no worker report semantics here."""
from hashlib import sha256
import ctypes
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
sys.path[:0] = [str(BASE / 'Hepta-agent-edit-native'), str(BASE / 'native-agent-edit-render-next/development')]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from graph_harness_r3 import capture, Actual as GraphWire

BAD = 0xfffffffd
M = lambda value: int.from_bytes(value, 'little')
CANARY = bytes(range(32))


class ActualReport:
    def __init__(self, out):
        self.out = Path(out)
        self.pins = {}
        self.calls = 0
        self.records = []

        def read(path):
            p = Path(path).resolve()
            raw = p.read_bytes()
            if p in self.pins:
                assert self.pins[p] == raw
            self.pins[p] = raw
            return raw

        manifest = json.loads(read(ROOT / 'development/report-compile-r1/agent-worker-report.manifest.json'))
        assert manifest['schema'] == 'hepta.hia.worker-report-development.v1'
        source = read(manifest['source_path'])
        assert source == read(ROOT / 'examples/hia_bootstrap/agent_worker_report.hiaasm')
        assert len(source) == manifest['source_bytes'] and sha256(source).hexdigest() == manifest['source_sha256']
        image = read(manifest['image_path'])
        assert len(image) == manifest['image_bytes'] and sha256(image).hexdigest() == manifest['image_sha256']
        receipt = json.loads(read(manifest['receipt_path']))
        assert receipt['input_sha256'] == manifest['source_sha256']
        assert receipt['produced_sha256'] == manifest['image_sha256']
        assert receipt['image_sha256'] == manifest['compiler_sha256']
        read(ROOT / 'tools/generate_hia_worker_report.py')
        read(Path(__file__))
        self.readback()
        self.out.mkdir(parents=True, exist_ok=False)
        self.image = NativeHiaJsonImage(image, manifest['image_sha256'])
        self.wire = GraphWire(self.out / 'wire')
        self.log = (self.out / 'entries.jsonl').open('w')
        self.raw = self.out / 'bytes'
        self.raw.mkdir()
        (self.out / 'source-before.json').write_text(json.dumps(self.pin_map(), indent=2, sort_keys=True) + '\n')

    def pin_map(self):
        return {str(p): dict(bytes=len(raw), sha256=sha256(raw).hexdigest()) for p, raw in self.pins.items()}

    def readback(self):
        assert all(p.read_bytes() == raw for p, raw in self.pins.items())

    def save(self, value):
        name = sha256(value).hexdigest()
        p = self.raw / name
        if p.exists():
            assert p.read_bytes() == value
        else:
            p.write_bytes(value)
        return dict(path=str(p), bytes=len(value), sha256=name)

    def call(self, source, command, work, size, label):
        source_buffer = ctypes.create_string_buffer(source + CANARY)
        command_buffer = ctypes.create_string_buffer(command + CANARY)
        before = ctypes.string_at(work, size)
        result = self.image._entry(source_buffer, len(source), command_buffer, len(command), work, size)
        self.calls += 1
        assert ctypes.string_at(source_buffer, len(source) + len(CANARY)) == source + CANARY
        assert ctypes.string_at(command_buffer, len(command) + len(CANARY)) == command + CANARY
        assert ctypes.string_at(ctypes.addressof(work) + size, len(CANARY)) == CANARY
        state = ctypes.string_at(work, size)
        event = struct.unpack_from('<16Q', state, 256) if size >= 384 else None
        row = dict(case=label, result=result, source=self.save(source), command=self.save(command),
                   before=self.save(before), after=self.save(state), event=event,
                   input_and_canaries_unchanged=True)
        self.records.append(row)
        self.log.write(json.dumps(row, sort_keys=True) + '\n')
        self.log.flush()
        return result, event

    def run(self, source, command, label, entropy=b'\0' * 16):
        original = bytes(source)
        command = list(command)
        size = 1024
        work = ctypes.create_string_buffer(size + len(CANARY))
        ctypes.memmove(ctypes.addressof(work) + size, CANARY, len(CANARY))
        grows = 0
        entropy_requests = 0
        for _ in range(64):
            result, event = self.call(source, struct.pack('<24Q', *command), work, size, label)
            assert result == 384 and event[0] == M(b'HIAWRE01'), (result, event)
            assert event[2:4] == (command[2], command[3]) and event[4] == command[4] + 1
            assert event[12] == command[5] and not any(event[13:])
            command[4] = event[4]
            if event[1] == 2:
                assert entropy_requests == 0 and event[8] == 0 and event[10:12] == (1, 0)
                entropy_requests += 1
                command[1] = 3
                command[10] = 1
                command[11:13] = struct.unpack('<2Q', entropy)
                continue
            if event[1] == 1:
                assert event[5] > size
                new_size = max(event[5], size * 2)
                replacement = ctypes.create_string_buffer(new_size + len(CANARY))
                ctypes.memmove(replacement, work, size)
                ctypes.memmove(ctypes.addressof(replacement) + new_size, CANARY, len(CANARY))
                work, size = replacement, new_size
                command[1] = 2
                grows += 1
                continue
            assert event[1] == 0 and event[8] == 0
            assert event[6] <= size and event[7] <= size - event[6]
            payload = ctypes.string_at(ctypes.addressof(work) + event[6], event[7])
            assert source == original
            row = dict(case=label, event=event, result=self.save(payload), grows=grows,
                       entropy_requests=entropy_requests, actual_entries=self.calls)
            if event[10] == 2:
                assert event[11] == 2
                row.update(output=payload, exit_code=2, kind='stderr')
            else:
                assert event[10:12] == (1, 0)
                complete = self.wire.serialize_graph(payload, 8 << 20, flags=2, digits=4300, case=label)
                if 'wire' in complete:
                    row.update(output=complete['wire'] + b'\n', exit_code=0, kind='stdout')
                else:
                    row.update(output=b'', exit_code=None, kind='wire-error', error=complete['error'],
                               cause_kind=complete['cause_kind'])
            return row
        raise AssertionError('finite report continuation did not terminate')

    def close(self):
        self.log.close()
        self.wire.close()
        for image in self.wire.images.values():
            image._entry = None
            image._mapping.close()
        self.image._entry = None
        self.image._mapping.close()
        self.readback()
        (self.out / 'source-after.json').write_text(json.dumps(self.pin_map(), indent=2, sort_keys=True) + '\n')
        (self.out / 'custody.json').write_text(json.dumps(dict(source_before_after_equal=True,
            pins=self.pin_map(), actual_report_entries=self.calls), indent=2, sort_keys=True) + '\n')


def inputs(request, identities, response, error, disposition, request_id=1):
    source = capture([request, identities, response, error], lease=221)
    nodes = struct.unpack_from('<Q', source, 16)[0]
    first = struct.unpack_from('<Q', source, 64 + 24)[0]
    ids = struct.unpack_from('<4Q', source, 64 + nodes * 64 + first * 8)
    req, identity, result, observed = ids
    if disposition == 3:
        req = result = observed = 0
    elif disposition == 0:
        observed = 0
    else:
        result = 0
    command = [M(b'HIAWRC01'), 1, 331, request_id, 0, disposition,
               req, identity, result, observed, 0, 0, 0] + [0] * 11
    return source, command
