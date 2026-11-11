"""Unexecuted development harness draft reconstructed after disconnection.

Publication replies below are explicitly private fixtures. They are not native
namespace effects. Reference Python calls occur only before/after actual entry.
"""
from contextlib import ExitStack
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import struct
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
WORKER = BASE / 'native-agent-worker-next'
RENDER = BASE / 'native-agent-edit-render-next'
REFERENCE = BASE / 'Hepta-agent-edit-native'
sys.path[:0] = [str(REFERENCE), str(RENDER / 'development')]
spec = importlib.util.spec_from_file_location('frozen_request_mechanics', WORKER / 'development/worker_request_harness.py')
mechanics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mechanics)
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from graph_harness_r3 import capture, ERRORS

M = lambda value: int.from_bytes(value, 'little')
BAD = 0xfffffffd


def root_elements(raw):
    nodes, root = struct.unpack_from('<2Q', raw, 16)
    first, count = struct.unpack_from('<2Q', raw, root * 64 + 24)
    return struct.unpack_from('<' + str(count) + 'Q', raw, 64 + 64 * nodes + first * 8)


def observed_value(raw):
    """Post-execution oracle only. Never used for a native continuation."""
    magic, lease, count, root, edges, scalar_bytes, total, reserved = struct.unpack_from('<8Q', raw)
    assert magic == M(b'HIAGRF01') and lease and reserved == 0 and total == len(raw)
    assert 64 + count * 64 + edges * 8 + scalar_bytes == len(raw)
    made = {}
    def value(node):
        assert 1 <= node <= count
        if node in made:
            return made[node]
        kind, at, size, first, amount, identity, aux, unused = struct.unpack_from('<8Q', raw, node * 64)
        assert unused == 0
        if kind == 0:
            result = None
        elif kind == 1:
            result = bool(aux)
        elif kind == 2:
            result = int.from_bytes(raw[at:at + size], 'little') * (-1 if aux else 1)
        elif kind == 3:
            result = struct.unpack('<d', raw[at:at + size])[0]
        elif kind == 4:
            result = raw[at:at + size].decode('utf-8', 'surrogatepass')
        elif kind == 9:
            result = raw[at:at + size]
        elif kind in (5, 6, 7):
            result = {} if kind == 6 else []
            made[node] = result
            positions = struct.unpack_from('<' + str(amount * (2 if kind == 6 else 1)) + 'Q', raw,
                                           64 + count * 64 + first * 8)
            if kind == 6:
                for index in range(amount):
                    result[value(positions[index * 2])] = value(positions[index * 2 + 1])
            else:
                result.extend(value(item) for item in positions)
                if kind == 7:
                    result = tuple(result)
        else:
            raise AssertionError(('foreign object is not reconstructed by the test oracle', kind))
        made[node] = result
        return result
    return value(root)


def forbid_retained(stack):
    def disabled(*args, **kwargs):
        raise AssertionError('retained record/JSON semantics invoked during native forwarding')
    for target in ('hepta.hia_agent_service.HIAAgentService._error',
                   'hepta.hia_agent_service.HIAAgentService._reference_call',
                   'hepta.hia_agent_store.wire', 'hepta.hia_agent_store.decode_data',
                   'hepta.hia_program_tools.bounded_json_wire', 'json.loads'):
        stack.enter_context(patch(target, new=disabled))


class Actual(mechanics.ActualRequest):
    def __init__(self, out):
        self.out = Path(out)
        self.pins = {}
        self.entries = dict(records=0, scan=0, emit=0)
        self.records = []
        def read(path):
            path = Path(path).resolve()
            raw = path.read_bytes()
            if path in self.pins:
                assert self.pins[path] == raw
            self.pins[path] = raw
            return raw
        row = json.loads(read(ROOT / 'development/records-compile-r1/service-records.manifest.json'))
        peers = json.loads(read(RENDER / 'development/compile-r3/bundle.json'))
        assert peers['status'] == 'PASS' and peers['scope'] == 'SOURCE_BOUND_GRAPH_WIRE_DEVELOPMENT_NOT_PUBLIC_ADMISSION_OR_COLD'
        rows = dict(records=row, **peers['components'])
        images = {}
        for role, row in rows.items():
            expected = ('hepta.hia.agent-service-records-development.v1' if role == 'records'
                        else 'hepta.hia.graph-json-wire-' + role + '-native.v1')
            assert row['schema'] == expected
            current = (ROOT / 'examples/hia_bootstrap/agent_service_records.hiaasm' if role == 'records'
                       else RENDER / ('examples/hia_bootstrap/graph_json_wire_' + role + '.hiaasm'))
            source = read(row['source_path'])
            assert read(current) == source and sha256(source).hexdigest() == row['source_sha256']
            image = read(row['image_path'])
            assert sha256(image).hexdigest() == row['image_sha256']
            assert row['compiler_sha256'] == '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
            receipt = json.loads(read(row.get('receipt_path') or str(row['image_path']).replace('.image.bin', '.receipt.json')))
            assert receipt['input_sha256'] == row['source_sha256']
            assert receipt['produced_sha256'] == row['image_sha256'] and receipt['image_sha256'] == row['compiler_sha256']
            images[role] = image, row['image_sha256']
        for path in [*sorted((ROOT / 'tools').glob('*.py')), Path(__file__),
                     WORKER / 'development/worker_request_harness.py',
                     REFERENCE / 'hepta/hia_agent_service.py', REFERENCE / 'hepta/hia_agent_store.py',
                     REFERENCE / 'hepta/hia_agent_contract.py', RENDER / 'development/graph_harness_r3.py']:
            read(path)
        self.readback()
        self.out.mkdir(parents=True, exist_ok=False)
        self.rawdir = self.out / 'raw'
        self.rawdir.mkdir()
        self.saved = set()
        self.images = {role: NativeHiaJsonImage(*data) for role, data in images.items()}
        self.log = (self.out / 'entries.jsonl').open('w')
        self.pinfile('source-before.json')

    @staticmethod
    def command(source, mode, *, request=1, lease=981):
        request_root, payload_root = root_elements(source)
        return struct.pack('<12Q', M(b'HIASRC01'), lease, request, mode, request_root, payload_root, 0, 0, 0, 0, 0, 0)

    def run(self, source, mode, *, publication_fixture=None, publication_failed=False,
            initial=1024, label='case', request=1, exact_growth=False):
        command = self.command(source, mode, request=request)
        work, size = self.buffer(initial), initial
        grows = publication_calls = sequence = 0
        source_lease = struct.unpack_from('<Q', source, 8)[0]
        with ExitStack() as stack:
            forbid_retained(stack)
            while True:
                ret, _, state, _ = self.call('records', source, command, work, size, label)
                event = struct.unpack_from('<16Q', state, 256)
                assert ret == 384 and event[0] == M(b'HIASRE01'), (label, ret, event)
                assert event[2:5] == (981, request, sequence + 1) and event[12] == source_lease and not any(event[14:])
                sequence = event[4]
                if event[1] == 1:
                    assert event[5] > size
                    size = event[5] if exact_growth else max(event[5], size * 2)
                    work = self.buffer(size, state)
                    grows += 1
                    continue
                if event[1] == 2:
                    assert publication_fixture is not None and publication_calls == 0 and mode == 1
                    assert event[11] != 0 and event[6:8] == (0, 0)
                    publication_calls += 1
                    command = struct.pack('<8Q', M(b'HIASRR01'), 981, request, sequence,
                                          int(publication_failed), len(publication_fixture), 0, 0) + publication_fixture
                    continue
                assert event[1] in (0, 3), event
                offset, amount = event[6:8]
                assert offset <= size and amount <= size - offset
                graph = state[offset:offset + amount]
                assert struct.unpack_from('<Q', graph, 24)[0] == event[10]
                return dict(event=event, graph=graph, grows=grows, publication_fixture_calls=publication_calls,
                            state=state, command=command, result=self.save(graph))

    def serialize(self, source, *, label='case', maximum=8 << 20):
        lease = struct.unpack_from('<Q', source, 8)[0]
        root = struct.unpack_from('<Q', source, 24)[0]
        # Exact hia_agent_store.wire policy: ensure_ascii=False, sort_keys=True.
        command = struct.pack('<8Q', M(b'HIAGWC01'), lease, 1, root, maximum, 2, 4300, 0)
        size, role = 32768, 'scan'
        work = self.buffer(size)
        with ExitStack() as stack:
            forbid_retained(stack)
            while True:
                ret, _, state, _ = self.call(role, source, command, work, size, label)
                event = struct.unpack_from('<16Q', state)
                assert ret == 128 and event[0] == M(b'HIAGWE01') and event[2:8] == (lease, 1, root, maximum, 2, 4300)
                if event[1] == 1:
                    assert event[10] > size
                    size = max(event[10], size * 2)
                    work = self.buffer(size, state)
                    continue
                if event[1] == 2:
                    assert role == 'scan'
                    role = 'emit'
                    continue
                if event[1] == 3:
                    return dict(error='E_HIA_EDIT: ' + ERRORS[event[8]], cause_kind=event[9])
                assert event[1] == 0 and role == 'emit'
                at, amount = event[11:13]
                assert at <= size and amount <= size - at
                result = state[at:at + amount]
                return dict(wire=result, original=self.save(result))
