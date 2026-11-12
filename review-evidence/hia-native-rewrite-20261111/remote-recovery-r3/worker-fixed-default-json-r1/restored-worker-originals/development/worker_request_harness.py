"""Opaque native calls and growth only; request decisions live in HIA."""
from contextlib import ExitStack
from hashlib import sha256
import ctypes
import gzip
import json
from pathlib import Path
import struct
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
RENDER = BASE / 'native-agent-edit-render-next'
sys.path[:0] = [str(BASE / 'Hepta-agent-edit-native'), str(RENDER / 'development')]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from graph_harness_r3 import capture

M = lambda s: int.from_bytes(s, 'little')
BAD = 0xfffffffd
CANARY = bytes(range(32))


class ActualRequest:
    def __init__(self, out):
        self.out = Path(out)
        self.pins = {}
        self.entries = dict(controller=0, scan=0, emit=0, sha=0)
        self.records = []

        def read(path):
            p = Path(path).resolve()
            raw = p.read_bytes()
            if p in self.pins:
                assert self.pins[p] == raw
            self.pins[p] = raw
            return raw

        bundle = json.loads(read(ROOT / 'development/request-compile-r1/bundle.json'))
        assert bundle['status'] == 'PASS'
        assert bundle['scope'] == 'WORKER_REQUEST_COMPONENT_DEVELOPMENT_NOT_COMPLETE_WORKER_OR_COLD'
        wire = json.loads(read(RENDER / 'development/compile-r3/bundle.json'))
        assert wire['status'] == 'PASS'
        assert wire['scope'] == 'SOURCE_BOUND_GRAPH_WIRE_DEVELOPMENT_NOT_PUBLIC_ADMISSION_OR_COLD'
        components = dict(controller=bundle['components']['request-driver'],
                          sha=bundle['components']['sha256-stream'], **wire['components'])
        current = dict(controller=ROOT / 'examples/hia_bootstrap/agent_worker_request_driver.hiaasm',
                       sha=BASE / 'Hepta-agent-edit-native/examples/hia_bootstrap/sha256_stream.hiaasm',
                       scan=RENDER / 'examples/hia_bootstrap/graph_json_wire_scan.hiaasm',
                       emit=RENDER / 'examples/hia_bootstrap/graph_json_wire_emit.hiaasm')
        schemas = dict(controller='hepta.hia.worker-request-driver-development.v1',
                       sha='hepta.hia.worker-sha256-stream-development.v1',
                       scan='hepta.hia.graph-json-wire-scan-native.v1',
                       emit='hepta.hia.graph-json-wire-emit-native.v1')
        images = {}
        for role, row in components.items():
            assert row['schema'] == schemas[role]
            source = read(row['source_path'])
            image = read(row['image_path'])
            assert read(current[role]) == source and sha256(source).hexdigest() == row['source_sha256']
            assert sha256(image).hexdigest() == row['image_sha256']
            assert row['compiler_sha256'] == '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
            receipt = json.loads(read(row.get('receipt_path') or str(row['image_path']).replace('.image.bin', '.receipt.json')))
            assert receipt['input_sha256'] == row['source_sha256']
            assert receipt['produced_sha256'] == row['image_sha256']
            assert receipt['image_sha256'] == row['compiler_sha256']
            images[role] = image, row['image_sha256']
        for path in (Path(__file__), ROOT / 'tools/generate_hia_worker_request_driver.py',
                     BASE / 'Hepta-agent-edit-native/hepta/hia_agent_worker.py',
                     BASE / 'Hepta-agent-edit-native/hepta/hia_agent_store.py'):
            read(path)
        self.readback()
        self.out.mkdir(parents=True, exist_ok=False)
        self.rawdir = self.out / 'raw'
        self.rawdir.mkdir()
        self.saved = set()
        self.images = {role: NativeHiaJsonImage(*row) for role, row in images.items()}
        self.log = (self.out / 'entries.jsonl').open('w')
        self.pinfile('source-before.json')

    def readback(self):
        assert all(p.read_bytes() == raw for p, raw in self.pins.items())

    def pinfile(self, name):
        data = {str(p): dict(bytes=len(raw), sha256=sha256(raw).hexdigest()) for p, raw in self.pins.items()}
        (self.out / name).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')

    def save(self, data):
        key = sha256(data).hexdigest()
        path = self.rawdir / (key + '.bin.gz')
        if key not in self.saved:
            if path.exists():
                assert gzip.decompress(path.read_bytes()) == data
            else:
                path.write_bytes(gzip.compress(data, compresslevel=1, mtime=0))
                assert gzip.decompress(path.read_bytes()) == data
            self.saved.add(key)
        return dict(path=str(path), bytes=len(data), sha256=key, storage='lossless-gzip')

    @staticmethod
    def buffer(size, previous=None):
        value = ctypes.create_string_buffer(size + len(CANARY))
        if previous is not None:
            assert len(previous) <= size
            ctypes.memmove(value, previous, len(previous))
        ctypes.memmove(ctypes.addressof(value) + size, CANARY, len(CANARY))
        return value

    def call(self, role, source, command, work, size, label, *, output=None, output_size=None):
        s = ctypes.create_string_buffer(source + CANARY)
        r = ctypes.create_string_buffer(command + CANARY) if output is None else output
        r_size = len(command) if output is None else output_size
        before = ctypes.string_at(work, size)
        output_before = ctypes.string_at(r, r_size) if output is not None else None
        ret = self.images[role]._entry(s, len(source), r, r_size, work, size)
        self.entries[role] += 1
        assert ctypes.string_at(s, len(source) + 32) == source + CANARY
        if output is None:
            assert ctypes.string_at(r, len(command) + 32) == command + CANARY
        else:
            assert ctypes.string_at(ctypes.addressof(r) + r_size, 32) == CANARY
        assert ctypes.string_at(ctypes.addressof(work) + size, 32) == CANARY
        after = ctypes.string_at(work, size)
        output_after = ctypes.string_at(r, r_size) if output is not None else b''
        event = struct.unpack_from('<32Q', after, 256) if role == 'controller' and size >= 512 else None
        row = dict(case=label, role=role, result=ret, source=self.save(source), command=self.save(command),
                   before=self.save(before), after=self.save(after), event=event,
                   output_before=self.save(output_before) if output_before is not None else None,
                   output_after=self.save(output_after), input_and_canaries_unchanged=True)
        self.records.append(row)
        self.log.write(json.dumps(row, sort_keys=True) + '\n')
        self.log.flush()
        return ret, event, after, output_after

    def run(self, source, catalog, *, digits=4300, label='case', initial=2048, request=1):
        command = struct.pack('<8Q', M(b'HIAWQC01'), 551, request, digits, len(source), 0, 0, 0) + catalog.encode()
        size = initial
        work = self.buffer(size)
        wire_work = wire_output = None
        wire_size = wire_output_size = 0
        sha_work = sha_output = None
        sequence = 0
        grows = services = 0
        for _ in range(256):
            ret, event, state, _ = self.call('controller', source, command, work, size, label)
            assert ret == 512 and event[0] == M(b'HIAWQE01'), (ret, event)
            assert event[2:5] == (551, request, sequence + 1) and not any(event[26:])
            sequence = event[4]
            if event[1] == 1:
                assert event[6] > size
                size = max(event[6], size * 2)
                work = self.buffer(size, state)
                grows += 1
                continue
            if event[1] in (0, 3):
                offset, amount = event[17:19]
                assert offset <= size and amount <= size - offset
                payload = state[offset:offset + amount]
                return dict(event=event, digest=payload if event[1] == 0 else None,
                            error=payload.decode() if event[1] == 3 else None,
                            grows=grows, services=services, result=self.save(payload))
            assert event[1] == 2 and event[7] in (1, 2, 3), event
            peer = event[7]
            at, count, command_at, command_count = event[8:12]
            assert at <= size and count <= size - at
            assert command_at <= size and command_count <= size - command_at
            peer_source, peer_command = state[at:at + count], state[command_at:command_at + command_count]
            need, out_size, reuse = event[12:15]
            if peer in (1, 2):
                if not reuse:
                    assert wire_work is None
                    wire_size, wire_output_size = need, out_size
                    wire_work = self.buffer(need)
                elif need != wire_size:
                    assert need > wire_size and out_size == wire_output_size
                    wire_work = self.buffer(need, ctypes.string_at(wire_work, wire_size))
                    wire_size = need
                ret, _, peer_state, peer_output = self.call('scan' if peer == 1 else 'emit',
                    peer_source, peer_command, wire_work, wire_size, label)
            else:
                assert not peer_command and need == 1184 and out_size == 32
                if not reuse:
                    assert sha_work is None
                    sha_work, sha_output = self.buffer(need), self.buffer(out_size)
                ret, _, peer_state, peer_output = self.call('sha', peer_source, b'', sha_work,
                    need, label, output=sha_output, output_size=out_size)
            services += 1
            command = struct.pack('<8Q', M(b'HIAWQA01'), 551, request, sequence,
                                  peer, ret, out_size, need) + peer_output + peer_state
        raise AssertionError('native request continuation did not terminate')

    def close(self):
        self.log.close()
        for image in self.images.values():
            image._entry = None
            image._mapping.close()
        self.readback()
        self.pinfile('source-after.json')
        (self.out / 'custody.json').write_text(json.dumps(dict(source_before_after_equal=True,
            entries=self.entries), indent=2, sort_keys=True) + '\n')


def forbid_retained(stack):
    def disabled(*args, **kwargs):
        raise AssertionError('retained worker request owner used during native forwarding')
    for target in ('hepta.hia_agent_worker.main', 'hepta.hia_agent_worker.wire',
                   'hepta.hia_agent_worker.decode_data', 'hepta.hia_agent_worker.keys',
                   'hepta.hia_agent_worker.canonical_digest', 'hepta.hia_agent_store.decode_data',
                   'hepta.hia_agent_store.wire', 'hepta.hia_program_tools.bounded_json_wire',
                   'json.loads'):
        stack.enter_context(patch(target, new=disabled))
