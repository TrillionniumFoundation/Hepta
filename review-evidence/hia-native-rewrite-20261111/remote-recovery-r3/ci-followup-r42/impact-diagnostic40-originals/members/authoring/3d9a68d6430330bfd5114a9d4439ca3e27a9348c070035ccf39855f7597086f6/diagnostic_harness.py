"""Exact old/new native state and full diagnostic oracle, development only."""
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import gzip
import json
import os
from pathlib import Path
import struct
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent / 'Hepta-v66-restored'
OLD = ROOT.parent / 'native-composite-driver-reconstructed'
sys.path[:0] = [str(ROOT), str(OLD / 'development'), str(BASE)]
from mechanical_executor import Buffer
from hepta.hia_core_admission_native import scratch_sizes, ERROR_CODES
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program import verify_program, HIAProgramRejected

BAD = 0xfffffffd
NEED = 0xfffffffe
TEXT_MAGIC = int.from_bytes(b'HIACDT01', 'little')
CONTEXT_MAGIC = int.from_bytes(b'HIACDG01', 'little')


def compact(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':'), sort_keys=True).encode()


class Harness:
    def __init__(self, name, script):
        self.pins = {}
        self.images = {}
        self.calls = Counter()
        self.rows = []
        self.started = time.monotonic_ns()
        self.dest = ROOT / 'development' / name
        assert not self.dest.exists()
        manifest = ROOT / 'development/build-r1/bundle.json'
        bundle = json.loads(self.read(manifest))
        assert bundle['status'] == 'PASS'
        self.read(Path(script)); self.read(Path(__file__))
        source_manifest = ROOT / 'checkpoints/source-r1/source.json'
        frozen = json.loads(self.read(source_manifest))
        for rel, row in frozen['files'].items():
            raw = self.read(ROOT / rel)
            assert len(raw) == row['bytes'] and sha256(raw).hexdigest() == row['sha256']
        components = {}
        for name in ('core_diagnostic_check', 'core_diagnostic_text'):
            row = bundle['components'][name]
            source = self.read(Path(row['source_path']))
            assert source == self.read(Path(row['frozen_source_path']))
            assert sha256(source).hexdigest() == row['source_sha256']
            image = self.read(Path(row['image_path']))
            assert len(image) == row['image_bytes'] and sha256(image).hexdigest() == row['image_sha256']
            receipt = json.loads(self.read(Path(row['receipt_path'])))
            assert receipt['input_sha256'] == row['source_sha256']
            assert receipt['produced_sha256'] == row['image_sha256']
            assert receipt['artifact_sha256'] == bundle['compiler_sha256']
            components[name] = (image, row['image_sha256'])
        oldbundle = json.loads(self.read(OLD / 'development/publication-bundle-r2/bundle.json'))
        row = oldbundle['components']['27']
        source = self.read(Path(row['source_path']))
        assert source == self.read(BASE / 'examples/hia_bootstrap/core_admission.hiaasm')
        assert sha256(source).hexdigest() == row['source_sha256']
        image = self.read(Path(row['image_path']))
        assert len(image) == row['image_bytes'] and sha256(image).hexdigest() == row['image_sha256']
        receipt = json.loads(self.read(Path(row['receipt_path'])))
        assert receipt['input_sha256'] == row['source_sha256'] and receipt['produced_sha256'] == row['image_sha256']
        components['original'] = (image, row['image_sha256'])
        for p in (BASE / 'hepta').glob('*.py'):
            self.read(p)
        assert not {k: v for k, v in os.environ.items() if k.startswith('HEPTA_HIA_') and k.endswith('_MANIFEST') and v}
        self.readback()
        self.dest.mkdir()
        (self.dest / 'source-before.json').write_text(json.dumps({str(p): {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            for p, raw in self.pins.items()}, indent=2, sort_keys=True) + '\n')
        for name, (raw, digest) in components.items():
            self.images[name] = NativeHiaJsonImage(raw, digest)

    def read(self, path):
        path = path.resolve(); raw = path.read_bytes()
        if path in self.pins:
            assert raw == self.pins[path]
        self.pins[path] = raw
        return raw

    def readback(self):
        assert all(path.read_bytes() == raw for path, raw in self.pins.items())

    def native(self, name, a, b, c):
        result = int(self.images[name]._entry(a.address, a.size, b.address, b.size, c.address, c.size))
        for item in (a, b, c):
            item.check()
        self.calls[name] += 1
        return result

    def run(self, name, document, *, capacity_control=True):
        wire = document if type(document) is bytes else compact(document)
        directory = self.dest / name
        directory.mkdir()
        (directory / 'input.json.gz').write_bytes(gzip.compress(wire, compresslevel=1, mtime=0))
        try:
            checked = verify_program(wire)
            oracle = {'accepted': True, 'core_sha256': checked.sha256}
            expected = b''
        except HIAProgramRejected as exc:
            oracle = {'accepted': False, 'code': exc.code, 'error': str(exc)}
            expected = str(exc).encode()
        (directory / 'oracle.json').write_text(json.dumps(oracle, ensure_ascii=False, indent=2) + '\n')
        original_state_size, arena_size = scratch_sizes(len(wire))
        state_size = original_state_size + 512
        s = Buffer(len(wire), wire, True)
        oldstate = Buffer(state_size); oldarena = Buffer(arena_size)
        state = Buffer(state_size); arena = Buffer(arena_size)
        small = Buffer(64); full = short = None
        row = {'case': name, 'oracle': oracle, 'input_bytes': len(wire), 'input_sha256': sha256(wire).hexdigest(),
               'state_bytes': state_size, 'arena_bytes': arena_size, 'status': 'INCOMPLETE'}
        start = time.monotonic_ns()
        try:
            with ExitStack() as stack:
                for target in ('hepta.hia_program.verify_program', 'hepta.hia_program._reference_primitive_structure',
                               'hepta.hia_program._reference_function_shape', 'hepta.hia_program._verify_function',
                               'hepta.hia_opcodes.check_instruction', 'json.loads'):
                    stack.enter_context(patch(target, side_effect=AssertionError('host semantic owner used: ' + target)))
                oldresult = self.native('original', s, oldstate, oldarena)
                result = self.native('core_diagnostic_check', s, state, arena)
                row['original_status'] = oldresult
                row['native_status'] = result
                oldraw = oldstate.read(0, oldstate.size)
                newraw = state.read(0, state.size)
                oldgraph = oldarena.read(0, oldarena.size)
                graph = arena.read(0, arena.size)
                (directory / 'original-state.bin.gz').write_bytes(gzip.compress(oldraw, compresslevel=1, mtime=0))
                (directory / 'new-state.bin.gz').write_bytes(gzip.compress(newraw, compresslevel=1, mtime=0))
                (directory / 'arena.bin.gz').write_bytes(gzip.compress(graph, compresslevel=1, mtime=0))
                row.update(original_state_sha256=sha256(oldraw).hexdigest(), new_state_sha256=sha256(newraw).hexdigest(),
                           original_arena_sha256=sha256(oldgraph).hexdigest(), new_arena_sha256=sha256(graph).hexdigest())
                if oldgraph != graph:
                    (directory / 'original-arena.bin.gz').write_bytes(gzip.compress(oldgraph, compresslevel=1, mtime=0))
                assert oldresult == result, row
                assert oldraw[:-512] == newraw[:-512], ('original state differs', name)
                assert oldgraph == graph, ('decoder arena differs', name)
                assert s.read(0, s.size) == wire
                row['all_original_state_and_arena_bytes_equal'] = True
                context = struct.unpack('<64Q', newraw[-512:])
                row['context'] = list(context)
                assert context[:2] == (CONTEXT_MAGIC, 1)
                assert context[2] == result
                assert bool(context[10]) == oracle['accepted']
                if result:
                    assert result in ERROR_CODES and ERROR_CODES[result] == oracle['code']
                else:
                    assert oracle['accepted']
                state.protect(True); arena.protect(True)
                rendered = self.native('core_diagnostic_text', arena, state, small)
                head = small.read(0, 64)
                words = struct.unpack('<8Q', head)
                row['measure_return'] = rendered
                row['measure_header'] = list(words)
                (directory / 'measure.header.bin').write_bytes(head)
                assert words[:4] == (TEXT_MAGIC, 1, result, context[3]), (row, words)
                needed = words[5]
                assert words[4] == needed - 64 and words[6] == context[8] and words[7] == 0
                if result == 0:
                    assert rendered == 64 and needed == 64
                    output = b''
                else:
                    assert rendered == NEED and needed == len(expected) + 64, (row, expected)
                    full = Buffer(needed)
                    returned = self.native('core_diagnostic_text', arena, state, full)
                    assert returned == needed and full.read(0, 64) == head
                    output = full.read(64, needed - 64)
                    (directory / 'text.bin').write_bytes(output)
                    assert output == expected, (name, output, expected)
                    if capacity_control:
                        short = Buffer(needed - 1, bytes([0xa5]) * (needed - 1))
                        returned = self.native('core_diagnostic_text', arena, state, short)
                        assert returned == NEED and short.read(0, 64) == head
                        assert short.read(64, short.size - 64) == bytes([0xa5]) * (short.size - 64)
                        row['capacity_minus_one_preserved_payload_and_complete_needed'] = True
                assert state.read(0, state.size) == newraw and arena.read(0, arena.size) == graph
                assert s.read(0, s.size) == wire
                row.update(status='PASS', text_bytes=len(output), text_sha256=sha256(output).hexdigest(),
                           exact_full_host_diagnostic=True, all_canaries_preserved=True,
                           immutable_source_and_actual_context_arena_preserved=True, host_semantic_owners_poisoned=True)
            self.rows.append(row)
            return row
        except BaseException as exc:
            row.update(status='FAIL', error_class=type(exc).__name__, error=str(exc))
            raise
        finally:
            row['wall_ns'] = time.monotonic_ns() - start
            (directory / 'result.json').write_text(json.dumps(row, indent=2, sort_keys=True) + '\n')
            print(json.dumps(row, sort_keys=True), flush=True)
            for buf in (s, oldstate, oldarena, state, arena, small, full, short):
                if buf is not None:
                    buf.close()

    def close(self, error=None):
        for image in self.images.values():
            image._mapping.close()
        self.readback()
        result = {'scope': 'ACTUAL_COMPLETE_CORE_OLD_NEW_STATE_AND_FULL_TEXT_DIFFERENTIAL',
                  'status': 'PASS' if error is None else 'FAIL', 'cases': len(self.rows),
                  'results': self.rows, 'actual_entries': dict(self.calls),
                  'source_images_and_hosted_oracle_unchanged': True,
                  'whole_stack_closed': False, 'public_executable_integrated': False,
                  'wall_ns': time.monotonic_ns() - self.started}
        if error is not None:
            result.update(error_class=type(error).__name__, error=str(error))
        (self.dest / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps({k: v for k, v in result.items() if k != 'results'}, sort_keys=True), flush=True)
