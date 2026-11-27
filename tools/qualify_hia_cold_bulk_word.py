"""Execute native cold-bulk-word construction, memory and driver controls.

The four original pinned seed roots construct B1. Real B1 and B2 emit B2 and
B3. Old byte stores, old word stores and old bulk operations remain independent
native controls. Python observes full buffers, SIGILL and timing; it does not
execute the candidate program. This finite component gate is not whole cold.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import ast
import ctypes
import json
import mmap
import os
import random
import resource
import signal
import statistics
import struct
import subprocess
import time
import traceback

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.generate_hia_cold_document import bulk_document, bulk_word_document
from tools.generate_hia_worker_config_json import document as word_document
from tools.generate_hia_cold_qualification_driver import policy_source
from tools.hia_cold_byte_loops import accelerate
from tools.hia_native_seed_test_support import NativeSeeds
from tools.qualify_hia_seed_cold_backend import call as compiler_call

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64) - 1
GUARD = b'\xA7' * 32
PUT = '''def put(w:mutbuf, at:u64, value:u64) -> u64:
    return 0
'''
PUT_ENTRY = '''def probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    put(w,word_load(s,0),word_load(s,8))
    return 517
'''
WORD_ENTRY = PUT_ENTRY.replace('put(w,', 'word_store(w,')
MOVE_ENTRY = '''def probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    move_within(w,word_load(s,0),word_load(s,8),word_load(s,16))
    return 517
'''
MIXED_ENTRY = '''def probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    put(w,0,word_load(s,0))
    move_within(w,3,0,61)
    fill_range(w,17,11,195)
    put(w,9,word_load(s,8))
    move_within(w,0,7,49)
    put(w,56,word_load(s,16))
    return 517
'''
BENCH_ENTRY = '''def probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    count = word_load(s,0)
    i = 0
    while i < count:
        put(w,(i & 511) * 8,i ^ 18364758544493064720)
        i = i + 1
    return 517
'''
DF_OBSERVER = '''.intel_syntax noprefix
.text
.global check_df
check_df:
    push rbx
    mov rbx, [rsp+16]
    cld
    call rbx
    pushfq
    pop rax
    cld
    pop rbx
    ret
'''


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    seeds = NativeSeeds(ROOT, args.bootstrap, output)
    report = {'schema': 'hepta.hia.cold-bulk-word-qualification.v1', 'passed': False,
              'whole_cold_qualified': False, 'budget_and_cleanup_changed': False,
              'products': {}, 'counts': {}, 'historical_qualification_reused': False}
    observed = (output / 'observations.jsonl').open('x')
    images = []
    captured = {}
    for name in ('tools/generate_hia_seed_cold_bulk_word_backend.py',
                 'tools/hia_seed_word_store.py', 'tools/generate_hia_seed_word_backend.py',
                 'tools/generate_hia_seed_backend.py', 'tools/generate_hia_seed_bulk_backend.py',
                 'tools/generate_hia_seed_cold_backend.py',
                 'tools/generate_hia_cold_document.py', 'tools/hia_cold_byte_loops.py',
                 'tools/generate_hia_cold_qualification_driver.py',
                 'tools/qualify_hia_cold_bulk_word.py',
                 *(f'examples/hia_bootstrap/seed_{p}_backend.hepta' for p in
                   ('bulk', 'word', 'cold_bulk', 'cold_endian', 'cold_bulk_word')),
                 'examples/hia_bootstrap/cold_qualification_driver.hepta'):
        captured[name] = (ROOT / name).read_bytes()
    report['source_pins'] = {name: pin(raw) for name, raw in captured.items()}

    def save():
        seeds.save()
        observed.flush()
        (output / 'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')

    def image(raw):
        result = NativeHiaJsonImage(raw, sha256(raw).hexdigest())
        images.append(result)
        return result

    def project(raw, name):
        (output / (name + '.hepta')).write_bytes(raw)
        core = seeds.invoke(output / 'hia-seed-assembly', raw, '--agent-compact')
        wire = seeds.invoke(output / 'hia-seed-projector', b'[' + core + b',"f0",1]')
        (output / (name + '.wire')).write_bytes(wire)
        return wire

    def emit(native, wire):
        result = compiler_call(native, wire, b'\xA5' * (1 << 20), b'\x6D' * (1 << 20))
        assert 0 < result[0] <= 1 << 20, result[0]
        assert result[2][result[0]:] == b'\xA5' * ((1 << 20) - result[0])
        return result[2][:result[0]]

    def record(group, detail):
        report['counts'][group] = report['counts'].get(group, 0) + 1
        observed.write(json.dumps({'group': group, **detail}, separators=(',', ':')) + '\n')

    def buffer_call(native, raw, before, extent, expected, *, alias=None, trap=False, flags=False):
        # Shared mapping retains a trapped child's exact partial writes.
        full = GUARD + before + GUARD
        shared = mmap.mmap(-1, len(full), flags=mmap.MAP_SHARED,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE)
        shared[:] = full
        view = (ctypes.c_char * len(full)).from_buffer(shared)
        source = ctypes.create_string_buffer(GUARD + raw + GUARD, len(raw) + 64)
        target = ctypes.create_string_buffer(GUARD + b'preserve' + GUARD, 72)
        s = ctypes.byref(source, 32)
        o = ctypes.byref(target, 32)
        w = ctypes.byref(view, 32)
        if alias is not None:
            s = ctypes.byref(view, 32 + alias[0])
            o = ctypes.byref(view, 32 + alias[1])
        arguments = (s, len(raw), o, 8, w, extent)
        try:
            if trap:
                child = os.fork()
                if child == 0:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                    signal.alarm(5)
                    native._entry(*arguments)
                    os._exit(111)
                _, status = os.waitpid(child, 0)
                assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGILL, status
            elif flags:
                assert observe_flags(*arguments, native._entry) & 0x400 == 0
            else:
                assert native._entry(*arguments) == 517
            assert shared[:] == GUARD + expected + GUARD
            assert source.raw == GUARD + raw + GUARD
            assert target.raw == GUARD + b'preserve' + GUARD
            return pin(shared[:])
        finally:
            del arguments, s, o, w
            del view
            shared.close()

    started = time.monotonic_ns()
    try:
        name = 'seed_cold_bulk_word_backend'
        wire = project(captured['examples/hia_bootstrap/' + name + '.hepta'], name)
        b1 = seeds.invoke(output / 'hia-seed-backend', wire)
        b1_image = image(b1)
        b2 = emit(b1_image, wire)
        b2_image = image(b2)
        b3 = emit(b2_image, wire)
        assert b1 != b2 and b2 == b3
        for label, raw in [('B1', b1), ('B2', b2), ('B3', b3)]:
            (output / (label + '.flat')).write_bytes(raw)
        report['fixedpoint'] = {'B1_from_original_v1': True, 'B2_equals_B3': True,
                               'B1': pin(b1), 'B2': pin(b2), 'B3': pin(b3)}
        parent_raw = seeds.compile(captured['examples/hia_bootstrap/seed_cold_bulk_backend.hepta'], 'v1')
        word_raw = seeds.compile(captured['examples/hia_bootstrap/seed_word_backend.hepta'], 'v1')
        parent, old_word = image(parent_raw), image(word_raw)

        def build(label, source, author, compiler):
            raw = render_assembly(author(source, label.replace('-', '_'))).encode()
            projected = project(raw, label)
            flat = emit(compiler, projected)
            if compiler is b1_image:
                assert emit(b2_image, projected) == flat, label
            (output / (label + '.flat')).write_bytes(flat)
            report['products'][label] = {'source': pin(raw), 'wire': pin(projected), 'image': pin(flat)}
            return image(flat), projected, flat

        old_put = accelerate(PUT_ENTRY + PUT)
        new_put = accelerate(PUT_ENTRY + PUT, word=True)
        byte_image, _, byte_flat = build('original-byte-put', old_put, bulk_document, parent)
        same_byte, _, same_byte_flat = build('unchanged-byte-put', old_put, bulk_document, b1_image)
        assert same_byte_flat == byte_flat
        put_image, _, _ = build('candidate-put', new_put, bulk_word_document, b1_image)
        word_image, word_wire, _ = build('candidate-word', WORD_ENTRY, bulk_word_document, b1_image)
        old_word_image, _, _ = build('original-word', WORD_ENTRY, word_document, old_word)
        move_image, _, _ = build('candidate-move', MOVE_ENTRY, bulk_word_document, b1_image)
        old_move, _, _ = build('original-move', MOVE_ENTRY, bulk_document, parent)
        old_mixed, _, _ = build('original-mixed', accelerate(MIXED_ENTRY + PUT), bulk_document, parent)
        mixed_image, _, _ = build('candidate-mixed', accelerate(MIXED_ENTRY + PUT, word=True), bulk_word_document, b1_image)
        # The exact entire current driver is actually compiled by both B1/B2.
        driver = captured['examples/hia_bootstrap/cold_qualification_driver.hepta']
        assert driver == render_assembly(bulk_word_document(policy_source(), 'cold_qualification_driver')).encode()
        driver_wire = project(driver, 'actual-cold-driver')
        driver_flat = emit(b1_image, driver_wire)
        assert driver_flat == emit(b2_image, driver_wire)
        (output / 'actual-cold-driver.flat').write_bytes(driver_flat)
        report['actual_cold_driver'] = {'source': pin(driver), 'image': pin(driver_flat),
                                      'B1_B2_output_equal': True}

        (output / 'df-observer.S').write_text(DF_OBSERVER)
        subprocess.run(['as', '--64', str(output / 'df-observer.S'), '-o', str(output / 'df-observer.o')], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(output / 'df-observer.o'), str(output / 'df-observer.flat')], check=True, capture_output=True)
        observer_raw = (output / 'df-observer.flat').read_bytes()
        region = mmap.mmap(-1, len(observer_raw), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        region[:] = observer_raw
        signature = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64,
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)
        observe_flags = signature(ctypes.addressof(ctypes.c_char.from_buffer(region)))
        report['mechanical_df_observer'] = pin(observer_raw)
        rng = random.Random(0xC01DB017)
        values = (0, 1, (1 << 31)-1, 1 << 31, (1 << 32)-1, 1 << 32,
                  (1 << 63)-1, 1 << 63, 0x0123456789ABCDEF, MASK)
        for extent in (8, 9, 15, 16, 31, 64, 255, 4096):
            before = rng.randbytes(extent + 16)
            for at in sorted({0, 1 if extent > 8 else 0, extent // 2 if extent >= 16 else 0, extent - 8}):
                for value in values:
                    expected = bytearray(before)
                    expected[at:at+8] = struct.pack('<Q', value)
                    raw = struct.pack('<2Q', at, value)
                    for native in (byte_image, put_image, old_word_image, word_image):
                        buffer_call(native, raw, before, extent, bytes(expected))
                    record('valid_u64_unaligned_and_end', {'extent': extent, 'at': at, 'value': value,
                                                         'expected': pin(expected)})
        invalid = [(n, at) for n in (0, 1, 7, 8, 9, 15, 16, 31)
                   for at in sorted({n, n+1, max(0, n-7), max(0, n-1)})]
        invalid += [(31, n) for n in (1 << 32, (1 << 32)+1, 1 << 63, MASK-7, MASK)]
        for extent, at in invalid:
            before = rng.randbytes(128)
            value = 0x0123456789ABCDEF
            raw = struct.pack('<2Q', at, value)
            expected = bytearray(before)
            written = max(0, min(8, extent-at))
            expected[at:at+written] = struct.pack('<Q', value)[:written] if written else b''
            for native in (byte_image, put_image):
                buffer_call(native, raw, before, extent, bytes(expected), trap=True)
            for native in (old_word_image, word_image):
                buffer_call(native, raw, before, extent, before, trap=True)
            record('partial_put_and_atomic_word_sigill', {'extent': extent, 'at': at, 'bytes_written': written,
                                                         'partial': pin(expected), 'atomic': pin(before)})
        for source_at, output_at, at in ((0, 0, 0), (0, 8, 3), (8, 0, 11), (31, 33, 32), (64, 79, 120)):
            before = bytearray(rng.randbytes(256))
            value = rng.getrandbits(64)
            raw = struct.pack('<2Q', at, value)
            before[source_at:source_at+16] = raw
            expected = bytearray(before)
            expected[at:at+8] = struct.pack('<Q', value)
            for native in (byte_image, put_image, old_word_image, word_image):
                buffer_call(native, raw, bytes(before), 256, bytes(expected), alias=(source_at, output_at))
            record('input_output_workspace_alias', {'source_at': source_at, 'output_at': output_at, 'at': at,
                                                    'expected': pin(expected)})
        for extent in (0, 1, 7, 8, 9, 16, 31, 64):
            before = rng.randbytes(96)
            for target in sorted({0, min(1, extent), min(3, extent), extent//2, extent}):
                for source in sorted({0, min(1, extent), min(3, extent), extent//2, extent}):
                    maximum = min(extent-target, extent-source)
                    for count in sorted({0, min(1, maximum), maximum}):
                        expected = bytearray(before)
                        expected[target:target+count] = bytes(before[source:source+count])
                        raw = struct.pack('<3Q', target, source, count)
                        for native in (old_move, move_image):
                            buffer_call(native, raw, before, extent, bytes(expected), flags=True)
                        record('move_overlap_direction_and_df', {'extent': extent, 'target': target,
                                                                'source': source, 'count': count})
        for extent, target, source, count in ((8, 9, 0, 0), (8, 0, 9, 0), (8, 7, 0, 2),
                (8, 0, 7, 2), (31, MASK, 0, 0), (31, 0, MASK, 0), (31, 0, 0, MASK),
                (31, 1 << 32, 0, 1), (31, 0, 1 << 63, 1)):
            before = rng.randbytes(96)
            raw = struct.pack('<3Q', target, source, count)
            for native in (old_move, move_image):
                buffer_call(native, raw, before, extent, before, trap=True)
            record('move_invalid_no_write_sigill', {'extent': extent, 'target': target, 'source': source, 'count': count})
        for first in values:
            raw = struct.pack('<3Q', first, first ^ MASK, first ^ 0x0123456789ABCDEF)
            before = rng.randbytes(96)
            expected = bytearray(before)
            expected[:8] = raw[:8]
            expected[3:64] = bytes(expected[:61])
            expected[17:28] = b'\xC3' * 11
            expected[9:17] = raw[8:16]
            expected[:49] = bytes(expected[7:56])
            expected[56:64] = raw[16:24]
            for native in (old_mixed, mixed_image):
                buffer_call(native, raw, before, 64, bytes(expected), flags=True)
            record('interleaved_word_fill_both_move_directions', {'values': raw.hex(), 'expected': pin(expected)})

        # Real sparse address space exercises offsets above 32 bits. Only a
        # handful of pages are resident; no widened wrapper or fake pointer.
        high = (1 << 32) + 1
        sparse = mmap.mmap(-1, high + 64, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | 0x4000,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE)
        sparse_view = ctypes.c_char.from_buffer(sparse)
        sparse_pointer = ctypes.addressof(sparse_view)
        try:
            for at in (high, high + 7, high + 16):
                value = MASK ^ at
                raw = ctypes.create_string_buffer(struct.pack('<2Q', at, value))
                out = ctypes.create_string_buffer(b'preserve', 8)
                for native in (byte_image, put_image, old_word_image, word_image):
                    sparse[high-8:high+40] = b'\xA5' * 48
                    assert native._entry(raw, 16, out, 8, sparse_pointer, high+32) == 517
                    expected = bytearray(b'\xA5' * 48)
                    expected[at-(high-8):at-(high-8)+8] = struct.pack('<Q', value)
                    assert sparse[high-8:high+40] == bytes(expected)
                    assert sparse[:32] == bytes(32) and out.raw == b'preserve'
                record('real_sparse_offset_above_u32', {'at': at, 'extent': high+32, 'value': value})
        finally:
            del sparse_view
            sparse.close()

        start = struct.unpack_from('<Q', word_wire, 64)[0]
        instructions = [at for at in range(start, len(word_wire)-63, 64)
                        if struct.unpack_from('<Q', word_wire, at)[0] == 38]
        stores = [(at, struct.unpack_from('<Q', word_wire, at+8)[0]) for at in instructions
                  if struct.unpack_from('<Q', word_wire, struct.unpack_from('<Q', word_wire, at+8)[0])[0] == 26]
        assert len(stores) == 1
        at, site = stores[0]
        refusals = [(site, 25), (site+8, 3), (site+8, 5), (site+16, 2), (site+16, 4),
                    (site+24, 1), (at+24, 2), (at+40, 1), (at+16, MASK), (at+48, 1)]
        for offset, value in refusals:
            bad = bytearray(word_wire)
            struct.pack_into('<Q', bad, offset, value)
            outcomes = [compiler_call(native, bytes(bad), b'\xA5'*(1<<20), b'\x6D'*(1<<20))
                        for native in (old_word, b1_image, b2_image)]
            assert outcomes[0] == outcomes[1] == outcomes[2]
            assert outcomes[0][0] in (4294967293, 4294967295) and outcomes[0][2] == b'\xA5'*(1<<20)
            record('word_admission_refusal_unchanged', {'offset': offset, 'value': value, 'status': outcomes[0][0]})

        old_bench, _, _ = build('original-put-loop', accelerate(BENCH_ENTRY + PUT), bulk_document, parent)
        new_bench, _, _ = build('candidate-put-loop', accelerate(BENCH_ENTRY + PUT, word=True), bulk_word_document, b1_image)
        iterations = 200000
        benchmark_input = ctypes.create_string_buffer(struct.pack('<Q', iterations))
        target = ctypes.create_string_buffer(b'preserve', 8)
        workspace = ctypes.create_string_buffer(4096)
        expected = bytearray(4096)
        for i in range(iterations):
            struct.pack_into('<Q', expected, (i & 511)*8, i ^ 18364758544493064720)
        timings = {'byte': [], 'word': []}
        for trial in range(6):
            order = [('byte', old_bench), ('word', new_bench)]
            if trial % 2:
                order.reverse()
            for label, native in order:
                ctypes.memset(workspace, 0, 4096)
                stamp = time.monotonic_ns()
                result = native._entry(benchmark_input, 8, target, 8, workspace, 4096)
                elapsed = time.monotonic_ns() - stamp
                assert result == 517 and workspace.raw == bytes(expected) and target.raw == b'preserve'
                timings[label].append(elapsed)
        report['finite_put_loop_timing'] = {
            'iterations_per_trial': iterations, 'alternating_order_trials': 6,
            'wall_ns': timings, 'byte_median_ns': statistics.median(timings['byte']),
            'word_median_ns': statistics.median(timings['word']),
            'median_speedup': statistics.median(timings['byte']) / statistics.median(timings['word']),
            'full_result_equal_every_trial': True, 'whole_cold_speedup_claimed': False}
        assert all((ROOT / name).read_bytes() == raw for name, raw in captured.items())
        report['source_unchanged'] = True
        report['elapsed_ns'] = time.monotonic_ns() - started
        report['passed'] = True
        print('COLD_BULK_WORD_PASS', json.dumps(report['counts'], sort_keys=True), flush=True)
        print('PUT_LOOP_TIMING', json.dumps(report['finite_put_loop_timing'], sort_keys=True), flush=True)
    except BaseException:
        report['error'] = traceback.format_exc()
        raise
    finally:
        observed.flush()
        report['observations'] = pin((output / 'observations.jsonl').read_bytes())
        save()
        observed.close()
        for native in images:
            native._mapping.close()


if __name__ == '__main__':
    main()
