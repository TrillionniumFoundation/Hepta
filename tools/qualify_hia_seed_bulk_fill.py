"""Independent native self-compilation and full fill ABI controls."""
from pathlib import Path
import ctypes, hashlib, json, mmap, os, random, resource, signal, struct, subprocess, sys

ROOT = Path(__file__).resolve().parents[1]
import argparse
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bootstrap', type=Path, required=True, help='directory containing the four pinned independent native seed roots')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
CUSTODY = args.bootstrap.resolve()
from tools.hia_native_seed_test_support import NativeSeeds
from tools.generate_hia_cold_document import bulk_document
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage

OUT = args.output.resolve()
seeds = NativeSeeds(ROOT, CUSTODY, OUT)
report = {'scope': 'two actual native seed profiles and bounded fill behavior; not full cold',
          'passed': False, 'profiles': {}, 'controls': {}}
FILL = '''def probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    fill_range(w,word_load(s,0),word_load(s,8),word_load(s,16))
    return 0
'''
MIXED = '''def probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    move_within(w,3,0,61)
    fill_range(w,17,11,195)
    move_within(w,0,7,49)
    return 0
'''
OBSERVER = '''.intel_syntax noprefix
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
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def compile_flat(source, profile):
    core = seeds.invoke(OUT / 'hia-seed-assembly', source, '--agent-compact')
    projected = seeds.invoke(OUT / 'hia-seed-projector', b'[' + core + b',"f0",1]')
    return seeds.invoke(profile, projected), projected


def pack(flat, label):
    raw = seeds.invoke(seeds.profiles['seed-packer'], b'HIAFLT01' + struct.pack('<Q', len(flat)) + flat)
    path = OUT / label
    path.write_bytes(raw)
    path.chmod(0o500)
    return path, raw


def trap(native, extent, offset, count):
    m = mmap.mmap(-1, 8192, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    before = random.Random(437 + extent).randbytes(8192)
    m[:] = before
    w = (ctypes.c_char * 8192).from_buffer(m)
    s = ctypes.create_string_buffer(struct.pack('<3Q', offset, count, 177))
    o = ctypes.create_string_buffer(8)
    pid = os.fork()
    if pid == 0:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        signal.alarm(5)
        native._entry(s, 24, o, 8, w, extent)
        os._exit(111)
    child, status = os.waitpid(pid, 0)
    assert child == pid and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGILL
    assert m[:] == before
    del w
    m.close()


try:
    seeds.backend('bulk')  # Native v1 construction also supplies the packer.
    (OUT / 'flags-observer.S').write_text(OBSERVER)
    subprocess.run(['as', '--64', str(OUT / 'flags-observer.S'), '-o', str(OUT / 'flags-observer.o')], check=True, capture_output=True)
    subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(OUT / 'flags-observer.o'), str(OUT / 'flags-observer.flat')], check=True, capture_output=True)
    observer_raw = (OUT / 'flags-observer.flat').read_bytes()
    region = mmap.mmap(-1, len(observer_raw), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    region[:] = observer_raw
    signature = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64,
        ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)
    observe_flags = signature(ctypes.addressof(ctypes.c_char.from_buffer(region)))
    report['mechanical_df_observer'] = pin(observer_raw)
    programs = {'fill': render_assembly(bulk_document(FILL, 'fill_abi_probe')).encode(),
                'mixed': render_assembly(bulk_document(MIXED, 'fill_move_probe')).encode()}
    for name, raw in programs.items():
        (OUT / (name + '.hepta')).write_bytes(raw)
    for profile in ['seed_bulk_backend', 'seed_div_bulk_backend']:
        current = (ROOT / 'examples/hia_bootstrap' / (profile + '.hepta')).read_bytes()
        original = subprocess.check_output(['git', 'show', '5622dafbcfa10ad0c6f99214994ee7dcf71523e0:examples/hia_bootstrap/' + profile + '.hepta'], cwd=ROOT)
        oldflat, _ = compile_flat(original, OUT / 'hia-seed-backend')
        oldtool, oldbytes = pack(oldflat, profile + '-original')
        first, wire = compile_flat(current, OUT / 'hia-seed-backend')
        first_tool, first_bytes = pack(first, profile + '-B1')
        second = seeds.invoke(first_tool, wire)
        second_tool, second_bytes = pack(second, profile + '-B2')
        third = seeds.invoke(second_tool, wire)
        assert first == second == third and first_bytes == second_bytes
        row = {'source': pin(current), 'original_source': pin(original),
               'original_tool': pin(oldbytes), 'B1': pin(first), 'B2': pin(second), 'B3': pin(third),
               'packed_B1_B2': pin(first_bytes), 'fixedpoint_equal': True, 'controls': {}}
        report['profiles'][profile] = row
        images = {}
        for name, program in programs.items():
            images[name] = {}
            for kind, tool in [('original', oldtool), ('candidate', second_tool)]:
                flat, _ = compile_flat(program, tool)
                (OUT / (profile + '-' + name + '-' + kind + '.flat')).write_bytes(flat)
                images[name][kind] = NativeHiaJsonImage(flat, hashlib.sha256(flat).hexdigest())
        rng = random.Random(187)
        initial = rng.randbytes(65536)
        valid = 0
        for extent in [0, 1, 7, 8, 63, 64, 65, 255, 4096, 65536]:
            for offset in sorted({0, extent // 2, extent}):
                for count in sorted({0, min(1, extent - offset), extent - offset}):
                    for value in [0, 1, 127, 128, 255, 256, (1 << 64) - 1]:
                        expected = bytearray(initial)
                        expected[offset:offset + count] = bytes([value & 255]) * count
                        for native in images['fill'].values():
                            w = ctypes.create_string_buffer(initial, len(initial))
                            s = ctypes.create_string_buffer(struct.pack('<3Q', offset, count, value))
                            o = ctypes.create_string_buffer(8)
                            assert native._entry(s, 24, o, 8, w, extent) == 0
                            assert w.raw == bytes(expected) and o.raw == bytes(8)
                            flags = observe_flags(s, 24, o, 8, w, extent, native._entry)
                            assert flags & 0x400 == 0 and w.raw == bytes(expected)
                        valid += 1
        row['controls']['valid_extents_values_and_df'] = valid
        for native in images['fill'].values():
            s = ctypes.create_string_buffer(struct.pack('<3Q', 0, 0, 255))
            o = ctypes.create_string_buffer(b'preserve', 8)
            assert native._entry(s, 24, o, 8, None, 0) == 0 and o.raw == b'preserve'
            assert observe_flags(s, 24, o, 8, None, 0, native._entry) & 0x400 == 0
        row['controls']['null_empty_view_and_df'] = 1
        invalid = [(0, 1, 0), (0, 0, 1), (1, 2, 0), (1, 1, 1), (8, 7, 2),
                   (4096, 4097, 0), (4096, 4095, 2), (4096, 0, (1 << 64) - 1),
                   (4096, (1 << 64) - 1, 0), (4096, (1 << 64) - 1, (1 << 64) - 1)]
        for extent, offset, count in invalid:
            for native in images['fill'].values():
                trap(native, extent, offset, count)
        row['controls']['original_sigill_and_no_partial_write'] = len(invalid)
        aliases = 0
        for source_at, output_at, offset, count in [(0, 5, 0, 64), (16, 31, 10, 20),
                (32, 40, 0, 64), (64, 128, 48, 96), (120, 17, 0, 0)]:
            before = bytearray(rng.randbytes(256))
            struct.pack_into('<3Q', before, source_at, offset, count, 173)
            expected = bytearray(before)
            expected[offset:offset + count] = bytes([173]) * count
            for native in images['fill'].values():
                w = ctypes.create_string_buffer(bytes(before), 256)
                assert native._entry(ctypes.byref(w, source_at), 24,
                                     ctypes.byref(w, output_at), 8, w, 256) == 0
                assert w.raw == bytes(expected)
            aliases += 1
        row['controls']['aliased_source_output_workspace'] = aliases
        expected = bytearray(range(64))
        expected[3:64] = expected[:61]
        expected[17:28] = bytes([195]) * 11
        expected[:49] = expected[7:56]
        for native in images['mixed'].values():
            w = ctypes.create_string_buffer(bytes(range(64)), 64)
            s = ctypes.create_string_buffer(1)
            o = ctypes.create_string_buffer(8)
            flags = observe_flags(s, 0, o, 8, w, 64, native._entry)
            assert flags & 0x400 == 0 and w.raw == bytes(expected) and o.raw == bytes(8)
        row['controls']['backward_move_fill_forward_move_and_df'] = 1
    report['passed'] = True
    print(json.dumps(report), flush=True)
finally:
    seeds.save()
    (OUT / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
