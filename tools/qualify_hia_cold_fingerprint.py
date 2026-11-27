"""Native equivalence of the unchanged ordered journal-table fingerprint.

The fingerprint is a table selector. All separate SHA and physical-byte
comparisons remain required. This finite component gate is not cold admission.
"""
from pathlib import Path
import argparse
import ast
import ctypes
from hashlib import sha256
import json
import mmap
import os
import random
import resource
import signal
import struct
import subprocess

from tools.hia_native_seed_test_support import NativeSeeds
from tools.hia_cold_journal_backrefs import HELPERS
from tools.generate_hia_cold_document import document
from tools.generate_hia_worker_config_json import ConfigBuilder
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bootstrap', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
OUT = args.output.resolve()
seeds = NativeSeeds(ROOT, args.bootstrap, OUT)
report = {'scope': __doc__, 'passed': False, 'products': {}, 'controls': {}}
ENTRY = '''def probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) != 16:
        return 0
    value = chunk_fingerprint(w,word_load(s,0),word_load(s,8))
    word_store(o,0,value)
    return 0
'''


def fingerprint(raw):
    value = 14695981039346656037
    at = 0
    while len(raw) - at >= 8:
        value = ((value ^ struct.unpack_from('<Q', raw, at)[0]) * 1099511628211) & ((1 << 64) - 1)
        at += 8
    for byte in raw[at:]:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return struct.pack('<Q', value)


try:
    reference = subprocess.check_output(['git', 'show',
        '5622dafbcfa10ad0c6f99214994ee7dcf71523e0:tools/hia_cold_journal_backrefs.py'], cwd=ROOT)
    assignment = next(node for node in ast.parse(reference).body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'HELPERS' for target in node.targets))
    original = ast.literal_eval(assignment.value)
    images = {}
    for name, source in [('original', original), ('current', HELPERS)]:
        function = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)
                        and node.name == 'chunk_fingerprint')
        author = ENTRY + ast.get_source_segment(source, function)
        body = render_assembly(document(author, 'journal_fingerprint_probe', builder_type=ConfigBuilder)).encode()
        flat = seeds.compile(body, 'word')
        (OUT / (name + '.hepta')).write_bytes(body)
        (OUT / (name + '.flat')).write_bytes(flat)
        images[name] = NativeHiaJsonImage(flat, sha256(flat).hexdigest())
        report['products'][name] = {'source_sha256': sha256(body).hexdigest(),
                                    'bytes': len(flat), 'sha256': sha256(flat).hexdigest()}
    rng = random.Random(771134)
    data = rng.randbytes(65536)
    cases = [(0, n) for n in list(range(130)) + [255, 256, 257, 511, 512, 513, 65503, 65504, 65535, 65536]]
    for _ in range(3000):
        start = rng.randrange(len(data) + 1)
        cases.append((start, rng.randrange(len(data) - start + 1)))
    cases += [((1 << 64) - 1, 0), (65537, 0)]
    w = ctypes.create_string_buffer(data, len(data))
    for start, size in cases:
        source = ctypes.create_string_buffer(struct.pack('<2Q', start, size))
        wanted = fingerprint(data[start:start + size])
        for native in images.values():
            output = ctypes.create_string_buffer(b'preserve', 8)
            assert native._entry(source, 16, output, 8, w, len(data)) == 0
            assert output.raw == wanted and w.raw == data
    report['controls']['boundaries_random_and_zero_count_full_workspace'] = len(cases)
    for source_at, output_at, start, size in [(0, 8, 0, 128), (32, 80, 1, 127), (16, 18, 0, 0)]:
        before = bytearray(data[:256])
        struct.pack_into('<2Q', before, source_at, start, size)
        wanted = bytearray(before)
        wanted[output_at:output_at + 8] = fingerprint(bytes(before[start:start + size]))
        for native in images.values():
            buffer = ctypes.create_string_buffer(bytes(before), len(before))
            assert native._entry(ctypes.byref(buffer, source_at), 16,
                                 ctypes.byref(buffer, output_at), 8, buffer, len(before)) == 0
            assert buffer.raw == bytes(wanted)
    report['controls']['physical_alias_after_original_reads'] = 3
    bad = [(65536, 1), (65535, 8), (65528, 9), ((1 << 64) - 1, 1), (0, (1 << 64) - 1)]
    for start, size in bad:
        for native in images.values():
            memory = mmap.mmap(-1, len(data) + 8, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            memory[:] = data + b'preserve'
            shared = (ctypes.c_ubyte * (len(data) + 8)).from_buffer(memory)
            source = ctypes.create_string_buffer(struct.pack('<2Q', start, size))
            child = os.fork()
            if child == 0:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                signal.alarm(5)
                native._entry(source, 16, ctypes.byref(shared, len(data)), 8, shared, len(data))
                os._exit(111)
            pid, status = os.waitpid(child, 0)
            assert pid == child and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGILL
            assert memory[:] == data + b'preserve'
            del shared
            memory.close()
    report['controls']['original_trap_no_workspace_or_output_writes'] = len(bad)
    report['passed'] = True
    print(json.dumps(report), flush=True)
finally:
    seeds.save()
    (OUT / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
