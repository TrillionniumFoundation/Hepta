"""Build the candidate from current actor authors, then run original codec gates."""
from pathlib import Path
import ast, ctypes, hashlib, json, random, struct, sys

ROOT = Path(__file__).resolve().parents[1]
import argparse
import subprocess
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bootstrap', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--profile', choices=('bulk', 'cold-bulk', 'cold-bulk-word'), default='bulk',
                    help='explicit candidate emitter; original/default parent gates are unchanged')
args = parser.parse_args()
from tools.hia_native_seed_test_support import NativeSeeds
from tools.generate_hia_cold_master_common import DECODER, helpers
from tools.hia_cold_byte_loops import accelerate
from tools.generate_hia_cold_qualification_driver import policy_source
from tools.generate_hia_cold_master_archive import source as archive_source
from tools.generate_hia_cold_qualification_codec import ENTRY as OLD_ENTRY, CODEC as OLD_CODEC, HELPERS as OLD_HELPERS
from tools.generate_hia_cold_qualification_codec_lz import ENTRY
from tools.generate_hia_cold_document import bulk_document, bulk_word_document, document
from tools.qualify_hia_cold_qualification_codec_lz import qualify, chunk
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage

OUT = args.output.resolve()
seeds = NativeSeeds(ROOT, args.bootstrap, OUT)
report = {'scope': 'current private cold actor codec components, not full cold',
          'candidate_profile': args.profile, 'passed': False, 'products': {}}


def selected(source, names):
    functions = {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}
    return '\n\n'.join(functions[name] for name in names)


def build(name, source, profile=None, builder=None):
    profile = args.profile if profile is None else profile
    builder = (bulk_word_document if profile == 'cold-bulk-word' else bulk_document) if builder is None else builder
    body = render_assembly(builder(source, name.replace("-", "_"))).encode()
    path = OUT / (name + '.hepta')
    path.write_bytes(body)
    flat = seeds.compile(body, profile)
    (OUT / (name + '.flat')).write_bytes(flat)
    report['products'][name] = {'source_bytes': len(body), 'source_sha256': hashlib.sha256(body).hexdigest(),
                               'bytes': len(flat), 'sha256': hashlib.sha256(flat).hexdigest()}
    return NativeHiaJsonImage(flat, hashlib.sha256(flat).hexdigest())


try:
    build('legacy-public', OLD_ENTRY + '\n' + OLD_CODEC + '\n' + OLD_HELPERS, 'v1', document)
    production = policy_source(word=args.profile == 'cold-bulk-word')
    names = ('pack_chunk_rle', 'unpack_chunk_rle', 'pack_lz', 'pack_chunk', 'unpack_chunk',
             'copy_forward', 'chunk_equal', 'get', 'put', 'copyw')
    # All actual cold actors admit exactly 4 MiB. This observer wrapper uses
    # the old codec wire framing, but does not widen that private actor view.
    wrapper = ENTRY.replace('length(w) < 3293184', 'length(w) != 4194304')
    build('candidate-codec', wrapper + '\n' + selected(production, names))
    entry = '''def probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) != 8 or length(w) != 4194304:
        return 4294967295
    return pack_chunk(w,word_load(s,0))
'''
    build('pack-current', entry + selected(production, ('pack_chunk_rle', 'pack_lz', 'pack_chunk', 'copyw', 'get', 'put')))
    decoder = build('decode-current', entry.replace('pack_chunk(w,', 'unpack_chunk(w,') + selected(
        archive_source(), ('unpack_chunk_rle', 'unpack_chunk', 'copy_forward', 'copyw', 'get', 'put')))
    qualify(OUT / 'legacy-public.flat', OUT / 'candidate-codec.flat', OUT / 'original-codec-gates')
    reference = subprocess.check_output(['git', 'show', '5622dafbcfa10ad0c6f99214994ee7dcf71523e0:examples/hia_bootstrap/seed_bulk_backend.hepta'], cwd=ROOT)
    assert hashlib.sha256(reference).hexdigest() == '692b5e942a10cdcb72e88bd1bdd65c99ab90a4fbe21bdd16e1c918672f549935'
    reference_flat = seeds.compile(reference, 'v1')
    reference_tool = seeds.invoke(seeds.profiles['seed-packer'], b'HIAFLT01' + struct.pack('<Q', len(reference_flat)) + reference_flat)
    assert hashlib.sha256(reference_tool).hexdigest() == 'ffc17746f9d2e47f11746162fee88b6dade303d7af69695ff019a1428b85c38e'
    path = OUT / 'reference-bulk'
    path.write_bytes(reference_tool)
    path.chmod(0o500)
    seeds.profiles['reference-bulk'] = path
    baseline = accelerate(DECODER + '\n' + helpers(), bulk=True)
    original = build('reference-decoder', entry.replace('pack_chunk(w,', 'unpack_chunk(w,') + selected(
        baseline, ('unpack_chunk_rle', 'unpack_chunk', 'copy_forward', 'copyw', 'get', 'put')), 'reference-bulk')
    assert report['products']['reference-decoder']['sha256'] == 'a8c78031678e5159ea0b27223502a116ea51600ad4b5347cf789167583b6db7c'
    valid = []
    for distance in (*range(1, 17), 31, 32, 63, 64, 127, 255, 256, 1023, 4096, 32768, 65496):
        prefix = bytes((i * 131 + 37) & 255 for i in range(distance))
        amount = min(65504 - distance, max(8, distance * 2 + 7))
        body = struct.pack('<BH', 0, len(prefix)) + prefix + struct.pack('<BHH', 1, amount, distance)
        valid.append(chunk(body, distance + amount))
    valid += [chunk(struct.pack('<BH', 0, 1) + b'x' + struct.pack('<BHH', 1, 65503, 1), 65504)]
    cases = list(valid)
    rng = random.Random(0x230411)
    for _ in range(2000):
        raw = bytearray(rng.choice(valid))
        action = rng.randrange(4)
        if action == 0:
            raw = raw[:rng.randrange(len(raw) + 1)]
        elif action == 1:
            raw.extend(rng.randbytes(rng.randrange(1, 9)))
        else:
            at = rng.randrange(len(raw))
            raw[at] ^= rng.randrange(1, 256)
        cases.append(bytes(raw))
    initial = rng.randbytes(4194304)
    compare = ctypes.CDLL(None).memcmp
    compare.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    compare.restype = ctypes.c_int
    for index, raw in enumerate(cases):
        if len(raw) > 65536:
            raw = raw[:65537]
        work = [ctypes.create_string_buffer(initial, len(initial)) for _ in range(2)]
        source = ctypes.create_string_buffer(struct.pack('<Q', len(raw)))
        results = []
        for native, buffer in zip([original, decoder], work):
            ctypes.memmove(ctypes.addressof(buffer) + 800000, raw, len(raw))
            output = ctypes.create_string_buffer(b'preserve', 8)
            results.append(native._entry(source, 8, output, 8, buffer, 4194304))
            assert output.raw == b'preserve'
        assert results[0] == results[1] and compare(work[0], work[1], 4194304) == 0, index
    report['malformed_and_overlap_full_workspace_controls'] = len(cases)
    report['passed'] = True
    print(json.dumps(report), flush=True)
finally:
    seeds.save()
    (OUT / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
