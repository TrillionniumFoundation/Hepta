"""Read-only full decode of the already full-GET verified u32 small Git capsule."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import time
import zlib

ROOT = Path('/tmp/hia-u32-custody-relay-r2-dda7')
CAPSULE = Path('/tmp/hia-root-v141-dda7/u32-complete-small-GIT-capsule.json')
OUT = Path('/tmp/hia-root-v141-dda7/ROOT-U32-COMPLETE-CUSTODY-REVIEW.json')
STAT_KEYS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
def check(raw, expected):
    got = identity(raw)
    assert all(got[k] == expected[k] for k in got), (got, {k:expected[k] for k in got})
    return got
def snapshot(path):
    return tuple(getattr(path.lstat(), k) for k in STAT_KEYS)
def local(relative, expected, content=None):
    p = PurePosixPath(relative)
    assert not p.is_absolute() and p.parts and all(x not in ('', '.', '..') for x in p.parts)
    path = ROOT
    for part in p.parts:
        path = path / part
        assert not path.is_symlink(), relative
    before = snapshot(path)
    assert stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == expected['mode'], relative
    raw = path.read_bytes()
    check(raw, expected)
    if content is not None:
        assert raw == content, relative
    assert before == snapshot(path), relative
    return len(raw)

started = time.monotonic_ns()
raw = CAPSULE.read_bytes()
capsule_pin = check(raw, {'bytes':2321905, 'git_blob':'b88da58d0898865bcac09bc2b57c08702b7dddf9',
                        'sha256':'9295afbd08a86068113071cd4fae41734c8f8b817519dbcd7f57c919cbe40ee6'})
envelope = json.loads(raw)
assert envelope['schema'] == 'hepta.lossless.zlib-base64.capsule.v1'
assert envelope['encoding'] == 'zlib+base64'
compressed = base64.b64decode(envelope['data_base64'], validate=True)
check(compressed, envelope['compressed_identity'])
decoder = zlib.decompressobj()
decoded = decoder.decompress(compressed) + decoder.flush()
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
check(decoded, envelope['payload_identity'])
payload = json.loads(decoded)
assert payload['schema'] == 'hepta.lossless.custody-small-originals.v1'
assert payload['product_executions'] == payload['original_runs_modified'] == 0
assert payload['binary_originals_all_retained_and_independently_verified'] is True
assert len(payload['files']) == 96
seen, logical = set(), 0
for row in payload['files']:
    assert row['path'] not in seen
    seen.add(row['path'])
    data = base64.b64decode(row['data_base64'], validate=True)
    check(data, row)
    logical += local(row['path'], row, data)
assert logical == 7152829
private = payload['private_signed_download_reference_originals']
assert len(private) == 11
private_bytes = 0
for row in private:
    assert row['path'] not in seen
    seen.add(row['path'])
    private_bytes += local(row['path'], row)
binaries = payload['binary_originals_not_embedded']
assert len(binaries) == len(set(binaries)) == 11
for relative in binaries:
    p = PurePosixPath(relative)
    assert not p.is_absolute() and all(x not in ('', '.', '..') for x in p.parts)
    path = ROOT.joinpath(*p.parts)
    assert path.is_file() and not path.is_symlink()
proof_row = next(x for x in payload['files'] if x['path'] == 'actual/COMPLETE-ORIGINAL-ZIP-READBACK.json')
verifier_row = next(x for x in payload['files'] if x['path'] == 'actual/verify_complete_spans.py')
assert proof_row['git_blob'] == '2b446e71aa6f73a20b39fa99313be146762cfefa'
assert verifier_row['git_blob'] == '5b838626c815c0496fc1dda2e6f33479802e4b7e'
report = {
    'schema':'hepta.hia.root-u32-complete-custody-review.v1',
    'status':'PASS_ROOT_FULL_SMALL_GIT_CAPSULE_DECODE_AND_ORIGINAL_BYTE_MODE_STAT_REVIEW',
    'capsule':capsule_pin, 'decoded_payload':identity(decoded),
    'complete_small_files':96, 'complete_small_logical_bytes':logical,
    'all_complete_bytes_sha256_git_blob_original_modes_and_seven_stats_verified':True,
    'private_signed_provider_originals':{'count':11,'bytes':private_bytes,
        'complete_local_bytes_hash_modes_and_stat_checked':True,
        'contents_not_printed_or_published':True},
    'binary_originals':{'count':11,'still_present_locally':True,
        'full_binary_replay_repeated_by_this_reader':False,'all_binary_bytes_in_Git':False},
    'accepted_full_binary_readback':{
        'actual_session':48864,'exit_code':0,'all_original_ZIP_members':4945,
        'source_files':3180,'complete_frame_observations':86,'complete_buffers_per_observation':6,
        'executor_proof_git_blob':proof_row['git_blob'],'executor_verifier_git_blob':verifier_row['git_blob'],
        'root_fully_reviewed_all_675_verifier_lines_and_complete_proof':True,
        'scope':'original frozen 5052-check/38-phase qualification; not whole-language closure'},
    'observer_limit':'Two complete observer references have serial source/witness order before B0, but no independent completion timestamps. The 17 fresh reference workers have their actual timestamps.',
    'actual_product_executions':0,'actual_product_retries':0,'source_mutations':0,
    'whole_native':False,'production_legacy_retired':False,
    'python':sys.version,'elapsed_ns':time.monotonic_ns()-started
}
with OUT.open('x', encoding='utf-8') as stream:
    stream.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
