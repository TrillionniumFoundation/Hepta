"""Read-only recovery of previously frozen Proof source and original records.

This does not execute project code, rerun tests, or grant current-cold authority.
Only a new recovery report is written; every old path is read without mutation.
"""
from pathlib import Path
from hashlib import sha1, sha256
import base64
import json
import os
import stat
import sys
import zlib

ROOT = Path(__file__).resolve().parent
OLD = ROOT.parent / 'v78-proof-contract-development-r1'
EXPECTED_OLD_CUMULATIVE_BLOB = '97c1542bd4d8a35a389168dc6e76273dbd575de7'


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read_original(relative):
    path = OLD / relative
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('original is not a regular file: ' + relative)
    raw = path.read_bytes()
    after = path.lstat()
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, key) != getattr(after, key) for key in keys):
        raise ValueError('original changed during recovery: ' + relative)
    return raw


def tree_hash(manifest):
    root = {}
    for path, row in manifest.items():
        parts = path.split('/')
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = (row['mode'], row['git_blob_sha'])
    def visit(node):
        body = bytearray()
        ordered = sorted(node.items(), key=lambda pair: (pair[0] + ('/' if isinstance(pair[1], dict) else '')).encode())
        for name, value in ordered:
            mode, digest = ('40000', visit(value)) if isinstance(value, dict) else value
            body += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
        return sha1(b'tree ' + str(len(body)).encode() + b'\0' + body).hexdigest()
    return visit(root)


def main():
    wrapper_raw = read_original('checkpoint-r2/CUMULATIVE-OVERLAY.zlib.json')
    wrapper_identity = identity(wrapper_raw)
    if wrapper_identity['git_blob_sha'] != EXPECTED_OLD_CUMULATIVE_BLOB:
        raise ValueError('original cumulative wrapper differs from pre-outage computed Git identity')
    wrapper = json.loads(wrapper_raw)
    compressed = base64.b64decode(wrapper['payload'], validate=True)
    raw = zlib.decompress(compressed)
    if identity(raw) != {key: wrapper['source_packet'][key] for key in ('bytes', 'sha256', 'git_blob_sha')}:
        raise ValueError('original complete cumulative packet differs')
    if raw != read_original('checkpoint-r2/CUMULATIVE-OVERLAY.json'):
        raise ValueError('original plain/compressed cumulative packet differs')
    source = json.loads(raw)
    if len(source['source_manifest']) != 3202 or len(source['files']) != 62:
        raise ValueError('original complete source inventory differs')
    observed = {}
    for directory, directories, names in os.walk(OLD / 'source'):
        directories[:] = sorted(name for name in directories if name != '__pycache__')
        if '.git' in directories:
            raise ValueError('plain export unexpectedly contains Git metadata')
        for name in directories:
            if (Path(directory) / name).is_symlink():
                raise ValueError('original source directory is a symlink')
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(OLD / 'source').as_posix()
            data = read_original('source/' + relative)
            mode = '100755' if path.lstat().st_mode & 0o111 else '100644'
            observed[relative] = {**identity(data), 'mode': mode}
    if observed != source['source_manifest']:
        raise ValueError('reappeared source differs from original complete snapshot')
    actual_tree = tree_hash(observed)
    if actual_tree != source['computed_source_tree']:
        raise ValueError('complete source Git tree differs')
    for path, member in source['files'].items():
        if member['text'].encode() != read_original('source/' + path):
            raise ValueError('cumulative source text differs: ' + path)
    report_raw = read_original('component-r5/REPORT.json')
    report = json.loads(report_raw)
    if identity(report_raw) != {key: source['local_component']['report'][key] for key in ('bytes', 'sha256', 'git_blob_sha')}:
        raise ValueError('original64 report differs from pre-outage source packet')
    if report['tests_run'] != 64 or any(report.get(key, []) for key in ('failures','errors','skips','expected_failures','unexpected_successes')):
        raise ValueError('original64 result is not the recorded success')
    simple = {path: {key: item[key] for key in ('bytes','sha256','mode')} for path, item in observed.items()}
    before = json.loads(read_original('component-r5/SOURCE-BEFORE.json'))
    after = json.loads(read_original('component-r5/SOURCE-AFTER.json'))
    if simple != before or simple != after:
        raise ValueError('original64 before/after/current bytes and Git modes differ')
    process_raw = read_original('component-r5/PROCESS.json')
    process = json.loads(process_raw)
    original_callers = json.loads(read_original('original-callers-r1/SUMMARY.json'))
    if original_callers['returncode'] != 1 or original_callers['all_source_bytes_modes_unchanged'] is not True:
        raise ValueError('original missing-Z3 preflight result differs')
    names = ('checkpoint-r2/IDENTITY.json', 'checkpoint-r2/CUMULATIVE-OVERLAY.zlib.json',
             'checkpoint-r2/INTEGRATION-DELTA.zlib.json', 'component-r5/REPORT.json',
             'component-r5/PROCESS.json', 'component-r5/SOURCE-BEFORE.json',
             'component-r5/SOURCE-AFTER.json', 'component-r5/stdout', 'component-r5/stderr',
             'original-callers-r1/SUMMARY.json', 'original-callers-r1/PROCESS.json',
             'original-callers-r1/stderr')
    result = {
        'schema': 'hia.original-proof.reappeared-environment-recovery.v80.r1',
        'status': 'ORIGINAL_BYTES_RECOVERED_AND_INDEPENDENTLY_VERIFIED',
        'recovery_python': sys.version, 'original64_python': report.get('python'),
        'old_cumulative_wrapper': wrapper_identity, 'pre_outage_wrapper_blob_matches': True,
        'source_files': len(observed), 'complete_delta_paths': len(source['files']),
        'source_tree': actual_tree, 'all_source_bytes_sha256_gitblob_gitmode_unchanged': True,
        'posix_mode_boundary': 'Original snapshots bind Git executable modes; no additional full historical POSIX permission assertion is inferred.',
        'original64_report': identity(report_raw), 'original64_process': process,
        'original64_tests': 64, 'original64_source_before_after_current_equal': True,
        'original40_preflight': original_callers, 'original40_business_tests_executed': False,
        'original_record_identities': {name: identity(read_original(name)) for name in names},
        'old_files_modified': False, 'project_code_executed': False, 'tests_rerun': False,
        'qualification_transferred_to_new_proof_r2_or_union': False,
        'current_source_cold': False, 'whole_native': False,
        'timeline': 'The old data could not be accessed while the environment was unavailable. Reappearance is newly observed; earlier missing-custody statements remain true at their original time.'}
    out = ROOT / 'ORIGINAL-PROOF-RECOVERY.json'
    encoded = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    with out.open('xb') as stream:
        stream.write(encoded)
    if out.read_bytes() != encoded:
        raise ValueError('new recovery report readback differs')
    print(json.dumps({key: result[key] for key in ('status','source_files','complete_delta_paths','source_tree','original64_tests','tests_rerun','current_source_cold','whole_native')}, sort_keys=True))
    print(json.dumps({'recovery_report': str(out), 'identity': identity(encoded)}, sort_keys=True))


if __name__ == '__main__':
    main()
