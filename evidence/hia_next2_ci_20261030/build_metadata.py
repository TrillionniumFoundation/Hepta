#!/usr/bin/env python3
"""Build fresh CI pins/manifest from one bounded, official-digest-pinned ZIP read.

This records reported counts; verify_ci.py independently checks every claimed
count against the raw full logs, per-binary logs, inventory, and matrix records.
Neither program extracts files or executes archive contents.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import time
import zipfile

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
HEAD = '953fa62dee5aa563551d57b1374ab95b6d548b45'
TREE = 'aa0683509a02ca97e4e0c1dd723e4047f50d81b3'
CONTRACT = '3ff0362f995c8341ab75fa32c19cc6bb9fc5d1bc1bbe932ab00d45409ef62faa'
READER = 'e2ab3be7afd0e2b47feb5a0d5a465cc9cc8c2a37426b002a89ec341d58e16437'


def save(name, value):
    with (ROOT / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def main():
    start = time.monotonic_ns()
    reader = ROOT / 'verify_ci.py'
    assert hashlib.sha256(reader.read_bytes()).hexdigest() == READER
    spec = importlib.util.spec_from_file_location('external_ci_reader', reader)
    v = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v)
    run_raw = v.bounded_read(ROOT / 'raw/final-api-run-953fa62.json', 256 * 1024)
    artifact_raw = v.bounded_read(ROOT / 'raw/api-artifacts-953fa62.json', 256 * 1024)
    download_raw = v.bounded_read(ROOT / 'raw/ci-953fa62.download.json', 256 * 1024)
    run, artifacts = v.parse(run_raw), v.parse(artifact_raw)
    v.require(run['id'] == 41081527613 and run['head_sha'] == HEAD and
              run['head_commit']['tree_id'] == TREE and run['status'] == 'completed' and
              run['conclusion'] == 'success', 'official run/source not complete')
    candidates = [a for a in artifacts['artifacts'] if a['name'] == 'hepta-integrated-evidence-' + HEAD]
    v.require(len(candidates) == 1, 'official artifact missing or duplicated')
    artifact = candidates[0]
    raw = v.bounded_read(ROOT / 'raw/ci-953fa62.zip', v.ZIP_LIMIT)
    v.require(len(raw) == artifact['size_in_bytes'] and
              'sha256:' + v.sha(raw) == artifact['digest'], 'official ZIP digest/size differs')
    members, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        v.require(0 < len(infos) <= v.MEMBER_COUNT_LIMIT, 'ZIP member bound')
        for info in infos:
            v.safe(info.filename)
            v.require(info.filename not in members and not info.is_dir() and
                      stat.S_ISREG(info.external_attr >> 16) and not info.flag_bits & 1 and
                      info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                      0 <= info.file_size <= v.MEMBER_LIMIT and
                      0 <= info.compress_size <= v.ZIP_LIMIT, 'unsupported ZIP member')
            total += info.file_size
            v.require(total <= v.TOTAL_LIMIT, 'ZIP aggregate bound')
            with archive.open(info) as stream:
                content = stream.read(info.file_size + 1)
            v.require(len(content) == info.file_size, 'expanded size differs')
            members[info.filename] = content
    q = v.parse(members[v.ROOT + 'qualification.json'])
    safety = v.parse(members['_temp/hepta-integrated-safety.json'])
    # Select by fixed gate order, independently checked by the final reader.
    full, rust, coverage = q['gates'][6], q['gates'][5], q['gates'][7]
    modules, methods = set(), set()
    for group in coverage['groups'].values():
        for module, recorded in group.items():
            modules.add(module)
            methods.update(recorded)
    v.require(q['source_before']['head'] == HEAD and q['source_before']['tree'] == TREE and
              len(q['source_before']['files']) == 6907, 'frozen source inventory differs')
    v.require(len(safety['contract']['capabilities']) == 50 and safety['expected_tests'] == 527 and
              safety['contract_sha256'] == CONTRACT, 'frozen canonical contract differs')

    def receipt(name, value):
        return {'file': name, 'bytes': len(value), 'sha256': v.sha(value)}

    pin = {'file': 'raw/ci-953fa62.zip', 'run_id': run['id'], 'artifact_id': artifact['id'],
           'head': HEAD, 'tree': TREE, 'bytes': len(raw), 'sha256': v.sha(raw),
           'members': len(members), 'payload_bytes': total, 'tracked_files': 6907,
           'external_files': len(q['external_inventory_before']),
           'python_tests': full['tests_run'], 'rust_tests': rust['tests_run'],
           'rust_binaries': rust['test_binaries'], 'critical_groups': len(coverage['groups']),
           'critical_modules': len(modules), 'critical_methods': len(methods),
           'capabilities': 50, 'matrix_tests': 527, 'contract_sha256': CONTRACT,
           'acquisition': {
               'run_api': receipt('raw/final-api-run-953fa62.json', run_raw),
               'artifacts_api': receipt('raw/api-artifacts-953fa62.json', artifact_raw),
               'download': receipt('raw/ci-953fa62.download.json', download_raw)}}
    pins = {'schema': 'hepta.ci.artifact-pins.v1', 'latest_required_source': HEAD, 'runs': {'953fa62': pin}}
    save('CI_PINS.json', pins)
    pins_raw = v.bounded_read(ROOT / 'CI_PINS.json', 256 * 1024)
    manifest = {'schema': 'hepta.ci.member-manifest.v1', 'pins_sha256': v.sha(pins_raw),
                'runs': {'953fa62': {'members': [
                    {'path': name, 'bytes': len(data), 'sha256': v.sha(data)}
                    for name, data in sorted(members.items())]}}}
    save('MANIFEST.json', manifest)
    record = {'schema': 'hepta.ci.metadata-build.v1', 'reported_counts_not_yet_offline_verified': True,
              'archive_extracted_or_executed': False, 'archive_reads': 1,
              'wall_ns_before_encoding': time.monotonic_ns() - start,
              'pins_sha256': v.sha(pins_raw), 'manifest_sha256': v.sha((ROOT / 'MANIFEST.json').read_bytes()),
              'verifier_sha256': READER, 'pin': pin}
    save('METADATA_BUILD.json', record)
    print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    main()
