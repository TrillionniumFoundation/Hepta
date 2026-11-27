"""Read original completed observations; never import or execute product code."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
OUT = ROOT / 'terminal-custody-r1'
COMPILER = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def load(path):
    return json.loads(path.read_bytes())


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if path.exists():
        assert path.read_bytes() == raw
    else:
        with path.open('xb') as f:
            f.write(raw)
    return pin(path)


def main():
    OUT.mkdir(exist_ok=True)
    reports = []
    raw_files = []
    for label, expected in [('source-r1', 29), ('build-r1', None), ('original43-r1', 43)]:
        folder = ROOT / 'evidence' / label
        report, owner, outer = [load(folder / n) for n in ('REPORT.json', 'OWNER.json', 'OUTER-RESULT.json')]
        assert report['status'] == outer['status'] == 'PASS'
        assert report['python'].startswith('3.14.4 ')
        assert report['cold_authority'] is False and report['whole_cli_native'] is False
        assert owner['qualification_seconds'] == 180 and owner['cleanup_seconds'] == 3
        assert type(owner['returncode']) is int and owner['returncode'] == 0
        assert owner['exit_observed_before_deadline'] and not owner['timed_out']
        assert owner['cleanup']['complete'] and owner['cleanup']['observed_echild']
        assert owner['cleanup']['errors'] == owner['cleanup']['remaining_direct_children'] == []
        assert outer['source_unchanged'] and outer['product_source_files'] == 3162
        before, after = load(folder / 'SOURCE-BEFORE.json'), load(folder / 'SOURCE-AFTER.json')
        assert before == after and len(before) == 3162
        if expected is not None:
            assert report['loaded'] == report['tests_run'] == expected
            assert report['expected_ids'] == report['loaded_ids'] == report['started_ids'] == report['stopped_ids']
            for field in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes'):
                assert report[field] == []
        for name in ('REPORT.json', 'OWNER.json', 'OUTER-RESULT.json', 'INTENT.json', 'OWNER.json.request.json',
                     'OWNER.json.stdout.log', 'OWNER.json.stderr.log', 'stdout.raw', 'stderr.raw',
                     'SOURCE-BEFORE.json', 'SOURCE-AFTER.json'):
            raw_files.append(pin(folder / name))
        reports.append({'label': label, 'count': expected, 'wall_ns': report['wall_ns'],
                        'report': pin(folder / 'REPORT.json'), 'owner': pin(folder / 'OWNER.json'),
                        'outer': pin(folder / 'OUTER-RESULT.json'), 'source_files': len(before)})
    old28 = load(BASE / 'v112-profile-resources-r2/evidence/source-r1/REPORT.json')['expected_ids']
    new29 = load(ROOT / 'evidence/source-r1/REPORT.json')['expected_ids']
    assert new29[:28] == old28
    old43 = load(BASE / 'v112-profile-resources-r1/evidence/original43-r1/REPORT.json')['expected_ids']
    new43 = load(ROOT / 'evidence/original43-r1/REPORT.json')['expected_ids']
    assert old43 == new43
    compiles = []
    for receipt_path in sorted((ROOT / 'evidence/build-r1/build').glob('*/*.receipt.json')):
        stem = str(receipt_path)[:-len('.receipt.json')]
        receipt = load(receipt_path)
        stdout = load(Path(stem + '.stdout.log'))
        request = load(Path(stem + '.request.json'))
        assert Path(stem + '.stderr.log').read_bytes() == b''
        extras = {'artifact_sha256', 'case', 'format', 'input_bytes', 'input_sha256', 'produced_bytes',
                  'produced_image', 'produced_sha256', 'runner_sha256', 'wall_elapsed_ns'}
        assert set(receipt) - set(stdout) == extras
        assert {k: receipt[k] for k in stdout} == stdout
        assert request['image_sha256'] == receipt['image_sha256'] == COMPILER
        assert request['capacity'] == request['workspace_size'] == 1048576
        assert receipt['limits']['output_capacity'] == receipt['limits']['workspace_bytes'] == 1048576
        assert receipt['status'] == 'returned' and receipt['abi_status'] == 0 and receipt['source_unchanged']
        assert receipt['forbidden_compiler_modules_loaded'] == []
        actual_in = Path(request['source']).read_bytes()
        actual_out = Path(request['output']).read_bytes()
        actual_image = Path(receipt['produced_image']).read_bytes()
        assert len(actual_out) == 1048576
        assert hashlib.sha256(actual_in).hexdigest() == receipt['source_sha256'] == request['source_sha256']
        assert hashlib.sha256(actual_out).hexdigest() == receipt['output_sha256']
        assert hashlib.sha256(actual_image).hexdigest() == receipt['produced_sha256']
        assert len(actual_image) == receipt['produced_bytes'] == receipt['result_u64'] == receipt['core_u32']
        assert actual_image == actual_out[:len(actual_image)]
        compiles.append({'receipt': pin(receipt_path), 'request': pin(Path(stem + '.request.json')),
                         'stdout': pin(Path(stem + '.stdout.log')), 'stderr': pin(Path(stem + '.stderr.log')),
                         'input': pin(Path(request['source'])), 'output': pin(Path(request['output'])),
                         'image': pin(Path(receipt['produced_image']))})
    assert len(compiles) == 6
    proof = {'schema': 'hepta.optional-profile-r3-terminal-readback.v1', 'status': 'ACTUAL_ORIGINALS_READBACK_PASS',
        'source_tree': '24754374b90df56de475e67274ceb9280f6882fa', 'source_files': 3162,
        'source_recipe': 'ab583f0455c4667e7895b33706bc16a4474b07e2', 'reports': reports,
        'six_compiles': compiles, 'original28_ordered_prefix_preserved': True, 'original43_ordered_ids_preserved': True,
        'raw_files': raw_files, 'all_raw_originals_remain_local': True,
        'r2_report140_not_repeated_for_setup_only_r3': True, 'r2_original43_never_started': True,
        'matching_current_source_cold_positive': False, 'whole_cli_native': False, 'whole_verify_native': False,
        'scope': 'ACTUAL_LOCAL_CPYTHON_3.14.4_DEVELOPMENT_ONLY',
        'no_product_execution_by_this_verifier': True,
        'retained_failures': ['R1 actual source and host FIFO reopen timeouts',
            'R2 first race fixture absolute-import-path subfailure',
            'R2 optional parent-symlink outside-directory creation observed by R3 control'],
        'temporary_wheel_boundary': 'Source packaging test temporary products were cleaned by original test; retained original43 installed-control products remain in the complete evidence tree.'}
    row = save(OUT / 'FINAL-EXECUTION-READBACK.json', proof)
    rows = [row] + [pin(ROOT / 'evidence' / stage / name) for stage in ('source-r1', 'build-r1', 'original43-r1')
                   for name in ('REPORT.json', 'OWNER.json', 'OUTER-RESULT.json')]
    rows.append(pin(Path(__file__)))
    save(OUT / 'PUBLICATION-INPUTS.json', rows)
    print(json.dumps({'proof': row, 'publications': len(rows), 'three_groups': ['29_PASS', '6_COMPILES_PASS', '43_PASS']}))


if __name__ == '__main__':
    main()
