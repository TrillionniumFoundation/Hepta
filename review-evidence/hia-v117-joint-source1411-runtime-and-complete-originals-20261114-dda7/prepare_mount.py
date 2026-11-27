"""Prepare additive V117 evidence and exact R19 inputs; no product qualification is inferred."""
from pathlib import Path
import base64
import hashlib
import json
import stat
import zlib

ROOT = Path(__file__).resolve().parent
AUDIT = ROOT.parent
WORK = AUDIT.parent
INPUT = AUDIT / 'v116-component-inputs'
UNION = WORK / 'v116-union-r19'
FORMAL = WORK / 'v116-source-parser-r19-harness/formal-preparation-r1'
COLLECTION = 'hia-v117-joint-source1411-runtime-and-complete-originals-20261114-dda7'


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def put(name, raw):
    with (ROOT / name).open('xb') as f:
        assert f.write(raw) == len(raw)


def main():
    leaves, groups, used = [], [], set()

    def add(path, raw, expected=None):
        assert path not in used and not path.startswith('/') and '..' not in Path(path).parts
        used.add(path)
        pin = identity(raw)
        if expected:
            assert pin['git_blob'] == (expected.get('git_blob') or expected.get('sha')), path
            for key in ('bytes', 'sha256'):
                if key in expected:
                    assert pin[key] == expected[key], (path, key)
        leaves.append({'path': path, 'sha': pin['git_blob'], 'mode': '100644', 'type': 'blob'})
        return pin

    recipes = {
        'profiles-complete': '4b89403507f997ecec96bacec6d77aff92eb9ce4',
        'roundtrip-r4': '905bebb4b8a62c16a79c1637937b5ad756ebb4ba',
        'r5-token-timeline': '407452b62c5627ad8552b1d550239224db88c07e',
        'r8-independent-proof': '581a7ea041940cb99d163e787ca542b15dc878f4',
    }
    for scope, sha in recipes.items():
        directory = INPUT / scope
        recipe_raw = (directory / 'MOUNT-RECIPE.json').read_bytes()
        recipe = json.loads(recipe_raw)
        assert identity(recipe_raw)['git_blob'] == sha
        local = None
        if scope == 'profiles-complete':
            local = {x['path']: x['local_original'] for x in json.loads((directory / 'ROOT-LOCAL-PINS.json').read_bytes())['files']}
        for row in recipe['entries']:
            assert row['mode'] == '100644'
            path = Path(local[row['path']]) if local else directory / row['path']
            assert stat.S_ISREG(path.lstat().st_mode)
            add(scope + '/' + row['path'], path.read_bytes(), row)
        pin = add(scope + '/MOUNT-RECIPE.json', recipe_raw)
        groups.append({'scope': scope, 'leaves': len(recipe['entries']), 'recipe': pin,
                       'Root_all_original_UTF8_blobs_full_Git_GET_verified': True})

    review = INPUT / 'roundtrip-review-r4'
    summary = json.loads((review / 'SUMMARY.json').read_bytes())
    add('roundtrip-review-r4/CAPSULE.json', (review / 'CAPSULE.json').read_bytes(), summary['capsule'])
    add('roundtrip-review-r4/SUMMARY.json', (review / 'SUMMARY.json').read_bytes())
    harness_manifest_raw = (FORMAL / 'HARNESS-MANIFEST.json').read_bytes()
    harness_manifest = json.loads(harness_manifest_raw)
    actual_paths = {p.relative_to(FORMAL / 'harness').as_posix() for p in (FORMAL / 'harness').rglob('*') if p.is_file()}
    assert actual_paths == set(harness_manifest) and len(actual_paths) == 17
    for path, pin in harness_manifest.items():
        assert pin['mode'] == '100644'
        file = FORMAL / 'harness' / path
        assert stat.S_IMODE(file.stat().st_mode) == 0o644
        add('r19-formal-harness/' + path, file.read_bytes(), pin)
    for filename in ('INPUT-PUBLICATION-INTENT.json', 'ROOT-PUBLICATION-INTENT.json'):
        intent = json.loads((UNION / filename).read_bytes())
        for row in intent['files']:
            assert row['mode'] == '100644'
            add('r19-inputs/' + row['path'], Path(row['local_path']).read_bytes(), row)
    review_dir = AUDIT / 'v117-r19-formal-review'
    formal_pins = {
        'EXACT-DIFFS.json': 'fb06213688ac1d163acda63d17cea8ab9ead5aba',
        'FULL-HARNESS-GIT-READBACK.json': 'f6984304cdcf052b81d3ea6671b3d3e2eea45cc6',
        'HARNESS-MANIFEST.json': 'fbfb4ac03eab8284e83c6fb459b5de58dc204b74',
        'HARNESS-PUBLICATION-INTENT.json': 'ab3dc5675dcf9dc077037f9582cc6778c7cc006b',
        'INITIAL-PUBLICATION-CAPSULE.json': '690178ba70d56d54674ff3b3464f0df5ab2657f1',
        'PARSER-CONTROLS.json': 'fe93b8ff08e03ded4f1da6418b24a8b52b48a8cc',
        'RECEIPT-RELOCATION-CAPSULE.json': 'fa3de6361ac7399a5de70ace5266e78a01e59932',
        'STATIC-PATH-CLOSURE.json': '20e6f82136bd212322053aca92404eee054760bf',
        'hia-combined-source.yml': 'd31d06af7c9fa4b75f7d7dfa94546b6c313d7752',
        'run_parser_bounded.py': '1025cd75e48eac2c63bae402b3c0d0b3dbfb40f0',
    }
    for name, sha in formal_pins.items():
        add('r19-formal-review/' + name, (review_dir / name).read_bytes(), {'git_blob': sha})

    # Full input packets and formal manifests above are actual mounted leaves.
    # The large combined authoring convenience file is reproducible from the
    # exact 84 input packets; it is an intermediate, not an execution original.
    separately_reachable = {'FORMAL-EXPECTED-IDS.json', 'SOURCE-MANIFEST.json', 'INTEGRATION.json'}
    derived = {'AUTHORING-R19.zlib.json', 'BASELINE-MANIFEST.json', 'COMPONENT-MANIFEST.json'}
    paths = {p for p in UNION.iterdir() if p.is_file() and p.name not in separately_reachable | derived}
    paths.add(WORK / 'v116-source-parser-r19-harness/prepare_harness.py')
    paths.add(Path(__file__).resolve())
    for name in ('v117-verify-timeline-stream.py', 'v117-verify-profiles-stream.py', 'v117-verify-r8-proof.py'):
        paths.add(AUDIT / name)
    for scope in recipes:
        for path in (INPUT / scope).rglob('*'):
            if path.is_file() and (path.name.startswith('ROOT-') or path.name.startswith('GET-')):
                paths.add(path)
    paths.add(review_dir / 'ROOT-GIT-READBACK.json')
    for path in (AUDIT / 'publication').iterdir():
        if path.is_file() and path.name.startswith(('v117-input-', 'v117-metadata-')):
            paths.add(path)
    for path in (FORMAL / 'publication').iterdir():
        if path.is_file():
            paths.add(path)
    previous = AUDIT / 'v116-component-custody-mount'
    for path in previous.iterdir():
        if path.is_file() and (path.name.startswith(('COMMIT-', 'REF-', 'PR889-', 'MAIN-AFTER-'))
                              or path.name in ('MOUNT-RESULT.json', 'TREES-VERIFIED.json')):
            paths.add(path)
    records = {}
    for path in sorted(paths):
        raw = path.read_bytes()
        records[path.relative_to(WORK).as_posix()] = {'mode': stat.S_IMODE(path.stat().st_mode),
            **identity(raw), 'base64': base64.b64encode(raw).decode()}
    root_raw = encode({'schema': 'hia.root.complete-execution-and-authoring-records.v117',
        'files': records, 'logical_files': len(records),
        'logical_bytes': sum(x['bytes'] for x in records.values()),
        'derived_intermediates_not_primary_raw': {n: identity((UNION / n).read_bytes()) for n in sorted(derived)},
        'separately_mounted_union_files': sorted(separately_reachable),
        'new_Root_product_executions': 0, 'whole_native': False})
    put('ROOT-RECORDS.json', root_raw)
    wrapper = encode({'schema': 'hia.lossless.zlib-json.v1', 'decoded': identity(root_raw),
                      'payload': base64.b64encode(zlib.compress(root_raw, 6)).decode()})
    put('ROOT-RECORDS.zlib.json', wrapper)
    add('ROOT-RECORDS.zlib.json', wrapper)
    add('prepare_mount.py', Path(__file__).read_bytes())

    status = {
        'whole_native': False, 'current_joint_cold': False, 'production_legacy_deleted': False,
        'previous_audit_commit': '0ae2d4204792a7a06a1c9bf842f8c3460b6c5acd',
        'production_main': 'f33d8da316de8fdf27b504371f1a5310997ff548',
        'PR889_product_head': '4b19af89a766593f7d5f1cc2db256e81aba7afcb',
        'R19': {
            'commit': 'd2a88992381c2c7ab680b7c97bb7c8405c02c6c1',
            'parent': '5217f8083876ed890a38c3f7291ba5a397c935b4',
            'harness_tree': 'a79fbde6576d4cd7b7e6d111ae9a57b3a27bd6cd',
            'run': 43544318748, 'job': 132291881222, 'attempt': 1,
            'observed_at_UTC': '2026-11-14 02:24:45', 'status': 'IN_PROGRESS',
            'steps_1_to_6': 'SUCCESS', 'step7_merge_generators_Source': 'IN_PROGRESS',
            'original62': 'PENDING', 'complete_Source_outcome': None,
            'prepared_source_files': 3175, 'prepared_source_tree': 'ab0514765fc819b921557b9d857a9a13a1a4f48b',
            'post_generation_source_tree': None, 'Source_expected': 1411, 'generators': 139,
            'selectors': 239, 'SOURCE_FILES': 1400, 'ENTRY_FILES': 19, 'NATIVE_FILES': 92,
            'default_resources': 210, 'optional_resources': 8,
            'original_R16_Python_test_files_exact': 616, 'original_R17_new_tests_exact': 6,
            'HIA_assets_exact': 257, 'author_paths': 524, 'overrides': 241, 'packets': 84,
            'new_packets': 6, 'old_packets_retained': 78,
            'workflow_minutes': 90, 'Source_seconds': 1800, 'bounded_seconds': 180,
            'cleanup_seconds': 3, 'compile_seconds': 20, 'output_limit': 1048576,
            'VM_limit': 10000000, 'native_execution_outcome': None},
        'roundtrip_R4': {
            'source_tree': 'ecaf40b0a56f2a0a8548b8c6c842374e1b09aac7', 'source_files': 3175,
            'changed_existing_paths': 4, 'Source23': 'PASS', 'events': 46,
            'original22_relative_order_preserved': True,
            'actual_version_probe': 'PASS_REAL_OWNER_WITH_PARENT_AMBIENT_LD_VARIABLES_REMOVED',
            'runtime': '3.14.4', 'real_child_runtime_context_equals_parent': True,
            'full_archive_restored_files': 136, 'full_archive_restored_dirs': 14,
            'full_archive_restored_bytes': 4801549,
            'external_interpreter_and_library_binaries_embedded': False,
            'new_Native_VM_cold_portable_positive_executions': 0},
        'profiles_complete_originals': {
            'Root_full_Git_GET_leaves': 123, 'nonLF_archive_parts': 118,
            'logical_files': 5302, 'directories': 311, 'symlinks': 2,
            'logical_bytes': 508252794, 'unique_bytes': 198025882,
            'archive_bytes': 61681946, 'Root_full_stream_readback': 'PASS',
            'expanded_directory_restore': False, 'all_actual_failures_preserved': True,
            'temporary_packaging_wheels_already_deleted_by_original_fixture': True},
        'R5_timeline': {
            'original_result': 'FAIL_AT_ORIGINAL_10000000_LIMIT', 'one_instrumented_execution': True,
            'original_full_FOW_and_VM_report_equal': True,
            'events': 30388, 'observed_next_token_calls': 11316,
            'logical_files': 56, 'logical_bytes': 33536726, 'Root_full_stream_readback': 'PASS',
            'post_first_clear_only_model_hits': 5477, 'old_step_zero_new_cost_upper_bound': 2277341,
            'actual_R8_savings': None, 'R8_compile_or_execution': False,
            'reviewer_proof_full_files': 10, 'reviewer_proof_full_bytes': 3335665},
        'remaining_blockers': [
            'Current full Source1411 and original62 formal results are pending.',
            'Original Native35 deadline failures and 103 skipped later steps remain original failures.',
            'R5 checker cross-target 10M failure remains; R6 and R7 are not adopted; R8 is unqualified.',
            'Matching-current-source cold, entire Native workflow, report and roundtrip are unqualified.',
            'Hosted production owners and legacy retirement are still open.']}
    index = {'schema': 'hia.additive-audit-checkpoint.v117', 'collection': COLLECTION,
             'status': status, 'recipes': groups, 'root_originals': identity(root_raw),
             'root_original_files': len(records), 'existing_object_leaves': leaves,
             'final_collection_leaves': len(leaves) + 2,
             'previous_review_children_preserved': 61, 'previous_nonreview_root_children_preserved': 19}
    raw = encode(index)
    put('INDEX.json', raw)
    add('INDEX.json', raw)
    readme = '''# Joint Source1411, exact runtime context, and complete originals

This additive checkpoint preserves all previous audit children. Whole-native closure, matching-current-source cold qualification, production promotion, and production legacy deletion remain false.

## Formal R19 execution is in progress

The exact17-file harness is commit d2a88992381c2c7ab680b7c97bb7c8405c02c6c1, with sole parent5217f8083876ed890a38c3f7291ba5a397c935b4. Its only new push run43544318748/job132291881222 started2026-11-14T02:05:22Z. At02:24:45Z the first six steps had succeeded; the fixed merge,139 generators twice, and complete Source1411 step was still running. Original62 and both uploads were pending. No final Source, Native or cold result is claimed.

The prepared union has3175 files/treeab0514765fc819b921557b9d857a9a13a1a4f48b,139 generators,239 selectors and1411 expected Source IDs. The original616 R16 Python test files, six R17 controls,257 HIA assets, original62 controls and all budgets remain exact. The worker contract remains ENTRY19/NATIVE92/default210; the optional union is8. All84 materialization input packets remain named, including the original78 and six successors. The new packet bytes, all four input manifests, the complete17-file harness, actual publication records, and strict Root reviews are mounted here.

Two preparation refusals are retained with their narrow corrections. The generated checker-identity baseline differed from its old authoring row in exactly five generated assignments; every function and class AST stayed exact, and both preimages are recorded. The first strict harness review rejected three publication sidecars inside the17-file harness. Those original sidecars were moved without changing their bytes or modes into receipts, then the same strict review passed. Neither refusal ran a product or relaxed a test.

## Actual component outcomes

Roundtrip R4 changed four existing paths. Original22 Source IDs retain their relative order and Source23 passed with46 start/stop events on actual Python3.14.4. A real version probe traversed the owner and supervisor after the running parent's ambient LD_LIBRARY_PATH and LD_PRELOAD were removed; the explicit verified runtime context matched in the actual child. The shared owner keeps the old behavior when its new supervisor_env argument is omitted. Root restored every one of136 archived files,14 directories and4,801,549 bytes. External Python and libpython distributions are exact pins, not embedded binaries. No current-cold, Native, VM or portable positive execution is attributed to Source23.

The complete optional-profile R1/R2/R3 history is now present as123 full-Git-read-back leaves, including every118 non-LF archive part. Root verified all1396 archive members and the full gzip CRC, resolving5302 files,311 directories and two recorded symlinks,508,252,794 logical bytes, through1395 exact CAS objects. All actual failures remain. This was complete streaming verification, not a second expanded directory restore. Temporary wheel files already removed by their original fixture are not retroactively claimed to exist.

The one authorized frozen-R5 timeline execution retained its original10M failure and byte-identical complete F/O/W and VM report. All56 logical originals/33,536,726 bytes are Git-backed and Root stream-verified. The independent source proof preserves ten full files/3,335,665 bytes. Its post-first-clear replay model found5477 hits and an old-call-cost zero-new-cost ceiling of2,277,341 steps. That is an offline bound, not measured savings or R8 qualification. No R8 compilation or execution is included here.

## Remaining closure

The current full Source and original62 result is still pending. The original Native35 deadline failures, its skipped later steps, the R5 checker fuel failure, current cold/native workflow qualification, hosted production owners and production legacy retirement remain open. Earlier failures and non-adopted R6/R7 are not replaced by later component passes.
'''.encode()
    put('README.md', readme)
    add('README.md', readme)
    put('MOUNT-LEAVES.json', encode(leaves))
    new_files = []
    for name in ('ROOT-RECORDS.zlib.json', 'prepare_mount.py', 'INDEX.json', 'README.md'):
        path = ROOT / name
        new_files.append({'path': name, 'local_path': str(path), 'mode': '100644', **identity(path.read_bytes())})
    put('PUBLICATION-INTENT.json', encode({'schema': 'hia.audit-metadata-publication.v117',
        'collection': COLLECTION, 'files': new_files, 'new_product_executions': 0,
        'previous_audit_commit': status['previous_audit_commit'], 'whole_native': False}))
    print(json.dumps({'collection': COLLECTION, 'leaves': len(leaves), 'recipes': len(groups),
        'root_original_files': len(records), 'metadata_bytes': sum(x['bytes'] for x in new_files),
        'root_records_wrapper_bytes': len(wrapper), 'whole_native': False}))


if __name__ == '__main__':
    main()
