"""Prepare an additive, explicitly incomplete whole-native development checkpoint."""
from pathlib import Path
import base64
from hashlib import sha1, sha256
import json
import stat
import zlib

ROOT = Path(__file__).resolve().parent
AUDIT = ROOT.parent
WORK = AUDIT.parent
INPUT = AUDIT / 'v116-component-inputs'
COLLECTION = 'hia-v116-optional-profile-safety-and-roundtrip-source-custody-20261114-dda7'


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def identity(raw):
    return dict(bytes=len(raw), sha256=sha256(raw).hexdigest(),
                git_blob=sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


def put(name, raw):
    with (ROOT / name).open('xb') as stream:
        assert stream.write(raw) == len(raw)


def main():
    assert not (ROOT / 'MOUNT-LEAVES.json').exists()
    leaves, groups, used = [], [], set()

    def add(path, raw, expected=None):
        assert path not in used and not path.startswith('/') and '..' not in Path(path).parts
        used.add(path)
        actual = identity(raw)
        if expected:
            blob = expected.get('git_blob') or expected.get('sha') or expected.get('blob')
            assert actual['git_blob'] == blob, path
            for key in ('bytes', 'sha256'):
                if key in expected:
                    assert actual[key] == expected[key], (path, key)
        leaves.append(dict(path=path, sha=actual['git_blob'], mode='100644', type='blob'))
        return actual

    scopes = ('profiles-v112', 'profiles-source24', 'profiles-r2', 'profiles-r3',
              'profiles-r3-terminal', 'roundtrip-v114', 'roundtrip-r2', 'roundtrip-r3',
              'field-cost-r6', 'profiles-complete-small')
    for scope in scopes:
        recipe_path = INPUT / scope / 'MOUNT-RECIPE.json'
        raw = recipe_path.read_bytes()
        recipe = json.loads(raw)
        entries = recipe['entries']
        for row in entries:
            assert row.get('mode', '100644') == '100644'
            add(scope + '/' + row['path'], (INPUT / scope / row['path']).read_bytes(), row)
        pin = add(scope + '/MOUNT-RECIPE.json', raw)
        groups.append(dict(scope=scope, leaves=len(entries), recipe=pin,
                           all_original_UTF8_blobs_Git_full_GET_verified=True))
    for scope in ('profiles-review-r1', 'profiles-review-r2', 'profiles-review-r3', 'roundtrip-review-r3'):
        capsule_name = 'REVIEW-CAPSULE.json' if scope in ('profiles-review-r1', 'profiles-review-r2') else 'CAPSULE.json'
        for name in (capsule_name, 'SUMMARY.json'):
            add(scope + '/' + name, (INPUT / scope / name).read_bytes())

    # Keep complete Root originals, including failed verification attempts and
    # draft preparers. Drafts have not been executed and confer no qualification.
    paths = set(path for path in (WORK / 'v116-union-r19').iterdir() if path.is_file())
    paths.add(WORK / 'v116-source-parser-r19-harness/prepare_harness.py')
    paths.add(Path(__file__).resolve())
    paths.add(ROOT / 'prepare_mount.py')
    paths.add(ROOT / 'PREPARATION-FAILURE-R1.json')
    paths.add(ROOT / 'PREPARER-R2-DIFF.json')
    for path in INPUT.rglob('*'):
        if path.is_file() and (path.name.startswith('ROOT-') or path.name.endswith('GIT-READBACK.json')):
            paths.add(path)
    previous = AUDIT / 'v115-complete-custody-mount'
    for path in previous.iterdir():
        if path.is_file() and (path.name.startswith(('COMMIT-', 'REF-', 'PR889-', 'MAIN-AFTER-'))
                              or path.name in ('MOUNT-RESULT.json', 'TREES-VERIFIED.json')):
            paths.add(path)
    records = {}
    for path in sorted(paths):
        raw = path.read_bytes()
        records[path.relative_to(WORK).as_posix()] = dict(identity(raw),
            mode=stat.S_IMODE(path.stat().st_mode), base64=base64.b64encode(raw).decode())
    root_raw = encode(dict(schema='hia.root.complete-originals.v116', files=records,
                           logical_files=len(records), logical_bytes=sum(row['bytes'] for row in records.values()),
                           root_product_executions=0, whole_native=False))
    put('ROOT-RECORDS.json', root_raw)
    wrapper = encode(dict(schema='hia.lossless.zlib-json.v1', decoded=identity(root_raw),
                          payload=base64.b64encode(zlib.compress(root_raw, 6)).decode()))
    put('ROOT-RECORDS.zlib.json', wrapper)
    add('ROOT-RECORDS.zlib.json', wrapper)
    add('prepare_mount_r2.py', Path(__file__).read_bytes())

    status = dict(
        whole_native=False, current_joint_cold=False, production_legacy_deleted=False,
        previous_audit_commit='2593e3ddc208f025c72a09da83907b5c955236e2',
        production_main='f33d8da316de8fdf27b504371f1a5310997ff548',
        PR889_product_head='4b19af89a766593f7d5f1cc2db256e81aba7afcb',
        optional_profiles=dict(default_ENTRY=19, default_NATIVE=92, default_resources=210,
            optional_union=8, original_HIA_assets_unchanged=True,
            R1_source_files=3161, R1_tree='60162b6c8cf5c0c375d3223fc28d6b66a0d5212a',
            R1_actual_groups=dict(Source=24, builds=6, report_methods=2, report_observations=140, original_cli=43),
            R1_two_FIFO_reopens_later_reproduced=True,
            R2_source_files=3162, R2_tree='3d8c3ff40f59d6f436bed1a193da8d5ebbe544f1',
            R2_actual_pass_groups=dict(Source=28, builds=6, report_methods=2, report_observations=140),
            R2_original43_never_started=True,
            R2_original_four_race_control_first_attempt='THREE_PASS_ONE_FAIL_FIXTURE_IMPORT_PATH_MATCH',
            R2_original_parent_symlink_counterexample='ONE_FAIL_OUTSIDE_hia_bootstrap_CREATED',
            R3_source_files=3162, R3_tree='24754374b90df56de475e67274ceb9280f6882fa',
            R3_actual_pass_groups=dict(Source=29, builds=6, original_cli=43),
            R3_parent_symlink_counterexample='PASS_OUTSIDE_EMPTY',
            R3_report140_not_repeated=True,
            current_cold_positive=False, original_all_failures_preserved=True,
            security_reviews=3, full_default_worker_contract_byte_identical_to_R14=True),
        roundtrip=dict(new_source_paths=13, R2_original_Source16='PASS',
            R2_source_tree='e991840b8cf00676e754585d3e6b383b8c3da410',
            R2_full_raw_restored_files=43, R2_full_raw_restored_bytes=5659979,
            initial_loader_exit127='PRESERVED_ZERO_TESTS_MISSING_ACTUAL_libpython_PATH',
            R3_Source22='PASS_ORIGINAL16_PLUS_CAPTURE6',
            R3_source_tree='e4630402ab3b5a83daef59ae74f4fd0a9cecd5ec',
            R3_full_raw_archive_not_in_this_checkpoint=False,
            R3_full_raw_restored_files=59, R3_full_raw_restored_bytes=5061146,
            original_Native140_ids_and_assertions_unchanged=True,
            current_cold_native_VM_portable_positive_executions=0,
            active_R4='THREE_NEW_ENVIRONMENT_SITES_NEED_EXACT_CURRENT_RUNTIME_LIBRARY_CONTEXT'),
        field_cost=dict(all_26_originals_Git_stream_verified=True,
            logical_bytes=3817643, actual_VM_status='FAILED_AT_ORIGINAL_10000000_LIMIT',
            adopted=False),
        R19=dict(status='DRAFT_PREPARERS_NOT_EXECUTED',
            final_source_tree=None, complete_Source_executed=False, formal_run_started=False,
            planned_generators=139, planned_selectors=239,
            final_Source_count_must_come_from_actual_final_source=True),
        raw_boundaries=dict(profile_Source24_complete_original_files=14,
            profile_Source24_original_bytes=1626610,
            profile_Source24_temporary_package_binaries_not_retained_by_original_fixture=True,
            complete_profiles_R1_R2_R3_archive_pending_separate_Git_parts=True,
            complete_R3_roundtrip_raw_pending_separate_Git_parts=False),
        remaining_original_blockers=['Original Native35 deadline failures and 103 skipped later steps',
            'R5 semantic checker cross-target 10M VM failure; R6 and R7 not adopted',
            'Matching-current-source cold and complete Native workflows remain unqualified',
            'Whole-system hosted owners and production legacy retirement remain open'])
    index = dict(schema='hia.additive-audit-checkpoint.v116', collection=COLLECTION,
                 status=status, recipes=groups, root_originals=identity(root_raw),
                 root_original_files=len(records), existing_object_leaves=leaves,
                 final_collection_leaves=len(leaves)+2,
                 previous_review_children_preserved=60, previous_nonreview_root_children_preserved=19)
    index_raw = encode(index)
    put('INDEX.json', index_raw)
    add('INDEX.json', index_raw)
    readme = '''# Optional profiles, safe source capture, and roundtrip Source custody

This additive development checkpoint preserves all prior audit subtrees. Whole-native closure, matching-current-source cold qualification, default migration and production legacy deletion remain false.

## Actual outcomes and their exact versions

| Version | Actual result | Boundary |
|---|---|---|
| Optional profiles R1 | Source24, six builds, two report methods with 140 retained observations, and original43 passed | Two later real FIFO substitutions exposed unsafe reopens; earlier passes remain their original results. |
| Optional profiles R2 | Source28, six builds and two report methods passed | Original43 never started. A later parent-symlink counterexample failed after creating an outside directory. |
| Optional profiles R3 | Source29, six actual builds and original43 passed | The same parent-symlink counterexample passed with the outside directory empty. No current-cold result; report140 was not repeated. |
| Roundtrip R2 | Original16 Source controls passed | The first interpreter launch exited127 before tests; its exact log remains. No current-cold, Native, VM or portable positive execution. |
| Roundtrip R3 | Original16 plus six new capture controls passed | Seven source successors consume securely captured bytes. Three future child environments still need the separate exact-runtime-library successor. No native authority is supplied by Source22. |

The complete default worker contract is byte-identical to its original ENTRY19/NATIVE92/210-resource form. All eight optional HIA assets retain their exact bytes and remain explicit source dependencies. Named profiles select optional packaging. R2 uses bounded nonblocking descriptor reads and captures actual bytes; R3 holds parent directories before creating optional destinations. Independent reviews and Root readbacks retain the actual before/after sources, original failures, full ordered IDs, actual Python3.14.4, the unchanged 180+3 owners and completed ECHILD cleanup.

## Evidence actually present here

All leaves named by the ten mounted recipes were fully read from Git and their complete bytes were checked. The Source24 package restores all fourteen retained originals. The roundtrip R2 archive restores all43 originals and 5,659,979 bytes, including the original loader127 failure. The field-cost archive streams all26 originals and 3,817,643 bytes. The roundtrip R3 archive also restores all59 originals and 5,061,146 bytes with all13 directory modes. The complete R1/R2/R3 profile image and buffer archive remains a separate pending custody object; its manifest, index and local full-stream verification are present, but reports and hashes do not stand in for the pending118 archive parts.

The Root records preserve verification scripts, successful readbacks, failed adapter checks, and the preceding audit commit/ref/PR mutation receipts. They also capture draft R19 source, plan and formal-harness preparers. These drafts have not run, have no final combined source tree and confer no Source or Native qualification. The next formal harness must retain all17 referenced files, including both byte-identical materializer paths, all original62 controls and all existing budgets.

The earlier R16 full Source failure, the R5 semantic checker fuel failure, non-adopted R6/R7, and the original Native35 deadline failures remain unchanged. No old production implementation is removed by this checkpoint.
'''.encode()
    put('README.md', readme)
    add('README.md', readme)
    put('MOUNT-LEAVES.json', encode(leaves))
    new_files = []
    for name in ('ROOT-RECORDS.zlib.json', 'prepare_mount_r2.py', 'INDEX.json', 'README.md'):
        path = ROOT / name
        new_files.append(dict(path=name, local_path=str(path), mode='100644', **identity(path.read_bytes())))
    put('PUBLICATION-INTENT.json', encode(dict(schema='hia.audit-four-metadata-publication.v116',
        collection=COLLECTION, files=new_files, new_product_executions=0,
        previous_audit_commit=status['previous_audit_commit'], whole_native=False)))
    print(json.dumps(dict(collection=COLLECTION, leaves=len(leaves), recipes=len(groups),
                          root_original_files=len(records), metadata_bytes=sum(row['bytes'] for row in new_files),
                          whole_native=False), sort_keys=True))


if __name__ == '__main__':
    main()
