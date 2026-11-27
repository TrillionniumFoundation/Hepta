"""Prepare one additive audit collection; no product ref or source is modified."""
from pathlib import Path
import base64
from hashlib import sha1, sha256
import json
import stat
import zlib

ROOT = Path(__file__).resolve().parent
AUDIT = ROOT.parent
WORK = AUDIT.parent
INPUT = AUDIT / 'v110-component-custody'
COLLECTION = 'hia-v115-r16-failures-r17-r18-integration-and-component-custody-20261114-dda7'


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
    leaves, groups = [], []
    paths = set()

    def add(path, sha, mode='100644', **metadata):
        assert path not in paths and len(sha) == 40 and set(sha) <= set('0123456789abcdef')
        assert mode in ('100644', '100755')
        paths.add(path)
        leaves.append(dict(path=path, sha=sha, mode=mode, type='blob'))

    def recipe(filename, prefix, recipe_path):
        path = INPUT / filename
        data = json.loads(path.read_bytes())
        before = len(leaves)
        for row in data['entries']:
            sha = row.get('sha') or row.get('git_blob') or row.get('blob')
            add(prefix + row['path'], sha, row.get('mode', '100644'))
        add(recipe_path, identity(path.read_bytes())['git_blob'])
        groups.append(dict(name=recipe_path, leaves=len(leaves)-before, recipe=identity(path.read_bytes())))

    recipe('compact-r1-r5-recipe.json', '', 'compact-render-R1-R5-present-raw/AUDIT-RECIPE.json')
    recipe('compact-r6-r7-raw-recipe.json', '', 'compact-render-R6-R7-present-raw/AUDIT-RECIPE.json')
    recipe('roundtrip-recipe.json', 'roundtrip-r3/', 'roundtrip-r3/MOUNT-RECIPE.json')
    recipe('portable-source-recipe.json', '', 'verified-report-portable-r1/MOUNT-RECIPE.json')
    recipe('namespace-cost-recipe.json', 'namespace-analysis-initial/', 'namespace-analysis-initial/MOUNT-RECIPE.json')
    recipe('namespace-full-recipe.json', 'namespace-analysis-complete/', 'namespace-analysis-complete/MOUNT-RECIPE.json')
    recipe('portable-review-recipe.json', 'portable-report-independent-review/', 'portable-report-independent-review/MOUNT-RECIPE.json')
    recipe('r16-source-failure-small-recipe.json', 'r16-source-failure/', 'r16-source-failure/SMALL-RECIPE.json')

    first = AUDIT / 'v108-r16-formal-repair/failure-mount-recipe.json'
    data = json.loads(first.read_bytes())
    for row in data['entries']:
        add('r16-first-formal-failure/' + row['path'], row['sha'], row['mode'])
    add('r16-first-formal-failure/MOUNT-RECIPE.json', identity(first.read_bytes())['git_blob'])

    for filename, target in (
        ('compact-r6-failed-candidate.json', 'compact-render-R6/FAILED-CANDIDATE.json'),
        ('compact-r7-failed-candidate.json', 'compact-render-R7/FAILED-CANDIDATE.json'),
        ('derived-restore-deletion-plan.json', 'derived-restore-cleanup/VERIFIED-PLAN.zlib.json'),
        ('derived-restore-deletion-result.json', 'derived-restore-cleanup/ACTUAL-RESULT.zlib.json'),
    ):
        add(target, identity((INPUT / filename).read_bytes())['git_blob'])

    manifest_raw = (INPUT / 'r16-source-failure-manifest.json').read_bytes()
    manifest = json.loads(manifest_raw)
    add('r16-source-failure/EVIDENCE-MANIFEST.json', identity(manifest_raw)['git_blob'])
    for number, row in enumerate(manifest['chunks']):
        assert row['index'] == number and row['full_readback_equal'] is True
        add(f'r16-source-failure/inner-archive/chunk-{number:03}.bin', row['blob'])
    assert len(manifest['chunks']) == 210

    checkpoint = json.loads((WORK / 'v113-root-checkpoint-r1/PUBLICATION-INTENT.json').read_bytes())
    checkpoint_readback = json.loads((ROOT / 'ROOT-CHECKPOINT-GIT-READBACK.json').read_bytes())
    assert checkpoint_readback['status'] == 'ALL_21_ACK_FULL_GET_PASS'
    for row in checkpoint['entries']:
        add(row['path'], row['git_blob'], row['mode'])
    assert len(checkpoint['entries']) == 21

    # Every newly authored proof is preserved as complete original bytes,
    # including failed read/restore adapter attempts and the binary-tool limit.
    originals = {}
    explicit = [
        INPUT / 'verify_r16_source_result.py', INPUT / 'R16-SOURCE-FAILURE-ROOT-READBACK.json',
        INPUT / 'verify_r16_original_archive.py', INPUT / 'R16-FULL-INNER-ROOT-READBACK.json',
        INPUT / 'COMPACT-R6-R7-ROOT-GIT-READBACK.json',
        INPUT / 'COMPACT-R6-R7-ROOT-STREAM-READBACK.json',
        INPUT / 'COMPACT-R6-R7-ROOT-VERIFY.stdout.raw',
        INPUT / 'COMPACT-R6-R7-ROOT-VERIFY.stderr.raw',
        Path(__file__).resolve(),
    ]
    explicit += sorted(p for p in ROOT.iterdir() if p.is_file() and p.suffix == '.json')
    explicit += sorted((AUDIT / 'publication').glob('v113-root-checkpoint-*.verified.json'))
    assert len([p for p in explicit if p.name.startswith('v113-root-checkpoint-')]) == 21
    for path in explicit:
        name = path.relative_to(WORK).as_posix()
        assert name not in originals
        raw = path.read_bytes()
        originals[name] = dict(identity(raw), mode=stat.S_IMODE(path.stat().st_mode),
                               base64=base64.b64encode(raw).decode())
    proof_raw = encode(dict(schema='hia.root.post-checkpoint.complete-originals.v1',
                            files=originals, logical_files=len(originals),
                            logical_bytes=sum(row['bytes'] for row in originals.values()),
                            new_product_executions=0, whole_native=False))
    put('ROOT-RECORDS.json', proof_raw)
    wrapped = encode(dict(schema='hia.lossless.zlib-json.v1', decoded=identity(proof_raw),
                          payload=base64.b64encode(zlib.compress(proof_raw, 1)).decode()))
    put('ROOT-RECORDS.zlib.json', wrapped)
    add('ROOT-RECORDS.zlib.json', identity(wrapped)['git_blob'])
    add('prepare_mount.py', identity(Path(__file__).read_bytes())['git_blob'])

    status = dict(
        repository='TrillionniumFoundation/Hepta', collection=COLLECTION,
        previous_audit_commit='159fdb8ad99ca1a9ffec4740bec15f39f585411b',
        main='f33d8da316de8fdf27b504371f1a5310997ff548',
        product_PR889_head='4b19af89a766593f7d5f1cc2db256e81aba7afcb',
        whole_native=False, current_cold_qualified=False, default_changed=False,
        R16_first_formal=dict(run=43520413130, job=132212950593,
                              result='FAIL_BEFORE_REPOSITORY_GENERATION_OR_TESTS', tests=0, original62='SKIPPED'),
        R16_source_successor=dict(run=43521833146, job=132217759086,
                                 commit='5217f8083876ed890a38c3f7291ba5a397c935b4',
                                 result='SOURCE_FAIL', source_tests=1357, source_pass=1353,
                                 source_failures=3, source_errors=1, source_skips=0,
                                 actual_start_stop_events=2714, source_wall_seconds=1493.0594082079997,
                                 actual_generator_count=134, actual_generation_passes=2,
                                 source_files=3133, source_tree='d87a062aefd4813fdd1425e4653cfca2a202daf6',
                                 original62='SKIPPED', native_execution_count=None,
                                 inner_archive_Git_chunks=210, inner_regular_files=5097, inner_directories=1287,
                                 whole_outer_ZIP_Git_copy=False, binary_connector_GETs=0),
        R17=dict(source_files=3152, source_tree='b64a023816bf7071f852507d6c2310db90baca4f',
                 first_new_Source_group='FAIL_4_METHOD_PASS_1_FAIL_1_ERROR',
                 first_default_generator_commands=10, first_default_generator_commands_pass=10,
                 test_only_successor_Source6='PASS', test_only_successor_wall_seconds=30.798456809003255,
                 full139_generators_executed=False, full_Source1363_executed=False,
                 Source_VM_steps=2407847, Source_VM_limit=10000000,
                 full_F_O_W_equal=True, actual_resident_calls=5, Native_compiles=0),
        R18=dict(source_files=3159, source_tree='a714329b61e9ce3a0cec2e78f70c34296bfdd67c',
                 result='PREPARED_NOT_EXECUTED_KNOWN_RESOURCE_REGISTRATION_BLOCKER',
                 source_expected=1374, selectors=235, generators=139,
                 old_worker_fixed_resources=210, planned_new_optional_resources=8,
                 original_Python_tests_exact=True, inherited_qualification=False),
        compact_R5=dict(Native_controls='162_PASS', VM='6_LOGICAL_5_PASS_1_10M_FAIL_ONE_PASS_REUSED_EXACT_IMAGE'),
        compact_R6=dict(result='NOT_ADOPTED_10M_VM_FAIL', image_bytes=557057,
                        image_growth_from_R5=5007, actual_aggregate_pack_executed=False),
        compact_R7=dict(result='NOT_ADOPTED_10M_VM_FAIL', image_bytes=573282,
                        image_growth_from_R5=21232, actual_aggregate_pack_executed=False),
        roundtrip_R3=dict(kernel_originals=130, kernel_result='PASS', pipeline_VM=7, pipeline_result='PASS',
                          actual_kernel_full_buffer_controls=6, last_byte_fault_controls=2,
                          image_bytes=1044480, remaining_1MiB_bytes=4096,
                          selected_Git_restore_files=234, selected_Git_restore_bytes=8910991,
                          large_raw_buffers_Git_complete=False),
        portable_report=dict(local_Source=11, local_Native_methods=2, retained_observations=140,
                             original_cli_methods=43, development_results='PASS',
                             current_joint_cold_positive_executed=False, whole_verify_native=False,
                             global_fixed_profile_registration_conflict=True),
        original_Native121=dict(run=43459534648, job=132002437588,
                               first35='3_FAIL', later_steps_skipped=103,
                               budget_or_freshness_guarantees_weakened=False),
        raw_custody=dict(R1_R5_present_files=4588, R1_R5_present_bytes=2275587257,
                         R1_R5_archive_parts=70, R1_historical_missing_originals=2,
                         R6_R7_present_files=272, R6_R7_present_bytes=100388719, R6_R7_archive_parts=12),
        derived_cleanup=dict(exact_previously_restored_files_deleted=4588,
                             logical_bytes=2275587257, original_raw_or_archive_deleted=False),
        root_work=dict(files=151, logical_bytes=58404068, archive_bytes=6624972, archive_parts=17,
                       includes_all_R17_R18_source_overlays=True,
                       guard_unroll_prototype='NOT_ADOPTED'),
        active_successors_at_capture=['V112 explicit optional resource profiles and installed report source binding',
                                      'V114 permanent portable roundtrip qualification'],
    )
    index = dict(schema='hia.additive-audit-checkpoint.v115', status=status,
                 component_recipes=groups, existing_object_leaves=leaves,
                 collection_leaf_count=len(leaves)+2,
                 metadata_not_self_referenced=['INDEX.json', 'README.md'],
                 root_post_checkpoint_originals=identity(proof_raw),
                 complete_prior_review_children_preserved=59, complete_nonreview_root_children_preserved=19)
    index_raw = encode(index)
    put('INDEX.json', index_raw)
    readme = '''# R16 failures, R17/R18 integration, and native component custody

This is an additive development checkpoint. Whole-native closure and matching-current-source cold qualification remain open. The production main and PR889 product head remain at their recorded versions.

## Actual joint results

| Scope | Actual outcome |
|---|---|
| R16 first formal run | Failed before repository creation, generation, or product tests because one harness alias was absent. The exact original ZIP is preserved. |
| R16 separate 17-file harness successor | 134 generators ran twice. Source ran all 1,357 original ordered IDs: 1,353 passed, three failed, one errored, zero skipped. The following original62 stage was skipped. |
| R17 first added component group | All ten new default generation commands passed; the six-method test group failed on two new fixture mistakes. The complete first outcome remains preserved. |
| R17 test-only successor | All six added Source methods passed in a 30.798457-second owner. Full file/output/workspace bytes matched the frozen pipeline fixture; five resident calls actually returned within 10M VM steps. |
| R18 | Prepared 3,159-file integration, with a known fixed-resource registration blocker. Its 1,374 expected Source methods and 139 generators have not run as a complete joint gate. |

The four R16 failures concern the exact original ENTRY19, NATIVE92, and 210-resource worker contract and its preflight allowlist. Adding optional components to that fixed contract was an integration error. The active successor separates explicit optional profiles, installation, and fresh source identity while retaining the complete original tests and limits. The optional report installation also needs an explicit captured source root in its selected bundle.

Formal runs: [first harness failure](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43520413130), [separate Source failure](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43521833146).

## Native scope and remaining blockers

The frozen roundtrip R3 component passed the original130 kernel controls, seven pipeline VM cases, six actual full-buffer kernel observations, and two last-byte comparison faults. Its actual ELF is 1,044,480 bytes, leaving 4,096 bytes below the original 1MiB ceiling. Its selected 234 files are fully recoverable here; the separate large raw-buffer archive is still a distinct delivery boundary.

The R5 checker passed 162 Native controls. Its six logical VM observations remain five passes and one unchanged 10M-fuel failure; one pass is an exact-image reuse. R6 and R7 both retain their actual 10M failures and are not adopted. Their 557,057-byte and 573,282-byte images exceed the aggregate's remaining growth allowance; neither was actually packed into a new aggregate.

The portable report component passed its local development Source11, two Native methods covering retained140 observations and cache controls, and the original43 CLI methods. These results do not qualify the future integrated source. Its fixed-profile registration conflict is preserved explicitly. The independent read-only review retains all thirteen before/after paths, the original43 IDs and bytes, seven original method bodies, and the R17 six-method boundary.

The older original Native121 workflow still has its three first-group failures and 103 later skipped steps. Namespace analysis found separate fresh-source reads across actual publication effects; it supplied no adopted cache or budget relaxation. The guard-unroll experiment is retained as NOT_ADOPTED.

## Complete evidence retained by this collection

- R16 first failure: exact outer ZIP, complete inner snapshot, original errors, and the separate exact alias repair.
- R16 Source successor: all 210 original binary Git chunks of the complete 109,873,612-byte inner archive, its exact manifest, full job log, result, Source report, 2,714 events, 3,133-source manifest, and custody verifiers. Root independently checked every actual chunk and all 5,097 inner files plus 1,287 directory modes from the downloaded ZIP. The UTF-8-only connector did not perform binary GETs; producer binary readback receipts and Root's actual ZIP-byte verification remain distinct. The entire 338MB outer ZIP is not represented as a complete Git copy.
- R1–R5: all 4,588 present originals, 2,275,587,257 logical bytes, through 70 archive parts. Two genuinely missing historical originals remain missing; later recaptures do not replace them.
- R6/R7: all 272 selected originals and complete failed-run buffers, 100,388,719 logical bytes, through twelve archive parts, including the original mode-checker failure and exact 0600/0644 repair.
- Root integration: 151 complete files, 58,404,068 logical bytes, including every failed and passing R17 group, full VM buffers, exact R17/R18 source overlays, and the rejected guard prototype. A separate small capsule preserves later Root checks and transport capability errors.
- The only cleanup deleted an independently verified, fully recoverable 4,588-file expanded archive copy. Original raw files, archives, and Git chunks remain retained.

Use `INDEX.json` for precise identities and scope. `root-work-checkpoint/TRANSPORT.json` identifies the full Root archive. Complete source overlays preserve the exact fixed base and before/after bytes; source-copy directories are not redundantly expanded in that archive. Every prior review collection and all nineteen non-review root entries are preserved by the additive audit commit.
'''.encode()
    put('README.md', readme)
    add('INDEX.json', identity(index_raw)['git_blob'])
    add('README.md', identity(readme)['git_blob'])
    assert len(leaves) == index['collection_leaf_count']
    put('MOUNT-LEAVES.json', encode(leaves))
    publication = []
    for name in ('ROOT-RECORDS.zlib.json', 'prepare_mount.py', 'INDEX.json', 'README.md'):
        path = ROOT / name
        publication.append(dict(path=name, local_path=str(path), mode='100644', **identity(path.read_bytes())))
    put('PUBLICATION-INTENT.json', encode(dict(schema='hia.audit.metadata-publication.v1', files=publication)))
    print(json.dumps(dict(collection=COLLECTION, leaves=len(leaves), root_records=len(originals),
                          root_records_bytes=len(proof_raw), new_metadata_blobs=len(publication),
                          inner_binary_chunks=210, whole_native=False), sort_keys=True))


if __name__ == '__main__':
    main()
