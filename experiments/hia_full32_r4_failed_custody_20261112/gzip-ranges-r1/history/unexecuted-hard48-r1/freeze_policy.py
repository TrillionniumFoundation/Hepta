"""Freeze actual provider metadata and renderable transport inputs; no dispatch."""
from pathlib import Path
from hashlib import sha256, sha1
import ast
import difflib
import json

ROOT = Path(__file__).resolve().parent
PREFIX = 'experiments/hia_full32_r4_failed_custody_20261112/gzip-ranges-r1'
BRANCH = 'codex/hia-full32-r4-gzip-originals-run-r1-20261112-e26e'
WORK = 'hia-full32-r4-gzip-originals-r1'
PUBLIC = 'hia-full32-r4-gzip-originals-public-r1'
SCHEMA = 'hia.actions.failed-full32-gzip-parts-policy.v1'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def save(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)


policy = json.loads((ROOT / 'reference/policy.json').read_bytes())
run = json.loads((ROOT / 'reference/RUN-2101.original.json').read_bytes())
jobs = json.loads((ROOT / 'reference/JOBS-2101.original.json').read_bytes())['jobs']
artifacts = json.loads((ROOT / 'reference/ARTIFACTS-2103.original.json').read_bytes())['artifacts']
assert run['id'] == 43305002328 and run['run_attempt'] == 1 and run['status'] == 'completed' and run['conclusion'] == 'failure'
assert len(jobs) == len(artifacts) == 1 and jobs[0]['id'] == 131485819365
artifact = artifacts[0]
assert artifact['id'] == 13982129929 and artifact['size_in_bytes'] == 3010752230
assert artifact['digest'] == 'sha256:4f5b0439a47f873e90fb6382c0232d9e3ae99b0dd05eb5b5e01132eeec4c9380'
assert artifact['workflow_run']['id'] == run['id'] and artifact['workflow_run']['head_sha'] == run['head_sha']
policy['artifact'] = {'id': artifact['id'], 'bytes': artifact['size_in_bytes'],
    'sha256': artifact['digest'].removeprefix('sha256:'), 'run_id': run['id'],
    'job_id': jobs[0]['id'], 'run_attempt': 1, 'event': 'create', 'workflow_terminal': 'failure',
    'checkout_commit': 'f5cadd86148c67d6a7eb36d1bd75412fa76401bb',
    'checkout_tree': '788bb63dd714b10f48b07004e890e425a373205e'}
policy.update(schema=SCHEMA, control_prefix=PREFIX, trigger_branch=BRANCH,
              work_root_name=WORK, public_root_name=PUBLIC)
policy['source']['head'] = policy['artifact']['checkout_commit']
policy['source']['tree'] = policy['artifact']['checkout_tree']
policy['actual_full32_inputs']['control_commit'] = '58b216cfe4c65c98df2a0d1001367e4d009e1492'
policy['limits'].update(compressed_part_bytes=313 << 20, small_original_bytes=160 << 20,
    small_derived_bytes=32 << 20, small_public_bytes=224 << 20,
    inner_stream_bytes=16 << 30, outer_stream_bytes=4 << 30)
policy['parts'] = []
offset = 0
while offset < artifact['size_in_bytes']:
    ordinal = len(policy['parts'])
    count = min(312 << 20, artifact['size_in_bytes'] - offset)
    policy['parts'].append({'ordinal': ordinal, 'offset': offset, 'bytes': count,
                            'name': 'part-%02d.bin.gz' % ordinal})
    offset += count
assert len(policy['parts']) == 10 and policy['parts'][-1]['bytes'] == 66350822
policy['control_files'] = {name: pin((ROOT / 'control' / name).read_bytes()) for name in (
    'controller.py', 'worker.py', 'guardian.py', 'process_owner_impl.py', 'original_receiver.py', 'gzip_evidence.py')}
policy['whole_ZIP_members_decompressed'] = True
policy['new_product_execution'] = False
policy['evidence_decompression_scope'] = 'Only authenticated original ZIP/TAR evidence; no executable member imported, extracted, or invoked.'
policy['range_encoding'] = {'method': 'gzip', 'compresslevel': 1, 'mtime': 0,
    'one_stream_per_fixed_raw_range': True, 'raw_ZIP_bytes_repacked_or_regenerated': False,
    'compressed_output_size_or_ratio_known_before_execution': False}
policy['capacity_scope'] = (
    'Original ZIP plus one complete gzip-range copy only; raw decompression is streamed into hashes. '
    'After closed ECHILD, range files relocate on the same filesystem. Original 8 GiB/100000 inodes '
    'remain required. The gzip expansion allowance, private/public bounded small originals, actual '
    'allocated blocks, final document reserves, one 320 MiB serial upload workspace and 512 MiB '
    'filesystem reserve are explicitly checked. No local acceptance is inferred from unavailable capacity.')
policy['downstream_acceptance'] = (
    'Require this unique receiver run/attempt/head/control/policy and original900/3 natural ECHILD. '
    'Read small artifact first. Then all ten official part artifacts must join identical FINAL/PART '
    'metadata and exact fixed raw offsets, individual complete compressed SHA/size, single-stream '
    'gzip CRC/end, complete raw-range SHA/size and concatenated original external size/SHA. '
    'Original failed full32 results and unreadable/missing originals are never reclassified.')
policy['small_diagnostics'] = {'outer_files_from_original_upload_log': 48,
    'fixed_outer_required': ['hia-v87-full-public/ORIGINAL-CATALOG.json',
        'hia-v87-full-public/CUSTODY.json', 'hia-v87-full-public/FINAL.json'],
    'inner_container': 'hia-v87-full-public/full-retained-originals.tar.gz',
    'inner_catalog': '.FULL-RETAINED-TYPED-MANIFEST.json',
    'root_apt_owned_exact_six_each': ['config.json', 'root-process.json', 'environment.json',
                                    'guardian.json', 'child.stdout.log', 'child.stderr.log'],
    'root_apt_owned_directories': ['supply/evidence/apt-owned-update/', 'supply/evidence/apt-owned-install/'],
    'missing_original_not_invented': True, 'oversized_or_budget_originals_omitted_whole': True,
    'small_artifact_uploaded_before_large_parts': True, 'maximum_public_bytes': 224 << 20}
save(ROOT / 'control/policy.json', wire(policy))

template = (ROOT / 'reference/workflow-template.yml').read_text()
template = template.replace('HIA v89 complete original ZIP in bounded artifacts', 'HIA full32 r4 failed originals as gzip ranges and small diagnostics')
template = template.replace('Retain one historical ZIP as a fixed complete partition', 'Read original failed evidence, retain lossless ZIP ranges')
template = template.replace('codex/hia-v89-full32-failed-original-parts-run-r1-20261112-e26e', BRANCH)
template = template.replace('experiments/hia_v89_full32_failed_custody_20261112/multipart-r1', PREFIX)
template = template.replace('hia-v89-full32-failed-parts-public-r1', PUBLIC)
template = template.replace('hia-v89-full32-failed-parts-r1', WORK)
template = template.replace('          show-progress: false\n', '''          show-progress: false
          sparse-checkout-cone-mode: false
          sparse-checkout: |
            /''' + PREFIX + '''/
            /.github/workflows/hia-core.yml
            /.github/workflows/hia-ndu-feedback.yml
            /.github/workflows/hia-source-custody.yml
''')
template = template.replace('UPLOAD_STEPS_PENDING_ACTUAL_COUNT\n', '''      - name: Preserve whole failure receipts, small originals, and complete inventories first
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: hia-full32-r4-small-originals-${{ github.run_id }}-1
          path: '${{ runner.temp }}/''' + PUBLIC + '''/small/'
          if-no-files-found: error
          include-hidden-files: false
          compression-level: 0
          retention-days: 14
          overwrite: false
UPLOAD_STEPS_PENDING_ACTUAL_COUNT
''')
save(ROOT / 'control/workflow-template.yml', template.encode())
renderer = (ROOT / 'reference/render_workflow.py').read_text()
renderer = renderer.replace('experiments/hia_v89_full32_failed_custody_20261112/multipart-r1', PREFIX)
renderer = renderer.replace('hia.actions.v88-full-original-parts-policy.v1', SCHEMA)
renderer = renderer.replace("    'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000,", """    'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000,
    'compressed_part_bytes': 313 << 20,
    'small_original_bytes': 160 << 20, 'small_derived_bytes': 32 << 20,
    'small_public_bytes': 224 << 20, 'inner_stream_bytes': 16 << 30, 'outer_stream_bytes': 4 << 30,""")
renderer = renderer.replace('hia-v89-full32-failed-original-part-', 'hia-full32-r4-original-gzip-part-')
renderer = renderer.replace('hia-v89-full32-failed-parts-public-r1', PUBLIC)
renderer = renderer.replace("'name': 'part-%02d.bin' % len(parts)", "'name': 'part-%02d.bin.gz' % len(parts)")
renderer = renderer.replace("'original_receiver.py', 'process_owner_impl.py'}", "'original_receiver.py', 'process_owner_impl.py', 'gzip_evidence.py'}")
renderer = renderer.replace('five exact control files are required', 'six exact control files are required')
ast.parse(renderer)
save(ROOT / 'control/render_workflow.py', renderer.encode())
save(ROOT / 'evidence/POLICY-DELTA.diff', ''.join(difflib.unified_diff(
    (ROOT / 'reference/policy.json').read_text().splitlines(True), wire(policy).decode().splitlines(True),
    fromfile='previous-successful-transport/policy.json', tofile='new-r4-originals/control/policy.json')).encode())
print(json.dumps({'policy': pin(wire(policy)), 'parts': policy['parts'],
                  'runtime_controls': policy['control_files'], 'executed': False}, sort_keys=True))
