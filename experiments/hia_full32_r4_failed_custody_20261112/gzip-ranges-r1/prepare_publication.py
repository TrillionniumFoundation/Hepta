"""Build the fixed evidence/control publication index without writing Git."""
from pathlib import Path
from hashlib import sha256, sha1
import ast
import difflib
import json
import os

ROOT = Path(__file__).resolve().parent
PREFIX = 'experiments/hia_full32_r4_failed_custody_20261112/gzip-ranges-r1'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def put(path, value):
    raw = value if isinstance(value, bytes) else wire(value)
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return pin(raw)


policy = json.loads((ROOT / 'control/policy.json').read_bytes())
actual1 = json.loads((ROOT / 'evidence/tiny-io-r1/REPORT.json').read_bytes())
actual2 = json.loads((ROOT / 'evidence/closed-storage-io-r1/REPORT.json').read_bytes())
actual3 = json.loads((ROOT / 'evidence/tiny-io-r2-observed-population/REPORT.json').read_bytes())
assert (actual1['status'], actual1['executed'], actual2['status'], actual2['executed'], actual3['status'], actual3['executed']) == ('PASS', 20, 'PASS', 8, 'PASS', 23)
old = ROOT / 'history/unexecuted-hard48-r1'
delta = ''.join(''.join(difflib.unified_diff((old / 'control' / name).read_text().splitlines(True),
    (ROOT / 'control' / name).read_text().splitlines(True), fromfile='old-unexecuted/' + name,
    tofile='observed-denominator/' + name)) for name in ('gzip_evidence.py', 'controller.py', 'policy.json'))
put(ROOT / 'evidence/OBSERVED-POPULATION-DELTA.diff', delta.encode())
log = (ROOT / 'reference/job-131485819365.original.log').read_bytes()
observation = [line for line in log.decode().splitlines() if 'there will be 48 files uploaded' in line]
assert len(observation) == 1
revision = {'schema': 'hia.failed-full32-gzip.observed-population-revision.v1',
    'old_state': 'UNEXECUTED_TRANSPORT_WITH_HARD_UPLOAD_PREDICTION_RETAINED',
    'current_r4_job': 131485819365, 'current_r4_log': pin(log),
    'current_r4_upload_prediction_original_line': observation[0],
    'prediction_is_not_a_verified_original_ZIP_entry_count': True,
    'historical_r3_observed_48_is_not_this_request_denominator': True,
    'new_rule': '4 mandatory regular names; full original directory <=256 entries; all actual entries CRC/SHA/bytes/kind exact set and count join; no hard48',
    'old20_and_old8_controls_unchanged_originals_retained': True,
    'new23_full_source_io_control_status': actual3['status'],
    'new_original_transport_or_product_execution': False,
    'closed_storage_function_body_unchanged_from_8_actual_IO_checks': True}
put(ROOT / 'evidence/OBSERVED-POPULATION-REVISION.json', revision)

def function(path, name):
    raw = path.read_text(); lines = raw.splitlines(True)
    node = next(n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ''.join(lines[node.lineno - 1:node.end_lineno])

assert function(old / 'control/controller.py', 'closed_storage_observation') == function(ROOT / 'control/controller.py', 'closed_storage_observation')
assert (old / 'control/worker.py').read_bytes() == (ROOT / 'control/worker.py').read_bytes()
limits = {'original_maximum_MiB': 3072, 'ten_gzip_ranges_maximum_MiB': 3130,
          'private_small_MiB': 192, 'public_small_before_final_docs_MiB': 200,
          'private_metadata_MiB': 64, 'eleven_current_diagnostic_sets_MiB': 22,
          'future_final_documents_MiB': 46, 'one_serial_upload_workspace_MiB': 320,
          'filesystem_reserve_MiB': 512}
total = sum(limits.values())
assert total == 7558 and total < 8192
put(ROOT / 'evidence/STORAGE-PLAN.json', {'schema': 'hia.failed-full32-gzip.fixed-storage-plan.v1',
    'maximum_logical_components_MiB': limits, 'sum_MiB': total, 'original_free_admission_MiB': 8192,
    'logical_headroom_MiB': 8192 - total,
    'actual_allocated_blocks_plus_reserves_still_required': True,
    'actual_remaining_bytes_and_inodes_still_required': True,
    'initial_free_inodes': 100000, 'actual_compressed_ratio': None,
    'gzip_ranges_relocated_same_device_no_third_payload_copy': True,
    'streaming_decode_creates_no_second_raw_ZIP': True,
    'local_artifact_download_or_8GiB_admission_executed': False})
context = {'schema': 'hia.failed-full32-r4-gzip.control-context.v1',
    'base_commit': 'e4fc00a775dab323758d77a2ef4918fd35585cdc',
    'base_tree': 'd9e8407c70e44a3ea0152b8b4c5eb2ed3833d790', 'base_leaves': 4076,
    'repository': policy['repository'], 'artifact': policy['artifact'],
    'actual_product_input': policy['actual_full32_inputs'],
    'old_transport_request_not_replayed': True, 'old_full32_failed_product_not_reexecuted': True,
    'new_scope': 'One single GET of the already published failed ZIP, full evidence-only CRC/SHA inspection, exact fixed raw ranges gzip transport, whole small failure originals',
    'new_runtime_controls': policy['control_files'], 'policy': pin((ROOT / 'control/policy.json').read_bytes()),
    'original_guardian_seconds': 900, 'original_cleanup_seconds': 3, 'original_transfer_seconds': 720,
    'new_network_owner_product_executed': False, 'triggered': False,
    'operator_only_trigger_after_root_exact_A_B_review': True,
    'small_diagnostics_uploaded_first': True,
    'whole_remote_original_and_gzip_parts_complete_only_after_actual_owner_and_actual_FULL_readback': True,
    'current_gzip_actual_size_unobserved': True,
    'local_storage_inadequate_for_unconditional_3GB_download': True}
put(ROOT / 'CONTEXT.json', context)
diff = ''.join(''.join(difflib.unified_diff((ROOT / 'reference' / name).read_text().splitlines(True),
    (ROOT / 'control' / name).read_text().splitlines(True), fromfile='prior-successful/' + name,
    tofile='new-gzip-control/' + name)) for name in ('controller.py', 'worker.py', 'render_workflow.py', 'workflow-template.yml'))
put(ROOT / 'evidence/CONTROL-DELTA.diff', diff.encode())
paths = []
for folder in ('control', 'reference', 'evidence', 'history'):
    paths.extend(path for path in (ROOT / folder).rglob('*') if path.is_file())
paths.extend(ROOT / name for name in ('controller_delta.py', 'author_controls.py', 'freeze_policy.py',
    'prepare_publication.py', 'check_transport_io.py', 'check_closed_storage_io.py', 'CONTEXT.json'))
paths = sorted(set(paths))
records = []
for path in paths:
    raw = path.read_bytes(); raw.decode('utf-8')
    relative = path.relative_to(ROOT).as_posix()
    # Runtime contents are flat under the frozen Git prefix; authoring/evidence stay in their own directories.
    suffix = relative.removeprefix('control/') if relative.startswith('control/') else relative
    records.append({'local': str(path), 'relative': relative, 'path': PREFIX + '/' + suffix,
                    'mode': '100644', **pin(raw)})
assert len({x['path'] for x in records}) == len(records)
put(ROOT / 'PUBLICATION-FILES.json', {'schema': 'hia.frozen-git-publication-files.v1',
    'prefix': PREFIX, 'files': records, 'bytes': sum(x['bytes'] for x in records),
    'no_ref_or_workflow_mutations_authorized_here': True})
print(json.dumps({'files': len(records), 'bytes': sum(x['bytes'] for x in records),
                  'policy': context['policy'], 'frozen_runtime': context['new_runtime_controls']}, sort_keys=True))
