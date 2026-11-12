"""Read the closed original19 run without promoting any synthetic HOLD record."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

CONTROL = Path(__file__).resolve().parent
OUT = CONTROL / 'custody19-controls-r1'
SOURCE_RUN = CONTROL / 'source-controls-r1'
sys.path.insert(0, str(SOURCE_RUN))
from common import ROOT, names, physical


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


pre = json.loads((OUT / 'PREEXECUTION.json').read_bytes())
raw_request = (OUT / 'guard/request.json').read_bytes()
if digest(raw_request) != pre['request_sha256']:
    raise ValueError('original frozen19 request differs')
request = json.loads(raw_request)
guardian_raw = (OUT / 'guard/guardian.json').read_bytes()
guardian = json.loads(guardian_raw)
life = guardian['lifecycle']
cleanup = life['cleanup']
if not (cleanup['complete'] is True and cleanup['leader_reaped'] is True and cleanup['observed_echild'] is True
        and cleanup['errors'] == [] and cleanup['remaining_direct_children'] == [] and cleanup['deadline_exceeded'] is False):
    raise ValueError('owner not closed; do not inspect original control output')
if not (guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED' and guardian['input_identity_preserved'] is True
        and guardian['source_identities_before'] == guardian['source_identities_after'] == request['source_identities']
        and life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
        and life['qualification_seconds'] == 20 and life['cleanup_seconds'] == 3
        and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
        and life['event_overflow'] is False and life['interrupted_signals'] == [] and life.get('owner_error') is None):
    raise ValueError('original19 did not naturally complete under original20')
for path, sha in guardian['logs'].items():
    if digest(Path(path).read_bytes()) != sha:
        raise ValueError('owner log differs')
report_raw = (OUT / 'actual/REPORT.json').read_bytes()
report = json.loads(report_raw)
expected = json.loads((OUT / 'EXPECTED-IDS.json').read_bytes())
if not (expected == pre['original_expected_ids'] == report['loaded_ids'] == report['executed_ids']
        and report['tests_run'] == 19 and type(report['tests_run']) is int and report['status'] == 'PASS'
        and report['loader_errors'] == [] and report['actual_product_tests_executed'] is False
        and report['original_custody_controls'] == 14 and report['new_controls'] == 5
        and all(report[k] == [] for k in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))):
    raise ValueError('original19 actual population or anomaly record differs')
layout = json.loads((OUT / 'SOURCE-LAYOUT.json').read_bytes())
alias = OUT / 'source'
info = alias.lstat()
current = {'dev': info.st_dev, 'ino': info.st_ino, 'mode': info.st_mode,
           'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
if not alias.is_symlink() or os.readlink(alias) != layout['actual_readlink'] or alias.resolve(strict=True) != ROOT \
        or current != layout['alias_identity']:
    raise ValueError('source alias changed during original19')
for pin in pre['original_scripts']:
    raw = (OUT / pin['path']).read_bytes()
    if len(raw) != pin['bytes'] or digest(raw) != pin['sha256']:
        raise ValueError('original control script changed')
before = json.loads((OUT / 'SOURCE-BEFORE.json').read_bytes())
after = physical(names())
if before != after or len(after) != 4075:
    raise ValueError('complete candidate source changed')
tree = subprocess.check_output(['git', '-C', str(ROOT), 'write-tree']).decode().strip()
if tree != pre['source_tree']:
    raise ValueError('source tree changed')
events = life['events']
start = next(e['monotonic_ns'] for e in events if e['kind'] == 'qualification_started')
end = next(e['monotonic_ns'] for e in events if e['kind'] == 'qualification_exit_observed')
validation = {'schema': 'hia.v88.original-custody19-readback.v1',
              'status': 'ORIGINAL19_SOURCE_CONTROLS_PASS_NOT_PRODUCT_QUALIFICATION',
              'source_tree': tree, 'physical_source_files': len(after), 'source_preserved': True,
              'expected_loaded_executed': 19, 'zero_five_anomalies_and_loader_errors': True,
              'qualification_seconds': 20, 'cleanup_seconds': 3, 'original_probe_seconds': 8,
              'actual_qualification_seconds': (end - start) / 1e9, 'cleanup_elapsed_ns': cleanup['elapsed_ns'],
              'owner_natural_and_ECHILD_closed': True,
              'historical_descendant_inventory_complete': life['historical_descendant_inventory_complete'],
              'source_alias_and_all_three_original_script_bytes_preserved': True,
              'guardian_sha256': digest(guardian_raw), 'report_sha256': digest(report_raw),
              'synthetic_expected_HOLD_records_reclassified': False,
              'original39_or_HIA_native_or_installed_or_cold_executed': False,
              'separate_from_source102': True, 'complete_native_rewrite': False}
for name, value in [('SOURCE-AFTER.json', after), ('VALIDATION.json', validation)]:
    with (OUT / name).open('x') as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n')
print(json.dumps(validation, sort_keys=True))
