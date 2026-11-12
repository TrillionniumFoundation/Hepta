"""Author controls from retained exact IO text; no product code is imported."""
import ast
from hashlib import sha1, sha256
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).absolute().parent.parent
CONTROL = ROOT / 'control'
PREFIX = 'experiments/hia_bounded_read_owner_20261112/actions-native-development-r2'
CANDIDATE = '0e36619bc65ada7072c1e8a1f1454728036fee4e'
TREE = '1d95802c453a006f077eb8735a6939b1957d500b'
TRIGGER = 'codex/hia-bounded-read-native-r4b-run-r2-20261112-e26e'
WORK_ROOT = 'hia-bounded-read-native-r4b-development-r2'

def wire(x):
    return (json.dumps(x, sort_keys=True, indent=2) + '\n').encode()

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

names = {'source_common.py', 'native_support.py', 'git_binding.py', 'prepare_native.py',
    'native_driver.py', 'actions_verify.py', 'actions_custody.py', 'controller.py', 'diagnostics.py',
    'diagnostic-targets.json', 'source-manifest.json', 'populations.json', 'control-manifest.json',
    'process_owner_impl.py', 'guardian.py', 'reject_cases.py', 'lifetime_cases.py', 'permission_cases.py',
    'filesystem_cases.py', 'original_eight.py', 'caller_observer.py', 'read_bounded.original.py'}
header = '''"""One fixed bounded-read Actions development; no trigger is performed by this file."""
from __future__ import annotations
import argparse
import base64
from contextlib import contextmanager
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import traceback

REPOSITORY = 'TrillionniumFoundation/Hepta'
'''
for key, value in [('PREFIX', PREFIX), ('CANDIDATE', CANDIDATE), ('TREE', TREE),
                   ('TRIGGER', TRIGGER), ('WORK_ROOT', WORK_ROOT)]:
    header += key + ' = ' + repr(value) + '\n'
header += "MAX_RECEIPT = 32 << 20\nNATURAL = {'qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'}\n"
header += 'CONTROL_NAMES = set(' + repr(sorted(names)) + ')\n\n'
io_source = (ROOT / 'authoring/controller_io.inc').read_text()
for output, body in [('controller.py', 'controller_body.inc'), ('diagnostics.py', 'diagnostics_body.inc')]:
    (CONTROL / output).write_text(header + io_source + '\n' + (ROOT / 'authoring' / body).read_text())

plan = json.loads((CONTROL / 'populations.json').read_bytes())
target_names = [name for name in ('setup.json', 'context.json', 'guard/request.json', 'guard/guardian.json',
    'evidence/build/bounded-read.hiaasm', 'evidence/build/entry-abi.json', 'evidence/build/manifest.json',
    'FINAL.json', 'evidence/report.json', 'evidence/build/report.json', 'evidence/build/B0.receipt.json')]
for label in ('B1', 'B2', 'bounded-read'):
    target_names.append('evidence/build/' + label + '.receipt.json')
target_names += ['evidence/' + group['name'] + '/report.json' for group in plan['groups']]
target_names += ['TERMINAL-ORIGINALS.json', 'guard/child.stdout.log', 'guard/child.stderr.log',
    'evidence/original-eight/unittest.log', 'evidence/original-eight/parent-original.json',
    'evidence/original-eight/child-policy.json', 'evidence/build/linker-version.stdout.log',
    'evidence/build/linker-version.stderr.log']
for label in ('B1', 'B2', 'bounded-read'):
    target_names += ['evidence/build/' + label + suffix for suffix in ('.request.json', '.stdout.log', '.stderr.log')]
for label in ('prepare-native', 'reject', 'lifetime', 'permission', 'filesystem', 'original-eight'):
    target_names += ['evidence/processes/' + label + suffix for suffix in ('.stdout.log', '.stderr.log',
        '.process-owner.json', '.process-owner.json.request.json', '.process-owner.json.stdout.log',
        '.process-owner.json.stderr.log')]
for group in plan['groups'][:-1]:
    target_names += ['evidence/' + group['name'] + '/' + case + '.json' for case in group['expected_ids']]
target_names += ['stage/' + phase + '.' + stream + '.log'
                 for phase in ('prepare', 'run', 'finalize') for stream in ('stdout', 'stderr')]
assert len(target_names) == len(set(target_names)) == 133
targets = {'schema': 'hepta.hia.bounded-read-small-targets.v1',
    'status': 'STATIC_FIXED_POPULATION_NOT_OBSERVED_RESULTS', 'fixed_targets': 133,
    'previous_targets': 130, 'added_targets': ['evidence/build/bounded-read.hiaasm',
        'evidence/build/entry-abi.json', 'evidence/build/manifest.json'],
    'small_raw_bytes': 512 << 10, 'small_stdout_bytes': 1 << 20, 'whole_file_selection_only': True,
    'complete_artifact_transport_claimed': False,
    'targets': [{'name': name, 'location': 'stage' if name.startswith('stage/') else 'root'} for name in target_names]}
(CONTROL / 'diagnostic-targets.json').write_bytes(wire(targets))

files = {name: pin((CONTROL / name).read_bytes()) for name in sorted(names - {'control-manifest.json'})}
manifest = {'schema': 'hepta.hia.bounded-read-native-development-control-manifest.v1',
    'candidate_commit': CANDIDATE, 'candidate_tree': TREE, 'outer_qualification_seconds': 180,
    'outer_cleanup_seconds': 3, 'dispatch_authorized_by_this_file': False, 'files': files,
    'scope': 'STATIC_ACTIONS_DEVELOPMENT_REQUIRES_ACTUAL_OUTER_ECHILD_AND_ALL_ORIGINAL_RESULTS'}
(CONTROL / 'control-manifest.json').write_bytes(wire(manifest))
files['control-manifest.json'] = pin((CONTROL / 'control-manifest.json').read_bytes())
policy = {'schema': 'hia.bounded-read-actions-policy.v1',
    'candidate': {'commit': CANDIDATE, 'tree': TREE, 'leaves': 4025},
    'trigger_branch': TRIGGER, 'runtime_root_basename': WORK_ROOT,
    'controller_seconds': 180, 'cleanup_seconds': 3, 'finite_cases': 55, 'original_methods': 8,
    'original_CLI_children': 7, 'original_CLI_timeout_seconds': 20,
    'compile_wall_seconds': 20, 'compile_CPU_seconds': 10, 'fresh_B0_B1_B2': True,
    'cold_qualification': False, 'whole_native_delivery_qualification': False,
    'checked_in_global_contract_updated': False,
    'original_contract_and_coverage_qualification_claimed': False,
    'controls': files, 'diagnostic_targets': 133, 'small_raw_bytes': 512 << 10,
    'small_stdout_bytes': 1 << 20, 'small_index_bytes': 64 << 10,
    'full_original_custody': 'closed-current-ECHILD typed tar; regular bytes, special metadata; no extraction',
    'small_channel_is_complete_artifact_transport': False,
    'initial_free_bytes': 8 << 30, 'initial_free_inodes': 100000,
    'HIA_function_count': 14, 'exact_group_populations': [12, 24, 10, 9, 8],
    'original_guardian_sha256': files['guardian.py']['sha256'],
    'original_owner_sha256': files['process_owner_impl.py']['sha256']}
(CONTROL / 'policy.json').write_bytes(wire(policy))
parsed = []
for path in sorted(CONTROL.glob('*.py')):
    raw = path.read_bytes()
    ast.parse(raw, filename=str(path))
    parsed.append({'path': str(path.relative_to(ROOT)), **pin(raw)})
result = {'schema': 'hepta.hia.bounded-read-actions-local-syntax.v1',
    'status': 'PYTHON_AST_PARSE_ONLY', 'python': sys.version, 'implementation': platform.python_implementation(),
    'files': parsed, 'parsed_count': len(parsed), 'product_generated': False,
    'native_compiled_or_executed': False, 'native_cases_executed': 0,
    'original_methods_executed': 0, 'workflow_triggered': False,
    'policy': pin((CONTROL / 'policy.json').read_bytes()), 'diagnostic_targets': len(target_names)}
(ROOT / 'authoring/AST-PARSE-ACTIONS.json').write_bytes(wire(result))
print(json.dumps({'parsed': len(parsed), 'targets': len(target_names), 'controls': len(files),
                  'policy': result['policy']}))
