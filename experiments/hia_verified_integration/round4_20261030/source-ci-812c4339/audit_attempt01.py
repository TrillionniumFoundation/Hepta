#!/usr/bin/env python3
"""Read selected CI ZIP evidence as data and correlate it with immutable Git blobs.

No extraction, compiler, solver, model, native workload or archive program is
executed. Only read-only `git cat-file`/`git ls-tree` commands are permitted.
This script is prepared statically; --execute must be used after model work ends.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time
import zipfile

LIMIT = 192 * 1024 * 1024
TOTAL_LIMIT = 768 * 1024 * 1024
ROOT_SUFFIX = 'artifacts/verified-optimization/source-sha.txt'
SPECS = {
    'regression': ('regression/result.json', 'hepta.hia.verified-increment.tests.v1', 'passed'),
    'guarded_cli': ('guarded-cli/result.json', 'hepta.hia.guarded-cli-qualification.v1', 'passed'),
    'narrowing_cli': ('narrowing-cli/RESULT.json', 'hepta.hia.narrowing-cli-qualification.v1', 'passed'),
    'ndu_loop': ('ndu-loop/RESULT.json', 'hepta.hia.ndu.loop.result.v1', 'all_episodes_completed'),
    'cpp_scoped': ('cpp-scoped/qualification.json', 'hepta.cpp-scoped-ownership-qualification.v1', 'ok'),
    'adaptive': ('adaptive/qualification.json', 'hepta.hia.adaptive-native-qualification.v1', 'ok'),
    'cpp_composed': ('cpp-composed-project/qualification.json', 'hepta.cpp-composed-project-native-qualification.v1', 'ok'),
    'owned_state': ('owned-state/qualification.json', 'hepta.hia.owned-state-qualification.v1', 'ok'),
    'narrowing': ('narrowing/RESULT.json', 'hepta.hia.narrowing-native-qualification.v1', 'passed'),
    'cpp_unique': ('cpp-unique-project/qualification.json', 'hepta.cpp-unique-project-native-qualification.v1', 'ok'),
    'cpp_assignment': ('cpp-unique-assignment-project/qualification.json', 'hepta.cpp-unique-assignment-project-native-qualification.v1', 'ok'),
    'continuation': ('owned-continuation/RESULT.json', 'hepta.hia.owned-continuation.qualification.v1', 'passed'),
    'assembly': ('agent-assembly/RESULT.json', 'hepta.hia.agent-assembly.qualification.v1', 'passed'),
}
CONTINUATION_CONTROLS = {
    'actual_cancelled_prefix', 'actual_verified_version_switch', 'exact_registered_suffix',
    'original_replay_refused', 'second_continuation_refused',
    'actual_suffix_and_complete_oracle', 'same_owner_and_allocation',
    'suffix_counterfactual_agrees', 'all_native_resources_released', 'sources_unchanged',
}


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def strict_json(data):
    def reject(value):
        raise ValueError('nonstandard JSON constant: ' + value)
    return json.loads(data, object_pairs_hook=strict_pairs, parse_constant=reject)


def path_ok(value):
    p = PurePosixPath(value)
    return (isinstance(value, str) and value and not p.is_absolute()
            and all(part not in ('', '.', '..') for part in value.split('/'))
            and '\\' not in value and '\0' not in value and '\n' not in value and '\r' not in value)


def git(repository, arguments, input_bytes=None):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0', LC_ALL='C')
    result = subprocess.run(['git', '--no-pager', '--no-optional-locks', '-C', str(repository),
                             *arguments], input=input_bytes, capture_output=True, timeout=60, env=env)
    if result.returncode:
        raise ValueError('read-only git command failed: ' + result.stderr.decode(errors='replace'))
    return result.stdout


def read_blobs(repository, commit, paths):
    names = sorted(paths)
    for name in names:
        if not path_ok(name):
            raise ValueError('unsafe source binding path: ' + str(name))
    raw = git(repository, ['cat-file', '--batch'],
              ''.join(commit + ':' + name + '\n' for name in names).encode())
    position, result = 0, {}
    for name in names:
        end = raw.find(b'\n', position)
        if end < 0:
            raise ValueError('truncated git batch header')
        header = raw[position:end].split()
        position = end + 1
        if len(header) != 3 or header[1] != b'blob':
            raise ValueError('expected commit blob missing: ' + name)
        size = int(header[2])
        if size > LIMIT or position + size + 1 > len(raw):
            raise ValueError('invalid git blob extent: ' + name)
        body = raw[position:position + size]
        if raw[position + size:position + size + 1] != b'\n':
            raise ValueError('invalid git batch framing')
        if sha1(b'blob ' + str(size).encode() + b'\0' + body).hexdigest().encode() != header[0]:
            raise ValueError('git blob content does not match object ID')
        result[name] = body
        position += size + 1
    if position != len(raw):
        raise ValueError('unexpected git batch trailing data')
    return result


class Audit:
    def __init__(self, options):
        self.options = options
        self.checks, self.reports, self.reads, self.binding_groups = [], {}, {}, {}
        self.compiler_bindings = {}
        self.expanded_read_bytes = 0
        self.zip = None
        self.prefix = None
        self.infos = {}
        self.regression_modules = []
        self.regression_log = ''
        self.ci_tree = {'availability': 'unavailable', 'verified': False,
                        'reason': 'not yet observed in the selected artifact'}
        self.ndu_elf = {'availability': 'unavailable', 'verified': False,
                        'reason': 'not yet observed in the selected artifact'}

    def check(self, name, condition, detail=None):
        row = {'check': name, 'passed': bool(condition)}
        if detail is not None:
            row['detail'] = detail
        self.checks.append(row)
        return bool(condition)

    def unique_suffix(self, suffix):
        matches = [name for name in self.infos if name == suffix or name.endswith('/' + suffix)]
        if len(matches) != 1:
            raise ValueError('expected exactly one ZIP member suffix ' + suffix + '; actual=' + repr(matches))
        return matches[0]

    def optional_suffix(self, suffix):
        matches = [name for name in self.infos if name == suffix or name.endswith('/' + suffix)]
        if len(matches) > 1:
            raise ValueError('ambiguous optional ZIP member suffix ' + suffix + '; actual=' + repr(matches))
        return matches[0] if matches else None

    def audit_ci_tree(self):
        member = self.prefix + 'source-tree.txt'
        if member not in self.infos:
            self.ci_tree = {'availability': 'unavailable', 'verified': False, 'member': None,
                            'reason': 'artifact has no direct CI source-tree.txt receipt'}
            if self.options.require_final_byte_evidence:
                self.check('final byte evidence: direct CI source-tree.txt is required', False, self.ci_tree)
            return
        data = self.read(member)
        value = data.decode('ascii').strip()
        matched = value == self.options.tree and data in {
            self.options.tree.encode(), self.options.tree.encode() + b'\n'}
        self.ci_tree = {'availability': 'present', 'verified': matched, 'member': member,
                        'actual_tree': value, 'expected_tree': self.options.tree,
                        'bytes': len(data), 'sha256': sha256(data).hexdigest()}
        self.check('actual source-tree.txt matches expected tree', matched, self.ci_tree)

    def audit_ndu_elf(self, manifest):
        member = self.optional_suffix('hia-ndu/target/release/hepta-hia-ndu-bridge')
        if member is None:
            self.ndu_elf = {'availability': 'unavailable', 'verified': False, 'member': None,
                            'reason': 'artifact does not contain the actual native NDU ELF body'}
            if self.options.require_final_byte_evidence:
                self.check('final byte evidence: actual uploaded native NDU ELF is required', False, self.ndu_elf)
            return
        data = self.read(member)
        digest = sha256(data).hexdigest()
        primary = manifest['binary_sha256']
        built = manifest.get('built_binary_sha256')
        built_present = 'built_binary_sha256' in manifest
        extent_ok = len(data) == self.infos[member].file_size and len(data) >= 64
        elf_ok = data[:4] == b'\x7fELF'
        primary_ok = digest == primary
        built_ok = not built_present or digest == built == primary
        matched = extent_ok and elf_ok and primary_ok and built_ok
        self.ndu_elf = {'availability': 'present', 'verified': matched, 'member': member,
                        'bytes': len(data), 'zip_uncompressed_bytes': self.infos[member].file_size,
                        'actual_sha256': digest, 'manifest_binary_sha256': primary,
                        'manifest_built_binary_sha256': built,
                        'manifest_built_binary_sha256_present': built_present,
                        'byte_count_matches_zip': extent_ok, 'elf_magic_valid': elf_ok,
                        'binary_sha256_matches': primary_ok, 'built_binary_sha256_matches_when_present': built_ok,
                        'extracted_loaded_or_executed': False}
        self.check('native NDU ELF: actual byte count and ELF magic', extent_ok and elf_ok, self.ndu_elf)
        self.check('native NDU ELF: byte SHA matches uploaded build identity', primary_ok and built_ok,
                   {'actual': digest, 'binary_sha256': primary, 'built_binary_sha256': built})

    def read(self, name):
        info = self.infos.get(name)
        if info is None:
            raise ValueError('required ZIP member missing: ' + name)
        if info.is_dir() or info.file_size > LIMIT:
            raise ValueError('not a bounded data file: ' + name)
        if self.expanded_read_bytes + info.file_size > TOTAL_LIMIT:
            raise ValueError('selected ZIP read budget exceeded')
        with self.zip.open(info) as stream:
            data = stream.read(LIMIT + 1)
            if len(data) != info.file_size or stream.read(1):
                raise ValueError('ZIP member extent differs: ' + name)
        self.expanded_read_bytes += len(data)
        self.reads[name] = {'bytes': len(data), 'sha256': sha256(data).hexdigest(),
                            'zip_crc32': '{:08x}'.format(info.CRC), 'full_member_crc_read': True}
        return data

    def load(self, relative):
        return strict_json(self.read(self.prefix + relative))

    def bind(self, label, values):
        if not isinstance(values, dict) or not values:
            raise ValueError('missing nonempty source bindings: ' + label)
        self.binding_groups[label] = values

    def file_hash(self, relative, digest, size=None):
        data = self.read(self.prefix + relative)
        return self.check(relative + ': bytes match receipt',
                          sha256(data).hexdigest() == digest and (size is None or len(data) == size))

    def audit_report(self, key):
        relative, schema, positive = SPECS[key]
        data = self.load(relative)
        if not isinstance(data, dict):
            raise ValueError('result is not an object')
        summary = {name: data[name] for name in ('schema', 'status', 'passed', 'ok', 'error',
                   'close_error', 'failure_details', 'failures', 'errors', 'skipped', 'controls', 'negative_controls',
                   'source_unchanged', 'source_bindings_unchanged', 'sources_unchanged') if name in data}
        self.reports[key] = summary
        self.check(key + ': exact schema', data.get('schema') == schema)
        self.check(key + ': implementation result', data.get(positive) is True)
        self.check(key + ': no top-level error', 'error' not in data and 'close_error' not in data)
        for field in ('source_bindings', 'source_sha256', 'source_identity'):
            if field in data:
                self.bind(key + '/' + field, data[field])
        required_source = {
            'regression': 'source_sha256', 'narrowing_cli': 'source_bindings',
            'ndu_loop': 'source_identity', 'cpp_composed': 'source_bindings',
            'cpp_unique': 'source_bindings', 'cpp_assignment': 'source_bindings',
            'owned_state': 'source_bindings', 'continuation': 'source_sha256',
        }.get(key)
        if required_source:
            self.check(key + ': required source bindings exist',
                       isinstance(data.get(required_source), dict) and bool(data[required_source]))
        required_unchanged = {
            'regression': 'source_unchanged', 'narrowing_cli': 'source_unchanged',
            'narrowing': 'source_unchanged', 'cpp_composed': 'source_bindings_unchanged',
            'cpp_unique': 'source_bindings_unchanged', 'cpp_assignment': 'source_bindings_unchanged',
            'owned_state': 'source_bindings_unchanged', 'assembly': 'sources_unchanged',
        }.get(key)
        if required_unchanged:
            self.check(key + ': required unchanged binding', data.get(required_unchanged) is True)
        for field in ('source_unchanged', 'source_bindings_unchanged', 'sources_unchanged'):
            if field in data:
                self.check(key + ': ' + field, data[field] is True)
        if 'controls' in data:
            controls = data['controls']
            self.check(key + ': all controls present and true',
                       isinstance(controls, dict) and bool(controls) and all(v is True for v in controls.values()), controls)
        if 'compiler_sha256' in data:
            self.compiler_bindings[key] = data['compiler_sha256']
        if key == 'regression':
            summary.update({name: data[name] for name in ('git_base', 'git_worktree_status', 'tests', 'modules')})
            self.regression_modules = data['modules']
            self.check('regression: expected commit', data['git_base'] == self.options.commit)
            self.check('regression: actual tests, no failure/error/skip',
                       type(data['tests']) is int and data['tests'] > 0 and data['failures'] == 0
                       and data['errors'] == 0 and data['skipped'] == [] and data['failure_details'] == [])
            self.check('regression: no tracked worktree changes',
                       all(line.startswith('?? ') for line in data['git_worktree_status'].splitlines()),
                       data['git_worktree_status'])
            log_bytes = self.read(self.prefix + 'regression/tests.log')
            self.check('regression: full actual test log SHA', sha256(log_bytes).hexdigest() == data['log_sha256'])
            self.regression_log = log_bytes.decode('utf-8', errors='strict')
            plan = self.load('regression/plan.json')
            self.check('regression: result preserves entire plan', all(data.get(k) == v for k, v in plan.items()))
        elif key in ('guarded_cli', 'narrowing_cli', 'narrowing'):
            observations = data['native_observations']
            count = {'guarded_cli': 36, 'narrowing_cli': 56, 'narrowing': 288}[key]
            summary['observations'] = len(observations)
            summary['failed_observations'] = [row for row in observations if row['actual'] != row['expected']]
            self.check(key + ': complete actual native observations', len(observations) == count
                       and all(row['actual'] == row['expected'] for row in observations))
            if key == 'guarded_cli':
                self.check(key + ': timeout never published', data['timeout_never_published'] is True)
                self.file_hash('guarded-cli/candidate.so', data['native_artifact_sha256'])
            elif key == 'narrowing_cli':
                self.check(key + ': timeout/unknown never published', data['timeout_and_unknown_never_published'] is True)
                for label in ('scalar', 'guarded'):
                    verification, native = data[label]['verification'], data[label]['build']['native']
                    self.check(key + '/' + label + ': exact proved Core', verification['status'] == 'verified'
                               and verification['candidate_sha256'] == native['core_sha256'])
                    self.file_hash('narrowing-cli/' + label + '.so', native['artifact_sha256'], native['artifact_bytes'])
            else:
                plan = self.load('narrowing/plan.json')
                self.bind('narrowing/plan', plan['source_bindings'])
                self.file_hash('narrowing/plan.json', data['plan_sha256'])
                self.check('narrowing: tools unchanged', data['tools_unchanged'] is True)
        elif key == 'ndu_loop':
            for name in ('all_actual_outputs_correct', 'all_actual_budgets_passed'):
                self.check('ndu_loop: ' + name, data[name] is True)
            self.check('ndu_loop: every recorded episode admitted', bool(data['episodes'])
                       and all(row['completion_admitted'] is True for row in data['episodes']))
            self.check('ndu_loop: no safety authority', data['authority'] == 'DENY_ALL'
                       and data['safety_from_ndu_claim'] is False)
            summary.update({name: data[name] for name in ('all_actual_outputs_correct', 'all_actual_budgets_passed',
                             'statistical_superiority_established', 'ndu_descriptive_cost_lower_than_selected_fixed',
                             'ndu_descriptive_cost_lower_than_light', 'native_identity', 'native_binary_sha256')})
            summary['episode_count'] = len(data['episodes'])
            summary['failed_episodes'] = [row for row in data['episodes'] if row['completion_admitted'] is not True]
        elif key.startswith('cpp_') and key != 'cpp_scoped':
            self.cpp_variants(key, relative.rsplit('/', 1)[0], data, summary)
        elif key == 'owned_state':
            ledger = data['final_native_ledger']
            self.check('owned_state: owner resources balanced', ledger['live'] == 0 and ledger['allocations'] == ledger['frees'])
            self.check('owned_state: performance not requested', data['performance']['status'] == 'not_requested')
            summary['final_native_ledger'] = ledger
        elif key == 'continuation':
            self.continuation(data, summary)
        elif key == 'assembly':
            self.assembly(data, summary)

    def cpp_variants(self, key, base, data, summary):
        variants = data['variants']
        self.check(key + ': both actual configurations', len(variants) == 2
                   and {row['name'] for row in variants} == {'three_weight', 'five_weight'})
        self.check(key + ': all declared builds executed', data['claims']['all_builds_in_declared_matrix_executed'] is True)
        summary['variants'] = []
        for row in variants:
            name, migration, native = row['name'], row['migration'], row['standalone_hia']
            expected = row['expected']
            reference = strict_json(row['reference']['execution']['stdout'])
            actual = strict_json(native['execution']['stdout'])
            self.check(key + '/' + name + ': native oracle agreement',
                       actual == expected == reference and expected['ok'] is True and expected['cases'] > 0
                       and row['reference']['execution']['returncode'] == native['execution']['returncode'] == 0
                       and expected['live'] == 0
                       and expected['allocations'] == expected['frees']
                       and expected['cases'] == row['case_count'])
            self.check(key + '/' + name + ': concrete migration and no C++ target bridge',
                       migration['unconverted_declarations'] == []
                       and migration['translation_statistics']['cross_unit_owner_transfers'] > 0
                       and native['original_cpp_link_inputs'] == [])
            self.file_hash(base + '/' + name + '/hia-native', native['artifact']['sha256'], native['artifact']['bytes'])
            missing = data['negative_controls'][name + '_missing_drop']
            self.check(key + '/' + name + ': missing drop never published',
                       missing['rejected'] is True and missing['artifact_exists'] is False)
            self.check(key + '/' + name + ': no missing-drop object in ZIP',
                       self.prefix + base + '/' + name + '/unreleased.o' not in self.infos)
            saved = {'name': name, 'case_count': row['case_count'], 'expected': expected,
                     'reference': reference, 'actual': actual, 'missing_drop': missing}
            if key in ('cpp_unique', 'cpp_assignment'):
                self.check(key + '/' + name + ': complete declaration accounting',
                           migration['claims']['all_captured_active_declarations_accounted_for'] is True
                           and migration['active_declaration_count'] == sum(
                               item['status'] != 'compiler_implicit_declaration' for item in migration['declarations'])
                           and migration['standard_library_declaration_count'] == len(migration['standard_library_declarations']))
                saved['migration_accounting'] = migration['migration_accounting']
                saved['active_declaration_count'] = migration['active_declaration_count']
                saved['standard_library_dependency_count'] = migration['standard_library_declaration_count']
            if key == 'cpp_assignment':
                controls = data['negative_controls'][name + '_wrong_assignment_cleanup_order']
                wrong = strict_json(controls['execution']['stdout'])
                self.check(key + '/' + name + ': actual wrong-order lifecycle detected',
                           controls['resource_check_passed'] is True and controls['detected'] is True
                           and controls['scope'] == 'deliberately_mutated_qualification_fixture'
                           and controls['execution']['returncode'] == 3
                           and wrong.get('ok') is False and wrong.get('failure') == 'lifecycle'
                           and wrong.get('case') == 0 and wrong.get('live') == 0)
                self.file_hash(base + '/' + name + '/wrong-assignment-order', controls['artifact_sha256'])
                self.check(key + '/' + name + ': move assignment and self move actually represented',
                           migration['translation_statistics']['owner_move_assignments'] > 0
                           and migration['translation_statistics']['owner_self_move_assignments'] > 0)
                saved['wrong_order_control'] = {'detected': controls['detected'], 'actual': wrong}
            summary['variants'].append(saved)

    def continuation(self, data, summary):
        prefix, suffix = data['prefix'], data['suffix']
        n = data['cancelled_prefix']
        self.check('continuation: all ten exact controls', set(data['controls']) == CONTINUATION_CONTROLS)
        self.check('continuation: incomplete real prefix and exact suffix', 1 <= n < 40
                   and prefix['status'] == 'cancelled' and prefix['executed_steps'] == n
                   and suffix['status'] == 'completed' and suffix['executed_steps'] == 40 - n
                   and prefix['replayed_steps'] == suffix['replayed_steps'] == 0)
        partial = [11 + 4 * 13 * min(n, 17), 17 + 4 * 7 * max(0, n - 17)]
        self.check('continuation: independent prefix/final oracle',
                   prefix['final_values'] == partial and suffix['final_values'] == [895, 661])
        self.check('continuation: same live owner through actual version change',
                   prefix['owner_id'] == suffix['owner_id']
                   and prefix['allocation_identity'] == suffix['allocation_identity']
                   and prefix['version'] != suffix['version'] and data['switched']['selected'] is True)
        ledger = data['final_native_ledger']
        self.check('continuation: balanced resources and complete costs', ledger['live'] == 0
                   and ledger['allocations'] == ledger['frees']
                   and prefix['cost_accounting_complete'] is True and suffix['cost_accounting_complete'] is True)
        for token, build in data['builds'].items():
            native = build['native']
            self.file_hash('owned-continuation/runtime/' + token + '.so', native['artifact_sha256'], native['artifact_bytes'])
        summary.update(cancelled_prefix=n, prefix=prefix, suffix=suffix, final_native_ledger=ledger)

    def assembly(self, data, summary):
        self.check('assembly: actual native qualification', data['native_requested'] is True
                   and data['status'] == 'qualified_native')
        self.check('assembly: no model success or safety authority inferred',
                   data['model_completion_requests'] == 0 and data['agent_advantage_qualified'] is False
                   and data['deployment_authority'] is False and data['safety_certificate'] is False)
        plan = self.load('agent-assembly/PLAN.json')
        self.bind('assembly/plan', plan['source_bindings'])
        self.check('assembly: exact two Core/LLVM roundtrips', len(data['representations']) == 2
                   and {row['name'] for row in data['representations']} == {'kernels', 'chain'}
                   and all(row['roundtrip_and_llvm_equal'] is True for row in data['representations']))
        vm, native = data['vm_observations'], data['native_observations']
        self.check('assembly: complete VM observations', len(vm) == 81
                   and all(row['original'] == row['actual'] for row in vm))
        self.check('assembly: all actual native values', len(native) == len(plan['cases']) == 24
                   and all(row['actual'] == row['expected'] for row in native))
        bad = data['negative_control']
        self.check('assembly: unknown instruction has no authority/artifact', bad['accepted'] is False
                   and bad['deployment_authority'] is False and bad['native_artifact_created'] is False)
        for name, identity in data['files'].items():
            if not path_ok(name) or '/' in name:
                raise ValueError('invalid assembly artifact filename')
            self.file_hash('agent-assembly/' + name, identity['sha256'], identity['bytes'])
        receipt = self.load('agent-assembly/native-receipt.json')
        self.file_hash('agent-assembly/kernels.so', receipt['artifact_sha256'], receipt['artifact_bytes'])
        kernel = next(row for row in data['representations'] if row['name'] == 'kernels')
        self.check('assembly: native receipt binds exact Core', receipt['core_sha256'] == kernel['core_sha256'])
        summary.update(vm_observations=len(vm), native_observations=len(native), representations=data['representations'])
        summary['failed_vm_observations'] = [row for row in vm if row['original'] != row['actual']]
        summary['failed_native_observations'] = [row for row in native if row['actual'] != row['expected']]

    def source_audit(self):
        options = self.options
        commit_body = git(options.repository, ['cat-file', 'commit', options.commit])
        actual_commit = sha1(b'commit ' + str(len(commit_body)).encode() + b'\0' + commit_body).hexdigest()
        tree = commit_body.splitlines()[0].decode().removeprefix('tree ')
        self.check('Git: immutable commit object and expected tree', actual_commit == options.commit and tree == options.tree)
        tree_body = git(options.repository, ['cat-file', 'tree', options.tree])
        self.check('Git: exact tree object bytes',
                   sha1(b'tree ' + str(len(tree_body)).encode() + b'\0' + tree_body).hexdigest() == options.tree)
        tracked = {x.decode() for x in git(options.repository,
                   ['ls-tree', '-r', '--name-only', '-z', options.commit]).split(b'\0') if x}
        core_paths = {p for p in tracked if p.startswith('hepta/') and p.count('/') == 1 and p.endswith('.py')}
        all_paths = set(core_paths) | {'tools/qualify_hia_verified_increment.py'}
        for values in self.binding_groups.values():
            all_paths.update(values)
        blobs = read_blobs(options.repository, options.commit, all_paths)
        tree_ast = ast.parse(blobs['tools/qualify_hia_verified_increment.py'])
        modules = next(ast.literal_eval(node.value) for node in tree_ast.body
                       if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in node.targets))
        inventory = next(node for node in tree_ast.body if isinstance(node, ast.FunctionDef) and node.name == 'inventory')
        folders = next(ast.literal_eval(node.iter) for node in inventory.body
                       if isinstance(node, ast.For) and isinstance(node.target, ast.Name) and node.target.id == 'folder')
        expected_paths = set(core_paths) | {p for p in tracked if p.startswith('tools/') and p.endswith('.py')}
        for folder in folders:
            for p in tracked:
                if str(PurePosixPath(p).parent) == folder and PurePosixPath(p).suffix in ('.py', '.json', '.h', '.cpp', '.c'):
                    if (not folder.startswith('experiments/') or PurePosixPath(p).suffix in ('.py', '.c')
                            or PurePosixPath(p).name in ('PROTOCOL.json', 'FIXTURES.json', 'REGISTRATION.json', 'ADMISSION_CONTROLS.json')):
                        expected_paths.add(p)
        expected_paths.update(name.replace('.', '/') + '.py' for name in modules)
        regression = self.binding_groups.get('regression/source_sha256', {})
        self.check('regression: all exact declared test modules', self.regression_modules == list(modules))
        self.check('regression: complete expected source inventory', set(regression) == expected_paths,
                   {'missing': sorted(expected_paths - set(regression)), 'extra': sorted(set(regression) - expected_paths)})
        mandatory_modules = ('tests.test_hia_continuation', 'tests.test_hia_agent_assembly',
                             'tests.test_cpp_unique_assignment_project', 'tests.test_hia_round4_routes',
                             'tests.test_hia_ndu_sealed_identity', 'tests.test_hia_ndu_session_cost')
        for module in mandatory_modules:
            file_ast = ast.parse(blobs[module.replace('.', '/') + '.py'])
            expected_test_ids = []
            for cls in file_ast.body:
                if isinstance(cls, ast.ClassDef):
                    for method in cls.body:
                        if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'):
                            expected_test_ids.append((method.name, module + '.' + cls.name + '.' + method.name))
            missing_tests = [test_id for method, test_id in expected_test_ids
                             if not re.search(r'^' + re.escape(method) + r' \(' + re.escape(test_id)
                                              + r'\) \.\.\. ok$', self.regression_log, re.MULTILINE)]
            self.check(module + ': each declared new control actually logged ok',
                       bool(expected_test_ids) and not missing_tests,
                       {'declared_tests': len(expected_test_ids), 'missing_or_not_ok': missing_tests})
        rows = {}
        for label, values in self.binding_groups.items():
            differences = []
            for name, recorded in values.items():
                body = blobs[name]
                digest = recorded if isinstance(recorded, str) else recorded['sha256']
                if sha256(body).hexdigest() != digest or (isinstance(recorded, dict) and recorded.get('bytes', len(body)) != len(body)):
                    differences.append(name)
            self.check(label + ': all source bytes match immutable commit', not differences,
                       {'count': len(values), 'different': differences})
            rows[label] = {'count': len(values), 'different': differences}
        compiler = sha256()
        for name in sorted(core_paths):
            compiler.update(PurePosixPath(name).name.encode() + b'\0' + blobs[name] + b'\0')
        for label, recorded in self.compiler_bindings.items():
            self.check(label + ': whole compiler source identity', recorded == compiler.hexdigest())
        return {'commit': actual_commit, 'commit_tree': tree, 'compiler_sha256': compiler.hexdigest(), 'bindings': rows,
                'direct_ci_tree_receipt_present': self.ci_tree['availability'] == 'present',
                'direct_ci_tree_receipt_verified': self.ci_tree['verified'],
                'scope': 'CI source-sha/git_base and bounded source bindings plus immutable Git objects; direct CI tree receipt separately checked when present'}

    def run(self):
        source = {}
        archive_sha = sha256()
        fd = os.open(self.options.zip, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            observed = os.fstat(stream.fileno())
            if not stat.S_ISREG(observed.st_mode):
                raise ValueError('ZIP is not a regular file')
            def fingerprint(item):
                return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            before = fingerprint(observed)
            while chunk := stream.read(1024 * 1024):
                archive_sha.update(chunk)
            if fingerprint(os.fstat(stream.fileno())) != before:
                raise ValueError('ZIP changed while hashing')
        self.archive_file_bytes = observed.st_size
        self.archive_sha = archive_sha.hexdigest()
        if self.options.archive_sha256:
            self.check('downloaded ZIP matches external expected SHA256', self.archive_sha == self.options.archive_sha256)
        with zipfile.ZipFile(self.options.zip) as archive:
            if fingerprint(os.fstat(archive.fp.fileno())) != before:
                raise ValueError('ZIP identity changed between digest and member reads')
            self.zip = archive
            infos = archive.infolist()
            self.check('ZIP: unique member names', len(infos) == len({i.filename for i in infos}))
            for info in infos:
                name = info.filename.rstrip('/') if info.is_dir() else info.filename
                if (not path_ok(name) or info.flag_bits & 1
                        or stat.S_ISLNK(info.external_attr >> 16)):
                    raise ValueError('unsafe, encrypted or symbolic ZIP member: ' + info.filename)
            self.infos = {i.filename: i for i in infos}
            root_member = self.unique_suffix(ROOT_SUFFIX)
            self.prefix = root_member[:-len('source-sha.txt')]
            actual_sha = self.read(root_member).decode('ascii').strip()
            self.check('actual source-sha.txt matches expected commit', actual_sha == self.options.commit)
            try:
                self.audit_ci_tree()
            except Exception as error:
                self.check('direct CI source-tree receipt audit', False,
                           {'type': type(error).__name__, 'message': str(error)})
            for key in SPECS:
                try:
                    self.audit_report(key)
                except Exception as error:
                    failure = {'type': type(error).__name__, 'message': str(error)}
                    self.reports.setdefault(key, {})['audit_error'] = failure
                    self.check(key + ': complete required report audit', False, failure)
            try:
                member = self.unique_suffix('hia-ndu/identity.json')
                manifest = strict_json(self.read(member))
                identity = manifest['identity']
                self.check('NDU identity: advisory authority only', identity['authority'] == 'DENY_ALL'
                           and identity['safety_certificate'] is False)
                loop = self.reports.get('ndu_loop', {})
                self.check('NDU identity: loop binds the actually uploaded manifest',
                           identity == loop.get('native_identity')
                           and manifest['binary_sha256'] == loop.get('native_binary_sha256'))
                self.audit_ndu_elf(manifest)
                self.reports['native_ndu_manifest'] = {'member': member, 'identity': identity,
                    'binary_sha256': manifest['binary_sha256'],
                    'native_binary_body_verified': self.ndu_elf['verified'], 'native_binary': self.ndu_elf}
            except Exception as error:
                self.check('NDU identity: retained actual manifest', False,
                           {'type': type(error).__name__, 'message': str(error)})
            try:
                source = self.source_audit()
            except Exception as error:
                self.check('complete source/commit/tree correlation', False,
                           {'type': type(error).__name__, 'message': str(error)})
            self.inventory = {'members': len(infos), 'uncompressed_bytes': sum(i.file_size for i in infos),
                              'prefix_observed': self.prefix, 'source_sha_observed': actual_sha}
            self.check('ZIP: identity unchanged throughout all selected reads',
                       fingerprint(os.fstat(archive.fp.fileno())) == before)
        return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--tree', required=True)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--archive-sha256', help='Optional independently obtained GitHub artifact digest')
    parser.add_argument('--require-final-byte-evidence', action='store_true',
                        help='Final mode: require actual CI source-tree.txt and uploaded native NDU ELF bytes. '
                             'Without this flag, legacy checkpoint mode marks absent evidence unavailable.')
    parser.add_argument('--execute', action='store_true')
    options = parser.parse_args()
    if not options.execute:
        parser.error('--execute required; wait until model work has ended')
    if not all(re.fullmatch('[0-9a-f]{40}', value) for value in (options.commit, options.tree)):
        parser.error('commit/tree must be exact lowercase SHA-1 IDs')
    if options.archive_sha256 and not re.fullmatch('[0-9a-f]{64}', options.archive_sha256):
        parser.error('artifact SHA256 must be exact lowercase digest')
    if os.path.lexists(options.output):
        parser.error('output exists; all prior attempts must be retained')
    audit = Audit(options)
    started = time.monotonic_ns()
    source = {}
    try:
        source = audit.run()
    except Exception as error:
        audit.check('ZIP evidence admission/read completed', False,
                    {'type': type(error).__name__, 'message': str(error)})
    failures = [row for row in audit.checks if not row['passed']]
    output = {'schema': 'hepta.hia.round4.readonly-ci-artifact-audit.v1',
              'recorded_utc': datetime.now(timezone.utc).isoformat(),
              'evidence_mode': ('final-byte-evidence' if options.require_final_byte_evidence
                                else 'legacy-source-checkpoint'),
              'final_byte_evidence_required': options.require_final_byte_evidence,
              'final_byte_evidence_verified': audit.ci_tree['verified'] and audit.ndu_elf['verified'],
              'actual_ci_tree_receipt': audit.ci_tree, 'actual_native_ndu_elf': audit.ndu_elf,
              'expected_commit': options.commit, 'expected_tree': options.tree,
              'archive': {'path': str(options.zip), 'sha256': getattr(audit, 'archive_sha', None),
                          'bytes': getattr(audit, 'archive_file_bytes', None),
                          'external_digest_supplied': options.archive_sha256 is not None,
                          'inventory': getattr(audit, 'inventory', None)},
              'passed': bool(audit.checks) and not failures, 'checks': audit.checks, 'failures': failures,
              'reports': audit.reports, 'source': source, 'member_reads': audit.reads,
              'selected_expanded_bytes_read': audit.expanded_read_bytes,
              'audit_wall_ns': time.monotonic_ns() - started,
              'audit_script_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
              'scope': {'archive_programs_executed': False, 'files_extracted': False,
                        'whole_zip_testzip_called': False, 'all_member_bodies_read': False,
                        'native_or_model_or_solver_reexecuted': False, 'deployment_authority': False,
                        'run_or_job_terminal_status_verified': False,
                        'scientific_performance_or_agent_acceptance_changed': False,
                        'direct_ci_tree_receipt_available': audit.ci_tree['availability'] == 'present',
                        'actual_native_ndu_elf_available': audit.ndu_elf['availability'] == 'present'}}
    with options.output.open('xb') as stream:
        stream.write((json.dumps(output, indent=2, sort_keys=True, allow_nan=False) + '\n').encode())
    print(json.dumps({'passed': output['passed'], 'evidence_mode': output['evidence_mode'],
                      'final_byte_evidence_verified': output['final_byte_evidence_verified'],
                      'checks': len(audit.checks), 'failures': len(failures),
                      'output': str(options.output), 'sha256': sha256(options.output.read_bytes()).hexdigest()}))
    return 0 if output['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
