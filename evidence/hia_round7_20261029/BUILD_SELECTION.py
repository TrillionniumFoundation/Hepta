#!/usr/bin/env python3
"""Inventory explicit public round-seven inputs; freeze only after owner review.

Default mode writes a new preflight report, never INPUT_SELECTION.json. Future
--freeze requires the exact approved preflight hash and an unchanged rescan.
Only the three declared data roots are scanned. No network, project tests,
packager, or archived program is executed. Private quarantine paths are never
traversed; any denied identity discovered under a public root blocks freezing.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
BASE = Path(os.path.abspath(__file__)).parent
WORKSPACE = BASE.parent
REPO = WORKSPACE / 'hepta-round6-integration'
ROOTS = {'evidence': WORKSPACE / 'round7-evidence',
         'guarded-development': WORKSPACE / 'round7-guarded-development',
         'resource-review': WORKSPACE / 'round7-resource-review'}
FINAL = 'e57f440c32b54ffc8da795370fc288652f3c3319'
FINAL_TREE = 'c5f098feb0cd1d9e465a364088b49f2568ceea31'
INITIAL = 'e6b10e9b74c6585f9dba18a78a31cf8f36c071c5'
INITIAL_TREE = '18d5689f68baa2b1e0c496b1ee097adffe43ae39'
FINAL_PREFIX = 'by-source/' + FINAL
PUBLIC_REPO = 'TrillionniumFoundation/Hepta'
API = 'https://api.github.com/repos/' + PUBLIC_REPO
VERIFIED_WORKFLOW = '.github/workflows/hepta-verified-optimization.yml'
EXPECTED_ZIPS = 32
REQUIRED_OWNER_SUMMARIES = ('publication/final-summary.json', 'publication/final-summary.md')

spec = importlib.util.spec_from_file_location('selection_archive_reader', BASE / 'RESTORE.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(path):
    data = reader.read_regular(path.parent, path.name)
    return {'path': str(path), 'bytes': len(data), 'sha256': digest(data)}


def source_state():
    def git(*argv):
        return subprocess.check_output(['git', '-C', str(REPO), *argv], text=True).strip()
    return {'head': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'status': git('status', '--porcelain=v1', '--untracked-files=all')}


def local_output(path):
    path = Path(os.path.abspath(path))
    reader.require(path.is_relative_to(BASE) and path != BASE, 'output must be under round7-publication')
    return path


def write_new(path, value):
    data = wire(value)
    with reader.new_file(path.parent, path.name) as output:
        output.write(data)
    return {'path': str(path), 'bytes': len(data), 'sha256': digest(data)}


def group(group_id, kind, description, source=None, tree=None, status='not-qualification'):
    return {'id': group_id, 'kind': kind, 'source_commit': source, 'source_tree': tree,
            'qualification_status': status, 'description': description}


def group_definitions():
    result = {}
    for tag, source, tree, kind in [('e6', INITIAL, INITIAL_TREE, 'historical-execution'),
                                    ('e57', FINAL, FINAL_TREE, 'final-source-execution')]:
        for suffix, description in [
            ('local', 'Local focused/Rust, C post-test, migration and frozen guarded execution at this exact source. Valid negative guarded economics are preserved and do not establish NDU gain.'),
            ('public-hosts', 'Public native C ABI, C++ reuse and migration workflow collection at this exact source; all raw metadata, earlier collection observations and diagnostics remain intact.'),
            ('core-six', 'Public six-outcome workflow execution and its original artifact at this exact source. The initial e6 IR-PGO SIGILL failure is preserved as failed execution, not reattributed to the repair.'),
            ('core-verified', 'Public allowlisted members and public metadata from the verified workflow at this exact source. Its whole original ZIP and private bridge/source payloads are forbidden.'),
            ('core-integrated', 'Public integrated qualification workflow execution, metadata, original ZIP and audits at this exact source.')]:
            key = tag + '-' + suffix
            result[key] = group(key, kind, description, source, tree, 'incomplete')
    for key, component, description in [
        ('development-local', 'development', 'Early local toolchain/build, workflow and matrix diagnostics span development worktrees; no single clean qualified source identity applies, so both source fields are null.'),
        ('development-resource', 'development', 'Resource implementation development controls include intermediate/dirty worktrees and diagnostic attempts; both source fields are null and these are not final-source qualification.'),
        ('development-migration', 'development', 'C migration development controls include initial failures, libclang setup and dirty-source refusals; source/tree are null because they span intermediate worktrees.'),
        ('development-guarded', 'development', 'Guarded optimization development, proof/partition and transport/cost diagnostics predate the final frozen campaign; mixed intermediate worktrees have no single qualified source identity, so both source fields are null.'),
        ('development-repair', 'development', 'IR-PGO repair development was executed in a dirty worktree over e6 before publication/amendment; reports retain their actual identities. It must not be counted as e57 qualification, so group source/tree are null.'),
        ('reviews', 'review', 'Cross-source independent reviews, original-failure inspection, historical public readback excerpts and synthetic archive-tooling controls. These are authored reviews, not execution qualification by one source; both source fields are null. Synthetic manifests/run IDs are explicitly fictional data controls.'),
        ('resource-review', 'review', 'Independent resource/origin review and exploration; it is not a source qualification run and has no single qualified source identity, so both source fields are null.'),
        ('publication-metadata', 'publication-metadata', 'Public registration, source/repair plans and receipts, PR text, CI observations and owner summaries span e6/e57/history. Both source fields are null; this group is not project execution.'),
        ('toolchain-provenance', 'toolchain-receipt', 'Public signed distribution metadata, compiler/Rust/QEMU installation receipts and environment descriptions; setup provenance is not project qualification and has no project source identity, so both source fields are null.')]:
        result[key] = group(key, component, description, status='mixed' if component == 'development' else 'not-qualification')
    return result


def classify(component, relative):
    if component == 'guarded-development':
        return 'development-guarded'
    if component == 'resource-review':
        return 'resource-review'
    prefixes = [('final-source/', 'e6-local'), ('ci-public-hosts/', 'e6-public-hosts'),
        ('ci-core/six-initial/', 'e6-core-six'), ('ci-core/verified-initial/', 'e6-core-verified'),
        ('ci-core/integrated-initial/', 'e6-core-integrated'),
        (FINAL_PREFIX + '/ci-public-hosts/', 'e57-public-hosts'),
        (FINAL_PREFIX + '/ci-core/six/', 'e57-core-six'),
        (FINAL_PREFIX + '/ci-core/verified/', 'e57-core-verified'),
        (FINAL_PREFIX + '/ci-core/integrated/', 'e57-core-integrated'),
        (FINAL_PREFIX + '/reviews/', 'reviews'),
        ('local/', 'development-local'), ('resource/', 'development-resource'),
        ('migration/', 'development-migration'), ('repair-development/', 'development-repair'),
        ('reviews/', 'reviews'), ('publication/', 'publication-metadata'),
        ('toolchain-provenance/', 'toolchain-provenance')]
    for prefix, label in prefixes:
        if relative.startswith(prefix):
            return label
    if relative.startswith(FINAL_PREFIX + '/'):
        remainder = relative[len(FINAL_PREFIX) + 1:]
        if remainder.split('/')[0] in {'c-posttest', 'focused', 'guarded-opportunity', 'migration-tests'}:
            return 'e57-local'
        if remainder in {'guarded-opportunity-command.json', 'guarded-opportunity.log',
                          'migration-harness-command.json', 'migration-harness.stderr.log',
                          'migration-harness.stdout.log', 'run-migration-tests.py'}:
            return 'e57-local'
    return None


def denied_path(relative):
    parts = Path(relative).parts
    if any(part.casefold() == '.git' or any(token in part.casefold() for token in reader.FORBIDDEN)
           for part in parts):
        return 'private directory marker or Git-control path; not traversed/read'
    if relative.casefold().endswith('.zip') and 'verified' in relative.casefold():
        return 'whole verified-workflow ZIP is forbidden; bytes not read'
    return None


def path_snapshot():
    """Walk only the three input roots, never following directory symlinks."""
    nodes, excluded, special = {}, [], []
    for component, root in ROOTS.items():
        with reader.directory_fd(root):
            pass
        for directory, directories, files in os.walk(root, followlinks=False):
            kept = []
            for name in sorted(directories):
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                reason = denied_path(relative)
                if reason:
                    excluded.append({'component': component, 'relative': relative, 'reason': reason, 'directory': True})
                    continue
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode):
                    special.append({'component': component, 'relative': relative, 'mode': info.st_mode,
                                    'reason': 'directory entry is a symlink or special path; not followed'})
                else:
                    kept.append(name)
            directories[:] = kept
            for name in sorted(files):
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                reason = denied_path(relative)
                if reason:
                    excluded.append({'component': component, 'relative': relative, 'reason': reason, 'directory': False})
                    continue
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    special.append({'component': component, 'relative': relative, 'mode': info.st_mode,
                                    'nlink': info.st_nlink, 'reason': 'not a single-link regular file; not read'})
                    continue
                nodes[(component, relative)] = (info.st_dev, info.st_ino, info.st_mode,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    return nodes, excluded, special


class Inventory:
    def __init__(self):
        self.groups = group_definitions()
        self.files, self.by_relative, self.zip_content = [], {}, set()
        self.gaps, self.unclassified, self.path_errors, self.read_errors = [], [], [], []
        self.zip_bindings, self.run_bindings, self.verified_member_bindings = [], [], []
        self.private_identities, self.private_payload_findings = {}, []
        self.metadata_cache = {}

    def gap(self, code, **details):
        self.gaps.append({'code': code, **details})

    def scan(self, nodes):
        names = reader.Namespace()
        for (component, relative), initial in sorted(nodes.items()):
            label = classify(component, relative)
            if label is None:
                self.unclassified.append({'component': component, 'relative': relative,
                    'bytes': initial[4], 'decision': 'owner must explicitly assign provenance; not selected'})
                continue
            archive_path = component + '/' + relative
            try:
                reader.safe_name(relative)
                names.add(archive_path)
            except Exception as error:
                self.path_errors.append({'path': archive_path, 'error': str(error)})
                continue
            try:
                reader.require(initial[4] <= reader.MAX_FILE, 'file exceeds archive reader size bound')
                with reader.regular_file(ROOTS[component], relative) as stream:
                    before = reader.stat_identity(stream)
                    reader.require(before == initial, 'input changed since path snapshot')
                    size, sha = reader.hashed_copy(stream, limit=initial[4])
                    stream.seek(0)
                    content_is_zip = zipfile.is_zipfile(stream)
                    reader.require(reader.stat_identity(stream) == before, 'input changed during hash/ZIP detection')
                row = {'component': component, 'relative': relative, 'archive_path': archive_path,
                       'bytes': size, 'sha256': sha, 'evidence_input': label}
                self.files.append(row)
                if component == 'evidence':
                    self.by_relative[relative] = row
                if content_is_zip or relative.casefold().endswith('.zip'):
                    self.zip_content.add(archive_path)
                    if not content_is_zip:
                        self.gap('zip_extension_but_invalid_zip', path=archive_path)
            except Exception as error:
                self.read_errors.append({'path': archive_path, 'error': type(error).__name__ + ': ' + str(error)})

    def load(self, relative, *, required=True):
        if relative in self.metadata_cache:
            return self.metadata_cache[relative]
        row = self.by_relative.get(relative)
        if row is None:
            if required:
                self.gap('missing_required_metadata', path='evidence/' + relative)
            return None
        try:
            raw = reader.read_regular(ROOTS['evidence'], relative)
            reader.verify_identity(len(raw), digest(raw), row, relative)
            value = reader.json_value(raw)
            self.metadata_cache[relative] = value
            return value
        except Exception as error:
            self.gap('metadata_read_or_identity_error', path='evidence/' + relative, error=str(error))
            return None

    def metadata_identity(self, relative):
        row = self.by_relative[relative]
        return {key: row[key] for key in ('archive_path', 'bytes', 'sha256')}

    def validate_run(self, relative, source, tree, workflow):
        run = self.load(relative)
        if run is None:
            return None
        try:
            reader.integer(run.get('id'), 1, 2**63 - 1, 'run ID')
            reader.integer(run.get('run_attempt'), 1, 1000, 'run attempt')
            reader.require(run.get('head_sha') == source and run.get('path') == workflow,
                           'run source or workflow path differs')
            reader.require(run.get('head_commit', {}).get('id') == source
                           and run['head_commit'].get('tree_id') == tree, 'run exact commit/tree differs')
            repository = run.get('repository', {})
            reader.require(repository.get('full_name') == PUBLIC_REPO and repository.get('private') is False,
                           'run is not declared from the public Hepta repository')
            reader.require(run.get('url') == API + '/actions/runs/' + str(run['id']), 'run API identity differs')
            if run.get('status') != 'completed':
                self.gap('run_not_complete', path=relative, run_id=run['id'], status=run.get('status'))
            self.run_bindings.append({'metadata': self.metadata_identity(relative), 'run_id': run['id'],
                'run_attempt': run['run_attempt'], 'workflow_path': workflow, 'source_commit': source,
                'source_tree': tree, 'status': run.get('status'), 'conclusion': run.get('conclusion')})
            return run
        except Exception as error:
            self.gap('invalid_run_provenance', path=relative, error=str(error))
            return None

    def artifacts(self, relative, run):
        record = self.load(relative)
        if record is None or run is None:
            return []
        try:
            items = record.get('artifacts')
            reader.require(isinstance(items, list) and record.get('total_count') == len(items),
                           'artifact metadata incomplete or paginated')
            ids = set()
            for artifact in items:
                aid = reader.integer(artifact.get('id'), 1, 2**63 - 1, 'artifact ID')
                reader.require(aid not in ids, 'duplicate artifact ID in metadata')
                ids.add(aid)
                reader.integer(artifact.get('size_in_bytes'), 1, reader.MAX_FILE, 'original artifact bytes')
                reader.require(isinstance(artifact.get('digest'), str)
                    and re.fullmatch(r'sha256:[0-9a-f]{64}', artifact['digest']), 'actual API artifact SHA required')
                workflow_run = artifact.get('workflow_run', {})
                reader.require(workflow_run.get('id') == run['id'] and workflow_run.get('head_sha') == run['head_sha']
                    and workflow_run.get('repository_id') == run['repository']['id']
                    and workflow_run.get('head_repository_id') == run['repository']['id'], 'artifact/run/source binding differs')
                reader.require(artifact.get('url') == API + '/actions/artifacts/' + str(aid)
                    and artifact.get('archive_download_url') == API + '/actions/artifacts/' + str(aid) + '/zip',
                    'artifact API paths differ')
            return items
        except Exception as error:
            self.gap('invalid_artifact_metadata', path=relative, error=str(error))
            return []

    def bind_zip(self, relative, index_path, artifact, run, profile, source, tree, metadata_path):
        row = self.by_relative.get(relative)
        index = self.load(index_path)
        if row is None:
            self.gap('missing_original_public_zip', path=relative, artifact_id=artifact['id'])
            return
        try:
            reader.require(row['archive_path'] in self.zip_content and index is not None, 'ZIP content or collection index missing')
            reader.require(row['sha256'] == artifact['digest'][7:] and row['bytes'] == artifact['size_in_bytes'],
                           'actual ZIP size/SHA differs from saved public artifact metadata')
            z = index.get('zip', index)
            indexed_sha = z.get('sha256', z.get('zip_sha256'))
            indexed_size = z.get('bytes', z.get('zip_bytes'))
            indexed_id = index.get('artifact_id', index.get('artifact', {}).get('id'))
            reader.require(indexed_sha == row['sha256'] and indexed_size == row['bytes']
                           and indexed_id == artifact['id'], 'collection index ZIP identity differs')
            if 'zip' in index:
                reader.require(relative.endswith('/' + z['path']), 'collection index local ZIP path differs')
            reader.require(index.get('source_commit', source) == source, 'collection index source differs')
            descriptor = {'archive_path': row['archive_path'], 'artifact_id': artifact['id'],
                'run_id': run['id'], 'run_attempt': run['run_attempt'], 'workflow_profile': profile,
                'workflow_path': run['path'], 'source_commit': source, 'source_tree': tree}
            self.zip_bindings.append({'descriptor': descriptor, 'actual_zip': self.metadata_identity(relative),
                'artifact_metadata': self.metadata_identity(metadata_path), 'collection_index': self.metadata_identity(index_path),
                'artifact_name': artifact.get('name'), 'github_digest': artifact['digest'],
                'github_size_in_bytes': artifact['size_in_bytes'], 'matches_saved_public_metadata': True,
                'inner_zip_members_reverified_by_this_preflight': False})
        except Exception as error:
            self.gap('zip_provenance_gap', path=relative, artifact_id=artifact['id'], error=str(error))

    @staticmethod
    def run_status(runs):
        if not runs or any(run is None or run.get('status') != 'completed' for run in runs):
            return 'incomplete'
        values = {run.get('conclusion') for run in runs}
        if values == {'success'}:
            return 'passed'
        if values == {'failure'}:
            return 'failed'
        return 'mixed'

    def hosts(self, tag, prefix, source, tree):
        runs = []
        for profile, expected_count in [('native-hosts', 7), ('cpp-upstream-hosts', 7), ('migration', 0)]:
            workflow = reader.PUBLIC_WORKFLOWS[profile]
            candidates = []
            for relative in self.by_relative:
                if re.fullmatch(re.escape(prefix) + r'/metadata/final/run-[0-9]+\.json', relative):
                    value = self.load(relative)
                    if isinstance(value, dict) and value.get('path') == workflow:
                        candidates.append(relative)
            if len(candidates) != 1:
                self.gap('missing_or_ambiguous_final_host_run', group=tag + '-public-hosts',
                         workflow=workflow, metadata_candidates=candidates)
                runs.append(None)
                continue
            relative = candidates[0]
            run = self.validate_run(relative, source, tree, workflow)
            runs.append(run)
            metadata_path = relative[:-5] + '-artifacts.json'
            artifacts = self.artifacts(metadata_path, run)
            if len(artifacts) != expected_count:
                self.gap('host_artifact_count', profile=profile, source=source,
                         expected=expected_count, actual=len(artifacts))
            for artifact in artifacts:
                aid = str(artifact['id'])
                self.bind_zip(prefix + '/zips/artifact-' + aid + '.zip',
                    prefix + '/indexes/artifact-' + aid + '.json', artifact, run, profile, source, tree, metadata_path)
        self.groups[tag + '-public-hosts']['qualification_status'] = self.run_status(runs)

    def core(self, tag, profile, prefix, source, tree):
        candidates = [name for name in self.by_relative if name == prefix + '/run.json'
                      or re.fullmatch(re.escape(prefix) + r'/run-[0-9]+-run\.json', name)]
        if len(candidates) != 1:
            self.gap('missing_or_ambiguous_final_core_run', group=tag + '-core-' + profile,
                     metadata_candidates=candidates)
            return
        relative = candidates[0]
        workflow = VERIFIED_WORKFLOW if profile == 'verified' else reader.PUBLIC_WORKFLOWS[
            'six-outcome' if profile == 'six' else profile]
        run = self.validate_run(relative, source, tree, workflow)
        self.groups[tag + '-core-' + profile]['qualification_status'] = self.run_status([run])
        if tag == 'e6' and run:
            expected_conclusion = 'failure' if profile == 'six' else 'success'
            if run.get('conclusion') != expected_conclusion:
                self.gap('historical_core_outcome_differs', path=relative, expected=expected_conclusion,
                         actual=run.get('conclusion'))
        metadata_path = prefix + '/artifacts.json' if relative.endswith('/run.json') else relative[:-9] + '-artifacts.json'
        artifacts = self.artifacts(metadata_path, run)
        if len(artifacts) != 1:
            self.gap('core_artifact_count', group=tag + '-core-' + profile, expected=1, actual=len(artifacts))
            return
        if profile != 'verified':
            self.bind_zip(prefix + '/original.zip', prefix + '/ZIP_INDEX.json', artifacts[0], run,
                          'six-outcome' if profile == 'six' else profile, source, tree, metadata_path)
            return
        allow_path = prefix + '/PUBLIC_EXTRACTION_ALLOWLIST.json'
        allow, receipt = self.load(allow_path), self.load(prefix + '/EXTRACTION_RECEIPT.json')
        if allow is None or receipt is None:
            return
        try:
            artifact = artifacts[0]
            reader.require(allow.get('source_commit') == source and allow.get('run_id') == run['id']
                and allow.get('artifact_id') == artifact['id'] and allow.get('original_zip_sha256') == artifact['digest'][7:]
                and allow.get('original_zip_bytes') == artifact['size_in_bytes'], 'verified public allowlist origin differs')
            reader.require(allow.get('original_zip_publication_allowed') is False
                and allow.get('original_zip_quarantined_outside_public_tree') is True
                and allow.get('private_bridge_or_private_source_payloads_copied') is False,
                'verified whole ZIP/private payload exclusion missing')
            self.private_identities[artifact['digest'][7:]] = {'kind': 'forbidden verified original ZIP',
                'source': source, 'artifact_id': artifact['id']}
            for item in allow.get('private_bridge_members_excluded', []):
                reader.require(reader.SHA.fullmatch(item['sha256']), 'invalid excluded private payload hash')
                self.private_identities[item['sha256']] = {'kind': 'forbidden private bridge member',
                    'source': source, 'original_member': item['original_member']}
            included = allow.get('included_files')
            reader.require(isinstance(included, list), 'verified member allowlist missing')
            expected = {}
            for item in included:
                name = reader.safe_name(item['archive_relative']).as_posix()
                reader.require(name.startswith('selected-public/') and name not in expected, 'invalid/duplicate public member path')
                expected[prefix + '/' + name] = item
            actual = {name: row for name, row in self.by_relative.items() if name.startswith(prefix + '/selected-public/')}
            reader.require(set(actual) == set(expected), 'verified selected-public path set differs from allowlist')
            for name, row in actual.items():
                reader.require(row['sha256'] == expected[name]['sha256'] and row['bytes'] == expected[name]['bytes'],
                               'verified public member bytes differ: ' + name)
            reader.require(receipt.get('all_selected_bytes_matched') is True and receipt.get('private_bridges_extracted') == 0
                and receipt.get('whole_zip_copied_into_public_tree') is False and receipt.get('source_commit') == source
                and receipt.get('allowlist_sha256') == self.by_relative[allow_path]['sha256']
                and receipt.get('selected_files') == len(expected), 'verified public extraction receipt differs')
            self.verified_member_bindings.append({'group': tag + '-core-verified', 'source_commit': source,
                'source_tree': tree, 'run_id': run['id'], 'artifact_id': artifact['id'],
                'included_members': len(expected), 'included_bytes': sum(row['bytes'] for row in actual.values()),
                'all_current_public_member_bytes_match_allowlist': True,
                'quarantined_original_zip_opened': False, 'original_zip_selected': False,
                'allowlist': self.metadata_identity(allow_path)})
        except Exception as error:
            self.gap('verified_public_allowlist_gap', group=tag + '-core-verified', error=str(error))

    def local(self, tag, prefix, source, tree):
        passed = []
        for name, result_key in [('focused', 'qualified'), ('guarded-opportunity', 'qualified'),
                                 ('c-posttest', 'ok'), ('migration-tests', 'ok')]:
            relative = prefix + '/' + name + '/RESULT.json'
            value = self.load(relative)
            if value is None:
                passed.append(None)
                continue
            try:
                reader.require(value.get('source', value.get('expected_source')) == source,
                               'local execution result source differs')
                if name in {'focused', 'migration-tests'}:
                    reader.require(value.get('tree') == tree, 'local execution result tree differs')
                if name in {'focused', 'c-posttest'}:
                    before = self.load(prefix + '/' + name + '/source-before.json')
                    after = self.load(prefix + '/' + name + '/source-after.json')
                    reader.require(before is not None and before == after and before.get('head') == source
                        and before.get('tree') == tree and before.get('status') == '', 'local full source snapshots differ')
                if name == 'guarded-opportunity':
                    before, after = value.get('source_state_before'), value.get('source_state_after')
                    reader.require(before is not None and before == after and before.get('head') == source
                        and before.get('tree') == tree and before.get('status') == '', 'guarded full source snapshots differ')
                    reader.require(value.get('status') == 'no-economic-opportunity'
                        and value['economics'].get('ndu_comparison_authorized_by_this_evidence') is False,
                        'recorded negative guarded economics must remain explicit')
                reader.require(type(value.get(result_key)) is bool, 'missing actual local result status')
                passed.append(value[result_key])
            except Exception as error:
                passed.append(None)
                self.gap('local_execution_provenance_gap', path=relative, error=str(error))
        self.groups[tag + '-local']['qualification_status'] = ('incomplete' if None in passed else
            'passed' if all(passed) else 'failed' if not any(passed) else 'mixed')


def preflight():
    started = datetime.now(timezone.utc).isoformat()
    before_source = source_state()
    tools = {name: file_identity(BASE / name) for name in
             ('build_selection.py', 'RESTORE.py', 'INPUT_SELECTION.schema.json')}
    initial_nodes, excluded, special = path_snapshot()
    inventory = Inventory()
    inventory.scan(initial_nodes)
    for relative in REQUIRED_OWNER_SUMMARIES:
        row = inventory.by_relative.get(relative)
        if row is None or row['bytes'] == 0:
            inventory.gap('owner_final_summary_pending', path='evidence/' + relative,
                          action='Owner writes the final integrated conclusion and complete scope before the final preflight/freeze.')
    for tag, source, tree, local_prefix, hosts_prefix, core_prefix in [
        ('e6', INITIAL, INITIAL_TREE, 'final-source', 'ci-public-hosts', 'ci-core'),
        ('e57', FINAL, FINAL_TREE, FINAL_PREFIX, FINAL_PREFIX + '/ci-public-hosts', FINAL_PREFIX + '/ci-core')]:
        inventory.local(tag, local_prefix, source, tree)
        inventory.hosts(tag, hosts_prefix, source, tree)
        for profile in ('six', 'verified', 'integrated'):
            prefix = core_prefix + '/' + profile + ('-initial' if tag == 'e6' else '')
            inventory.core(tag, profile, prefix, source, tree)
    retained = []
    for row in inventory.files:
        if row['sha256'] in inventory.private_identities:
            finding = {'path': row['archive_path'], 'sha256': row['sha256'],
                       **inventory.private_identities[row['sha256']]}
            inventory.private_payload_findings.append(finding)
            inventory.gap('forbidden_private_identity_in_scanned_root', **finding)
        else:
            retained.append(row)
    inventory.files = retained
    zip_descriptors = [binding['descriptor'] for binding in inventory.zip_bindings]
    selected_zips = {row['archive_path'] for row in zip_descriptors}
    unknown_zips = sorted(inventory.zip_content - selected_zips)
    for name in unknown_zips:
        inventory.gap('standalone_zip_has_no_approved_public_ci_provenance', path=name,
            synthetic_control=('archive-tooling-controls/' in name),
            action='owner must exclude or explicitly redesign data representation; never invent CI provenance')
    if len(zip_descriptors) != EXPECTED_ZIPS:
        inventory.gap('original_public_zip_total_pending', expected=EXPECTED_ZIPS, actual=len(zip_descriptors))
    if len({row['artifact_id'] for row in zip_descriptors}) != len(zip_descriptors):
        inventory.gap('duplicate_public_artifact_id')
    final_nodes, excluded_after, special_after = path_snapshot()
    changed = [component + '/' + relative for component, relative in sorted(set(initial_nodes) | set(final_nodes))
               if initial_nodes.get((component, relative)) != final_nodes.get((component, relative))]
    after_source = source_state()
    if before_source != {'head': FINAL, 'tree': FINAL_TREE, 'status': ''} or after_source != before_source:
        inventory.gap('final_root_source_not_exact_clean_unchanged', before=before_source, after=after_source)
    if changed or excluded_after != excluded or special_after != special:
        inventory.gap('input_tree_changed_during_preflight', changed_regular_paths=changed,
                      policy_or_special_entries_changed=excluded_after != excluded or special_after != special)
    if any(file_identity(BASE / name) != value for name, value in tools.items()):
        inventory.gap('selection_tooling_changed_during_preflight')
    rows = sorted(inventory.files, key=lambda row: row['archive_path'])
    groups = [inventory.groups[key] for key in sorted(inventory.groups)]
    zip_descriptors.sort(key=lambda row: row['archive_path'])
    candidate = {'source_commit': FINAL, 'source_tree': FINAL_TREE, 'files': rows,
                 'evidence_inputs': groups, 'public_ci_zips': zip_descriptors}
    try:
        # Shape/size/provenance validation only; this is not a frozen public
        # declaration and is never written as INPUT_SELECTION in preflight mode.
        reader.validate_selection({'schema': 'hepta.hia-round7.input-selection.v1',
            'public_evidence_only': True, 'file_count': len(rows),
            'bytes': sum(row['bytes'] for row in rows), **candidate})
    except Exception as error:
        inventory.gap('candidate_shape_or_archive_policy_gap', error=str(error))
    by_hash = defaultdict(list)
    for row in rows:
        by_hash[(row['bytes'], row['sha256'])].append(row['archive_path'])
    duplicates = [{'bytes_each': size, 'sha256': sha, 'paths': names}
                  for (size, sha), names in sorted(by_hash.items()) if len(names) > 1]
    counts = Counter(row['evidence_input'] for row in rows)
    sizes = Counter()
    for row in rows:
        sizes[row['evidence_input']] += row['bytes']
    report = {'schema': 'hepta.hia-round7.selection-preflight.v1', 'started_utc': started,
        'finished_utc': datetime.now(timezone.utc).isoformat(), 'frozen': False,
        'final_input_selection_written': False, 'owner_public_content_and_final_summary_review_pending': True,
        'source_before': before_source, 'source_after': after_source, 'tooling': tools,
        'scanned_roots': {key: str(value) for key, value in ROOTS.items()},
        'outside_roots_scanned': False, 'private_quarantine_path_opened': False,
        'private_original_zip_identity_found_during_scan': any(
            item['kind'] == 'forbidden verified original ZIP' for item in inventory.private_payload_findings),
        'historical_round6_repository_scanned_or_copied': False,
        'file_count': len(rows), 'bytes': sum(row['bytes'] for row in rows),
        'files': rows, 'evidence_inputs': groups,
        'group_totals': [{'id': key, 'files': counts[key], 'bytes': sizes[key]} for key in sorted(inventory.groups)],
        'public_ci_zips': zip_descriptors, 'public_zip_count': len(zip_descriptors),
        'expected_public_zip_count': EXPECTED_ZIPS, 'zip_provenance_bindings': inventory.zip_bindings,
        'run_provenance_bindings': inventory.run_bindings,
        'verified_public_member_bindings': inventory.verified_member_bindings,
        'excluded_by_explicit_policy': excluded, 'private_identity_findings': inventory.private_payload_findings,
        'unclassified_paths': inventory.unclassified, 'special_paths': special,
        'unsafe_or_duplicate_namespace_paths': inventory.path_errors, 'read_errors': inventory.read_errors,
        'unapproved_standalone_zip_paths': unknown_zips, 'provenance_gaps': inventory.gaps,
        'duplicate_content_groups': duplicates,
        'duplicate_content_policy': 'Retain distinct original evidence paths and report byte duplicates; no silent deduplication.',
        'required_owner_summary_paths': ['evidence/' + name for name in REQUIRED_OWNER_SUMMARIES],
        'readme_scope': 'The owner README under round7-publication is bundle-level publication metadata, not an automatically added fourth raw-input root.',
        'candidate_snapshot_sha256': digest(wire(candidate)),
        'preservation_notes': ['Keep original e6 failure, Cargo CORRECTION and negative economics.',
            'Keep development/repair/synthetic-control results separate from exact-source execution.',
            'Toolchain provenance is setup evidence, not qualification.',
            'Historical README/API excerpts in reviews are retained as review context; no round-six repository is rescanned.'],
        'project_tests_or_native_or_packager_executed': False,
        'technical_gaps_clear': not any((inventory.gaps, inventory.unclassified, special,
                                        inventory.path_errors, inventory.read_errors)),
        'final_freeze_requires': 'Explicit owner instruction plus approved preflight SHA; a fresh identical scan and no technical gaps are required.'}
    return report


def freeze(args):
    reader.require(args.approved_preflight_sha256 is not None
                   and reader.SHA.fullmatch(args.approved_preflight_sha256), 'exact approved preflight SHA required')
    approved_path = local_output(args.approved_preflight)
    raw = reader.read_regular(approved_path.parent, approved_path.name)
    reader.require(digest(raw) == args.approved_preflight_sha256, 'approved preflight bytes differ')
    approved = reader.json_value(raw)
    reader.require(approved.get('technical_gaps_clear') is True, 'approved preflight still has technical gaps')
    current = preflight()
    reader.require(current['technical_gaps_clear'], 'fresh inventory has technical gaps; generate/review a new preflight')
    reader.require(current['candidate_snapshot_sha256'] == approved.get('candidate_snapshot_sha256')
                   and current['tooling'] == approved.get('tooling'), 'inputs/classification/tooling changed since approved preflight')
    selection = {'schema': 'hepta.hia-round7.input-selection.v1',
        'source_commit': FINAL, 'source_tree': FINAL_TREE, 'public_evidence_only': True,
        'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'file_count': current['file_count'], 'bytes': current['bytes'],
        'files': current['files'], 'evidence_inputs': current['evidence_inputs'],
        'public_ci_zips': current['public_ci_zips'],
        'notes': current['preservation_notes'] + ['Frozen from owner-reviewed preflight SHA-256 ' + args.approved_preflight_sha256]}
    reader.validate_selection(selection)
    result = write_new(local_output(args.selection_output), selection)
    print(json.dumps({'mode': 'explicit-freeze', 'selection': result, 'files': selection['file_count'],
                      'public_ci_zips': len(selection['public_ci_zips']), 'packager_executed': False}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', action='store_true', help='Only after explicit owner review/instruction.')
    parser.add_argument('--preflight-output', type=Path, default=BASE / 'selection-preflight.json')
    parser.add_argument('--approved-preflight', type=Path, default=BASE / 'selection-preflight.json')
    parser.add_argument('--approved-preflight-sha256')
    parser.add_argument('--selection-output', type=Path, default=BASE / 'INPUT_SELECTION.json')
    args = parser.parse_args()
    if args.freeze:
        freeze(args)
    else:
        reader.require(args.approved_preflight_sha256 is None, 'approval hash is only used with explicit --freeze')
        report = preflight()
        result = write_new(local_output(args.preflight_output), report)
        print(json.dumps({'mode': 'preflight-only', 'preflight': result, 'files': report['file_count'],
            'bytes': report['bytes'], 'public_ci_zips': report['public_zip_count'],
            'expected_public_ci_zips': EXPECTED_ZIPS, 'technical_gaps_clear': report['technical_gaps_clear'],
            'provenance_gap_count': len(report['provenance_gaps']),
            'unclassified': len(report['unclassified_paths']), 'special': len(report['special_paths']),
            'final_input_selection_written': False}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
