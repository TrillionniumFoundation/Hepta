"""Run the original 39 publication tests with explicit, optional custody.

No new product timeout or process owner is introduced.  Archive is a separate
command after the test process has exited; its result never reclassifies the
original unittest result.  Special fixture entries are metadata, not streams.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import traceback
import unittest

from tools.hia_artifact_publication_custody import (
    Session, copy_cold_evidence, create_directory, direct_child_custody_closed, identity,
    observe_cold_evidence, parent_fd, process_identity,
    read_file, write_json, write_new,
)

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    'tests.test_hia_artifact_publication_native',
    'tests.test_hia_artifact_publication_route',
    'tests.test_hia_agent_artifact_store_native',
)
ORIGINAL_TEST_IDS = (
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_copied_empty_PATH_link_verify_withdraw_and_kernel_object',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_post_link_actual_open_IO_failure_withdraws_own_link',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_post_link_competitor_replacement_is_never_withdrawn',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_post_link_in_place_corruption_withdraws_only_own_link',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_real_syscall_EINTR_retry_and_no_child_or_dynamic_runtime',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_receipt_write_failure_keeps_verified_link_without_success_claim',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_refuses_missing_extra_changed_bytes_same_path_and_existing_entries',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_regular_to_FIFO_race_is_nonblocking_and_refused',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_streaming_exceeds_fixed_chunk_and_old_one_shot_limit',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationKernelTests.test_symlink_fifo_and_independent_equal_byte_inode_are_not_identity',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests.test_authoring_source_is_exact_and_resource_checked',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests.test_builder_rejects_old_source_cold_before_creating_output',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests.test_bytes_are_authoritative_and_extra_or_missing_bytes_refused',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests.test_identity_uses_inode_mode_size_mtime_ctime_not_uid_or_atime',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests.test_native_packer_independent_VM_and_exact_generator',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests.test_paths_match_absolute_lexical_reference_without_resolving_dotdot',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests.test_receipt_formats_real_digest_and_full_u64_decimal',
    'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests.test_unknown_phase_and_unowned_withdrawal_refused',
    'tests.test_hia_artifact_publication_route.PublicationRouteNativeTests.test_real_selected_API_uses_sealed_code_and_native_filesystem_only',
    'tests.test_hia_artifact_publication_route.PublicationRouteSourceTests.test_explicit_selection_routes_all_operations_and_never_falls_back',
    'tests.test_hia_artifact_publication_route.PublicationRouteSourceTests.test_missing_or_malformed_selected_manifest_fails_before_effects',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_actual_directory_fsync_failure_leaves_no_success_and_preserves_possible_content',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_actual_empty_binary_and_multichunk_put_get_dedup_private_file',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_actual_file_fsync_failure_no_content_or_success_receipt',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_corrupt_existing_file_and_different_digest_refuse_without_replacing',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_quota_is_original_64MiB_and_never_applied_to_generic_publisher',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_real_file_and_directory_fsync_and_post_fsync_receipt_boundary',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_real_post_link_competitor_inode_is_never_deleted',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_real_post_link_corruption_withdraws_only_own_content_inode',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_symlink_FIFO_root_permissions_and_path_traversal_refuse',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStorePolicyTests.test_commands_root_and_only_exact_lower_hex_file_names',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStorePolicyTests.test_owned_non_writable_directory_guard_and_full_store_quota',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStorePolicyTests.test_temporary_name_UUID4_bits_and_content_SHA_are_formed_in_HIA',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreRouteTests.test_actual_native_fsync_failures_cannot_issue_DB_refs_or_replay_effects',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreRouteTests.test_missing_selected_code_never_falls_back_or_issues_reference',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreRouteTests.test_one_put_uses_one_immutable_code_admission_but_next_call_revalidates',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreRouteTests.test_real_store_bytes_metadata_dedup_restart_and_namespace_authority',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreRouteTests.test_ref_and_kind_checks_precede_native_file_access_and_corruption_refuses',
    'tests.test_hia_agent_artifact_store_native.AgentArtifactStoreRouteTests.test_selection_cannot_change_between_hash_and_file_publication',
)
SOURCE_INPUTS = (
    'tests/test_hia_artifact_publication_native.py',
    'tests/test_hia_artifact_publication_route.py',
    'tests/test_hia_agent_artifact_store_native.py',
    'hepta/artifact_publication_native.py',
    'tools/build_hia_artifact_publication.py',
    'tools/generate_hia_artifact_publication.py',
    'tools/generate_hia_sha256_stream.py',
    'examples/hia_bootstrap/artifact_publication_policy.hiaasm',
    'examples/hia_bootstrap/artifact_publication_packer.hiaasm',
    'examples/hia_bootstrap/sha256_stream.hiaasm',
    'tools/hia_artifact_publication_syscalls.S',
)

# New custody-only aggregate for the three complete cold input originals.
# The original product's 64 MiB quota, subprocess timeouts and test population
# do not use this value. The outer report and compiler keep their 8/1 MiB bounds.
COLD_INPUT_CUSTODY_BYTES = 256 << 20


def copied_json(record):
    raw, observed = read_file(Path(record['path']), record['bytes'])
    if observed != record['identity'] or sha256(raw).hexdigest() != record['sha256']:
        raise ValueError('retained cold JSON changed before parsing')
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate cold JSON key: ' + key)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def cold_digest(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('cold evidence requires an actual SHA256 digest')
    return value


def copy_cold_inputs(cold_path, directory, *, maximum_bytes=COLD_INPUT_CUSTODY_BYTES):
    """Preserve complete outer/nested/B3 originals before loading any tests."""
    if type(maximum_bytes) is not int or not 0 < maximum_bytes <= COLD_INPUT_CUSTODY_BYTES:
        raise ValueError('cold evidence aggregate exceeds its custody budget')
    directory = Path(directory)
    rows = []
    used = 0
    def retain(source, name, maximum, *, expected_bytes=None, expected_sha256=None):
        nonlocal used
        row = copy_cold_evidence(source, directory / name, min(maximum, maximum_bytes - used),
                                 expected_bytes=expected_bytes, expected_sha256=expected_sha256)
        rows.append(row)
        used += row['retained']['bytes']
        return row['retained']
    outer_record = retain(Path(cold_path).absolute(), 'cold-report.json', 8 << 20)
    cold = copied_json(outer_record)
    if type(cold) is not dict or cold.get('schema') != 'hepta.hia.selfhost-cold-replay.v1':
        raise ValueError('original cold replay schema required for input custody')
    if type(cold.get('nested_report')) is not str:
        raise ValueError('original cold nested-report path required')
    nested_path = Path(cold['nested_report'])
    nested_record = retain(nested_path, 'cold-qualification.json', maximum_bytes,
                           expected_sha256=cold_digest(cold.get('nested_report_sha256')))
    nested = copied_json(nested_record)
    if (type(nested) is not dict or nested.get('schema') != 'hepta.hia.selfhost-qualification.v6' or
            nested.get('source_manifest') != cold.get('source_manifest') or
            type(nested.get('source_manifest')) is not dict or
            nested.get('profile') != cold.get('profile') or type(nested.get('profile')) is not str):
        raise ValueError('original nested qualification schema/source/profile binding differs')
    generations = nested.get('generations')
    if (type(generations) is not list or len(generations) != 3 or
            any(type(row) is not dict for row in generations) or
            [row.get('case') for row in generations] != ['B1', 'B2', 'B3']):
        raise ValueError('original B1/B2/B3 generation records required')
    digests = [cold_digest(row.get('produced_sha256')) for row in generations]
    if cold.get('generation_sha256') != digests:
        raise ValueError('outer and nested generation hashes differ')
    generation = generations[-1]
    count = generation.get('produced_bytes')
    if (type(count) is not int or not 0 < count <= 1 << 20 or
            type(generation.get('produced_image')) is not str):
        raise ValueError('bounded B3 actual byte count and path required')
    compiler_path = Path(generation['produced_image'])
    compiler_record = retain(compiler_path, 'compiler.image.bin', 1 << 20,
                             expected_bytes=count, expected_sha256=digests[-1])
    # Re-observe every original and every retained byte after all three copies.
    # This joins the final B3 to the same outer/nested originals used above.
    for row in rows:
        record = row['retained']
        for path, expected_identity in ((Path(row['source']), row['original_identity']),
                                        (Path(record['path']), record['identity'])):
            current = observe_cold_evidence(path, record['bytes'], expected_bytes=record['bytes'],
                                            expected_sha256=record['sha256'])
            if current['identity'] != expected_identity:
                raise ValueError('cold evidence identity changed after the complete input chain')
    binding = {'schema': 'hepta.hia.publication-cold-input-custody.v1',
               'status': 'FULL_COLD_INPUT_BYTES_RETAINED_AND_BOUND',
               'evidence_only': True, 'product_or_cold_result_reclassified': False,
               'raw_original_count': 3, 'raw_original_bytes': used,
               'aggregate_custody_maximum_bytes': maximum_bytes,
               'outer_report_maximum_bytes': 8 << 20, 'compiler_maximum_bytes': 1 << 20,
               'outer_report': outer_record, 'nested_report': nested_record,
               'nested_report_expected_sha256': cold['nested_report_sha256'],
               'compiler': compiler_record, 'generation': generation,
               'cold_status_observed': cold.get('status'), 'nested_status_observed': nested.get('status')}
    write_json(directory / 'cold-binding.json', binding)
    return rows


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def source_snapshot():
    raw, _ = read_file(ROOT / 'docs/HIA_SELFHOST_CORE_SUPPORT.json', 8 << 20)
    record = json.loads(raw)
    files = dict(record['source_identity']['files'])
    files['docs/HIA_SELFHOST_CORE_SUPPORT.json'] = sha256(raw).hexdigest()
    rows = {}
    for name, digest in files.items():
        path = Path(name)
        if path.is_absolute() or not path.parts or any(part in ('.', '..') for part in path.parts):
            raise ValueError('source declaration has a non-repository path')
        data, observed = read_file(ROOT / path)
        actual = sha256(data).hexdigest()
        if actual != digest:
            raise ValueError('declared source bytes differ: ' + name)
        rows[name] = {'bytes': len(data), 'sha256': actual, 'identity': observed}
    return {'profile': record['profile'], 'files': rows}


def copy_inputs(session):
    rows = []
    for index, name in enumerate(SOURCE_INPUTS):
        raw, observed = read_file(ROOT / name)
        saved = write_new(session.root / 'inputs' / ('source-%02d.bin' % index), raw)
        rows.append({'source': name, 'original_identity': observed, 'retained': saved})
    cold_path = os.environ.get('HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT')
    if cold_path:
        rows.extend(copy_cold_inputs(cold_path, session.root / 'inputs'))
    write_json(session.root / 'INPUTS.json', rows)
    return rows


class RecordedResult(unittest.TextTestResult):
    session = None

    def startTest(self, test):
        super().startTest(test)
        self.session.test_id = test.id()
        self.session.tests.append({'id': test.id(), 'started_ns': time.monotonic_ns(), 'events': []})

    def _event(self, test, kind, detail=None):
        row = {'kind': kind, 'id': test.id(), 'detail': detail}
        if self.session.tests and self.session.tests[-1]['id'] == test.id():
            self.session.tests[-1]['events'].append(row)
        else:
            # Fixture errors (for example setUpClass) are real loader outcomes,
            # not fabricated executions of all tests in the fixture.
            self.session.tests.append({'id': test.id(), 'fixture_event': True, 'events': [row]})

    def addSuccess(self, test):
        self._event(test, 'success')
        super().addSuccess(test)

    def addError(self, test, err):
        self._event(test, 'error', ''.join(traceback.format_exception(*err)))
        super().addError(test, err)

    def addFailure(self, test, err):
        self._event(test, 'failure', ''.join(traceback.format_exception(*err)))
        super().addFailure(test, err)

    def addSkip(self, test, reason):
        self._event(test, 'skip', reason)
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self._event(test, 'expected_failure', ''.join(traceback.format_exception(*err)))
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self._event(test, 'unexpected_success')
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        self._event(test, 'subtest_success' if err is None else 'subtest_failure',
                    subtest.id() if err is None else ''.join(traceback.format_exception(*err)))
        super().addSubTest(test, subtest, err)

    def stopTest(self, test):
        self.session.flush_calls()
        self.session.tests[-1]['stopped_ns'] = time.monotonic_ns()
        self.session.test_id = None
        super().stopTest(test)


def run_tests(retain):
    session = Session(retain)
    report = {'schema': 'hepta.hia.publication-original-tests.v1', 'status': 'HOLD',
              'modules': list(MODULES), 'expected_test_ids': list(ORIGINAL_TEST_IDS),
              'new_outer_timeout_or_owner': False, 'original_timeouts_changed': False,
              'runner': session.runner, 'github_sha_observation': os.environ.get('GITHUB_SHA')}
    result = None
    try:
        before = source_snapshot()
        write_json(session.root / 'SOURCE-BEFORE.json', before)
        report['inputs'] = copy_inputs(session)
        suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
        loaded = [test.id() for test in flatten(suite)]
        report['loaded_test_ids'] = loaded
        report['loader_errors'] = list(unittest.defaultTestLoader.errors)
        if loaded != list(ORIGINAL_TEST_IDS) or report['loader_errors']:
            raise ValueError('exact original 39 test population required')
        RecordedResult.session = session
        session.install()
        try:
            result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
        finally:
            session.restore()
        run = session.finish(result)
        executed = [row['id'] for row in session.tests if not row.get('fixture_event')]
        report['executed_test_ids'] = executed
        report['tests_run'] = result.testsRun
        report['anomalies'] = {name: len(getattr(result, name)) for name in
                               ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}
        report['test_result_successful'] = result.wasSuccessful()
        after = source_snapshot()
        write_json(session.root / 'SOURCE-AFTER.json', after)
        report['source_stable'] = before == after
        report['custody_errors'] = list(session.errors)
        if (result.wasSuccessful() and report['source_stable'] and not session.errors and
                executed == list(ORIGINAL_TEST_IDS) and result.testsRun == 39 and
                not any(report['anomalies'].values()) and run['known_direct_children_reaped']):
            report['status'] = 'ORIGINAL_39_TESTS_PASS_WITH_EXPLICIT_RETENTION'
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
    finally:
        if session is not None:
            session.flush_calls()
            if not (session.root / 'RUN.json').exists():
                write_json(session.root / 'RUN.json', {
                    'schema': 'hepta.hia.publication-test-custody.v1', 'status': 'INCOMPLETE_OR_HOLD',
                    'runner': session.runner, 'calls': [call.summary() for call in session.calls],
                    'tests': session.tests, 'errors': session.errors, 'fixtures': session.fixtures,
                    'full_process_tree_cleanup_claimed': False})
        write_json(session.root / 'REPORT.json', report)
    print(json.dumps({'status': report['status'], 'report': str(session.root / 'REPORT.json')}))
    return 0 if report['status'] == 'ORIGINAL_39_TESTS_PASS_WITH_EXPLICIT_RETENTION' else 1


def live_identity(original):
    if original is None:
        return None
    actual = process_identity(original['pid'])
    if actual is None or actual['starttime'] != original['starttime']:
        return None
    return actual


def quiescence(root):
    raw, _ = read_file(root / 'RUN.json', 16 << 20)
    record = json.loads(raw)
    live = []
    if found := live_identity(record['runner']):
        live.append(found)
    incomplete = []
    for index, call in enumerate(record['calls']):
        expected = root / 'calls' / ('%05d' % index)
        if call['ordinal'] != index or call['path'] != str(expected) or call['request'] != str(expected / 'request.json'):
            raise ValueError('call record path or ordinal differs')
        if call['process'] is not None:
            if found := live_identity(call['process']):
                live.append(found)
        if not direct_child_custody_closed(call):
            incomplete.append(call['ordinal'])
        for seen in call.get('descendants_seen', []):
            if found := live_identity(seen):
                live.append(found)
    # A killed strace may outlive or detach from its tracee.  The original suite
    # supplied no descendant owner, so refuse data custody in that ambiguous
    # case rather than claim an ECHILD guarantee that never existed.
    ambiguous_strace_kills = []
    for call in record['calls']:
        request_raw, _ = read_file(Path(call['request']), 8 << 20)
        request = json.loads(request_raw)
        if '/usr/bin/strace' in request['argv']:
            for event in sorted(Path(call['path']).glob('*-event.json')):
                event_raw, _ = read_file(event, 8 << 20)
                if json.loads(event_raw)['kind'] == 'ORIGINAL_CALLER_KILL_REQUEST':
                    ambiguous_strace_kills.append(call['ordinal'])
    return {'runner_and_known_children_absent': not live, 'live': live,
            'not_observed_reaped': incomplete, 'ambiguous_strace_kills': ambiguous_strace_kills,
            'fixture_roots': record.get('fixtures', []),
            'full_process_tree_cleanup_claimed': False,
            'ready_for_fixture_read': not live and not incomplete and not ambiguous_strace_kills,
            'run_sha256': sha256(raw).hexdigest()}


def typed_inventory(root, expected_root_identity=None):
    """Metadata-only traversal; do not open FIFO, symlink, socket or device."""
    rows = []
    def walk(fd, prefix):
        before = identity(os.fstat(fd))
        for name in sorted(os.listdir(fd)):
            value = os.stat(name, dir_fd=fd, follow_symlinks=False)
            relative = prefix + name
            row = {'path': relative, 'identity': identity(value)}
            if stat.S_ISDIR(value.st_mode):
                row['kind'] = 'directory'
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    if identity(os.fstat(child)) != identity(value):
                        raise ValueError('fixture directory changed while opening')
                    rows.append(row)
                    walk(child, relative + '/')
                finally:
                    os.close(child)
            elif stat.S_ISREG(value.st_mode):
                row['kind'] = 'regular'
                rows.append(row)
            else:
                row['kind'] = ('symlink' if stat.S_ISLNK(value.st_mode) else 'fifo' if stat.S_ISFIFO(value.st_mode)
                               else 'socket' if stat.S_ISSOCK(value.st_mode) else 'special')
                if row['kind'] == 'symlink':
                    row['link_target'] = os.readlink(name, dir_fd=fd)
                rows.append(row)
            if identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity(value):
                raise ValueError('fixture entry changed during inventory')
        if identity(os.fstat(fd)) != before:
            raise ValueError('fixture directory changed during inventory')
    with parent_fd(root) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            if expected_root_identity is not None and identity(os.fstat(fd)) != expected_root_identity:
                raise ValueError('retained root identity differs from its admission')
            walk(fd, '')
        finally:
            os.close(fd)
    return rows


def retained_roots(root, quiet):
    with parent_fd(root) as (fd, name):
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
    roots = [{'label': 'records', 'path': root, 'identity': identity(current)}]
    for index, fixture in enumerate(quiet['fixture_roots']):
        raw, _ = read_file(root / ('fixture-%03d.json' % index), 1 << 20)
        if json.loads(raw) != fixture:
            raise ValueError('retained temporary fixture registration differs')
        path = Path(fixture['path'])
        if not path.name.startswith(fixture['prefix']) or fixture['allocation'] != 'stdlib tempfile.mkdtemp(prefix), no dir override':
            raise ValueError('original tempfile allocation record differs')
        with parent_fd(path) as (fd, name):
            current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        observed = identity(current)
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid() or
                stat.S_IMODE(current.st_mode) != 0o700 or
                any(observed[k] != fixture['root_identity_at_creation'][k] for k in ('dev','ino','mode','uid','gid'))):
            raise ValueError('retained original temporary root changed')
        roots.append({'label': 'fixture-%03d' % index, 'path': path, 'identity': observed})
    if len({(r['identity']['dev'], r['identity']['ino']) for r in roots}) != len(roots):
        raise ValueError('retained roots alias each other')
    return roots


def root_inventory(roots):
    rows = []
    for root in roots:
        for row in typed_inventory(root['path'], root['identity']):
            relative = row['path']
            rows.append({**row, 'path': root['label'] + '/' + relative,
                         'original_path': str(root['path'] / relative)})
    return rows


class HashingReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = sha256()
        self.size = 0
    def read(self, size=-1):
        raw = self.stream.read(size)
        self.digest.update(raw)
        self.size += len(raw)
        return raw


@contextmanager
def new_archive_stream(path):
    with parent_fd(path) as (fd, name):
        leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=fd)
        with os.fdopen(leaf, 'wb') as stream:
            yield stream
            stream.flush(); os.fsync(stream.fileno())
            if identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity(os.fstat(stream.fileno())):
                raise ValueError('archive output link changed')
        os.fsync(fd)


def archive_evidence(root, output):
    root = Path(root).absolute()
    output = create_directory(Path(output).absolute())
    report = {'schema': 'hepta.hia.publication-test-archive.v1', 'status': 'HOLD',
              'source': str(root), 'output': str(output), 'test_result_reclassified': False,
              'special_entries_are_metadata_only': True, 'full_process_tree_cleanup_claimed': False}
    try:
        quiet = quiescence(root)
        report['quiescence_before'] = quiet
        if not quiet['ready_for_fixture_read']:
            raise ValueError('test process or known child closure is not established')
        roots = retained_roots(root, quiet)
        report['retained_roots'] = [{**r, 'path': str(r['path'])} for r in roots]
        rows = root_inventory(roots)
        archive = output / 'publication-originals.tar.gz'
        with new_archive_stream(archive) as destination:
            with tarfile.open(fileobj=destination, mode='w|gz', format=tarfile.PAX_FORMAT, dereference=False) as tar:
                for row in rows:
                    if row['kind'] != 'regular':
                        continue
                    path = Path(row['original_path'])
                    with parent_fd(path) as (fd, name):
                        leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                        with os.fdopen(leaf, 'rb') as stream:
                            if identity(os.fstat(stream.fileno())) != row['identity']:
                                raise ValueError('archive regular file identity changed')
                            info = tarfile.TarInfo('regular/' + row['path'])
                            info.size = row['identity']['size']
                            info.mode = stat.S_IMODE(row['identity']['mode'])
                            info.uid = row['identity']['uid']; info.gid = row['identity']['gid']
                            info.mtime = row['identity']['mtime_ns'] // 1000000000
                            reader = HashingReader(stream)
                            tar.addfile(info, reader)
                            if reader.size != info.size or identity(os.fstat(stream.fileno())) != row['identity']:
                                raise ValueError('regular file changed during archive read')
                            if identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != row['identity']:
                                raise ValueError('regular file name changed during archive read')
                            row['sha256'] = reader.digest.hexdigest()
                body = (json.dumps(rows, sort_keys=True, indent=2) + '\n').encode()
                info = tarfile.TarInfo('TYPED-MANIFEST.json');info.size = len(body);info.mode = 0o600
                tar.addfile(info, io.BytesIO(body))
            destination.flush(); os.fsync(destination.fileno())
            archive_identity = identity(os.fstat(destination.fileno()))
        archive_raw, readback_identity = read_file(archive)
        if readback_identity != archive_identity:
            raise ValueError('archive path identity changed after writing')
        after = root_inventory(roots)
        if [{k: v for k, v in row.items() if k != 'sha256'} for row in rows] != after:
            raise ValueError('fixture namespace or identity changed during archive')
        quiet_after = quiescence(root)
        report['quiescence_after'] = quiet_after
        if quiet_after != quiet:
            raise ValueError('process closure observation changed')
        expected = {'regular/' + row['path']: row for row in rows if row['kind'] == 'regular'}
        seen = []
        manifests = 0
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r|gz') as tar:
            for member in tar:
                if member.name == 'TYPED-MANIFEST.json':
                    manifests += 1
                    if not member.isreg() or manifests != 1 or tar.extractfile(member).read() != body:
                        raise ValueError('typed metadata archive readback differs')
                    continue
                if member.name not in expected or member.name in seen or not member.isreg():
                    raise ValueError('archive member differs')
                row = expected[member.name]
                digest = sha256(); count = 0
                with tar.extractfile(member) as stream:
                    while raw := stream.read(1 << 20):
                        count += len(raw); digest.update(raw)
                if (count != row['identity']['size'] or digest.hexdigest() != row['sha256'] or
                        member.mode != stat.S_IMODE(row['identity']['mode']) or
                        member.uid != row['identity']['uid'] or member.gid != row['identity']['gid']):
                    raise ValueError('archive original bytes or mode differ')
                seen.append(member.name)
        if set(seen) != set(expected) or manifests != 1:
            raise ValueError('archive original member missing')
        report.update(status='CLOSED_ORIGINAL_FIXTURES_RETAINED', archive=str(archive),
                      archive_sha256=sha256(archive_raw).hexdigest(), archive_bytes=len(archive_raw),
                      archive_identity=archive_identity,
                      typed_members=len(rows), regular_members=len(expected),
                      regular_bytes=sum(row['identity']['size'] for row in expected.values()))
        write_json(output / 'TYPED-MANIFEST.json', rows)
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
        # On a non-closed child never read fixture files. The fixed session
        # records are independent runner-produced diagnostics, not live output.
        for name in ('START.json', 'RUN.json', 'REPORT.json'):
            try:
                raw, observed = read_file(root / name, 16 << 20)
                write_new(output / name, raw)
                report.setdefault('fixed_metadata', []).append({'name': name, 'sha256': sha256(raw).hexdigest(), 'identity': observed})
            except BaseException as error:
                report.setdefault('metadata_errors', []).append({'name': name, 'type': type(error).__name__, 'message': str(error)})
    write_json(output / 'ARCHIVE.json', report)
    print(json.dumps({'status': report['status'], 'report': str(output / 'ARCHIVE.json')}))
    return 0 if report['status'] == 'CLOSED_ORIGINAL_FIXTURES_RETAINED' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run'); run.add_argument('--retain-evidence', required=True, type=Path)
    archive = commands.add_parser('archive'); archive.add_argument('--retain-evidence', required=True, type=Path)
    archive.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'run':
        return run_tests(args.retain_evidence)
    return archive_evidence(args.retain_evidence, args.output)


if __name__ == '__main__':
    raise SystemExit(main())
