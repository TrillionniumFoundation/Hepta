"""Exercise existing bounded-wire and Agent callers through the selected HIA owner."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

DEFAULT_MODULES = (
    'tests.test_hia_bounded_agent_json',
    'tests.test_hia_inmemory_surrogate_wire',
    'tests.test_hia_inmemory_json_key_collisions',
    'tests.test_hia_inmemory_agent_node_ceiling',
    'tests.test_hia_agent_native_tools',
    'tests.test_hia_agent_native_proof_contract',
    'tests.test_hia_agent_native_lease_snapshot',
    'tests.test_hia_agent_native_machine_choices',
    'tests.test_hia_agent_native_campaign',
)


TIMEOUT_FAILURE_ID = (
    'tests.test_hia_agent_native_tools.NativeLifecycleTests.'
    'test_native_timeout_is_incomplete_terminated_and_not_adoptable'
)
TIMEOUT_RAW_LIMIT = 8 * 1024 * 1024
TIMEOUT_MANIFEST_LIMIT = 64 * 1024
TIMEOUT_ARTIFACTS = (
    ('measurements', 'measurements.json'),
    ('full_cost_ledger', 'cost-ledger.json'),
    ('evaluation_receipt', 'evaluation-receipt.json'),
)


def retain_timeout_evaluation(test, destination, binding):
    """Copy existing evaluation bytes after addFailure, before fixture teardown."""
    report = {
        'schema': 'hepta.hia.native-timeout-retention.v1',
        'status': 'incomplete', 'test_id': TIMEOUT_FAILURE_ID,
        'trigger': 'original unittest failure already recorded',
        'qualification_authority': False, 'original_failure_preserved': True,
        'capture_after_original_elapsed_assertion': True,
        'additional_product_calls': False, 'raw_json_reserialized': False,
        'limits': {'each_raw_bytes': TIMEOUT_RAW_LIMIT,
                   'manifest_bytes': TIMEOUT_MANIFEST_LIMIT,
                   'total_artifact_bytes': 3 * TIMEOUT_RAW_LIMIT + TIMEOUT_MANIFEST_LIMIT},
        'binding': binding, 'files': [], 'errors': [],
    }
    stage = 'create-retention-directory'
    output_fd = None

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def version(info):
        return [info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                info.st_nlink, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns]

    def directory(name, parent=None):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and not info.st_mode & 0o022, 'unexpected directory identity')
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def read_blob(parent, name, maximum, mode):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
                    and 0 < before.st_size <= maximum, 'unexpected file identity or size')
            raw = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
            require(len(raw) == before.st_size and version(before) == version(after)
                    and version(os.stat(name, dir_fd=parent, follow_symlinks=False)) == version(before),
                    'file changed during read')
        return raw, {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                     'version': version(before)}

    def publish(name, raw, maximum):
        require(0 < len(raw) <= maximum, 'retained file exceeds its output bound')
        pending = '.' + name + '.pending'
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=output_fd)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        require(read_blob(output_fd, pending, maximum, 0o600)[0] == raw,
                'pending copy differs from original bytes')
        os.link(pending, name, src_dir_fd=output_fd, dst_dir_fd=output_fd,
                follow_symlinks=False)
        os.unlink(pending, dir_fd=output_fd)
        copied, identity = read_blob(output_fd, name, maximum, 0o600)
        require(copied == raw, 'published copy differs from original bytes')
        os.fsync(output_fd)
        return identity

    def failed(exc):
        report['status'] = 'incomplete'
        report['errors'].append({'stage': stage, 'type': type(exc).__name__,
                                 'errno': getattr(exc, 'errno', None)})

    try:
        destination.mkdir(mode=0o700)
        output_fd = directory(destination)
        stage = 'select-existing-completed-evaluation'
        require(test.id() == TIMEOUT_FAILURE_ID, 'unexpected failure method')
        records = test.client.records
        require(type(records) is list, 'unexpected recorded client history')
        completed = [(index, record) for index, record in enumerate(records)
                     if type(record) is dict and record.get('tool') == 'hia_evaluate'
                     and type(record.get('response')) is dict
                     and record['response'].get('status') == 'completed']
        require(len(completed) == 1, 'expected one completed hia_evaluate response')
        record_index, record = completed[0]
        record_raw = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')
        require(len(record_raw) <= TIMEOUT_MANIFEST_LIMIT,
                'completed record exceeds manifest allowance')
        report['completed_record_index'] = record_index
        report['client_record_count'] = len(records)
        report['completed_record'] = json.loads(record_raw)
        result = record['response']['result']
        require(type(result) is dict, 'completed evaluation result is not an object')
        require(test.state_root == test.root / 'state', 'unexpected fixture state root')
        report['source_artifact_directory'] = str(test.state_root / 'artifacts')
        with ExitStack() as opened:
            root_fd = directory(test.root)
            opened.callback(os.close, root_fd)
            state_fd = directory('state', root_fd)
            opened.callback(os.close, state_fd)
            artifacts_fd = directory('artifacts', state_fd)
            opened.callback(os.close, artifacts_fd)
            directories = [(root_fd, version(os.fstat(root_fd))),
                           (state_fd, version(os.fstat(state_fd))),
                           (artifacts_fd, version(os.fstat(artifacts_fd)))]
            originals = []
            for key, name in TIMEOUT_ARTIFACTS:
                stage = 'copy-existing-' + key
                ref = result[key]
                require(type(ref) is dict and set(ref) == {'id', 'sha256', 'uri'}
                        and all(type(ref[field]) is str for field in ref),
                        'unexpected issued artifact reference')
                digest = ref['sha256']
                require(len(digest) == 64 and all(ch in '0123456789abcdef' for ch in digest),
                        'unexpected artifact digest')
                raw, source = read_blob(artifacts_fd, digest, TIMEOUT_RAW_LIMIT, 0o400)
                require(source['sha256'] == digest, 'original bytes differ from issued digest')
                retained = publish(name, raw, TIMEOUT_RAW_LIMIT)
                report['files'].append({'response_key': key, 'name': name,
                                        'reference': dict(ref), 'source': source,
                                        'retained': retained})
                originals.append((digest, source['version']))
            stage = 'verify-existing-inputs-unchanged'
            require(all(version(os.fstat(descriptor)) == before for descriptor, before in directories),
                    'fixture directory changed during retention')
            require(all(version(os.stat(name, dir_fd=artifacts_fd, follow_symlinks=False)) == before
                        for name, before in originals), 'original artifact changed during retention')
            require(version(os.stat(test.root, follow_symlinks=False)) == directories[0][1]
                    and version(os.stat('state', dir_fd=root_fd, follow_symlinks=False)) == directories[1][1]
                    and version(os.stat('artifacts', dir_fd=state_fd, follow_symlinks=False)) == directories[2][1],
                    'fixture directory path changed during retention')
            require(len(records) == report['client_record_count'] and records[record_index] is record
                    and json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8') == record_raw,
                    'recorded evaluation changed during retention')
        report['status'] = 'complete'
    except Exception as exc:
        failed(exc)
    try:
        if output_fd is not None:
            stage = 'publish-retention-manifest'
            raw = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('utf-8')
            manifest = publish('manifest.json', raw, TIMEOUT_MANIFEST_LIMIT)
            report['manifest'] = {'path': str(destination / 'manifest.json'), **manifest}
    except Exception as exc:
        failed(exc)
    finally:
        if output_fd is not None:
            try:
                os.close(output_fd)
            except OSError as exc:
                stage = 'close-retention-directory'
                failed(exc)
    return report


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--manifest', type=Path)
    parser.add_argument('--development', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--evidence-dir', '--fixture-evidence', dest='evidence_dir', type=Path)
    parser.add_argument('--module', action='append')
    parser.add_argument('--exclude', action='append', default=[], metavar='TEST_ID=REASON')
    args = parser.parse_args()
    if bool(args.manifest) != args.development:
        parser.error('--manifest requires --development; cold cannot be relabeled development')
    if args.cold_report and args.exclude:
        parser.error('qualified runs cannot exclude existing callers')
    if args.output.exists():
        parser.error('output already exists; preserve prior observations')
    exclusions = {}
    for value in args.exclude:
        name, equal, reason = value.partition('=')
        if not equal or not reason.strip() or name in exclusions:
            parser.error('exclusions require a unique test ID and reason')
        exclusions[name] = reason
    from hepta import hia_program_tools as program_tools
    from hepta.hia_agent_journal_native import TOOLS
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_json_wire_native import NativeJsonWire, WireSession, SELECTOR, ORDINARY_PROFILE, installed_json_wire
    from tools.build_hia_json_wire import build, current_sources
    with ExitStack() as stack:
        if args.evidence_dir is None:
            folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hia-wire-callers-')))
        else:
            folder = args.evidence_dir.absolute()
            folder.mkdir(mode=0o700, parents=True)
        if args.cold_report:
            outer = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            manifest = build(folder / 'wire', compiler, args.cold_report)
            scope = 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
        else:
            manifest = args.manifest.resolve(strict=True)
            scope = 'DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'
        cold_source_snapshot = current_sources() if args.cold_report else None
        image = installed_json_wire(str(manifest))
        manifest_raw = manifest.read_bytes()
        manifest_value = json.loads(manifest_raw)
        executable = (manifest.parent / manifest_value['image_path']).resolve(strict=True)
        executable_sha = sha256(executable.read_bytes()).hexdigest()
        source_names = ('hepta/hia_json_wire_native.py', 'hepta/hia_program_tools.py',
                        'hepta/hia_agent_store.py', 'tools/generate_hia_json_wire.py',
                        'examples/hia_bootstrap/json_wire.hepta', 'tools/qualify_hia_json_wire_native_callers.py')
        sources = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_names}
        loaded = list(flatten(unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name)
                                                for name in (args.module or DEFAULT_MODULES))))
        loaded_ids = [test.id() for test in loaded]
        if len(set(loaded_ids)) != len(loaded_ids):
            parser.error('loaded caller IDs are not unique')
        if set(exclusions) - set(loaded_ids):
            parser.error('an exclusion does not identify a loaded test')
        chosen = [test for test in loaded if test.id() not in exclusions]
        chosen_ids = [test.id() for test in chosen]
        executed_ids, retained_entries, encoder_entries = [], [], []
        failure_artifact_retention = []
        calls, steps, tools_with_wire, tools_without_wire, per_test = Counter(), Counter(), Counter(), Counter(), {}
        current = ['outside-test']
        original_encode, original_step, original_call = NativeJsonWire.encode_ordinary, WireSession.step, HIAAgentService.call

        def forbidden_owner(*args, **kwargs):
            retained_entries.append(current[0])
            raise AssertionError('retained bounded-wire decision owner entered')

        def forbidden_encoder(*args, **kwargs):
            encoder_entries.append(current[0])
            raise AssertionError('host JSON encoder entered selected native wire')

        def encode(owner, *values, **options):
            if owner.image_sha256 != image.image_sha256:
                raise AssertionError('ordinary wire selected a different executable')
            calls['ordinary'] += 1
            per_test.setdefault(current[0], Counter())['ordinary_wire_calls'] += 1
            with patch.object(json.JSONEncoder, 'iterencode', forbidden_encoder):
                return original_encode(owner, *values, **options)

        def step(session, packet=None):
            result = original_step(session, packet)
            steps[str(result)] += 1
            per_test.setdefault(current[0], Counter())['native_step_returns'] += 1
            return result

        def call(service, tool, arguments):
            before = calls['ordinary']
            try:
                return original_call(service, tool, arguments)
            finally:
                name = tool if type(tool) is str else type(tool).__name__
                (tools_with_wire if calls['ordinary'] > before else tools_without_wire)[name] += 1

        class Result(unittest.TextTestResult):
            def startTest(self, test):
                current[0] = test.id()
                executed_ids.append(test.id())
                super().startTest(test)
            def stopTest(self, test):
                super().stopTest(test)
                current[0] = 'outside-test'
            def addFailure(self, test, err):
                super().addFailure(test, err)
                if test.id() == TIMEOUT_FAILURE_ID:
                    try:
                        retained = retain_timeout_evaluation(
                            test, folder / 'native-timeout-evaluation',
                            {'source_sha256': sources, 'wire_manifest_path': str(manifest),
                             'wire_manifest_sha256': sha256(manifest_raw).hexdigest(),
                             'wire_image_sha256': image.image_sha256})
                    except Exception as exc:
                        retained = {'status': 'incomplete', 'test_id': TIMEOUT_FAILURE_ID,
                                    'errors': [{'stage': 'failure-retention-callback',
                                                'type': type(exc).__name__}],
                                    'original_failure_preserved': True}
                    failure_artifact_retention.append(retained)

        started = time.monotonic()
        with (patch.dict(os.environ, {SELECTOR: str(manifest)}),
              patch.object(program_tools, '_reference_bounded_json_wire', forbidden_owner),
              patch.object(NativeJsonWire, 'encode_ordinary', encode),
              patch.object(WireSession, 'step', step),
              patch.object(HIAAgentService, 'call', call)):
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(unittest.TestSuite(chosen))
        stable = (manifest.read_bytes() == manifest_raw
                  and sha256(executable.read_bytes()).hexdigest() == executable_sha
                  and all(sha256((ROOT / name).read_bytes()).hexdigest() == value for name, value in sources.items()))
        cold_stable = current_sources() == cold_source_snapshot if args.cold_report else None
        stable = stable and cold_stable is not False
        all_tools = set(TOOLS[:-1]) <= set(tools_with_wire)
        anomalies = (result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses)
        passed = (bool(chosen_ids) and result.testsRun == len(chosen_ids) and executed_ids == chosen_ids
                  and not any(anomalies) and not retained_entries and not encoder_entries
                  and bool(calls['ordinary']) and bool(steps) and all_tools and stable)
        report = {
            'schema': 'hepta.hia.json-wire-selected-callers.v1', 'status': 'PASS' if passed else 'FAIL_OR_INCOMPLETE',
            'scope': scope, 'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
            'loaded_test_ids': loaded_ids, 'chosen_test_ids': chosen_ids, 'executed_test_ids': executed_ids,
            'tests_loaded': len(loaded_ids), 'tests_chosen': len(chosen_ids), 'tests_run': result.testsRun,
            'failures': [{'test': test.id(), 'trace': trace} for test, trace in result.failures],
            'failure_artifact_retention': failure_artifact_retention,
            'errors': [{'test': test.id(), 'trace': trace} for test, trace in result.errors],
            'skipped': [{'test': test.id(), 'reason': reason} for test, reason in result.skipped],
            'expected_failures': [{'test': test.id(), 'trace': trace} for test, trace in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
            'explicit_development_exclusions': exclusions, 'retained_owner_forbidden': True,
            'retained_owner_entries': retained_entries, 'host_encoder_forbidden_inside_native_owner': True,
            'host_encoder_entries': encoder_entries, 'ordinary_wire_calls': calls['ordinary'],
            'actual_native_step_returns': dict(steps), 'per_test_entries': {k: dict(v) for k, v in per_test.items()},
            'all_eleven_agent_tools_entered_selected_wire': all_tools,
            'agent_tools_with_native_wire': dict(tools_with_wire), 'agent_tools_without_native_wire': dict(tools_without_wire),
            'source_sha256': sources, 'manifest': manifest_value, 'manifest_path': str(manifest),
            'image_sha256': image.image_sha256, 'source_manifest_image_stable': stable,
            'matching_cold_source_closure_stable': cold_stable,
            'ordinary_entry_profile': ORDINARY_PROFILE, 'wall_seconds': time.monotonic() - started,
            'evidence_dir': str(folder), 'evidence_dir_retained': args.evidence_dir is not None,
            'subprocesses_inherit_selector': True, 'subprocess_entries_in_parent_counters': False,
            'default_whole_regression_claimed': False, 'sqlite_durability_replaced': False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': report['status'], 'report': str(args.output),
                          'tests_run': result.testsRun, 'scope': scope, 'all_eleven_tools': all_tools}), flush=True)
        return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
