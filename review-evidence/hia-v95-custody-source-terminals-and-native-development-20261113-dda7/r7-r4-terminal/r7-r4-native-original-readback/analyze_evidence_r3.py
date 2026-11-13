"""Read original evidence only; never import or execute product code."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import stat
import traceback
import zipfile

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / 'analysis-r3'
ORIGINAL = ROOT.parent
NATIVE = ROOT / 'restored/native'
FORMAL = Path('/workspace/scratch/dda74a4fae35/v90-source-r7-r4-original/artifact')
HEAD = 'abeef212e34023534d91f8f952280e2a8d0cbde6'
TREE = 'f2bc61c11104136d3f56e3c4aefa00a4dada910b'
RUN = 43459534648
MANIFEST_SHA = '528498d09e5ff306be28e666a5634fe967e667e71381ad5758c7f302b8584ac7'
FORMAL_MANIFEST_SHA = 'b8a0c8753c3a0f8578e2e40ebf44d206546f2ce951345ebae27c579501dc1d33'


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def dump(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()
    with (OUTPUT / name).open('xb') as stream:
        stream.write(raw)
    return identity(raw)


def require(value, label):
    if value is not True:
        raise AssertionError(label)


def tree_hash(rows):
    root = {}
    for row in rows:
        node = root
        parts = row['path'].split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        require(parts[-1] not in node, 'duplicate source index path')
        mode = row['mode']
        require(type(mode) is int and stat.S_IFMT(mode) in (0, stat.S_IFREG), 'source index mode')
        node[parts[-1]] = ('100755' if mode & 0o111 else '100644', row['blob'])

    def recurse(node):
        entries = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode, oid, sortname = '40000', recurse(value), name + '/'
            else:
                mode, oid = value
                sortname = name
            entries.append((sortname.encode(), mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)))
        raw = b''.join(value for _, value in sorted(entries))
        return sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return recurse(root)


def log_lines(path):
    return [re.sub(r'^\d{4}-\d\d-\d\dT\S+Z ', '', line)
            for line in path.read_text(encoding='utf-8-sig').splitlines()]


def source_ids(lines):
    starts = []
    pattern = re.compile(r'^(test_\S+) \((tests\.[^)]+)\)(.*)$')
    for index, line in enumerate(lines):
        match = pattern.match(line)
        if match:
            method, test_id, tail = match.groups()
            require(test_id.endswith('.' + method), 'unittest log method / ID mismatch')
            starts.append((index, test_id, tail))
    rows = []
    for number, (index, test_id, tail) in enumerate(starts):
        end = starts[number + 1][0] if number + 1 < len(starts) else len(lines)
        if tail == ' ... ok':
            conclusion_line, diagnostic = index, []
        else:
            require(tail.startswith(' ... usage: '), 'unexpected Source result presentation')
            completions = [i for i in range(index + 1, end) if lines[i] == 'ok']
            require(len(completions) == 1, 'diagnostic-interleaved Source result has no unique ok')
            conclusion_line = completions[0]
            diagnostic = lines[index:conclusion_line]
            require('--development-compiler /not-a-cold-input' in '\n'.join(diagnostic),
                    'unexpected diagnostic-interleaved test')
        rows.append({'id': test_id, 'start_log_line_1based': index + 1,
                     'result_log_line_1based': conclusion_line + 1, 'result': 'ok',
                     'interleaved_original_diagnostics': diagnostic})
    return rows


def main():
    result = {'schema': 'hia.r7-r4.original-evidence-semantic-readback.v1',
              'scope': 'READ_ONLY_ORIGINAL_EVIDENCE_NO_PRODUCT_EXECUTION',
              'started_at_utc': datetime.now(timezone.utc).isoformat(),
              'product_tests_executed': 0, 'product_refs_changed': 0,
              'qualification_transferred_to_new_source': False,
              'failures': []}
    try:
        restoration = json.loads((ROOT / 'RESTORATION-RESULT.json').read_bytes())
        require(restoration['status'] == 'EVIDENCE_INTEGRITY_AND_RESTORATION_PASS', 'original restoration failed')
        manifest_bytes = (ROOT / 'MEMBER-MANIFEST.json').read_bytes()
        require(sha256(manifest_bytes).hexdigest() == MANIFEST_SHA, 'complete member manifest drift')
        manifest = json.loads(manifest_bytes)
        result['member_manifest'] = identity(manifest_bytes)
        outer = {row['name']: row for row in manifest['archives']}
        rows = {row['path']: row for row in outer['native.zip']['members']}
        nested = {row['container']: row for row in manifest['nested_archives']}
        bindings = {}

        def original_bytes(relative):
            raw = (NATIVE / relative).read_bytes()
            observed = identity(raw)
            expected = rows[relative]
            require(all(observed[key] == expected[key] for key in observed), ('restored evidence drift', relative))
            require(stat.S_IMODE((NATIVE / relative).stat().st_mode) == int(expected['unix_permission_bits'], 8),
                    ('restored evidence mode drift', relative))
            bindings[relative] = observed
            return raw

        def original_json(relative):
            return json.loads(original_bytes(relative))

        run = json.loads((ROOT / 'ACTUAL-RUN-API.json').read_bytes())
        commit = json.loads((ROOT / 'ACTUAL-COMMIT-API.json').read_bytes())
        jobs = json.loads((ROOT / 'ACTUAL-JOBS-API.json').read_bytes())['jobs']
        require(run['id'] == RUN and run['head_sha'] == HEAD and run['run_attempt'] == 1
                and run['status'] == 'completed' and run['conclusion'] == 'failure', 'run authority mismatch')
        require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE, 'fixed product commit tree')
        require([x['sha'] for x in commit['parents']] == [
            'f33d8da316de8fdf27b504371f1a5310997ff548', 'a733926a2786a3d4a37304bd2d18ebb2eac57ac9'], 'product parent set')
        require(len(jobs) == 2 and all(j['run_id'] == RUN for j in jobs), 'actual job inventory')
        by_name = {j['name']: j for j in jobs}
        require(by_name['source']['id'] == 132002438040 and by_name['source']['conclusion'] == 'success', 'Source API result')
        require(by_name['native']['id'] == 132002437588 and by_name['native']['conclusion'] == 'failure', 'Native API result')
        steps = by_name['native']['steps']
        counts = Counter(step['conclusion'] for step in steps)
        require(len(steps) == 122 and counts == {'success': 18, 'failure': 1, 'skipped': 103}, 'Native complete step result counts')
        failed_steps = [step for step in steps if step['conclusion'] == 'failure']
        require(failed_steps[0]['number'] == 15 and failed_steps[0]['name'] == 'Native Store lifecycle original namespace callers',
                'Native failure step')
        result['execution_authority'] = {'run': RUN, 'head': HEAD, 'tree': TREE, 'run_attempt': 1,
            'event': run['event'], 'run_conclusion': run['conclusion'],
            'jobs': [{k: j[k] for k in ('id', 'name', 'status', 'conclusion', 'run_id', 'steps')} for j in jobs],
            'native_step_counts_including_setup_and_post': dict(counts),
            'steps_not_executed': [step for step in steps if step['conclusion'] == 'skipped']}

        # The earlier formal report is a reference for IDs/source identity only.
        # Its portable outputs are not substituted for the later product Source job.
        formal_bytes = (FORMAL / 'EVIDENCE-MANIFEST.json').read_bytes()
        require(sha256(formal_bytes).hexdigest() == FORMAL_MANIFEST_SHA, 'formal evidence manifest identity')
        formal_manifest = json.loads(formal_bytes)
        formal_rows = {row['path']: row for row in formal_manifest['members']}

        def formal_read(relative):
            raw = (FORMAL / 'raw' / relative).read_bytes()
            pin, observed = formal_rows[relative], identity(raw)
            require(observed['bytes'] == pin['bytes'] and observed['sha256'] == pin['sha256']
                    and observed['git_blob'] == pin['blob'], ('formal member pin', relative))
            require(stat.S_IMODE((FORMAL / 'raw' / relative).stat().st_mode) == pin['mode'], ('formal member mode', relative))
            return json.loads(raw), observed

        formal_tests, formal_test_pin = formal_read('checks/SOURCE-TESTS.json')
        source_index, source_index_pin = formal_read('terminal-worktree/INDEX.json')
        require(len(source_index['files']) == 3055 and tree_hash(source_index['files']) == TREE, 'formal complete source tree')
        source_map = {row['path']: row for row in source_index['files']}
        require(len(source_map) == 3055, 'formal duplicate source paths')
        require(formal_tests['status'] == 'PASS' and formal_tests['expected'] == 1274
                and formal_tests['tests_run'] == 1274 and formal_tests['complete'] is True, 'formal Source result')
        require(formal_tests['actual_started_ids'] == formal_tests['ordered_ids'] == formal_tests['actual_stopped_ids'],
                'formal loaded/start/stop sequence')
        require(all(not value for value in formal_tests['loader_errors'].values()), 'formal loader errors')
        source_log_bytes = (ORIGINAL / 'SOURCE-JOB.log').read_bytes()
        native_log_bytes = (ORIGINAL / 'FULL-JOB.log').read_bytes()
        require(identity(source_log_bytes)['git_blob'] == '7cd5bf57c7ac02807c1855f3403a0e80d5470f7b', 'Source log identity')
        require(identity(native_log_bytes)['git_blob'] == 'd304602ea70e0bcc541c215f1265e5b17448e22b', 'Native log identity')
        source_lines, native_lines = log_lines(ORIGINAL / 'SOURCE-JOB.log'), log_lines(ORIGINAL / 'FULL-JOB.log')
        require(HEAD in source_lines and HEAD in native_lines, 'both actual checkout log HEADs')
        source_observations = source_ids(source_lines)
        observed_ids = [row['id'] for row in source_observations]
        require(len(observed_ids) == len(set(observed_ids)) == 1274, 'product Source ID count or uniqueness')
        require(observed_ids == formal_tests['ordered_ids'], 'product Source ordered IDs differ from formal original 1274')
        summary_index = source_lines.index('Ran 1274 tests in 804.168s')
        require(source_lines[summary_index + 1:summary_index + 3] == ['', 'OK'], 'product Source unittest completion')
        require(all(test_id in observed_ids for test_id in formal_tests['main_projection_ids']), 'main projection missing')
        require(all(test_id in observed_ids for test_id in formal_tests['mapped_a733_projection_ids']), 'a733 projection missing')
        source_result = {'schema': 'hia.original-source-ordered-id-readback.v1',
            'actual_product_run': RUN, 'actual_product_job': 132002438040, 'actual_product_head': HEAD,
            'actual_product_log': identity(source_log_bytes), 'actual_tests_run': 1274,
            'actual_unittest_wall_seconds': 804.168, 'actual_terminal': 'OK',
            'actual_ordered_observations': source_observations,
            'formal_reference_run': 43451128811, 'formal_reference_report': formal_test_pin,
            'formal_source_index': source_index_pin, 'formal_manifest': identity(formal_bytes),
            'formal_reference_tests_run': 1274, 'ordered_ids_exact_equal': True,
            'original_main_ids': formal_tests['frozen_original_main_ids'],
            'original_a733_projected_ids': formal_tests['frozen_original_a733_projected_ids'],
            'actual_main_projection_ids': formal_tests['main_projection_ids'],
            'actual_a733_projection_ids': formal_tests['mapped_a733_projection_ids'],
            'raw_custody_boundary': {
                'actual_product_source_raw': 'SOURCE-JOB.log and source-vm.zip only as actually retained by this run; no replacement portable fixture raw',
                'earlier_formal_source_raw': str(FORMAL / 'raw'),
                'earlier_formal_raw_used_as_later_product_raw': False}}
        result['source_id_comparison'] = dump('SOURCE-ID-COMPARISON.json', source_result)
        result['source'] = {'status': 'ACTUAL_SOURCE_1274_PASS', 'wall_seconds': 804.168,
            'exact_order_equal_to_formal_1274': True, 'original_main_ids': 530,
            'original_a733_projected_ids': 973, 'current_main_projection': 554,
            'current_a733_projection': 1005, 'source_vm_retained_members': 69,
            'formal_portable_raw_not_substituted': True}

        cold = original_json('hia-cold.json')
        require(cold['status'] == 'COLD_SELFHOST_REPLAY_PASS' and len(cold['checks']) == 11
                and all(value is True for value in cold['checks'].values()), 'cold outer authority')
        require(type(cold['qualification_wall_limit_seconds']) is int and cold['qualification_wall_limit_seconds'] == 180
                and type(cold['cleanup_wall_limit_seconds']) is int and cold['cleanup_wall_limit_seconds'] == 3,
                'cold original budgets')
        qualification_bytes = original_bytes('hia-cold.cold/qualification.json')
        require(sha256(qualification_bytes).hexdigest() == cold['nested_report_sha256'], 'cold nested original report binding')
        qualification = json.loads(qualification_bytes)
        require(qualification['status'] == 'SELF_HOSTED_FIXED_CORE_PASS' and len(qualification['checks']) == 5052
                and all(value is True for value in qualification['checks'].values()), 'nested full qualification')
        require(cold['source_manifest'] == qualification['source_manifest'] and len(cold['source_manifest']) == 1430,
                'cold source manifest equality')
        source_prefix = 'hia-cold.cold/source/'
        actual_export = {path[len(source_prefix):]: row for path, row in rows.items() if path.startswith(source_prefix)}
        require(set(actual_export) == set(cold['source_manifest']), 'complete cold source export inventory')
        source_bindings = []
        for path, digest in cold['source_manifest'].items():
            actual, original = actual_export[path], source_map[path]
            require(actual['sha256'] == digest == original['sha256'], ('cold source bytes', path))
            require(actual['bytes'] == original['bytes'] and actual['git_blob'] == original['blob'], ('cold source Git identity', path))
            require(actual['unix_permission_bits'] == actual['restored_mode'] == '0400', ('readonly cold export mode', path))
            source_bindings.append({'path': path, 'bytes': actual['bytes'], 'sha256': digest,
                'git_blob': actual['git_blob'], 'formal_original_git_permission_mode': original['mode'],
                'cold_zip_and_restored_permission_mode': '0400'})
        result['cold_source_bindings'] = dump('COLD-SOURCE-BINDINGS.json', {
            'source_count': 1430, 'actual_product_head': HEAD, 'complete_product_tree': TREE,
            'full_tree_source_count': 3055, 'formal_source_index': source_index_pin,
            'export_permissions': 'Original export deliberately chmods files to 0400; this is not the repository mode.',
            'all_bytes_and_git_blob_identities_equal': True, 'files': source_bindings})

        owner_bytes = original_bytes('hia-cold.cold/process-owner.json')
        owner = json.loads(owner_bytes)
        require(sha256(owner_bytes).hexdigest() == cold['process_owner']['receipt_sha256'], 'cold process-owner bytes')
        require({key: cold['process_owner'][key] for key in owner} == owner, 'cold embedded owner fields')
        owner_request_bytes = original_bytes('hia-cold.cold/process-owner.json.request.json')
        owner_request = json.loads(owner_request_bytes)
        require(sha256(owner_request_bytes).hexdigest() == owner['request_sha256'], 'owner request binding')
        require(owner['status'] == 'OWNED_PROCESS_COMPLETED' and type(owner['returncode']) is int and owner['returncode'] == 0
                and cold['process_owner']['supervisor_returncode'] == 0 and owner['timed_out'] is False
                and owner['exit_observed_before_deadline'] is True and owner['qualification_started'] is True
                and owner['subreaper_enabled'] is True and owner['event_overflow'] is False
                and owner['interrupted_signals'] == [], 'owner original completed boundary')
        require(owner['qualification_seconds'] == owner_request['qualification_seconds'] == 180
                and owner['cleanup_seconds'] == owner_request['cleanup_seconds'] == 3, 'owner 180 + 3 limits')
        cleanup = owner['cleanup']
        require(cleanup['complete'] is True and cleanup['leader_reaped'] is True and cleanup['observed_echild'] is True
                and cleanup['deadline_exceeded'] is False and cleanup['errors'] == []
                and cleanup['remaining_direct_children'] == [], 'cold cleanup')
        start = [e for e in owner['events'] if e['kind'] == 'qualification_started']
        exit_events = [e for e in owner['events'] if e['kind'] == 'qualification_exit_observed']
        require(len(start) == len(exit_events) == 1, 'owner event uniqueness')
        require(exit_events[0]['monotonic_ns'] < owner_request['deadline_ns'], 'actual exit before deadline')

        scheduling = qualification['qualification_scheduling']
        phases, references = scheduling['phases'], scheduling['reference_processes']
        require(len(phases) == len(scheduling['phase_inventory']) == 38, 'cold 38 phase inventory')
        phase_index = original_json('hia-cold.cold/qualification.evidence/phase-index.json')
        require(type(phase_index['completed']) is int and phase_index['completed'] == 38
                and type(phase_index['exceptions']) is int and phase_index['exceptions'] == 0,
                'cold phase completion index')
        require(all(row['state'] == 'completed' and row['report_status'] == 'PASS' for row in phase_index['phases']),
                'cold phase terminal states')
        require({r['family'] + '-' + r['compiler_label'] for r in phases} == set(scheduling['phase_inventory']), 'phase exact inventory')
        manifest_digest = sha256(canonical(cold['source_manifest'])).hexdigest()
        phase_bindings = []
        for phase in phases:
            stem = 'phase-' + phase['family'] + '-' + phase['compiler_label']
            prefix = 'hia-cold.cold/qualification.evidence/'
            process = original_json(prefix + stem + '.process.json')
            require(process == phase, ('full phase receipt equality', stem))
            report_bytes = original_bytes(prefix + stem + '.json')
            report = json.loads(report_bytes)
            require(sha256(report_bytes).hexdigest() == phase['report_sha256'] and phase['returncode'] == 0,
                    ('phase report receipt binding', stem))
            require(report['status'] == 'PASS' and all(value is True for value in report['checks'].values())
                    and report['source_manifest_sha256'] == manifest_digest, ('phase original status', stem))
            archive = phase['raw_artifacts']
            relative = prefix + 'phase-runs/' + Path(archive['archive']).name
            require(rows[relative]['sha256'] == archive['archive_sha256'] and rows[relative]['bytes'] == archive['packed_bytes'],
                    ('phase full archive original bytes', stem))
            nested_rows = {r['path']: r for r in nested['native.zip!/' + relative]['members']}
            with zipfile.ZipFile(NATIVE / relative) as zf:
                raw = zf.read('HIA_ARCHIVE_MANIFEST.json')
            require(sha256(raw).hexdigest() == archive['manifest_sha256'], ('phase archive manifest identity', stem))
            archive_manifest = json.loads(raw)
            require(set(nested_rows) == set(archive_manifest['files']) | {'HIA_ARCHIVE_MANIFEST.json'},
                    ('phase full member inventory', stem))
            require(len(archive_manifest['files']) == archive['files'], ('phase file count', stem))
            for path, pin in archive_manifest['files'].items():
                actual = nested_rows[path]
                require(actual['bytes'] == pin['bytes'] and actual['sha256'] == pin['sha256']
                        and int(actual['unix_permission_bits'], 8) == pin['mode'], ('phase member hash/mode', stem, path))
            require(sum(pin['bytes'] for pin in archive_manifest['files'].values()) == archive['unpacked_bytes'],
                    ('phase unpacked byte count', stem))
            phase_bindings.append({'family': phase['family'], 'compiler_label': phase['compiler_label'],
                'status': report['status'], 'returncode': phase['returncode'], 'report': identity(report_bytes),
                'archive_member': relative, 'archive_sha256': archive['archive_sha256'],
                'archive_manifest': identity(raw), 'original_files': archive['files'],
                'all_archived_file_hashes_and_modes_verified': True})
        require(len(references) == 17 and len({r['family'] for r in references}) == 17, '17 independent workers')
        ref_bindings = []
        reference_field = {'exports': 'independent_explicit_export_reference', 'names': 'independent_function_name_reference',
            'cli': 'independent_executable_cli_reference', 'explicit-traps': 'independent_explicit_trap_reference',
            'resource': 'independent_resource_reference', 'bulk': 'independent_bulk_reference',
            'loan': 'independent_loan_reference', 'cfg': 'independent_cfg_worklist_reference',
            'capacity': 'independent_capacity_reference', 'tail': 'independent_tail_reference',
            'select': 'independent_select_reference', 'effects': 'independent_effect_reference',
            'multi': 'independent_multi_result_reference', 'keyword': 'independent_keyword_reference',
            'signed': 'independent_signed_reference', 'scalar-casts': 'independent_scalar_cast_reference',
            'core': 'independent_core_reference'}
        for process in references:
            family = process['family']
            raw = original_bytes('hia-cold.cold/qualification.evidence/reference-' + family + '.worker.json')
            worker = json.loads(raw)
            require(sha256(raw).hexdigest() == process['report_sha256'] and process['returncode'] == 0, ('reference report', family))
            require(worker['reference_sha256'] == process['reference_sha256'] == sha256(canonical(worker['reference'])).hexdigest(),
                    ('reference exact canonical payload', family))
            require(worker['reference'] == qualification[reference_field[family]], ('reference final-report payload', family))
            require(worker['family'] == family and worker['worker_pid'] == process['worker_pid']
                    and worker['before_B0'] is True and worker['source_manifest_sha256'] == manifest_digest,
                    ('reference identity', family))
            require(process['completed_monotonic_ns'] <= scheduling['seed_started_monotonic_ns'], ('reference before seed', family))
            ref_bindings.append({'family': family, 'report': identity(raw), 'reference_sha256': worker['reference_sha256'],
                'source_manifest_sha256': manifest_digest, 'worker_pid': worker['worker_pid'],
                'completed_before_B0': True, 'returncode': process['returncode']})

        generation_bindings = []
        for field in ('generations', 'modified_generations'):
            require(len(qualification[field]) == 3, ('three compiler images', field))
            for receipt in qualification[field]:
                label = receipt['case']
                image_relative = 'hia-cold.cold/qualification.evidence/' + label + '.image.bin'
                receipt_relative = 'hia-cold.cold/qualification.evidence/' + label + '.receipt.json'
                saved = original_json(receipt_relative)
                require(saved == receipt, ('generation full receipt', label))
                image = rows[image_relative]
                require(image['bytes'] == receipt['produced_bytes'] and image['sha256'] == receipt['produced_sha256'],
                        ('actual generation image bytes', label))
                require(receipt['status'] == 'returned' and receipt['abi_status'] == 0
                        and receipt['source_unchanged'] is True and receipt['forbidden_compiler_modules_loaded'] == [],
                        ('actual generation receipt status', label))
                generation_bindings.append({'case': label, 'path': image_relative,
                    'bytes': image['bytes'], 'sha256': image['sha256'], 'git_blob': image['git_blob']})
        require([r['produced_sha256'] for r in qualification['generations']] == cold['generation_sha256'], 'B chain outer equality')
        require([r['produced_sha256'] for r in qualification['modified_generations']] == cold['modified_generation_sha256'], 'M chain outer equality')
        require(len(set(cold['generation_sha256'])) == 1
                and cold['modified_generation_sha256'][0] != cold['modified_generation_sha256'][1]
                and cold['modified_generation_sha256'][1] == cold['modified_generation_sha256'][2]
                and cold['generation_sha256'][2] != cold['modified_generation_sha256'][2],
                'original B1=B2=B3 and deliberate M1!=M2=M3 fixed-point contract')
        wire_row = outer['wire.zip']['members'][0]
        require(wire_row['path'] == 'hia-cold.json' and wire_row['sha256'] == rows['hia-cold.json']['sha256']
                and (ROOT / 'restored/wire/hia-cold.json').read_bytes() == original_bytes('hia-cold.json'), 'wire artifact holds only same cold report')
        result['cold'] = {'status': cold['status'], 'outer_checks': 11, 'inner_status': qualification['status'],
            'inner_checks': 5052, 'source_count': 1430, 'qualification_seconds': 180, 'cleanup_seconds': 3,
            'wrapper_wall_seconds': cold['wall_elapsed_ns'] / 1e9,
            'qualification_elapsed_seconds': qualification['elapsed_ns'] / 1e9,
            'owner_event_elapsed_seconds': (exit_events[0]['monotonic_ns'] - start[0]['monotonic_ns']) / 1e9,
            'exit_observed_before_deadline': True, 'cleanup': cleanup,
            'historical_descendant_inventory_complete': owner['historical_descendant_inventory_complete'],
            'phase_count': 38, 'phase_pending_count': 0, 'independent_reference_workers': 17,
            'full_phase_archive_originals_verified': True,
            'generation_bindings': generation_bindings, 'phases': phase_bindings, 'references': ref_bindings,
            'qualification_scope': qualification['scope'], 'whole_stack_native': False}

        language_bytes = original_bytes('hia-language.json')
        language, assertions = json.loads(language_bytes), original_json('hia-language.assertions.json')
        require(language['status'] == 'SELFHOST_LANGUAGE_COVERAGE_PASS'
                and all(value is True for value in language['checks'].values()), 'language original pass')
        require(assertions['passed'] is True and assertions['tests_run'] == 10
                and assertions['report_sha256'] == sha256(language_bytes).hexdigest()
                and assertions['failures'] == assertions['errors'] == assertions['skipped'] == [], 'language original assertion gate')
        launch = original_json('hia-release-launch-matching-cold/REPORT.json')
        require(launch['status'] == 'MATCHING_SOURCE_COLD_RELEASE_LAUNCH_PASS' and launch['qualification_complete'] is True
                and launch['matching_cold'] is True and launch['expected_count'] == 26, 'launcher original report')
        launch_ids = []
        for group, expected in zip(launch['groups'], (21, 5), strict=True):
            observation, terminal = group['observations'], group['terminal']
            require(group['status'] == observation['status'] == terminal['status'] == 'PASS'
                    and observation['tests_run'] == expected and len(observation['loaded_ids']) == expected
                    and observation['loaded_ids'] == observation['executed_ids']
                    and all(value == [] for value in observation['anomalies'].values())
                    and terminal['returncode'] == 0 and terminal['timed_out'] is False, 'launcher strict original group')
            launch_ids.extend(observation['executed_ids'])
        # The original qualifier deliberately partitions its fixed discovery list into
        # 21 local observations followed by 5 required ptrace observations.
        import ast
        launcher_author = ast.parse(original_bytes('hia-cold.cold/source/tools/qualify_hia_release_launch.py'))
        fixed_ids = [ast.literal_eval(node.value) for node in launcher_author.body
                     if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                         and target.id == 'EXPECTED_IDS' for target in node.targets)]
        require(len(fixed_ids) == 1 and list(fixed_ids[0]) == launch['expected_ids'],
                'launcher full fixed original expected IDs')
        ptrace = [value for value in launch['expected_ids'] if '.ReleaseLaunchSyscallFaultTests.' in value
                  or value.endswith('.test_actual_trace_seals_readback_single_exec_and_descriptor_cleanup')]
        local = [value for value in launch['expected_ids'] if value not in ptrace]
        require([g['group'] for g in launch['groups']] == ['local-observations', 'required-ptrace']
                and launch['groups'][0]['observations']['loaded_ids'] == local
                and launch['groups'][1]['observations']['loaded_ids'] == ptrace
                and launch_ids == local + ptrace and len(set(launch_ids)) == 26,
                'launcher exact original ordered 21 + 5 partition')
        candidate = original_json('hia-candidate-build/QUALIFICATION.json')
        require(candidate['status'] == 'MATCHING_COLD_CANDIDATE_BUILD_COMPONENTS_PASS'
                and candidate['qualification_complete'] is True and candidate['matching_cold'] is True
                and candidate['tests_run'] == 9 and len(candidate['loaded_ids']) == 9
                and candidate['loaded_ids'] == candidate['started_ids'] == candidate['stopped_ids'], 'candidate original nine')
        require(candidate['actual']['canonical_image_and_manifest_pairs'] == 55
                and candidate['actual']['native_process_observations'] == 75
                and candidate['actual']['independent_vm_full_frames'] == 69, 'candidate original observation counts')
        store_ids = [row for row in source_ids(native_lines)
                     if '.StoreLifecycleNativeTests.' in row['id']]
        require(len(store_ids) == 8 and 'Ran 8 tests in 34.612s' in native_lines, 'Store actual eight original tests')
        agent = original_json('hia-store-lifecycle-agent/report.json')
        agent_original = original_json('hia-store-lifecycle-agent/original-agent-48.json')
        require(agent['original_agent'] == agent_original and agent['status'] == 'MATCHING_SOURCE_COLD_CALLERS_PASS'
                and agent['expected_count'] == 48 and agent_original['status'] == 'PASS'
                and agent_original['tests_run'] == 48 and len(agent_original['loaded_ids']) == 48
                and agent_original['loaded_ids'] == agent_original['executed_ids'], 'Store actual original 48 callers')
        require(all(agent_original[key] == [] for key in ('errors', 'failures', 'skips', 'expected_failures', 'unexpected_successes')),
                'Store Agent 48 anomaly arrays')
        result['completed_native_groups'] = {'call_graph_native': {'tests': 2, 'unittest_seconds': 4.382},
            'language': {'checks': len(language['checks']), 'assertions': 10, 'status': language['status']},
            'release_launch': {'tests': 26, 'group_sizes': [21, 5], 'matching_cold': True},
            'candidate_build': {'tests': 9, 'images': 55, 'process_observations': 75, 'vm_frames': 69, 'matching_cold': True},
            'store_lifecycle': {'tests': 8, 'unittest_seconds': 34.612, 'actual_ordered_log_ids': store_ids},
            'store_agent_callers': {'tests': 48, 'machine_returns': agent_original['actual_machine_returns'],
                                    'mappings': agent_original['actual_mappings']}}
        namespace = original_json('hia-store-lifecycle-namespace/report.json')
        child = original_json('hia-store-lifecycle-namespace/original-agent-48.json')
        require(namespace['status'] == child['status'] == 'FAIL' and namespace['expected_count'] == child['tests_run'] == 1
                and namespace['nested_expected_count'] == 35, 'namespace original outer failure')
        require(namespace['original_agent'] == child and len(child['failures']) == 1
                and child['errors'] == child['skips'] == child['expected_failures'] == child['unexpected_successes'] == [],
                'namespace exact one failure without errors/skips')
        require(len(child['nested_results']) == 1, 'namespace one nested original suite')
        inner = child['nested_results'][0]
        require(inner['tests_run'] == 35 and len(inner['loaded_ids']) == 35 and len(inner['failures']) == 3
                and inner['errors'] == inner['skips'] == inner['expected_failures'] == inner['unexpected_successes'] == [],
                'namespace exact nested original result')
        failures_text = json.dumps(inner['failures'], sort_keys=True)
        require('5.7218977530000075 not less than 5' in failures_text
                and failures_text.count('frozen context deadline expired before emission') == 2, 'three original failure facts')
        require(namespace['terminal']['returncode'] == 1 and namespace['terminal']['timed_out'] is False
                and namespace['terminal']['timeout_seconds'] == 1800 and namespace['group_limit_seconds'] == 1800
                and namespace['compiler_child_limit_seconds'] == 20 and namespace['original_test_budgets_changed'] is False,
                'namespace original limits and non-timeout terminal')
        result['native_failure'] = {'step': 15, 'step_name': failed_steps[0]['name'],
            'status': 'FAIL', 'outer_tests_run': 1, 'outer_failures': child['failures'],
            'outer_loaded_ids': child['loaded_ids'], 'outer_executed_ids': child['executed_ids'],
            'nested_tests_run': 35, 'nested_original_loaded_ids': inner['loaded_ids'],
            'nested_failures': inner['failures'], 'nested_errors': [],
            'group_limit_seconds': 1800, 'compiler_child_limit_seconds': 20,
            'original_budget_policy_unchanged': True, 'terminal': namespace['terminal'],
            'source_and_inputs_unchanged': namespace['source_and_inputs_unchanged'],
            'whole_native': False, 'later_skipped_api_steps': 103}
        result['wire_artifact'] = {'members': 1, 'same_cold_report_bytes': True,
            'does_not_establish_json_wire_tests_ran': True}
        result['original_evidence_bindings'] = dump('SELECTED-ORIGINAL-BINDINGS.json', bindings)
        result['restoration'] = {'outer_members': restoration['outer_member_count'],
            'nested_archives': restoration['nested_archive_count'], 'nested_members': restoration['nested_member_count'],
            'original_inputs_unchanged': True, 'native_actual_unix_file_modes': outer['native.zip']['mode_counts'],
            'directory_modes': 'No outer ZIP directory entries; original directory modes are NOT_RECORDED. Restored directories are local 0700 only.'}
        result['status'] = 'ORIGINAL_EVIDENCE_READBACK_PASS_NATIVE_QUALIFICATION_FAIL_PRESERVED'
    except BaseException:
        result['status'] = 'EVIDENCE_READBACK_ERROR'
        result['failures'].append(traceback.format_exc())
        raise
    finally:
        result['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
        dump('ANALYSIS-RESULT.json', result)
        print(json.dumps({key: result.get(key) for key in ('status', 'source', 'restoration', 'product_tests_executed', 'product_refs_changed')}, sort_keys=True))


if __name__ == '__main__':
    OUTPUT.mkdir()
    main()
