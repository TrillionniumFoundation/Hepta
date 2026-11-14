"""Independently verify complete original report bytes; no product execution."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import stat
import zipfile

ROOT = Path(__file__).resolve().parent
BASE = Path('/workspace/scratch/dda74a4fae35')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def tree_id(files):
    nested = {}
    for path, row in files.items():
        parts = PurePosixPath(path).parts
        assert parts and not path.startswith('/') and '..' not in parts
        node = nested
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        assert row['git_mode'] in ('100644', '100755')
        node[parts[-1]] = (row['git_mode'], row['git_blob'])
    def encode(node):
        rows = []
        for name, value in node.items():
            mode, sha = ('40000', encode(value)) if isinstance(value, dict) else value
            rows.append((name, mode, sha))
        raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
                       for name, mode, sha in sorted(rows, key=lambda row: (row[0] + ('/' if row[1] == '40000' else '')).encode()))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return encode(nested)


def main():
    received = json.loads((ROOT / 'REPORTS-ZIP-MANIFEST.json').read_bytes())
    assert received['status'] == 'COMPLETE_REPORTS_ZIP_SHA_GIT_EVERY_MEMBER_SHA_GIT_CRC_PASS'
    assert received['zip']['sha256'] == 'c7cc9ebf536332fb72b2f7f3f7fc62f879f4c40271f386717193f9da723a3594'
    metadata = {row['path']: row for row in received['members']}
    original_pins, selected_reads = {}, []
    with zipfile.ZipFile(ROOT / 'reports.zip') as archive:
        def raw_member(name):
            raw = archive.read(name)
            assert all(metadata[name][key] == value for key, value in pin(raw).items())
            return raw
        selected = json.loads(raw_member('SELECTED-ORIGINALS.json'))
        node_raw = raw_member('original/NODE-MANIFEST.json')
        assert pin(node_raw) == selected['manifest_identity']
        nodes_list = json.loads(node_raw)
        nodes = {row['path']: row for row in nodes_list}
        assert len(nodes) == len(nodes_list) == selected['logical_nodes'] == 11421
        assert sum(row['kind'] == 'file' for row in nodes_list) == selected['all_manifest_file_identities_verified'] == 4941
        entries = {row['logical_path']: row for row in selected['reports']}
        assert len(entries) == len(selected['reports']) == 98
        for logical, row in entries.items():
            record = row['record']
            assert record == nodes[logical] and record['kind'] == 'file'
            assert row['ZIP_member'] == 'retained/' + record['storage_path']
            raw = raw_member(row['output'])
            assert all(record[key] == value for key, value in pin(raw).items())
            assert record['mode'] == stat.S_IMODE(record['stat_before']['st_mode']) == stat.S_IMODE(record['stat_after']['st_mode'])
            original_pins[logical] = dict(pin(raw), mode=record['mode'], reports_ZIP_member=row['output'])
            selected_reads.append(logical)
        def original(name):
            return json.loads(raw_member(entries[name]['output']))
        prefix = 'scope/evidence/full-qualification-r2/'
        outer = original(prefix + 'OUTER.json')
        owner = original(prefix + 'OWNER.json')
        returned = original(prefix + 'OWNER-RETURNED.json')
        child = original(prefix + 'RESULT.json')
        qualification = original(prefix + 'qualification.json')
        plan = original(prefix + 'PLAN.json')
        unbound_plan = original('evidence/bind/ORIGINAL-full.json')
        launch_exit = original('evidence/launch/PROCESS-EXIT.json')
        launch_result = original('evidence/launch/RESULT.json')
        assert outer['status'] == child['status'] == 'PASS_EXPLICIT_U32_FULL_QUALIFICATION_ONLY'
        assert outer['child'] == child and outer['owner'] == returned
        assert outer['owner_launch_intents'] == 1 and outer['product_retries'] == 0
        assert outer['finalization_errors'] == child['finalization_errors'] == []
        assert outer['whole'] is child['whole'] is False
        assert outer['matching_current_new_cold'] is child['matching_current_new_cold'] is False
        assert set(returned) - set(owner) == {'receipt_sha256', 'supervisor_returncode'}
        assert {key: returned[key] for key in owner} == owner
        assert returned['receipt_sha256'] == original_pins[prefix + 'OWNER.json']['sha256']
        assert returned['supervisor_returncode'] == 0
        assert owner['status'] == 'OWNED_PROCESS_COMPLETED' and owner['returncode'] == 0
        assert owner['qualification_seconds'] == 180 and owner['cleanup_seconds'] == 3
        assert owner['timed_out'] is False and owner['exit_observed_before_deadline'] is True
        assert owner['event_overflow'] is False and owner['interrupted_signals'] == []
        cleanup = owner['cleanup']
        assert cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
        assert cleanup['deadline_exceeded'] is False and cleanup['remaining_direct_children'] == cleanup['errors'] == []
        assert 0 <= cleanup['elapsed_ns'] < 3_000_000_000
        assert launch_exit['returncode'] == 0 and launch_exit['product_invocations'] == 1
        assert launch_result['status'] == 'ORIGINAL_R2_PROCESS_AND_OUTER_PASS_FIXED_SCOPE_ONLY' and launch_result['exit_code'] == 0
        inventory_path = BASE / 'v121-selfhost-small-constant-r1/authoring/full-qualification-plan-r1/ORIGINAL-5052-INVENTORY.json'
        inventory_raw = inventory_path.read_bytes()
        assert all(plan['original_inventory']['identity'][key] == value for key, value in pin(inventory_raw).items())
        inventory = json.loads(inventory_raw)
        checks = qualification['checks']
        assert type(checks) is dict and len(checks) == 5052 and sorted(checks) == inventory['original_checks']
        assert all(type(value) is bool and value is True for value in checks.values())
        assert qualification['status'] == 'U32_ENCODING_FULL_QUALIFICATION_PASS'
        assert qualification['schema'] == 'hepta.hia.selfhost-u32-qualification.v1'
        assert qualification['profile'] == plan['encoding_profile']
        assert qualification['source_sha256'] == plan['new_source']['identity']['sha256']
        assert qualification['source_bytes'] == plan['new_source']['identity']['bytes'] == 466876
        assert all(child['report'][key] == value for key, value in original_pins[prefix + 'qualification.json'].items() if key in ('bytes', 'sha256', 'git_blob', 'mode'))
        scheduling = qualification['qualification_scheduling']
        assert scheduling['phase_inventory'] == inventory['phase_inventory']
        assert len(scheduling['phases']) == 38
        assert [[row['family'], row['compiler_label']] for row in scheduling['phases']] == plan['phase_schedule'] == unbound_plan['phase_schedule']
        references = scheduling['reference_processes']
        assert len(references) == len({row['worker_pid'] for row in references}) == 17
        assert [row['family'] for row in references] == plan['reference_schedule'] == unbound_plan['reference_schedule']
        assert all(row['returncode'] == 0 and row['completed_monotonic_ns'] <= scheduling['seed_started_monotonic_ns'] for row in references)
        for key, value in {'maximum_host_oracle_workers': 2, 'maximum_archive_workers': 1,
                           'maximum_pending_archives': 2, 'maximum_unsealed_phase_directories': 4,
                           'phase_completed_only_after_verified_archive': True,
                           'native_child_processes_reused': False}.items():
            assert scheduling[key] == value
        assert plan['budgets'] == unbound_plan['budgets']
        images = qualification['generations']
        assert [row['case'] for row in images] == ['B1', 'B2', 'B3']
        assert all(row['produced_bytes'] == plan['previous_observed_new_B3_identity']['bytes']
                   and row['produced_sha256'] == plan['previous_observed_new_B3_identity']['sha256']
                   and row['source_unchanged'] is True and row['forbidden_compiler_modules_loaded'] == [] for row in images)
        sources = [original(prefix + name) for name in ('SOURCE-BEFORE.json', 'SOURCE-AFTER.json', 'SOURCE-PREFLIGHT.json', 'SOURCE-OUTER-AFTER.json')]
        assert all(row == sources[0] for row in sources)
        assert len(sources[0]) == plan['source_files'] == 3180
        source_tree = tree_id(sources[0])
        assert source_tree == plan['source_tree'] == '4c62be4ed66ff107fa6f88c6131313a354868bd9'
        scope = PurePosixPath(plan['evidence']).parents[1]
        assert PurePosixPath(plan['evidence']) == scope / 'evidence/full-qualification-r2'
        source_prefix = 'scope/' + str(PurePosixPath(plan['source_root']).relative_to(scope)) + '/'
        actual_node_source_files = {name[len(source_prefix):]: row for name, row in nodes.items() if name.startswith(source_prefix) and row['kind'] == 'file'}
        assert set(actual_node_source_files) == set(sources[0])
        for name, row in sources[0].items():
            node = actual_node_source_files[name]
            assert all(node[key] == row[key] for key in ('bytes', 'sha256', 'git_blob', 'mode'))
        controls = [original(prefix + name) for name in ('CONTROLS-BEFORE.json', 'CONTROLS-AFTER.json', 'CONTROLS-PREFLIGHT.json', 'CONTROLS-OUTER-AFTER.json')]
        assert all(row == controls[0] for row in controls)
        assert original(prefix + 'ORIGINAL-FUNCTIONS-BEFORE.json') == original(prefix + 'FUNCTIONS-AFTER.json')
        bindings = original('evidence/bind/JSON-BINDING-READBACK.json')
        counts = {key: len(row['changes']) for key, row in bindings.items()}
        assert counts == {'full': 120, 'generation': 6, 'projection': 12, 'storage': 17} and sum(counts.values()) == 155
        runtime = original(prefix + 'RUNTIME-BEFORE.json')
        assert runtime['version'].startswith('3.14.4 ')
        frame_index = original(prefix + 'LOADER-FRAMES-AFTER.json')
        assert frame_index['after_frames_synthesized'] is False
        frames = {row['label']: row for row in frame_index['rows']}
        assert all(frames[label]['complete_actual_six_frames'] is True for label in ('B1', 'B2', 'B3', 'M1', 'M2', 'M3'))
        relay_result = json.loads(raw_member('RESULT.json'))
        transport = json.loads(raw_member('TRANSPORT.json'))
        assert relay_result['status'] == 'EXACT_ORIGINAL_ZIP_CUSTODY_COMPLETE_NO_PRODUCT_EXECUTION' and relay_result['exit_code'] == 0
        assert transport['original_bytes'] == 1270286664 and transport['original_sha256'] == 'f318593523cc6294e9507aae9ef351d64231a2ead829d325e2e563a96176fb02'
        assert transport['complete_expected_original'] is True and transport['original_ZIP_repacking_performed'] is False
        assert len(transport['parts']) == 10
        assert all(row['index'] == i and row['original_ZIP_offset'] == i * (128 << 20)
                   and row['bytes'] == min(128 << 20, 1270286664 - row['original_ZIP_offset']) for i, row in enumerate(transport['parts']))
        result = {'schema': 'hepta.u32.hosted-original-reports-independent-readback.v1',
            'status': 'FULL_ORIGINAL_REPORTS_5052_38_17_OWNER_AND_SOURCE_MANIFESTS_VERIFIED',
            'original_run': 43579403463, 'original_job': 132400693130,
            'original_head': 'de4afa1f7f4cb1fc2d5284965f7f2a7c55632d2a',
            'custody_run': 43582958164, 'reports_zip': received['zip'],
            'all_114_report_ZIP_members_bytes_CRC_verified': True,
            'complete_original_reports_read': len(entries), 'selected_originals': original_pins,
            'original_inventory': {'path': str(inventory_path), **pin(inventory_raw)},
            'original_5052_complete_sorted_ID_projection_equal': True,
            'checks': 5052, 'passing': 5052, 'failing': [], 'phases': 38,
            'complete_phase_order_equal': True, 'fresh_reference_processes': 17,
            'complete_reference_order_equal': True, 'all_references_completed_before_B0': True,
            'source_files': 3180, 'source_tree_from_all_four_complete_manifests': source_tree,
            'all_3180_source_metadata_equal_original_NODE_records': True,
            'source_bytes_independently_read_from_original_large_ZIP_in_this_report': False,
            'original_callable_before_after_equal': True, 'all_four_control_maps_equal': True,
            'actual_JSON_binding_counts': counts, 'original_budgets_equal': True,
            'owner': owner, 'outer_elapsed_ns': outer['elapsed_ns'], 'child_elapsed_ns': child['elapsed_ns'],
            'qualification_elapsed_ns': qualification['elapsed_ns'], 'runtime_version': runtime['version'],
            'six_generation_frame_indices_complete': True,
            'generation_raw_frames_independently_read_here': False,
            'B1_B2_B3_produced_bytes': images[0]['produced_bytes'],
            'B1_B2_B3_produced_sha256': images[0]['produced_sha256'],
            'scope': qualification['scope'], 'whole': False, 'matching_current_new_cold': False,
            'ordinary_encoding_and_entry_layout_separate_gates': 'NOT_RUN',
            'original_4945_large_ZIP_members_local_full_readback': 'PENDING_SPAN_RECEIVE',
            'product_executions_in_this_verifier': 0, 'original_run_mutations': 0}
    with (ROOT / 'ORIGINAL-REPORTS-INDEPENDENT-READBACK.json').open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('selected_originals', 'owner')}, sort_keys=True))


if __name__ == '__main__':
    main()
