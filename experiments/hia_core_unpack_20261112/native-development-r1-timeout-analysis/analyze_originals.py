"""Read only the fixed failed run's small originals; never import product code."""
from pathlib import Path
import ast
import hashlib
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parent
SOURCE = Path('/tmp/hia-core-unpack-v83-20261112-r1/source')
ARCHIVE = Path('/workspace/scratch/e26ed3e2edcf/root/core-unpack-v83-native-r1/artifact-13940526186.original.zip')
PREFIX = 'hia-core-unpack-native-development-r1/'


def pin(raw):
    return {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def save(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    (ROOT / name).write_bytes(raw)
    return pin(raw)


def assignments(path):
    return {node.targets[0].id: ast.literal_eval(node.value)
            for node in ast.parse(path.read_bytes()).body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in ('COMPONENT_IDS', 'ORIGINAL_IDS', 'CORE_IDS')}


def main():
    expected = assignments(SOURCE / 'tools/qualify_hia_core_lowering_callers.py')
    guardians = ROOT / 'tests-guard/guardian.json'
    guardian = json.loads(guardians.read_bytes())
    request = json.loads((ROOT / 'tests-guard/request.json').read_bytes())
    final = json.loads((ROOT / 'FINAL.json').read_bytes())
    source_files = (
        'hepta/hia_program_native.py', 'hepta/hia_core_lowering_native.py',
        'hepta/hia_core_lowering_selection.py', 'hepta/hia_core_unpack_native.py',
        'hepta/hia_core_unpack_selection.py', 'tools/generate_hia_core_unpack.py',
        'tools/qualify_hia_core_lowering_callers.py',
        'tools/qualify_hia_core_unpack_callers.py',
        'tests/test_hia_machine_lowering_edges.py',
        'tests/test_hia_program_native_review.py')
    source_rows = []
    for relative in source_files:
        raw = (SOURCE / relative).read_bytes()
        entry = pin(raw)
        paths = [p for p in request['source_identities'] if p.endswith('/source/' + relative)]
        assert len(paths) == 1, relative
        path = paths[0]
        assert all(x == entry['sha256'] for x in (
            request['source_identities'][path], guardian['source_identities_before'][path],
            guardian['source_identities_after'][path])), relative
        source_rows.append(dict(path=relative, actual_runtime_path=path,
                                request_and_guardian_before_after_equal=True, **entry))

    selected = ['tests-guard/guardian.json', 'tests-guard/request.json', 'FINAL.json',
                'callers/core-callers/component-fixture/installed-control/report.json']
    groups = []
    member_pins = []
    with zipfile.ZipFile(ARCHIVE) as archive:
        assert len(archive.infolist()) == 1550
        for label, key in (('component', 'COMPONENT_IDS'), ('original-machine', 'ORIGINAL_IDS'),
                           ('original-core', 'CORE_IDS')):
            relative = 'callers/core-callers/' + label + '.unittest.log'
            raw = archive.read(PREFIX + relative)  # zipfile validates this member's CRC.
            assert raw == (ROOT / relative).read_bytes()
            text = raw.decode('utf-8')
            ids = re.findall(r'^test_[^ ]+ \(([^\n)]+)\) \.\.\. ok$', text, re.M)
            assert ids == expected[key][:len(ids)]
            descriptions = re.findall(r'^test_[^ ]+ \(([^\n)]+)\) \.\.\. ', text, re.M)
            assert descriptions == ids  # There is no printed unfinished next method.
            summary = re.search(r'^Ran ([0-9]+) tests in ([0-9.]+)s$', text, re.M)
            item = {'label': label, 'expected_ids': expected[key], 'ok_ids': ids,
                    'observed_ok_count': len(ids), 'log': relative, **pin(raw),
                    'complete_summary': summary is not None,
                    'printed_unfinished_method': None,
                    'unobserved_ids': expected[key][len(ids):],
                    'zip_mtime_wall_2s_precision': list(archive.getinfo(PREFIX + relative).date_time)}
            if summary:
                assert int(summary[1]) == len(expected[key]) and text.endswith('\nOK\n')
                item['unittest_seconds'] = float(summary[2])
            groups.append(item)
            selected.append(relative)
        for relative in selected:
            raw = archive.read(PREFIX + relative)
            assert raw == (ROOT / relative).read_bytes()
            member_pins.append(dict(path=relative, zip_crc_verified_for_this_member=True, **pin(raw)))
        report_path = PREFIX + 'callers/core-callers/report.json'
        companion_report_path = PREFIX + 'callers/report.json'
        report_presence = {p: p in archive.namelist() for p in (report_path, companion_report_path)}

    assert [g['observed_ok_count'] for g in groups] == [15, 51, 28]
    life = guardian['lifecycle']
    assert guardian['status'] == 'HOLD' and life['status'] == 'QUALIFICATION_TIMEOUT'
    assert life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3
    assert life['timed_out'] is True and life['returncode'] == -9
    cleanup = life['cleanup']
    assert cleanup['complete'] and cleanup['leader_reaped'] and cleanup['observed_echild']
    assert cleanup['remaining_direct_children'] == [] and cleanup['errors'] == []
    events = life['events']
    kills = [x for x in events if x['kind'] == 'owned_child_sigkill']
    assert len(kills) == 1
    assert guardian['input_identity_preserved'] and final['status'] == 'HOLD'
    installed = json.loads((ROOT / selected[3]).read_bytes())
    original_facts = {
        'run_id': 43207324933, 'job_id': 131145694244, 'attempt': 1,
        'candidate_commit': '006accd3d73d48b9ef39c821be55a5346cd48ce0',
        'A': '418062f8d4771e09e4f5acd8e6ecd05ff4612fd6',
        'B': '7207a911aa9c7f6f218f70d145b3c87ec5d54e91',
        'archive': {'path': str(ARCHIVE), 'size': ARCHIVE.stat().st_size,
                    'sha256_reported_and_verified_by_parent': '7b963b2db27ca29a62ad8090d20b78589c3e27945bd067d2cf3e8f9c590d29a6',
                    'whole_archive_digest_recomputed_by_this_analysis': False,
                    'central_directory_members': 1550},
        'selected_member_pins': member_pins, 'source_identity_joins': source_rows,
        'groups': groups, 'complete_caller_report_presence': report_presence,
        'owner': {'status': life['status'], 'limit': life['qualification_seconds'],
                  'cleanup_limit': life['cleanup_seconds'], 'returncode': life['returncode'],
                  'timed_out': life['timed_out'], 'events': events, 'cleanup': cleanup,
                  'input_identity_preserved': guardian['input_identity_preserved']},
        'installed_only': {'status': installed['status'],
                           'actual_core_native_steps': installed['actual_native_steps'],
                           'unpack_observations': installed['unpack_observations'],
                           'not_evidence_of_complete_116': True},
        'completed_textual_methods': 94, 'remaining_unobserved_methods': 22,
        'progress_limit': ('No next method description was printed. Official 3.14.4 TestSuite.run '
                           'performs prior-class teardown, module fixture handling and next-class '
                           'setup before TestCase.startTest. The next substantive custom fixture '
                           'is MachineLoweringEdgeTests.setUpClass. These files do not identify '
                           'a specific instruction, which of its five documents, or exact duration.'),
        'legacy_result_preserved': 'HOLD/timeout; no full116 PASS; first42/18 phase conclusions remain separate'}

    normal_paths = []
    for n in range(1, 5):
        opcodes = [1] + [2] * (n + 1) + [9, 11] + [12] * n + [13, 9]
        assert len(opcodes) == 2 * n + 6
        normal_paths.append({'arity': n, 'primitive_opcodes': opcodes,
                             'effects': len(opcodes), 'HIA_step_returns': 2 * n + 7,
                             'transaction_shim_calls': 2 * n + 5,
                             'native_boundary_calls_total': 4 * n + 12,
                             'C_API_calls_inside_transactions': 3 * (2 * n + 5)})
    static_findings = {
        'classification': 'SOURCE_DERIVED_COST_STRUCTURE_NOT_A_TIME_PROFILE',
        'normal_successful_unpack': normal_paths,
        'one_unpack_fresh_raw_buffer_bytes': 832,
        'fresh_buffers': {'cells': 80, 'transaction': 112, 'workspace': 256, 'output': 256, 'input': 128},
        'per_request_output_clear_word_count': 32,
        'per_request_output_clear_byte_stores': 256,
        'entry_type_factory': {
            'source': 'hepta/hia_core_unpack_native.py:UnpackSession.__init__',
            'operation': 'ctypes.PYFUNCTYPE(c_uint64, *(c_void_p,c_uint64)*3)(address)',
            'frequency': 'once per fresh UNPACK session',
            'official_source': 'references/cpython-v3.14.4/Lib/ctypes/__init__.py:PYFUNCTYPE',
            'fact': 'PYFUNCTYPE defines a new CFunctionType class on every call and has no cache.',
            'time_fraction_measured': False,
            'minimal_candidate': ('Cache the fixed six-argument function-pointer TYPE only; '
                                  'continue to read each actual image._entry address and instantiate '
                                  'a new pointer object per session. Preserve fresh buffers, GIL/error '
                                  'flags, all HIA bytes and each requested primitive.')},
        'not_per_unpack_mmap': ('NativeUnpack and CpythonLeaves are created by cached _load. '
                               'CpythonLeaves mmap/mprotect is per newly admitted owner, not each '
                               'ordinary session. It must not be described as the proven per-unpack cost.'),
        'qualification_costs_unmeasured': [
            'Outer opcode14 attempt/normal/exception Counters and ContextVar set/reset.',
            'Every actual UNPACK step adds its per-image/status Counter after the real native return.',
            'Every session also appends its low-level actual_steps and actual_primitives lists.',
            'Existing outer Core step ledger remains active; its own cost is not newly attributed to UNPACK.'
        ],
        'edge_fixture_expected_work_if_completed': {
            'source': 'tests/test_hia_machine_lowering_edges.py:setUpClass',
            'documents_in_order': ['arith', 'other', 'cast_checked', 'cast_wrap', 'control'],
            'function_count_arithmetic': 10 * 3 * 2,
            'function_count_other': 10 * (4 + 1 + 6),
            'function_count_each_cast': 10 * 10,
            'function_count_control': 5,
            'total_function_definitions': 375,
            'ordinary_emits_per_document': 2,
            'second_emit_reason': 'compile_program_machine re-emits to compare origin before linking',
            'total_function_emissions_if_completed': 750,
            'large_frame_operations': 700 + 699,
            'status': 'Static fixture construction facts; no claim all these operations ran before timeout.'},
        'not_changed_or_waived': ['116 exact IDs', 'owner180/3', 'all cold/compiler limits',
                                'source admission', 'foreign n+1 iteration', 'release/error order',
                                'old host UNPACK poison', 'all qualification ledgers'],
        'remaining_unknown': ['exact operation alive at kill', 'actual total UNPACK count before kill',
                              'per-phase native/bridge/ledger time fractions',
                              'how much time the type-only cache will save',
                              'whether that alone suffices for complete116 in180s']}
    save('ORIGINAL-READBACK.json', original_facts)
    save('STATIC-COST-ANALYSIS.json', static_findings)
    print(json.dumps({'readback': '94 completed textual methods;22 unobserved;original timeout preserved',
                      'source_joins': len(source_rows), 'product_executions': 0,
                      'source_imports': 0, 'whole_archive_extracted': False}))


if __name__ == '__main__':
    main()
