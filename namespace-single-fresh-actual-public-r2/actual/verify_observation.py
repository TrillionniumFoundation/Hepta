"""Reconcile complete original diagnostic evidence; zero project execution."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parent
RAW = ROOT / 'raw/Hepta/Hepta'
E = RAW / 'evidence'
O = E / 'case-0/observations'
H = RAW / 'harness'
AUTHOR = Path('/tmp/hia-namespace-fresh-execution-r1-dda7/harness')

def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def read(path):
    return json.loads(path.read_bytes())

def main():
    manifest = read(ROOT / 'ZIP-MANIFEST.json')
    assert manifest['files'] == 27 and manifest['logical_bytes'] == 11917163
    for row in manifest['members']:
        path = ROOT / 'raw' / row['member']
        assert identity(path.read_bytes()) == {k: row[k] for k in ('bytes','sha256','git_blob')}
        assert stat.S_IMODE(path.stat().st_mode) == row['mode'] == 0o644
    author = read(ROOT.parent / 'HARNESS-MANIFEST.json')
    for row in author['files']:
        path = H / row['path']
        assert path.read_bytes() == (AUTHOR / row['path']).read_bytes()
        assert identity(path.read_bytes()) == {k: row[k] for k in ('bytes','sha256','git_blob')}
    assert sorted(p.relative_to(H).as_posix() for p in H.rglob('*') if p.is_file()) == sorted(row['path'] for row in author['files'])
    inputs = read(H / 'inputs/EXECUTION-INPUTS.json')
    expected = read(H / 'inputs/SOURCE-MANIFEST.json')
    expected_snapshot = {name: {'mode': row['git_mode'], **{k: row[k] for k in ('bytes','sha256','git_blob')}}
                         for name,row in expected.items()}
    source_snaps = [E / 'SOURCE-BEFORE.json', E / 'SOURCE-AFTER.json', O / 'SOURCE-BEFORE.json', O / 'SOURCE-AFTER.json']
    snapshots = [p.read_bytes() for p in source_snaps]
    assert len(set(snapshots)) == 1
    snapshot = json.loads(snapshots[0])
    assert snapshot['head'] == inputs['source_commit'] == '26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d'
    assert snapshot['tree'] == inputs['source_tree'] == '84df4b42f1e20fd7d0c7229e658cf3b458984ffb'
    assert snapshot['files'] == expected_snapshot and len(expected_snapshot) == 3177
    assert read(E / 'EXECUTION-FILES-BEFORE.json') == read(E / 'EXECUTION-FILES-AFTER.json') == inputs['execution_files']
    fresh = read(H / 'inputs/EXPECTED-FRESH-MAP.json')
    current = read(O / 'ACTUAL-CURRENT-SOURCES.json')
    support = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
    assert len(fresh) == 1551 and len(current) == 1552 and set(current) - set(fresh) == {support}
    assert current == {**fresh, support: expected[support]['sha256']}
    assert all(expected[name]['sha256'] == value for name,value in fresh.items())
    assert sum(expected[name]['bytes'] for name in fresh) == 58637295
    supervisor, child, process = read(E / 'REPORT.json'), read(O / 'REPORT.json'), read(E / 'case-0/PROCESS.json')
    assert supervisor['status'] == child['status'] == 'ONE_ORIGINAL_FRESH_OBSERVATION_COMPLETE'
    assert supervisor['process_launch_attempts'] == child['product_calls_attempted'] == 1
    assert supervisor['cases'][0]['process'] == process
    assert supervisor['cases'][0]['report_identity'] == identity((O / 'REPORT.json').read_bytes())
    assert process['returncode'] == 0 and process['timed_out'] is False and process['same_process_group_absent'] is True
    assert process['original_group_seconds'] == 1800 and process['cleanup_seconds'] == 3
    assert 0 < process['remaining_group_seconds'] <= 1800
    assert read(E / 'case-0/stdout.log') == child and (E / 'case-0/stderr.log').read_bytes() == b''
    for row in (supervisor, child):
        assert row['source_unchanged'] is True and row['qualification'] is False and row['whole_native'] is False
        assert row['automatic_retry'] is False and row['terminal_evidence_errors'] == []
    assert supervisor['execution_files_unchanged'] is True
    assert all(child[k] == 0 for k in ('Native','VM','compilers','product_tests'))
    assert child['actual_fresh_paths'] == 1551 and child['actual_current_sources_paths'] == 1552
    assert child['observer_cleanup_errors'] == [] and child['profile_is_original_none'] is True
    assert child['monitor_tool_released'] is True and child['bindings_and_function_definitions_unchanged'] is True
    data = read(O / 'ORDERED-EVENTS.json')
    assert data['incomplete_stack'] == [] and data['observer_errors'] == []
    intervals, events = data['intervals'], data['events']
    assert len(intervals) == 11410 and len(events) == 22820
    assert [row['sequence'] for row in intervals] == list(range(len(intervals)))
    stack, observed = [], set()
    previous_wall = previous_cpu = -1
    for index, event in enumerate(events):
        sequence, kind, target, wall, cpu = event
        assert sequence == index and wall >= previous_wall and cpu >= previous_cpu
        previous_wall, previous_cpu = wall, cpu
        row = intervals[target]
        if kind == 'begin':
            assert target not in observed
            observed.add(target)
            assert row['parent'] == (stack[-1] if stack else None)
            assert (row['wall_start_ns'],row['cpu_start_ns']) == (wall,cpu)
            stack.append(target)
        else:
            assert kind == 'end' and stack.pop() == target
            assert (row['wall_end_ns'],row['cpu_end_ns']) == (wall,cpu)
    assert not stack and len(observed) == len(intervals)
    totals, direct_children = {}, Counter()
    for row in intervals:
        wall, cpu = row['wall_end_ns']-row['wall_start_ns'], row['cpu_end_ns']-row['cpu_start_ns']
        assert wall >= 0 and cpu >= 0
        assert row['exit_event'] == ('return' if row['kind']=='python' else 'c_return')
        key = row['kind'] + ':' + row['name']
        target = totals.setdefault(key, {'calls':0,'inclusive_wall_ns':0,'inclusive_cpu_ns':0})
        target['calls'] += 1; target['inclusive_wall_ns'] += wall; target['inclusive_cpu_ns'] += cpu
        if row['parent'] is not None:
            direct_children[row['parent']] += wall
    components = read(O / 'COMPONENTS.json')
    assert totals == components['inclusive_totals']
    py = Counter(row['name'] for row in intervals if row['kind'] == 'python')
    fresh_c = Counter(row['name'] for row in intervals if row['kind'] == 'c' and row['fresh'])
    assert dict(py) == components['python_calls'] == {'current_sources':1,'validate_contract':1,
        'support_contract':1,'file_digests':1,'_source_protocol_current':1823,
        '_source_relative_name':271,'_source_lexical_read':1551}
    assert dict(fresh_c) == components['fresh_c_calls'] == {name:1551 for name in ('open','read','context_exit','sha256','hexdigest')}
    residuals = [{'sequence':r['sequence'],'name':r['name'],'unlabelled_wall_residual_ns':
        r['wall_end_ns']-r['wall_start_ns']-direct_children[r['sequence']]}
        for r in intervals if r['kind']=='python']
    assert residuals == components['residuals'] and all(r['unlabelled_wall_residual_ns']>=0 for r in residuals)
    lexical = [r for r in intervals if r['name']=='_source_lexical_read']
    assert all(r['return_type']=='bytes' for r in lexical)
    assert sum(r['return_length'] for r in lexical)==58637295
    guards = [r for r in intervals if r['name']=='_source_protocol_current']
    assert len(guards)==1823 and all(r['fresh'] and r['guard_true'] is True for r in guards)
    per_file = {}
    for row in intervals:
        if row['kind']=='c' and row['fresh']:
            per_file.setdefault(row['ordinal'],Counter())[row['name']] += 1
    associations = []
    for ordinal,(name,row) in enumerate(zip(sorted(fresh),lexical,strict=True),1):
        assert row['ordinal']==ordinal and row['return_length']==expected[name]['bytes']
        assert dict(per_file[ordinal]) == {key:1 for key in ('open','read','context_exit','sha256','hexdigest')}
        associations.append({'ordinal':ordinal,'inferred_from_pinned_source_path':name,
            'observed_bytes_length':row['return_length'],'actual_path_argument_observed':False})
    assert components['inferred_path_associations']==associations
    first = next(r for r in data['line_events'] if r[0] == 1795)
    last = next(r for r in data['line_events'] if r[0] == 1800)
    assert components['inventory_statement_interval']=={'wall_start_ns':first[1],'cpu_start_ns':first[2],
        'wall_end_ns':last[1],'cpu_end_ns':last[2]}
    fresh_totals = {}
    for name in ('open','read','context_exit','sha256','hexdigest'):
        rows=[r for r in intervals if r['kind']=='c' and r['fresh'] and r['name']==name]
        fresh_totals[name]={'calls':len(rows),'inclusive_wall_ns':sum(r['wall_end_ns']-r['wall_start_ns'] for r in rows),
                            'inclusive_cpu_ns':sum(r['cpu_end_ns']-r['cpu_start_ns'] for r in rows)}
    summary={'schema':'hepta.namespace-single-fresh-complete-readback.v1','status':'COMPLETE_ORIGINAL_EVIDENCE_READBACK_PASS',
        'run_id':43595690951,'job_id':132449559860,'run_attempt':1,'head':'ce4a685248b49dab31b9740ced57b0c84a8363e8',
        'harness_tree':author['tree'],'harness_actual_files_exact':11,'source_head':snapshot['head'],'source_tree':snapshot['tree'],
        'source_manifest_entries':3177,'four_original_source_snapshot_bytes_identical':True,'fresh_paths':1551,
        'fresh_bytes':58637295,'current_sources_paths':1552,'guard_calls':1823,'lexical_returns':1551,
        'product_calls':1,'event_rows':22820,'complete_paired_intervals':11410,'line_events':len(data['line_events']),
        'fresh_c_totals':fresh_totals,'inclusive_totals':totals,'inventory_statement_wall_ns':last[1]-first[1],
        'inventory_statement_cpu_ns':last[2]-first[2],'group_elapsed_ns':supervisor['group_elapsed_ns'],
        'cleanup_scope':supervisor['supervision_scope'],'same_process_group_absent':True,
        'observer_errors':[],'source_and_bindings_unchanged':True,'original_zip':manifest['archive'],
        'original_zip_files':27,'original_zip_logical_bytes':11917163,'new_product_executions_during_readback':0,
        'qualification':False,'whole_native':False,'methodological_limits':child['methodological_limits']+
          ['Python inclusive, C inclusive, and LINE inventory intervals overlap and must not be added.',
           'Global callback overhead can disproportionately affect frequently called guards; these instrumented proportions are not achievable optimization gains.',
           'The four source snapshots are original recorded full path/bytes/mode/hash reports; this readback does not re-execute production or duplicate the source tree.'],
        'reports':{name:identity((E/name).read_bytes()) for name in ('REPORT.json','case-0/PROCESS.json',
            'case-0/observations/REPORT.json','case-0/observations/COMPONENTS.json','case-0/observations/ORDERED-EVENTS.json')}}
    target=ROOT/'ACTUAL-READBACK.json';target.open('x').write(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'status':summary['status'],'report':identity(target.read_bytes()),
        'current_sources_wall_ns':totals['python:current_sources']['inclusive_wall_ns'],
        'source_guards':1823,'events':22820,'intervals':11410,'fresh_c_totals':fresh_totals},sort_keys=True))

if __name__=='__main__':
    main()
