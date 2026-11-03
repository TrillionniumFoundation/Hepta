"""Four-process, nonaccepting compositional byte-facts CertPart02 diagnostic."""
import json
import os
from pathlib import Path
import time

from tools import check_core_syntax_staged as base
from tools import core_syntax_diagnostic_capture as collector
from tools import core_syntax_partition_sources as sources
from tools.check_guarded_slice_lean import require, theorem_inventory
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS

ROOT = base.ROOT
PROTOCOL = 'compositional-byte-facts-prefix-diagnostic-v1'
DIAGNOSTIC_NAMES = ('Baseline', 'SyntaxData', 'CertPart01', 'CertPart02')
CAPTURE_FILES = tuple('CertPart02'+s for s in ('.stdout', '.stderr', '.events.jsonl'))
LIVE_NAMES = ('RESULT.json',) + CAPTURE_FILES
PARENT_FILES = tuple(n+s for n in DIAGNOSTIC_NAMES[:3]
                     for s in ('.started.json', '.stdout', '.stderr', '.finished.json'))
PREPARATION = ('RUN.json', 'IDENTITY.json', 'original-manifest.json', 'transformation-manifest.json', 'diagnostic-manifest.json')
TARGET_INVENTORY = 'CertPart02.inventory.json'
STATUSES = ('diagnostic_completed', 'diagnostic_timeout', 'diagnostic_failed',
            'diagnostic_infrastructure_failed', 'diagnostic_output_limit')


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def _denials():
    return dict(diagnostic_only=True, kernel_core_syntax_connection_checked=False,
                actual_core_bridge_proved=False, python_exporter_refinement_proved=False,
                body_prefix_refinement_proved=False, all_edge_transfer_proved=False,
                obligations=[dict(id=n, status='unproved') for n, _ in OBLIGATIONS], **DENY)


def _evidence_budget(files):
    require(sum(len(files.get(n,b'')) for n in CAPTURE_FILES[:2]) <= collector.RAW_LIMIT,
            'raw evidence budget')
    require(len(files.get('RESULT.json',b''))+len(files.get(CAPTURE_FILES[2],b'')) <= collector.METADATA_LIMIT,
            'metadata evidence budget')
    display = sum(len(n.encode())+2+len(raw) for n, raw in files.items())
    require(sum(map(len, files.values()))+display <= base.MAX_DIAGNOSTIC,
            'durable plus display evidence budget')


def execute_diagnostic(executable, output_directory, prepared, proposal, diagnostic, identity, support,
                       source_reader, support_reader, expected_binary_sha,
                       run_process=base.capture_result, capture=None):
    from tools.core_byte_facts_diagnostic_sources import validate_diagnostic_sources
    # The complete acceptance input is independently checked before the derivative.
    require(prepared['manifest'].get('protocol') == sources.PROTOCOL, 'exact11 original required')
    # This validator begins with base.validate_plan on the complete exact11.
    validate_diagnostic_sources(prepared, proposal, diagnostic)
    require(tuple(s.name for s in diagnostic.stages) == DIAGNOSTIC_NAMES, 'exact four diagnostic stages')
    base._support_imports(prepared, support)
    root = base.SafeRoot(output_directory)
    allowed, frozen, accepted = set(), {}, {}
    report = dict(schema='hepta.hia.compositional-byte-facts-prefix-diagnostic.v1', protocol=PROTOCOL,
                  status='diagnostic_running', invocation_limit=4, invocations=0,
                  invocation_count_exact=True, stages=[],
                  not_scheduled=[s.name for s in prepared['stages'][4:]], **_denials())
    started = time.monotonic()
    module_root = Path(executable).parent.parent/'lib/lean'
    current = None

    def write(name, raw):
        root.write(name, raw)
        allowed.add(name)
        frozen[name] = base.digest(raw)

    def write_json(name, value):
        write(name, _encoded(value))

    def state(extra=()):
        require(not os.path.lexists(module_root/base.MODULE_PREFIX) and
                not os.path.lexists(module_root/(base.MODULE_PREFIX+'.olean')), 'module prefix shadows support')
        require(base.digest(Path(executable).read_bytes()) == expected_binary_sha, 'Lean binary changed')
        require(source_reader() == identity and support_reader(executable) == support, 'source/support changed')
        files = root.scan(allowed | set(extra))
        for name, digest in frozen.items():
            cap = base.MAX_MODULE if name.endswith('.olean') else base.MAX_SOURCE if name.endswith('.lean') else base.MAX_DIAGNOSTIC
            require(base.digest(root.read(name, cap)) == digest, 'frozen evidence changed: '+name)
        modules = {n:size for n,size in files.items() if n.endswith('.olean')}
        require(all(size <= base.MAX_MODULE for size in modules.values()) and
                sum(modules.values()) <= base.MAX_TOTAL_MODULE, 'module byte budget')
        return files

    try:
        write('original-manifest.json', prepared['manifest_json'].encode())
        write('transformation-manifest.json', proposal.manifest_json.encode())
        write('diagnostic-manifest.json', diagnostic.manifest_json.encode())
        write_json('IDENTITY.json', dict(source_sha256=identity, support_sha256=support,
                                       lean_binary_sha256=expected_binary_sha))
        write_json('RUN.json', dict(protocol=PROTOCOL, invocation_limit=4,
                                   original_manifest_sha256=prepared['manifest_sha256'],
                                   transformation_manifest_sha256=proposal.manifest_sha256,
                                   diagnostic_manifest_sha256=diagnostic.manifest_sha256,
                                   identity_sha256=frozen['IDENTITY.json']))
        source_bytes = 0
        # Every original and transformed source is retained byte-for-byte.
        # The first three transformed parents already live in the package;
        # downstream transformed sources remain outside Lean's import package.
        for stage in prepared['stages']:
            write('original/'+stage.name+'.lean', stage.source.encode())
            source_bytes += len(stage.source.encode())
        for index, stage in enumerate(proposal.stages):
            name = stage.module_name.replace('.', '/')+'.lean' if index < 3 else 'transformed/'+stage.name+'.lean'
            write(name, stage.source.encode())
            source_bytes += len(stage.source.encode())
        stage = diagnostic.stages[3]
        write(stage.module_name.replace('.', '/')+'.lean', stage.source.encode())
        source_bytes += len(stage.source.encode())
        require(source_bytes <= base.MAX_TOTAL_SOURCE, 'retained source byte budget')
        state()
        for index, stage in enumerate(diagnostic.stages):
            require(index < 4 and report['invocations'] < 4, 'four-process hard launch boundary')
            require(time.monotonic()-started < base.LAUNCH_SECONDS, 'new-stage deadline')
            require(all(p in accepted for p in stage.parents), 'fresh same-run parent required')
            state()
            source_rel = stage.module_name.replace('.', '/')+'.lean'
            output_rel = stage.module_name.replace('.', '/')+'.olean'
            require(output_rel not in root.scan(allowed), 'fresh output required')
            current = dict(name=stage.name, source_sha256=stage.source_sha256,
                           parents={p:accepted[p] for p in stage.parents})
            if index < 3:
                write_json(stage.name+'.started.json', current)
                report['invocations'] += 1
                report['invocation_count_exact'] = False
                result = run_process(executable, root.path/source_rel, root.path/output_rel, root.path)
                report['invocation_count_exact'] = True
                require(type(result) is dict, 'parent process receipt missing')
                out, err = result.get('stdout','').encode(), result.get('stderr','').encode()
                require(len(out)+len(err) <= base.MAX_DIAGNOSTIC, 'parent diagnostic budget')
                write(stage.name+'.stdout',out); write(stage.name+'.stderr',err)
                state((output_rel,))
                require(type(result.get('returncode')) is int and result['returncode'] == 0 and
                        result.get('timed_out') is False and result.get('incomplete') is False and
                        result.get('output_truncated') is False, 'parent process incomplete or failed')
                inventory = theorem_inventory(out.decode()+err.decode(), set(stage.expected_theorems))
                raw = root.read(output_rel, base.MAX_MODULE)
                require(raw, 'empty parent module')
                allowed.add(output_rel)
                frozen[output_rel] = base.digest(raw)
                item = dict(path=output_rel, sha256=frozen[output_rel], bytes=len(raw),
                            source_sha256=stage.source_sha256)
                current.update(status='parent_checked', inventory=inventory, olean=item,
                               process={k:v for k,v in result.items() if k not in ('stdout','stderr')},
                               stdout_sha256=frozen[stage.name+'.stdout'], stderr_sha256=frozen[stage.name+'.stderr'])
                receipt = stage.name+'.finished.json'
                write_json(receipt, current)
                accepted[stage.module_name] = dict(item, receipt=receipt, receipt_sha256=frozen[receipt])
                report['stages'].append(dict(name=stage.name, status='parent_checked', receipt=receipt,
                                             receipt_sha256=frozen[receipt]))
                state()
                current = None
                continue
            report['invocations'] += 1
            report['invocation_count_exact'] = False
            result = (capture or collector.capture_result)(
                executable, root.path/source_rel, root.path/output_rel, root.path,
                safe_root=root, markers=diagnostic.manifest['markers'], target='CertPart02',
                manifest_reference=dict(path='diagnostic-manifest.json', sha256=diagnostic.manifest_sha256))
            require(type(result) is dict and type(result.get('process_started')) is bool, 'capture receipt missing')
            if not result['process_started']:
                report['invocations'] -= 1
            report['invocation_count_exact'] = True
            allowed.update(CAPTURE_FILES)
            existing = state((output_rel,))
            actual = {}
            for name in CAPTURE_FILES:
                if name in existing:
                    raw = root.read(name, base.MAX_DIAGNOSTIC)
                    actual[name] = dict(path=name, bytes=len(raw), sha256=base.digest(raw))
                    frozen[name] = base.digest(raw)
            require(type(result.get('files')) is dict and result['files'] == actual, 'capture file identity differs')
            require(result.get('raw_files') == {n:v for n,v in actual.items() if n != CAPTURE_FILES[2]},
                    'capture raw identity differs')
            require(result.get('status') in STATUSES, 'nonaccepting capture status required')
            event_bytes = actual.get(CAPTURE_FILES[2],{}).get('bytes',0)
            require(type(result.get('metadata_remaining_bytes')) is int and
                    result['metadata_remaining_bytes'] == collector.METADATA_LIMIT-event_bytes,
                    'capture metadata receipt differs')
            if result['process_started']:
                require(set(actual) == set(CAPTURE_FILES), 'incomplete capture files')
            # The target output is retained only as untrusted bytes. Never admitted.
            if output_rel in existing:
                frozen[output_rel] = base.digest(root.read(output_rel, base.MAX_MODULE))
                allowed.add(output_rel)
            if CAPTURE_FILES[2] in actual:
                _verify_capture(root,diagnostic.manifest_sha256,result)
            target_receipt = {}
            if result['status'] == 'diagnostic_completed':
                require(result['process_started'] and type(result.get('returncode')) is int and
                        result['returncode'] == 0 and result.get('leader_reaped') is True and
                        result.get('drain_complete') is True and result.get('output_truncated') is False and
                        result.get('cleanup_incomplete') is False, 'completed target process incomplete')
                log = ''.join(root.read(n,collector.RAW_LIMIT).decode('utf-8',errors='strict')
                              for n in CAPTURE_FILES[:2]).replace('\r\n','\n')
                inventory = theorem_inventory(log,set(stage.expected_theorems))
                write_json(TARGET_INVENTORY, dict(name=stage.name, diagnostic_only=True,
                    source_sha256=stage.source_sha256, inventory=inventory,
                    stdout_sha256=frozen[CAPTURE_FILES[0]], stderr_sha256=frozen[CAPTURE_FILES[1]]))
                target_receipt = dict(inventory_receipt=TARGET_INVENTORY,
                                      inventory_receipt_sha256=frozen[TARGET_INVENTORY])
            report['stages'].append(dict(name=stage.name, status=result['status'],
                                         process_started=result['process_started'], diagnostic_only=True,
                                         **target_receipt))
            report['status'] = result['status']
            current = None
            state()
    except Exception as error:
        report.update(status='diagnostic_failed', error_type=type(error).__name__, error=str(error)[:512])
        if current is not None:
            report['failed_stage'] = current['name']
            if current['name'] != 'CertPart02':
                current.update(status='failed', error_type=type(error).__name__, error=str(error)[:512])
                receipt = current['name']+'.finished.json'
                if receipt not in frozen:
                    write_json(receipt, current)
    finally:
        report['wall_seconds'] = time.monotonic()-started
        try:
            # Retain interrupted capture bytes and failed outputs as untrusted
            # evidence, never as successful parents. Do not overwrite any frozen hash.
            candidates = list(CAPTURE_FILES) + [s.module_name.replace('.', '/')+'.olean'
                                                for s in diagnostic.stages]
            for name in candidates:
                if name not in frozen:
                    try:
                        raw = root.read(name, base.MAX_MODULE if name.endswith('.olean') else base.MAX_DIAGNOSTIC)
                    except FileNotFoundError:
                        continue
                    frozen[name] = base.digest(raw)
            # Keep the original frozen hashes even on mutation failure. Presentation
            # must then refuse the entire evidence set, not bless the changed bytes.
            write_json('EVIDENCE.json', dict(protocol=PROTOCOL, sha256=dict(frozen)))
            report['evidence_sha256'] = frozen['EVIDENCE.json']
            live = {}
            for name in CAPTURE_FILES:
                try:
                    live[name] = root.read(name, base.MAX_DIAGNOSTIC)
                except FileNotFoundError:
                    pass
            live['RESULT.json'] = _encoded(report)
            _evidence_budget(live)
            root.write('RESULT.json', live['RESULT.json'])
        finally:
            root.close()
    return report


def source_identity():
    from tools.check_core_syntax_partitioned import source_identity as original
    result = original()
    for name in ('tools/diagnose_core_byte_facts.py', 'tools/core_byte_facts_diagnostic_sources.py',
                 'tools/core_byte_facts_sources.py', 'tools/core_byte_facts_dag.py',
                 'tools/core_byte_facts_verify.py',
                 'experiments/hia_initialization_frontiers_20261103/ByteFactsResearch.lean',
                 'tools/core_syntax_partition_diagnostic_sources.py',
                 'tools/core_syntax_diagnostic_capture.py', 'tools/core_syntax_declaration_diagnostic_sources.py',
                 '.github/workflows/hia-core-syntax-kernel-research.yml'):
        result[name] = base.digest((ROOT/name).read_bytes())
    return result


def diagnose(lean, output_directory):
    from tools.core_byte_facts_diagnostic_sources import build_diagnostic_sources
    from tools.core_byte_facts_sources import build_sources
    from tools.qualify_hia_selected_formal import _support_identity
    executable = Path(lean).resolve(strict=True)
    pinned = json.loads((ROOT/'formal/toolchain-lock.json').read_text())['lean_binary_sha256']
    require(base.digest(executable.read_bytes()) == pinned, 'pinned binary required')
    identity, support = source_identity(), _support_identity(executable)
    prepared = sources.build_inputs()
    proposal = build_sources(prepared)
    diagnostic = build_diagnostic_sources(prepared, proposal)
    require(source_identity() == identity, 'sources changed during preparation')
    return execute_diagnostic(executable, output_directory, prepared, proposal, diagnostic, identity, support,
                              source_identity, _support_identity, pinned)


def _verify_capture(root, manifest_sha, stage):
    raw = root.read(CAPTURE_FILES[2],collector.METADATA_LIMIT)
    records = [json.loads(line) for line in raw.splitlines()]
    require(records and all(type(row) is dict for row in records), 'invalid capture events')
    starts = [r for r in records if r.get('kind') == 'start']
    terminals = [r for r in records if r.get('kind') == 'terminal']
    require(len(terminals) == 1 and records[-1] == terminals[0], 'terminal capture event missing or reordered')
    terminal = terminals[0]['process']
    reference = dict(path='diagnostic-manifest.json',sha256=manifest_sha)
    require(terminal.get('manifest_reference') == reference, 'terminal manifest reference differs')
    require(terminal.get('status') == stage['status'] and
            terminal.get('process_started') is stage['process_started'], 'terminal result differs')
    if stage['process_started']:
        require(len(starts) == 1 and records[0] == starts[0] and
                starts[0]['process'].get('manifest_reference') == reference,
                'start manifest reference differs')
    actual = {}
    for name in CAPTURE_FILES[:2]:
        data = root.read(name,collector.RAW_LIMIT)
        actual[name] = dict(path=name,bytes=len(data),sha256=base.digest(data))
    require(terminal.get('raw_files') == actual, 'terminal raw capture identity differs')
    manifest = json.loads(root.read('diagnostic-manifest.json',32768))
    if stage['process_started']:
        require(starts[0].get('planned_markers') == len(manifest['markers']) and
                starts[0].get('raw_limit') == collector.RAW_LIMIT and
                starts[0].get('metadata_limit') == collector.METADATA_LIMIT, 'capture start budget differs')
    observer = collector.MarkerObserver(manifest['markers'],target='CertPart02')
    positions = {'stdout':0,'stderr':0}
    streams = {stream:root.read(name,collector.RAW_LIMIT) for stream,name in zip(positions,CAPTURE_FILES[:2])}
    observed_markers, recorded_markers = [], []
    previous_receive = -1
    for row in records:
        if row.get('kind') == 'receive':
            require(len(observed_markers) == len(recorded_markers), 'marker event delayed past next receive')
            stream,offset,size = row.get('stream'),row.get('offset'),row.get('bytes')
            require(stream in streams and type(offset) is int and type(size) is int and size > 0 and
                    offset == positions[stream] and offset+size <= len(streams[stream]),
                    'capture receive byte offsets differ')
            elapsed = row.get('received_seconds')
            require(type(elapsed) in (int,float) and 0 <= elapsed <= 600 and elapsed >= previous_receive,
                    'capture receive time differs')
            previous_receive = elapsed
            observed_markers.extend(observer(stream,streams[stream][offset:offset+size],offset,elapsed))
            positions[stream] += size
        elif row.get('kind') == 'marker':
            require(row.get('received_seconds') == row.get('event',{}).get('received_seconds'), 'marker time differs')
            require(len(recorded_markers) < len(observed_markers) and
                    row.get('event') == observed_markers[len(recorded_markers)], 'marker event precedes or differs from raw receive')
            recorded_markers.append(row.get('event'))
        else:
            require(row.get('kind') in ('start','terminal'), 'unknown capture event')
    require(recorded_markers == observed_markers and positions == {s:len(v) for s,v in streams.items()},
            'capture observations differ from raw streams')
    require(terminal.get('marker_count') == len(recorded_markers) and
            terminal.get('last_observed_marker') == (recorded_markers[-1] if recorded_markers else None),
            'terminal marker observation differs')

    if stage['status'] == 'diagnostic_completed':
        require(type(terminal.get('returncode')) is int and terminal['returncode'] == 0 and
                terminal.get('leader_reaped') is True and terminal.get('drain_complete') is True and
                terminal.get('cleanup_incomplete') is False and terminal.get('output_truncated') is False,
                'terminal completed process differs')


def _verify_provenance(root, frozen, result):
    """Reconcile complete retained source, inventory and same-run receipt chains."""
    import re
    from tools import core_byte_facts_sources as facts
    from tools.core_byte_facts_diagnostic_sources import strip_markers
    def read_json(name):
        cap = 32768 if name in ('transformation-manifest.json','diagnostic-manifest.json') else base.MAX_DIAGNOSTIC
        return json.loads(root.read(name,cap))
    original = read_json('original-manifest.json')
    transformed = read_json('transformation-manifest.json')
    diagnostic = read_json('diagnostic-manifest.json')
    run, identity = read_json('RUN.json'), read_json('IDENTITY.json')
    require(original.get('protocol') == sources.PROTOCOL and transformed.get('protocol') == facts.PROTOCOL and
            diagnostic.get('protocol') == PROTOCOL == run.get('protocol'), 'manifest protocol chain differs')
    require(run.get('identity_sha256') == frozen['IDENTITY.json'] and run.get('invocation_limit') == 4,
            'RUN identity chain differs')
    for key,name in (('original_manifest_sha256','original-manifest.json'),
                     ('transformation_manifest_sha256','transformation-manifest.json'),
                     ('diagnostic_manifest_sha256','diagnostic-manifest.json')):
        require(run.get(key) == frozen[name], 'RUN manifest chain differs')
    require(transformed.get('original_manifest_sha256') == frozen['original-manifest.json'] and
            diagnostic.get('original_manifest_sha256') == frozen['original-manifest.json'] and
            diagnostic.get('transformation_manifest_sha256') == frozen['transformation-manifest.json'],
            'transformation provenance differs')
    require(transformed.get('helper_sha256') == identity.get('source_sha256',{}).get(facts.HELPER_PATH),
            'helper identity chain differs')
    expected_names = list(sources.NAMES)
    require([s.get('name') for s in original.get('stages',[])] == expected_names and
            [s.get('name') for s in transformed.get('stages',[])] == expected_names and
            [s.get('name') for s in transformed.get('original_stages',[])] == expected_names and
            [s.get('name') for s in diagnostic.get('stages',[])] == list(DIAGNOSTIC_NAMES),
            'manifest stage inventory differs')
    inventories, stage_manifests = {}, {}
    old_total = new_total = 0
    for index,(old,new,old_compact) in enumerate(zip(original['stages'],transformed['stages'],transformed['original_stages'])):
        name = old['name']; module = base.MODULE_PREFIX+'.'+name
        require(old['module_name'] == new['module_name'] == old_compact['module_name'] == module,
                'canonical module differs')
        old_raw = root.read('original/'+name+'.lean',base.MAX_SOURCE)
        path = module.replace('.','/')+'.lean' if index < 3 else 'transformed/'+name+'.lean'
        new_raw = root.read(path,base.MAX_SOURCE)
        old_total += len(old_raw); new_total += len(new_raw)
        require(old.get('source_sha256') == old_compact.get('source_sha256') == base.digest(old_raw) and
                old.get('source_bytes') == old_compact.get('source_bytes') == len(old_raw) and
                new.get('source_sha256') == base.digest(new_raw) and new.get('source_bytes') == len(new_raw),
                'manifest source bytes differ')
        names = re.findall(r'(?m)^#print axioms ([A-Za-z_][A-Za-z0-9_.]*)$',new_raw.decode())
        if new_raw == old_raw:
            require(len(names) == len(old['expected_theorems']), 'unchanged print inventory count differs')
            names = list(old['expected_theorems'])
        require(len(names) == len(set(names)) == new.get('inventory_count') and
                base.digest(facts.encode(sorted(names)).encode()) == new.get('inventory_sha256') and
                old_compact.get('inventory_count') == len(old['expected_theorems']) and
                old_compact.get('inventory_sha256') == base.digest(facts.encode(old['expected_theorems']).encode()),
                'complete theorem inventory binding differs')
        require(facts.inverse_source(new_raw.decode(),old_raw.decode(),transformed['edits'][name]) == old_raw,
                'transformation inverse differs')
        inventories[name] = set(names)
        stage_manifests[name] = dict(old,source_sha256=base.digest(new_raw),source_bytes=len(new_raw),expected_theorems=sorted(names))
        if index < 4:
            binding = diagnostic['stages'][index]
            executed = root.read(module.replace('.','/')+'.lean',base.MAX_SOURCE)
            require(binding.get('module_name') == module and binding.get('source_sha256') == base.digest(executed) and
                    binding.get('source_bytes') == len(executed) and
                    binding.get('inventory_count') == len(names) and
                    binding.get('inventory_sha256') == new['inventory_sha256'] and
                    binding.get('original_stage_manifest_sha256') == base.digest(facts.encode(stage_manifests[name]).encode()),
                    'executed diagnostic source chain differs')
    marked = root.read(base.MODULE_PREFIX+'/CertPart02.lean',base.MAX_SOURCE)
    target = root.read('transformed/CertPart02.lean',base.MAX_SOURCE)
    require(strip_markers(marked.decode(),diagnostic) == target and
            diagnostic.get('original_target_source_sha256') == base.digest(target) and
            diagnostic.get('diagnostic_target_source_sha256') == base.digest(marked) and
            diagnostic.get('original_total_source_bytes') == old_total and
            diagnostic.get('transformed_total_source_bytes') == new_total and
            diagnostic.get('retained_total_source_bytes') == old_total+new_total+len(marked) <= base.MAX_TOTAL_SOURCE,
            'complete diagnostic source accounting differs')
    accepted = {}
    for stage in result['stages']:
        name = stage['name']
        if name == 'CertPart02':
            if CAPTURE_FILES[2] in frozen:
                _verify_capture(root,frozen['diagnostic-manifest.json'],stage)
            else:
                require(stage.get('process_started') is False and stage.get('status') == 'diagnostic_infrastructure_failed',
                        'capture evidence missing')
            require(stage.get('status') == result['status'], 'target stage result differs')
            require('olean' not in stage and stage.get('diagnostic_only') is True, 'target cannot be admitted')
            if stage.get('status') == 'diagnostic_completed':
                require(stage.get('inventory_receipt') == TARGET_INVENTORY and
                        stage.get('inventory_receipt_sha256') == frozen.get(TARGET_INVENTORY),
                        'completed target inventory receipt missing')
                receipt = read_json(TARGET_INVENTORY)
                log = ''.join(root.read(n,collector.RAW_LIMIT).decode() for n in CAPTURE_FILES[:2]).replace('\r\n','\n')
                require(receipt.get('inventory') == theorem_inventory(log,inventories[name]) and
                        receipt.get('source_sha256') == base.digest(marked) and receipt.get('diagnostic_only') is True and
                        receipt.get('stdout_sha256') == frozen[CAPTURE_FILES[0]] and
                        receipt.get('stderr_sha256') == frozen[CAPTURE_FILES[1]], 'target inventory identity differs')
            continue
        started = read_json(name+'.started.json'); receipt = read_json(name+'.finished.json')
        manifest = stage_manifests[name]
        parents = {p:accepted[p] for p in manifest['parents']}
        require(started.get('parents') == receipt.get('parents') == parents and
                started.get('source_sha256') == receipt.get('source_sha256') == manifest['source_sha256'] and
                receipt.get('status') == 'parent_checked', 'same-run parent receipt chain differs')
        log = ''.join(root.read(name+s,base.MAX_DIAGNOSTIC).decode() for s in ('.stdout','.stderr'))
        require(receipt.get('inventory') == theorem_inventory(log,inventories[name]) and
                receipt.get('stdout_sha256') == frozen[name+'.stdout'] and
                receipt.get('stderr_sha256') == frozen[name+'.stderr'], 'parent inventory identity differs')
        process = receipt.get('process',{})
        require(type(process.get('returncode')) is int and process['returncode'] == 0 and
                all(process.get(k) is False for k in ('timed_out','incomplete','output_truncated')),
                'parent process receipt differs')
        output = manifest['olean_relative_path']; raw = root.read(output,base.MAX_MODULE)
        item = dict(path=output,sha256=base.digest(raw),bytes=len(raw),source_sha256=manifest['source_sha256'])
        require(receipt.get('olean') == item, 'parent output identity differs')
        accepted[manifest['module_name']] = dict(item,receipt=name+'.finished.json',receipt_sha256=frozen[name+'.finished.json'])


def print_events(directory):
    """Verify every frozen file before presenting any trusted evidence."""
    import sys
    path = Path(directory).absolute()
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'diagnostic ancestor symlink')
    if not path.exists():
        print('Incomplete diagnostic output: output directory is missing; no proof evidence.')
        return
    # SafeRoot normally creates an exclusive directory. Attach read-only here.
    root = object.__new__(base.SafeRoot)
    root.path = path
    root.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root.identity = os.fstat(root.fd)
    try:
        try:
            result_raw = root.read('RESULT.json', collector.METADATA_LIMIT)
        except FileNotFoundError:
            print('Incomplete diagnostic output: final RESULT.json is missing; no proof evidence.')
            return
        result = json.loads(result_raw)
        require(result.get('protocol') == PROTOCOL and result.get('status') in STATUSES, 'invalid diagnostic result')
        require(all(result.get(k) == v for k,v in _denials().items()), 'diagnostic denial flags changed')
        evidence_raw = root.read('EVIDENCE.json', base.MAX_DIAGNOSTIC)
        require(base.digest(evidence_raw) == result.get('evidence_sha256'), 'frozen evidence container changed')
        evidence = json.loads(evidence_raw)
        frozen = evidence.get('sha256')
        require(evidence.get('protocol') == PROTOCOL and type(frozen) is dict, 'invalid frozen evidence')
        stage_names = ('Baseline','SyntaxData')+tuple('CertPart%02d'%i for i in range(1,7))+('Connections','TransportRejections','WrongArm')
        source_names = {base.MODULE_PREFIX+'/'+n+'.lean' for n in DIAGNOSTIC_NAMES}
        source_names |= {'original/'+n+'.lean' for n in stage_names}
        source_names |= {'transformed/'+n+'.lean' for n in stage_names[3:]}
        module_names = {base.MODULE_PREFIX+'/'+n+'.olean' for n in DIAGNOSTIC_NAMES}
        fixed = set(PREPARATION+PARENT_FILES+CAPTURE_FILES+(TARGET_INVENTORY,)) | source_names | module_names
        require(set(frozen) <= fixed and set(PREPARATION) | source_names <= set(frozen), 'frozen file set mismatch')
        actual_names = set(root.scan(fixed | {'RESULT.json','EVIDENCE.json'}))
        require(actual_names == set(frozen) | {'RESULT.json','EVIDENCE.json'}, 'unbound diagnostic evidence')
        require(type(result.get('invocations')) is int and 0 <= result['invocations'] <= 4 and
                result.get('invocation_limit') == 4, 'invalid invocation bound')
        if result['status'] in ('diagnostic_completed','diagnostic_timeout','diagnostic_output_limit'):
            require(result['invocations'] == 4 and
                    [s.get('name') for s in result.get('stages',[])] == list(DIAGNOSTIC_NAMES) and
                    set(PARENT_FILES+CAPTURE_FILES) <= set(frozen) and source_names <= set(frozen),
                    'terminal diagnostic evidence incomplete')
        stages = result.get('stages')
        require(type(stages) is list and len(stages) <= 4 and
                [s.get('name') for s in stages] == list(DIAGNOSTIC_NAMES[:len(stages)]),
                'diagnostic stage order differs')
        for stage in stages:
            name = stage['name']
            if name != 'CertPart02':
                receipt = name+'.finished.json'
                required = {name+s for s in ('.started.json','.stdout','.stderr','.finished.json')}
                required.add(base.MODULE_PREFIX+'/'+name+'.olean')
                require(stage.get('status') == 'parent_checked' and required <= set(frozen) and
                        stage.get('receipt') == receipt and stage.get('receipt_sha256') == frozen[receipt],
                        'parent evidence incomplete or changed')
            elif stage.get('process_started') is True:
                require(set(CAPTURE_FILES) <= set(frozen), 'target evidence incomplete')
        require(result['invocations'] >= min(len(stages),3), 'stage count exceeds invocation count')
        captured = {'RESULT.json':result_raw, 'EVIDENCE.json':evidence_raw}
        for name, expected in frozen.items():
            cap = (base.MAX_MODULE if name in module_names else base.MAX_SOURCE if name in source_names else
                   32768 if name in ('transformation-manifest.json','diagnostic-manifest.json') else base.MAX_DIAGNOSTIC)
            raw = root.read(name, cap)
            require(base.digest(raw) == expected, 'frozen evidence changed before presentation: '+name)
            if name in PARENT_FILES+CAPTURE_FILES+('RUN.json','IDENTITY.json','transformation-manifest.json','diagnostic-manifest.json'):
                captured[name] = raw
        _verify_provenance(root, frozen, result)
        # Rejected/partial target records are retained and hash-checked, but
        # never presented as validated marker observations. The failure RESULT
        # remains visible alongside independently verified parent evidence.
        if not any(s.get('name') == 'CertPart02' for s in stages):
            for name in CAPTURE_FILES:
                captured.pop(name,None)
        live = {'RESULT.json':result_raw}
        for name in CAPTURE_FILES:
            if name in frozen:
                live[name] = root.read(name,base.MAX_DIAGNOSTIC)
        _evidence_budget(live)
        require(sum(len(n.encode())+2+len(v) for n,v in captured.items())+
                sum(map(len,live.values())) <= base.MAX_DIAGNOSTIC,
                'complete presentation budget')
        # Recheck directory identity and every file after the full read pass.
        root.unchanged()
        for name, expected in frozen.items():
            cap = (base.MAX_MODULE if name in module_names else base.MAX_SOURCE if name in source_names else
                   32768 if name in ('transformation-manifest.json','diagnostic-manifest.json') else base.MAX_DIAGNOSTIC)
            require(base.digest(root.read(name,cap)) == expected, 'evidence changed during presentation verification')
        require(root.read('RESULT.json',collector.METADATA_LIMIT) == result_raw and
                root.read('EVIDENCE.json',base.MAX_DIAGNOSTIC) == evidence_raw, 'result changed during verification')
        for name in ('RUN.json','IDENTITY.json','transformation-manifest.json','diagnostic-manifest.json','EVIDENCE.json')+PARENT_FILES+LIVE_NAMES:
            if name in captured:
                sys.stdout.buffer.write(name.encode()+b'\n'+captured[name]+b'\n')
        sys.stdout.buffer.flush()
    finally:
        root.close()


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', type=Path)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--print-diagnostics', action='store_true')
    args = parser.parse_args(argv)
    if args.print_diagnostics:
        print_events(args.output_directory)
        return 0
    require(args.lean is not None, '--lean required')
    diagnose(args.lean, args.output_directory)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
