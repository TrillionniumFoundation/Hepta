"""Four-process, nonaccepting CertPart02 reporting-frontier diagnostic."""
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
PROTOCOL = 'partition-position-diagnostic-v1'
DIAGNOSTIC_NAMES = ('Baseline', 'SyntaxData', 'CertPart01', 'CertPart02')
CAPTURE_FILES = tuple('CertPart02'+s for s in ('.stdout', '.stderr', '.events.jsonl'))
LIVE_NAMES = ('RESULT.json',) + CAPTURE_FILES
PARENT_FILES = tuple(n+s for n in DIAGNOSTIC_NAMES[:3]
                     for s in ('.started.json', '.stdout', '.stderr', '.finished.json'))
PREPARATION = ('RUN.json', 'IDENTITY.json', 'original-manifest.json', 'diagnostic-manifest.json')
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


def execute_diagnostic(executable, output_directory, prepared, diagnostic, identity, support,
                       source_reader, support_reader, expected_binary_sha,
                       run_process=base.capture_result, capture=None):
    from tools.core_syntax_partition_diagnostic_sources import validate_diagnostic_sources
    # The complete acceptance input is independently checked before the derivative.
    require(prepared['manifest'].get('protocol') == sources.PROTOCOL, 'exact11 original required')
    # This validator begins with base.validate_plan on the complete exact11.
    validate_diagnostic_sources(prepared, diagnostic)
    require(tuple(s.name for s in diagnostic.stages) == DIAGNOSTIC_NAMES, 'exact four diagnostic stages')
    base._support_imports(prepared, support)
    root = base.SafeRoot(output_directory)
    allowed, frozen, accepted = set(), {}, {}
    report = dict(schema='hepta.hia.partition-position-diagnostic.v1', protocol=PROTOCOL,
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
        write('diagnostic-manifest.json', diagnostic.manifest_json.encode())
        write_json('IDENTITY.json', dict(source_sha256=identity, support_sha256=support,
                                       lean_binary_sha256=expected_binary_sha))
        write_json('RUN.json', dict(protocol=PROTOCOL, invocation_limit=4,
                                   original_manifest_sha256=prepared['manifest_sha256'],
                                   diagnostic_manifest_sha256=diagnostic.manifest_sha256,
                                   identity_sha256=frozen['IDENTITY.json']))
        source_bytes = 0
        for index, stage in enumerate(prepared['stages']):
            name = stage.module_name.replace('.', '/')+'.lean' if index < 3 else 'original/'+stage.name+'.lean'
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
            report['stages'].append(dict(name=stage.name, status=result['status'],
                                         process_started=result['process_started'], diagnostic_only=True))
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
    for name in ('tools/diagnose_core_syntax_partition.py', 'tools/core_syntax_partition_diagnostic_sources.py',
                 'tools/core_syntax_diagnostic_capture.py', 'tools/core_syntax_declaration_diagnostic_sources.py', '.github/workflows/hia-core-syntax-kernel-research.yml'):
        result[name] = base.digest((ROOT/name).read_bytes())
    return result


def diagnose(lean, output_directory):
    from tools.core_syntax_partition_diagnostic_sources import build_diagnostic_sources
    from tools.qualify_hia_selected_formal import _support_identity
    executable = Path(lean).resolve(strict=True)
    pinned = json.loads((ROOT/'formal/toolchain-lock.json').read_text())['lean_binary_sha256']
    require(base.digest(executable.read_bytes()) == pinned, 'pinned binary required')
    identity, support = source_identity(), _support_identity(executable)
    prepared = sources.build_inputs()
    diagnostic = build_diagnostic_sources(prepared)
    require(source_identity() == identity, 'sources changed during preparation')
    return execute_diagnostic(executable, output_directory, prepared, diagnostic, identity, support,
                              source_identity, _support_identity, pinned)


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
        source_names |= {'original/'+n+'.lean' for n in stage_names[3:]}
        module_names = {base.MODULE_PREFIX+'/'+n+'.olean' for n in DIAGNOSTIC_NAMES}
        fixed = set(PREPARATION+PARENT_FILES+CAPTURE_FILES) | source_names | module_names
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
            cap = base.MAX_MODULE if name in module_names else base.MAX_SOURCE if name in source_names else base.MAX_DIAGNOSTIC
            raw = root.read(name, cap)
            require(base.digest(raw) == expected, 'frozen evidence changed before presentation: '+name)
            if name in PARENT_FILES+CAPTURE_FILES+('RUN.json','IDENTITY.json','diagnostic-manifest.json'):
                captured[name] = raw
        _evidence_budget({n:v for n,v in captured.items() if n in LIVE_NAMES})
        require(sum(len(n.encode())+2+len(v) for n,v in captured.items())+
                sum(len(v) for n,v in captured.items() if n in LIVE_NAMES) <= base.MAX_DIAGNOSTIC,
                'complete presentation budget')
        # Recheck directory identity and every file after the full read pass.
        root.unchanged()
        for name, expected in frozen.items():
            cap = base.MAX_MODULE if name in module_names else base.MAX_SOURCE if name in source_names else base.MAX_DIAGNOSTIC
            require(base.digest(root.read(name,cap)) == expected, 'evidence changed during presentation verification')
        require(root.read('RESULT.json',collector.METADATA_LIMIT) == result_raw and
                root.read('EVIDENCE.json',base.MAX_DIAGNOSTIC) == evidence_raw, 'result changed during verification')
        for name in ('RUN.json','IDENTITY.json','diagnostic-manifest.json','EVIDENCE.json')+PARENT_FILES+LIVE_NAMES:
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
