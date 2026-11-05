"""Nonaccepting three-process declaration-position diagnostic; never qualification."""
from hashlib import sha256
import json
import os
from pathlib import Path
import time

from tools import check_core_syntax_staged as base
from tools.check_guarded_slice_lean import require, theorem_inventory
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS

ROOT = base.ROOT
DIAGNOSTIC_NAMES = ('Baseline', 'SyntaxData', 'LinearTransport')


def execute_diagnostic(executable, output_directory, prepared, diagnostic, identity, support,
                       source_reader, support_reader, expected_binary_sha,
                       run_process=base.capture_result, capture=None, *, noncomputable=False):
    from tools.core_syntax_declaration_diagnostic_sources import validate_diagnostic_sources
    from tools import core_syntax_diagnostic_capture as collector
    require(type(noncomputable) is bool, 'explicit diagnostic mode required')
    if noncomputable:
        from tools.core_syntax_noncomputable_diagnostic_sources import validate_noncomputable_diagnostic
        validate_noncomputable_diagnostic(prepared, diagnostic)
        extra_sources = diagnostic.retained_extra_sources
        markers = diagnostic.markers
    else:
        validate_diagnostic_sources(prepared, diagnostic)
        extra_sources = {}
        markers = diagnostic.manifest['markers']
    require(tuple(s.name for s in diagnostic.stages) == DIAGNOSTIC_NAMES, 'exact diagnostic stage order')
    base._support_imports(prepared, support)
    require(source_reader() == identity and support_reader(executable) == support,
            'initial source/support changed')
    require(base.digest(Path(executable).read_bytes()) == expected_binary_sha, 'pinned Lean binary changed')
    module_root = Path(executable).parent.parent / 'lib/lean'
    def no_shadow():
        require(not os.path.lexists(module_root / base.MODULE_PREFIX) and
                not os.path.lexists(module_root / (base.MODULE_PREFIX + '.olean')), 'module prefix shadows support')
    no_shadow()
    root = base.SafeRoot(output_directory)
    allowed, hashes, accepted = set(), {}, {}
    report = dict(schema='hepta.hia.declaration-position-diagnostic.v1', status='diagnostic_running',
                  kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
                  python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                  all_edge_transfer_proved=False, diagnostic_only=True, invocation_limit=3,
                  data_codegen_mode='explicit_noncomputable' if noncomputable else 'original',
                  invocations=0, invocation_count_exact=True, stages=[], not_scheduled=[s.name for s in prepared['stages'][3:]],
                  not_scheduled_reason='diagnostic_not_scheduled',
                  obligations=[dict(id=n, status='unproved') for n, _ in OBLIGATIONS], **DENY)
    started = time.monotonic()
    def write(name, data):
        root.write(name, data)
        allowed.add(name)
    def write_json(name, value):
        write(name, (json.dumps(value, sort_keys=True, indent=2)+'\n').encode())
    def state(extra=()):
        no_shadow()
        require(base.digest(Path(executable).read_bytes()) == expected_binary_sha, 'Lean binary changed')
        files = root.scan(allowed | set(extra))
        for rel, expected in hashes.items():
            require(base.digest(root.read(rel, base.MAX_SOURCE)) == expected, 'diagnostic source changed')
        total = 0
        for item in accepted.values():
            raw = root.read(item['path'], base.MAX_MODULE)
            require(base.digest(raw) == item['sha256'] and len(raw) == item['bytes'], 'parent module changed')
            total += len(raw)
        for rel in extra:
            if rel.endswith('.olean') and rel in files:
                total += files[rel]
                require(files[rel] <= base.MAX_MODULE, 'module budget')
        require(total <= base.MAX_TOTAL_MODULE, 'aggregate module budget')
        require(source_reader() == identity and support_reader(executable) == support, 'source/support changed')
    current = None
    try:
        write('original-manifest.json', prepared['manifest_json'].encode())
        hashes['original-manifest.json'] = prepared['manifest_sha256']
        write('diagnostic-manifest.json', diagnostic.manifest_json.encode())
        hashes['diagnostic-manifest.json'] = diagnostic.manifest_sha256
        write_json('IDENTITY.json', dict(source_sha256=identity, support_sha256=support,
                                       lean_binary_sha256=expected_binary_sha))
        hashes['IDENTITY.json'] = base.digest(root.read('IDENTITY.json', base.MAX_DIAGNOSTIC))
        write_json('RUN.json', dict(status='diagnostic_running', identity_sha256=hashes['IDENTITY.json'],
                                   original_manifest_sha256=prepared['manifest_sha256'],
                                   diagnostic_manifest_sha256=diagnostic.manifest_sha256))
        # Keep all original full sources, independently bound, outside the Lean package.
        for stage in prepared['stages']:
            rel = (stage.module_name.replace('.', '/') + '.lean' if stage.name in DIAGNOSTIC_NAMES[:2]
                   else 'original/' + stage.name + '.lean')
            write(rel, stage.source.encode())
            hashes[rel] = stage.source_sha256
        for stage in diagnostic.stages[2:]:
            rel = stage.module_name.replace('.', '/') + '.lean'
            write(rel, stage.source.encode())
            hashes[rel] = stage.source_sha256
        for relative, source in extra_sources.items():
            require(type(source) is str and len(source.encode()) <= base.MAX_SOURCE, 'retained extra source budget')
            write(relative,source.encode())
            hashes[relative] = base.digest(source.encode())
        require(sum(len(s.source.encode()) for s in prepared['stages']) +
                len(diagnostic.stages[2].source.encode()) + sum(len(s.encode()) for s in extra_sources.values()) <= base.MAX_TOTAL_SOURCE,
                'all retained source byte budget')
        state()
        for index, stage in enumerate(diagnostic.stages):
            require(index < 3 and report['invocations'] < 3, 'diagnostic hard launch boundary')
            require(time.monotonic()-started < base.LAUNCH_SECONDS, 'new-stage deadline')
            require(all(p in accepted for p in stage.parents), 'parent not successfully checked in this run')
            state()
            source_rel = stage.module_name.replace('.', '/') + '.lean'
            output_rel = stage.module_name.replace('.', '/') + '.olean'
            require(output_rel not in root.scan(allowed), 'fresh output required')
            current = dict(name=stage.name, status='running', source_sha256=stage.source_sha256,
                           parents={p:accepted[p] for p in stage.parents})
            if index < 2:
                report['stages'].append(current)
                write_json(stage.name + '.started.json', current)
                report['invocations'] += 1
                result = run_process(executable, root.path/source_rel, root.path/output_rel, root.path)
                out, err = result.get('stdout', '').encode(), result.get('stderr', '').encode()
                require(len(out)+len(err) <= base.MAX_DIAGNOSTIC, 'baseline diagnostic budget')
                write(stage.name+'.stdout', out); write(stage.name+'.stderr', err)
                current['process'] = {k:v for k,v in result.items() if k not in ('stdout','stderr')}
                state((output_rel,))
                require(type(result.get('returncode')) is int and result['returncode'] == 0 and
                        result.get('timed_out') is False and result.get('incomplete') is False and
                        result.get('output_truncated') is False, 'parent process incomplete or failed')
                inventory = theorem_inventory(out.decode()+err.decode(), set(stage.expected_theorems))
                raw = root.read(output_rel, base.MAX_MODULE)
                require(raw and sum(v['bytes'] for v in accepted.values())+len(raw) <= base.MAX_TOTAL_MODULE,
                        'parent module budget')
                item = dict(path=output_rel, sha256=base.digest(raw), bytes=len(raw), source_sha256=stage.source_sha256)
                accepted[stage.module_name] = item
                allowed.add(output_rel)
                current.update(status='parent_checked', inventory=inventory, olean=item)
                write_json(stage.name+'.finished.json', current)
                report['stages'][-1] = dict(name=stage.name, status='parent_checked',
                    receipt=stage.name+'.finished.json',
                    receipt_sha256=base.digest(root.read(stage.name+'.finished.json',base.MAX_DIAGNOSTIC)))
                current = None
                continue
            # This branch never calls theorem_inventory and never admits the output olean.
            capture_fn = capture or collector.capture_result
            report['invocations'] += 1
            report['invocation_count_exact'] = False
            result = capture_fn(executable, root.path/source_rel, root.path/output_rel, root.path,
                                safe_root=root, markers=markers,
                                manifest_reference={'path':'diagnostic-manifest.json', 'sha256':diagnostic.manifest_sha256})
            require(type(result) is dict and type(result.get('process_started')) is bool, 'diagnostic receipt missing')
            collector.validate_cleanup_status(result)
            if not result['process_started']:
                report['invocations'] -= 1
            report['invocation_count_exact'] = True
            files = collector.DIAGNOSTIC_FILES
            allowed.update(files)
            state((output_rel,))
            existing = root.scan(allowed | {output_rel})
            actual_files = {}
            for name in files:
                if name in existing:
                    data = root.read(name, base.MAX_DIAGNOSTIC)
                    actual_files[name] = dict(path=name, bytes=len(data), sha256=base.digest(data))
            require(type(result.get('files')) is dict and _encoded(result['files']) == _encoded(actual_files),
                    'capture file identity differs after collection')
            actual_raw = {n:v for n,v in actual_files.items() if n != 'LinearTransport.events.jsonl'}
            require(type(result.get('raw_files')) is dict and _encoded(result['raw_files']) == _encoded(actual_raw),
                    'capture raw file identity differs after collection')
            refs = {name:item['sha256'] for name,item in actual_files.items()}
            require(result.get('status') in ('diagnostic_completed', 'diagnostic_timeout', 'diagnostic_failed',
                    'diagnostic_infrastructure_failed', 'diagnostic_output_limit'), 'nonaccepting diagnostic status required')
            compact = dict(name='LinearTransport', status=result['status'],
                           capture_files=actual_files,
                           process_started=result['process_started'], diagnostic_only=True)
            event_bytes = len(root.read('LinearTransport.events.jsonl', collector.METADATA_LIMIT)) if 'LinearTransport.events.jsonl' in existing else 0
            require(type(result.get('metadata_remaining_bytes')) is int and
                    result['metadata_remaining_bytes'] == collector.METADATA_LIMIT-event_bytes,
                    'diagnostic metadata receipt differs from actual bytes')
            if 'LinearTransport.events.jsonl' in existing:
                collector.validate_terminal_cleanup(root.read('LinearTransport.events.jsonl', collector.METADATA_LIMIT), result,
                    dict(path='diagnostic-manifest.json', sha256=diagnostic.manifest_sha256))
            # The compact reference occurs once in RESULT; no second finished receipt or raw copies.
            report['stages'].append(compact)
            report['status'] = result['status']
            current = None
        require(report['invocations'] <= 3 and len(report['stages']) <= 3, 'diagnostic stage budget')
    except Exception as error:
        report.update(status='diagnostic_failed', error_type=type(error).__name__, error=str(error)[:512])
        if current is not None and current['name'] != 'LinearTransport':
            current.update(status='failed', error_type=type(error).__name__, error=str(error)[:512])
    finally:
        report['wall_seconds'] = time.monotonic()-started
        try:
            write_result_with_budget(root, report, collector)
        finally:
            root.close()
    return report


def source_identity():
    result = base.source_identity()
    for relative in ('tools/diagnose_core_syntax_declarations.py',
                     'tools/core_syntax_declaration_diagnostic_sources.py',
                     'tools/core_syntax_diagnostic_capture.py',
                     'tools/core_syntax_noncomputable_diagnostic_sources.py',
                     '.github/workflows/hia-core-syntax-kernel-research.yml'):
        result[relative] = base.digest((ROOT/relative).read_bytes())
    return result


def diagnose(lean, output_directory, *, noncomputable=False):
    from tools.core_syntax_structured_stages import build_inputs
    from tools.core_syntax_declaration_diagnostic_sources import build_diagnostic_sources
    from tools.qualify_hia_selected_formal import _support_identity
    executable = Path(lean).resolve(strict=True)
    lock = json.loads((ROOT/'formal/toolchain-lock.json').read_text())
    binary = lock['lean_binary_sha256']
    require(base.digest(executable.read_bytes()) == binary, 'pinned binary required')
    identity, support = source_identity(), _support_identity(executable)
    prepared = build_inputs()
    require(type(noncomputable) is bool, 'explicit diagnostic mode required')
    if noncomputable:
        from tools.core_syntax_noncomputable_diagnostic_sources import build_noncomputable_diagnostic
        diagnostic = build_noncomputable_diagnostic(prepared)
    else:
        diagnostic = build_diagnostic_sources(prepared)
    require(source_identity() == identity, 'sources changed during preparation')
    return execute_diagnostic(executable, output_directory, prepared, diagnostic,
                              identity, support, source_identity, _support_identity, binary, noncomputable=noncomputable)


LIVE_NAMES = ('RESULT.json', 'LinearTransport.stdout', 'LinearTransport.stderr', 'LinearTransport.events.jsonl')


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def _display_size(files):
    return sum(len(name.encode())+2+len(raw) for name,raw in files.items())


def _evidence_budget(files, collector):
    raw_bytes = sum(len(files.get(n,b'')) for n in LIVE_NAMES[1:3])
    metadata = len(files.get(LIVE_NAMES[0],b''))+len(files.get(LIVE_NAMES[3],b''))
    require(raw_bytes <= collector.RAW_LIMIT and metadata <= collector.METADATA_LIMIT,
            'actual durable evidence budget')
    durable = sum(map(len,files.values()))
    require(durable+_display_size(files) <= base.MAX_DIAGNOSTIC, 'actual durable plus display budget')


def write_result_with_budget(root, report, collector):
    files = {}
    for name in LIVE_NAMES[1:]:
        try:
            files[name] = root.read(name, base.MAX_DIAGNOSTIC)
        except FileNotFoundError:
            pass
    files['RESULT.json'] = _encoded(report)
    try:
        _evidence_budget(files,collector)
    except ValueError:
        # Never write an oversized successful summary. Keep all denial flags and
        # the failure; detailed parent/obligation records remain separately bound.
        report.clear()
        report.update(schema='hepta.hia.declaration-position-diagnostic.v1',status='diagnostic_failed',
                      error='final evidence budget exceeded', diagnostic_only=True,
                      kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
                      python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                      all_edge_transfer_proved=False, global_obligations='all twelve remain unproved',**DENY)
        files['RESULT.json'] = _encoded(report)
        _evidence_budget(files,collector)  # If even this cannot fit, leave an incomplete receipt.
    root.write('RESULT.json',files['RESULT.json'])


def print_events(directory):
    """One byte-exact presentation; preparation/parent records are separate scope."""
    import stat
    import sys
    from tools import core_syntax_diagnostic_capture as collector
    path=Path(directory).absolute()
    for parent in (path,*path.parents):
        require(not parent.is_symlink(),'diagnostic ancestor symlink')
    if not path.exists():
        return
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    files={}
    preparation=['RUN.json','IDENTITY.json','diagnostic-manifest.json']
    parents=[n+s for n in DIAGNOSTIC_NAMES[:2] for s in ('.started.json','.stdout','.stderr','.finished.json')]
    names=preparation+parents+list(LIVE_NAMES)
    try:
        for name in names:
            cap=32768 if name=='diagnostic-manifest.json' else base.MAX_DIAGNOSTIC
            try:
                handle=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            except FileNotFoundError:
                continue
            try:
                before=os.fstat(handle)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=cap,
                        'unsafe diagnostic reference file')
                raw=os.read(handle,cap+1)
                after=os.fstat(handle)
                require(len(raw)<=cap and (before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                        (after.st_size,after.st_mtime_ns,after.st_ctime_ns),'reference file changed')
                files[name]=raw
            finally:
                os.close(handle)
    finally:
        os.close(fd)
    _evidence_budget({n:files[n] for n in LIVE_NAMES if n in files},collector)
    if 'RESULT.json' in files:
        receipt=collector.decode_cleanup_json(files['RESULT.json'])
        targets=[stage for stage in receipt.get('stages',[]) if stage.get('name')=='LinearTransport']
        if receipt.get('status') == 'diagnostic_completed':
            require(len(targets)==1 and targets[0].get('status')=='diagnostic_completed' and
                    type(targets[0].get('capture_files')) is dict and
                    'LinearTransport.events.jsonl' in files, 'completed diagnostic target status differs')
        for stage in receipt.get('stages',[]):
            if stage.get('name')=='LinearTransport' and 'capture_files' in stage:
                actual={n:dict(path=n,bytes=len(files[n]),sha256=base.digest(files[n]))
                        for n in collector.DIAGNOSTIC_FILES if n in files}
                require(_encoded(actual)==_encoded(stage['capture_files']),
                        'diagnostic evidence changed before presentation')
                if 'LinearTransport.events.jsonl' in files:
                    require('diagnostic-manifest.json' in files, 'cleanup manifest missing before presentation')
                    collector.validate_terminal_cleanup(files['LinearTransport.events.jsonl'], stage,
                        dict(path='diagnostic-manifest.json', sha256=base.digest(files['diagnostic-manifest.json'])))
    # No errors=replace expansion, pretty JSON, or second main() report copy.
    output=sys.stdout.buffer
    for name in names:
        if name in files:
            output.write(name.encode()+b'\n'+files[name]+b'\n')
    output.flush()


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', type=Path)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--print-diagnostics', action='store_true')
    parser.add_argument('--noncomputable-data', action='store_true',
                        help='single-factor research data-codegen diagnostic; never acceptance')
    args = parser.parse_args()
    if args.print_diagnostics:
        print_events(args.output_directory)
        return 0
    require(args.lean is not None, '--lean required')
    diagnose(args.lean,args.output_directory,noncomputable=args.noncomputable_data)
    return 1  # This lane cannot report a qualification success.


if __name__ == '__main__':
    raise SystemExit(main())
