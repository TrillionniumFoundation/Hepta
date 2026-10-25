"""Bounded source-unchanged ABI regression probe; never call mismatched ABIs.

Six real-Clang migrations, raw AST/argv receipts, independent layout executables.
Bad accepted attributed translations intentionally make this gate fail.
"""
from __future__ import annotations
import hashlib
import ctypes
import selectors
import signal
import subprocess
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / 'artifacts/c-typedef-alignment'
LIMIT = 128 * 1024 * 1024
EXPECTED_TRANSLATOR_SHA256 = '5729dc9d659779ad2d5d425793fb13a9688420826cf0d5c8e5ce17d81e59d0fb'
BASELINE_RED_WITNESS = {
    'head': 'e221d0e182c322d6b9a06ed9787f37c521dbe908',
    'run': 40152643065, 'artifact': 12582748803,
    'archive_sha256': '2ad9b1881db95f2478b5273a815cd066c9ce1226a0245702f20d5c1dcde85191',
    'translator_sha256': '54145de3475e417b068532b46ef2cdc347c98445293960ca667cdb6f0ff8f550',
    'independent_audit_sha256': 'd3e7b4d950cd4ddba49b9c806068324c2bdf6fa8d1549c961d88ba7d0f4d0542',
    'workflow_conclusion': 'failure',
    'scope': 'Historical real 4 attributed failures / 2 ordinary controls, 36 layout comparisons; not this candidate execution',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def layout(text):
    parts = text.strip().split()
    require(len(parts) == 4 and all(p.isdecimal() for p in parts), 'Invalid layout output')
    values = [int(p) for p in parts]
    require(all(0 <= v <= 4096 for v in values) and values[0] > 0 and values[1] > 0,
            'Unbounded/empty layout')
    return values


def gate(negative, report, bundle_exists, layouts):
    if negative:
        return (not report.get('ok') and not bundle_exists and
                'E_C_ATTRIBUTE' in [d.get('code') for d in report.get('diagnostics', [])])
    return bool(report.get('ok') and bundle_exists and len(layouts) == 6 and
                all(row['original'] == row['generated'] for row in layouts))


def _capture(proc, timeout, max_output, chunks, sinks=None):
    deadline = time.monotonic() + timeout
    total = 0
    with selectors.DefaultSelector() as selector:
        for pipe in (proc.stdout, proc.stderr):
            selector.register(pipe, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Command capture deadline exceeded')
            for key, _ in selector.select(min(remaining, 0.05)):
                data = os.read(key.fileobj.fileno(), min(65536, max_output - total + 1))
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                keep = min(len(data), max_output - total)
                chunks[key.fileobj].extend(data[:keep])
                if sinks:
                    sinks[key.fileobj].write(data[:keep])
                    sinks[key.fileobj].flush()
                total += len(data)
                require(total <= max_output, 'Command combined output limit exceeded')
        # Observe exit WITHOUT reaping: the owned leader PID/PGID cannot be
        # recycled before the outer supervisor has signalled its group.
        while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            require(time.monotonic() < deadline, 'Command exit deadline exceeded')
            time.sleep(0.01)


class WorkerAbort(BaseException):
    """Stop all worker work; only its outer owner may signal the workload."""
    def __init__(self, message, stdout=b'', stderr=b''):
        super().__init__(message)
        self.stdout, self.stderr = stdout, stderr


def execution_guard(call, *args, **kwargs):
    """Stop at an actual execution denial before production can normalize it."""
    try:
        return call(*args, **kwargs)
    except PermissionError as exc:
        raise WorkerAbort('Execution denied; refusing further work: ' + str(exc)) from exc


def inherited_run(argv, *, timeout, max_output, capture_paths=None):
    require(os.getsid(0) == os.getpid() and os.getpgrp() == os.getpid(),
            'Inner commands require the dedicated outer-owned worker session')
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=False)
    except PermissionError as exc:
        raise WorkerAbort(str(exc)) from exc
    chunks = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    sinks = {}
    try:
        if capture_paths:
            for pipe, path in zip((proc.stdout, proc.stderr), capture_paths):
                sinks[pipe] = Path(path).open('wb')
        _capture(proc, timeout, max_output, chunks, sinks)
        status = proc.wait(timeout=1)
        return subprocess.CompletedProcess(argv, status, bytes(chunks[proc.stdout]), bytes(chunks[proc.stderr]))
    except Exception as exc:
        # No inner signals or alternate permission-denial retry. Abort worker
        # immediately; the single outer owner kills and reaps the entire group.
        raise WorkerAbort(str(exc), bytes(chunks[proc.stdout]), bytes(chunks[proc.stderr])) from exc
    finally:
        proc.stdout.close()
        proc.stderr.close()
        for sink in (sinks or {}).values():
            sink.close()


def _no_children():
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return True
    return False


def _subreaper():
    require(sys.platform == 'linux', 'Confirmed owned teardown requires Linux')
    libc = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0, 'PR_GET_CHILD_SUBREAPER failed')
    previous = value.value
    require(previous in (0, 1), 'Unknown child subreaper state')
    if previous == 0:
        require(libc.prctl(36, 1, 0, 0, 0) == 0, 'PR_SET_CHILD_SUBREAPER failed')
    # Process-local child reaping only; no privilege, namespace or host change.
    return previous


def _cleanup_owned(proc, *, timeout=5):
    receipt = {'worker_pid': proc.pid, 'owned_pgid': proc.pid, 'confirmed': False,
               'signal_attempts': [], 'reaped_descendants': []}
    deadline = time.monotonic() + timeout
    try:
        receipt['signal_attempts'].append('SIGKILL')
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # Any permission denial exits immediately: no signal retry/escalation.
        receipt['worker_exit'] = proc.wait(timeout=max(0.01, deadline-time.monotonic()))
        while True:
            try:
                child, status = os.waitpid(-proc.pid, os.WNOHANG)
            except ChildProcessError:
                child = -1
            if child > 0:
                receipt['reaped_descendants'].append({'pid':child, 'wait_status':status})
                continue
            if child == -1:
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    require(_no_children(), 'Unexpected adopted children outside the owned group')
                    receipt['confirmed'] = True
                    break
            require(time.monotonic() < deadline, 'Owned group teardown did not reach quiescence')
            time.sleep(0.01)
    except Exception as exc:
        receipt['error'] = str(exc)
    return receipt


def supervise(argv, *, timeout=480, max_output=1_000_000):
    result = {'argv':list(argv), 'timeout_seconds':timeout, 'max_output_bytes':max_output,
              'cleanup':{'confirmed':False}, 'exit_code':1, 'stdout':b'', 'stderr':b''}
    proc = None
    try:
        result['prior_child_subreaper'] = _subreaper()
        require(_no_children(), 'Supervisor must exclusively own its child workload')
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        chunks = {proc.stdout:bytearray(), proc.stderr:bytearray()}
        try:
            _capture(proc, timeout, max_output, chunks)
        except Exception as exc:
            result['error'] = str(exc)
        finally:
            result['cleanup'] = _cleanup_owned(proc)
            result['stdout'] = bytes(chunks[proc.stdout])
            result['stderr'] = bytes(chunks[proc.stderr])
            proc.stdout.close()
            proc.stderr.close()
        if result['cleanup']['confirmed'] and 'error' not in result:
            result['exit_code'] = result['cleanup']['worker_exit']
    except Exception as exc:
        result['error'] = str(exc)
    return result


def run(argv, directory, tag, *, timeout=30):
    directory.mkdir(parents=True, exist_ok=True)
    started = time.time()
    receipt = {'argv': list(map(str, argv)), 'cwd': str(Path.cwd()), 'timeout_seconds': timeout,
               'max_combined_output_bytes': 4_000_000, 'started_unix': started, 'state':'running'}
    for suffix in ('.stdout','.stderr'):
        (directory/(tag+suffix)).write_bytes(b'')
    write(directory/(tag+'.command.json'), receipt)
    try:
        result = inherited_run(receipt['argv'], timeout=timeout, max_output=4_000_000,
            capture_paths=(directory/(tag+'.stdout'), directory/(tag+'.stderr')))
        (directory/(tag+'.stdout')).write_bytes(result.stdout)
        (directory/(tag+'.stderr')).write_bytes(result.stderr)
        receipt.update(exit_code=result.returncode, stdout_sha256=sha(directory/(tag+'.stdout')),
                       stderr_sha256=sha(directory/(tag+'.stderr')))
        require(result.returncode == 0, f'{tag} exited {result.returncode}')
        return result.stdout.decode('utf-8')
    except BaseException as exc:
        if isinstance(exc, WorkerAbort):
            (directory/(tag+'.stdout')).write_bytes(exc.stdout)
            (directory/(tag+'.stderr')).write_bytes(exc.stderr)
            receipt.update(exit_code=None, worker_abort=True,
                stdout_sha256=sha(directory/(tag+'.stdout')), stderr_sha256=sha(directory/(tag+'.stderr')))
        receipt['error'] = str(exc)
        raise
    finally:
        receipt['state'] = 'finished_or_worker_aborted'
        receipt['elapsed_seconds'] = time.time() - started
        write(directory/(tag+'.command.json'), receipt)


def source_hashes():
    return {str(p.relative_to(ROOT)): sha(p) for directory in ('hepta', 'tools')
            for p in sorted((ROOT/directory).rglob('*.py'))}


def packet_layout_binding(emitter, generated):
    """Bind this fixture's Packet to the SAME emitter instance's actual type.

    Never select an ordinal/first aggregate or infer identity from layout sizes.
    The checked source record, injective type map, emitted declaration and probe
    function parameter must agree before any generated layout is compiled.
    """
    from hepta.ast import Type
    import re
    packet = Type("C_Packet")
    records = [s for s in emitter.program.structs if s.name == "C_Packet"]
    require(len(records) == 1 and records[0].repr_c and not records[0].type_params,
            'Expected exactly one concrete repr(C) Packet record')
    fields = [(f.name, str(f.type)) for f in records[0].fields]
    require(fields == [('f_lead', 'i8'), ('f_value', 'i32'), ('f_tail', 'i8')],
            'Packet source fields changed from the fixed scientific fixture')
    require(emitter.structs.get('C_Packet') is records[0], 'Emitter record identity mismatch')
    name = emitter.types.get(packet)
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name),
            'Packet has no emitted C type mapping')
    require([t for t, value in emitter.types.items() if value == name] == [packet],
            'Packet C mapping aliases a different source type')
    declaration = 'typedef struct { int8_t h_f_lead; int32_t h_f_value; int8_t h_f_tail; } ' + name + ';'
    require(emitter.declarations.count(declaration) == 1 and generated.count(declaration) == 1,
            'Mapped Packet declaration is absent, duplicated or has wrong fields')
    functions = [f for f in emitter.program.functions if f.name == 'c_probe']
    require(len(functions) == 1 and len(functions[0].params) == 1 and functions[0].params[0].type == packet,
            'Scientific probe no longer accepts the checked Packet type')
    signature = 'int32_t __hepta_cb_fn_c_probe(' + name + ' h_p_p)'
    require(signature + ';' in generated and signature + ' {' in generated,
            'Emitted scientific probe parameter does not use the mapped Packet')
    return {'hepta_type': str(packet), 'c_type': name, 'fields': fields,
            'declaration': declaration, 'probe_signature': signature,
            'generated_sha256': hashlib.sha256(generated.encode()).hexdigest()}


def worker():
    from hepta.c_migrate import migrate_c_project
    from hepta.parser import parse
    from hepta.checker import check
    from hepta.c_backend import CEmitter
    import hepta.c_project as project
    import hepta.c_translation as translation
    baseline = source_hashes()
    report = {'schema': 'hepta.c-typedef-alignment-probe.v1', 'ok': False,
              'expected_head': os.environ.get('HEPTA_QUALIFICATION_HEAD_SHA'),
              'scope': 'Independent layout executions; no mismatched ABI calls; no equivalence proof',
              'source_before': baseline, 'cases': [], 'tools': {},
              'baseline_red_witness': BASELINE_RED_WITNESS}
    try:
        require(baseline['hepta/c_translation.py'] == EXPECTED_TRANSLATOR_SHA256,
                'Regression requires the exact reviewed repaired translator')
        for name, version_arg, required in [('clang', '--version', '19.1.7'),
                ('gcc', '--version', '14.2.0'), ('rustc', '--version', '1.90.0')]:
            selected = os.environ.get('RUSTC') if name == 'rustc' else shutil.which(name)
            require(bool(selected), name+' is mandatory; no skips')
            path = str(Path(selected).resolve(strict=True))
            version = run([path, version_arg], OUT/'tools', name).splitlines()[0]
            require(required in version, 'Unexpected '+name+' version: '+version)
            report['tools'][name] = {'path': path, 'sha256': sha(path), 'version': version}
        head = run(['git', '-c', 'safe.directory='+str(ROOT), 'rev-parse', 'HEAD'], OUT/'tools', 'head').strip()
        require(head == report['expected_head'], 'Probe checkout differs from workflow head')
        report['actual_head'] = head
        clang = report['tools']['clang']['path']
        gcc = report['tools']['gcc']['path']
        rustc = report['tools']['rustc']['path']
        for negative, header, chain in [(True,h,c) for h in (False,True) for c in (False,True)] + [(False,h,True) for h in (False,True)]:
            name = ('aligned' if negative else 'plain') + ('-header' if header else '-local') + ('-chain' if chain else '-direct')
            case = OUT/name
            case.mkdir()
            item = {'name': name, 'negative': negative, 'ok': False, 'layouts': []}
            report['cases'].append(item)
            try:
                alias = 'Base' if chain else 'Wide'
                definitions = f'typedef int {alias}' + (' __attribute__((aligned(16)))' if negative else '') + ';\n'
                if chain:
                    definitions += 'typedef Base Wide;\n'
                source = 'struct Packet { char lead; Wide value; char tail; };\nint probe(struct Packet p) { return p.value; }\n'
                if header:
                    (case/'types.h').write_text(definitions)
                    source = '#include "types.h"\n' + source
                else:
                    source = definitions + source
                (case/'input.c').write_text(source)
                write(case/'compile_commands.json', [{'directory':str(case), 'file':'input.c',
                    'arguments':['clang','-std=c11','-c','input.c']}])
                ast_text = run([clang,'-std=c11','-Werror','-fsyntax-only','-Xclang','-ast-dump=json',str(case/'input.c')], case, 'actual-ast')
                ast = json.loads(ast_text)
                require(ast.get('kind') == 'TranslationUnitDecl', 'Not an actual Clang translation unit')
                attributed = [n for n in ast.get('inner',[]) if n.get('kind') == 'TypedefDecl' and
                              any(c.get('kind') == 'AlignedAttr' for c in n.get('inner',[]))]
                item['aligned_typedefs'] = [n.get('name') for n in attributed]
                require(bool(attributed) == negative, 'Actual AST attribute location differs from the proposed witness')
                # Observational wrappers delegate to EXACT original invoke, without changing flags,
                # return values, environment, timeout, cwd or production source.
                calls=[]
                original_invoke=project.invoke
                def observed(args, directory, *, stdin=None):
                    index=len(calls); rec={'argv':args,'cwd':str(directory),'stdin':stdin}
                    calls.append(rec)
                    write(case/'migration-invocations.json',calls)
                    try:
                        value=original_invoke(args,directory,stdin=stdin)
                        require(len(value.encode()) <= 32_000_000, 'Migration output bound exceeded')
                        output=case/f'migration-invoke-{index:02}.stdout'
                        output.write_text(value)
                        rec.update(returned=True, stdout_sha256=sha(output))
                        return value
                    except BaseException as exc:
                        rec['error']=str(exc)
                        rec['execution_denied']=isinstance(exc.__cause__, PermissionError)
                        raise
                    finally:
                        write(case/'migration-invocations.json',calls)
                real_run = subprocess.run
                def guarded_run(*args, **kwargs):
                    return execution_guard(real_run, *args, **kwargs)
                with patch.object(project,'invoke',observed), patch.object(translation,'invoke',observed), patch.object(subprocess,'run',guarded_run):
                    migrated=migrate_c_project(case/'compile_commands.json', case/'bundle', clang=clang)
                write(case/'migration-report.json', migrated)
                item['migration_ok']=migrated['ok']
                item['diagnostics']=migrated['diagnostics']
                if migrated['ok']:
                    program=parse((case/'bundle/source.hepta').read_text())
                    checked=check(program)
                    require(checked.ok,'Actual generated source failed frontend')
                    emitter = CEmitter(program, checked, 'obj')
                    generated = emitter.emit()
                    binding = packet_layout_binding(emitter, generated)
                    (case/'generated.c').write_text(generated)
                    write(case/'generated-type-binding.json', binding)
                    prefix='#include <stddef.h>\n#include <stdio.h>\n'
                    suffix='int main(void) { printf("%zu %zu %zu %zu\\n", sizeof(TYPE), _Alignof(TYPE), offsetof(TYPE, VALUE), offsetof(TYPE, TAIL)); return 0; }\n'
                    (case/'original-layout.c').write_text(prefix+'#include "input.c"\n'+suffix.replace('TYPE','struct Packet').replace('VALUE','value').replace('TAIL','tail'))
                    (case/'generated-layout.c').write_text(prefix+'#include "generated.c"\n'+suffix.replace('TYPE',binding['c_type']).replace('VALUE','h_f_value').replace('TAIL','h_f_tail'))
                    rust=(case/'bundle/generated.rs').read_text()
                    rust+='\nfn main() { println!("{} {} {} {}", std::mem::size_of::<H_C_Packet>(), std::mem::align_of::<H_C_Packet>(), std::mem::offset_of!(H_C_Packet, h_f_value), std::mem::offset_of!(H_C_Packet, h_f_tail)); }\n'
                    (case/'generated-layout.rs').write_text(rust)
                    original_values={}
                    for compiler_name, compiler in [('clang',clang),('gcc',gcc)]:
                        for opt in ('0','2'):
                            values={}
                            for kind in ('original','generated'):
                                tag=f'{compiler_name}-{kind}-O{opt}'
                                binary=case/tag
                                run([compiler,'-std=c11','-O'+opt,str(case/(kind+'-layout.c')),'-o',str(binary)],case,tag+'-compile')
                                values[kind]=layout(run([str(binary)],case,tag+'-run',timeout=5))
                            original_values[opt]=values['original']
                            item['layouts'].append({'compiler':compiler_name,'optimization':opt,**values})
                    for opt in ('0','2'):
                        tag='rust-generated-O'+opt;binary=case/tag
                        run([rustc,'--crate-name','hepta_layout','--edition=2021','-C','opt-level='+opt,str(case/'generated-layout.rs'),'-o',str(binary)],case,tag+'-compile')
                        value=layout(run([str(binary)],case,tag+'-run',timeout=5))
                        item['layouts'].append({'compiler':'rustc','optimization':opt,'original':original_values[opt],'generated':value})
                item['layout_mismatch_observed']=any(v['original'] != v['generated'] for v in item['layouts'])
                item['ok']=gate(negative,migrated,(case/'bundle').exists(),item['layouts'])
            except Exception as exc:
                item['error']=str(exc)
                (case/'exception.txt').write_text(traceback.format_exc())
            finally:
                write(OUT/'report.json',report)
        require(source_hashes() == baseline, 'Production/probe source changed during execution')
        report['source_after']=source_hashes()
        report['ok']=len(report['cases']) == 6 and all(c['ok'] for c in report['cases'])
    except Exception as exc:
        report['error']=str(exc)
        (OUT/'worker-exception.txt').write_text(traceback.format_exc())
    finally:
        write(OUT/'report.json',report)
    return 0 if report['ok'] else 1


def main():
    if '--worker' in sys.argv:
        return worker()
    require(not OUT.exists(), 'Refuse stale probe evidence directory')
    OUT.mkdir(parents=True)
    result = supervise([sys.executable,str(Path(__file__).resolve()),'--worker'])
    (OUT/'worker.stdout').write_bytes(result.pop('stdout'))
    (OUT/'worker.stderr').write_bytes(result.pop('stderr'))
    write(OUT/'owned-process-receipt.json', result)
    if not result['cleanup']['confirmed']:
        # Evidence may still be changing: retain diagnostics, but DO NOT seal.
        write(OUT/'UNSEALED.json', {'reason':'Owned cleanup is unknown', 'supervisor':result})
        return 1
    status=result['exit_code']
    files={str(p.relative_to(OUT)):{'bytes':p.stat().st_size,'sha256':sha(p)}
           for p in sorted(OUT.rglob('*')) if p.is_file()}
    total=sum(f['bytes'] for f in files.values())
    if total > LIMIT:
        status=1
    write(OUT/'manifest.json',{'schema':'hepta.c-typedef-alignment-artifacts.v1',
        'exit_code':status,'total_bytes':total,'byte_limit':LIMIT,'files':files,
        'owned_cleanup_confirmed':True,
        'expected_head':os.environ.get('HEPTA_QUALIFICATION_HEAD_SHA'),
        'claims':{'whole_project_blockers_closed':False,'mismatched_abi_calls_executed':False}})
    return status


if __name__ == '__main__':
    raise SystemExit(main())
