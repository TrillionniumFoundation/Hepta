"""Local mechanical process-tree controls; no HIA or original target executes."""
from pathlib import Path
import importlib.util
import json
import os
import signal
import sys

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'ci-process-precheck-r2'
OUT.mkdir()
spec = importlib.util.spec_from_file_location('selfbuild_ci_control', ROOT / 'ci_self_rebuild_r4.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
subreaper = m.become_subreaper()
state = m.Qualification(ROOT, OUT, ROOT / 'ci-source-index-r2.json')
cases = [
    ('normal', "print('ordinary child returned')\n", False, 3),
    ('orphan-same-group', "import os,time\nif os.fork()==0:\n time.sleep(600)\nelse:\n os._exit(0)\n", True, 3),
    ('orphan-detached', "import os,time\nr,w=os.pipe()\nif os.fork()==0:\n os.close(r);os.setsid();os.write(w,b'x');os.close(w);time.sleep(600)\nelse:\n os.close(w);assert os.read(r,1)==b'x';os.close(r);os._exit(0)\n", True, 3),
    ('timeout-detached', "import os,time\nr,w=os.pipe()\nif os.fork()==0:\n os.close(r);os.setsid();os.write(w,b'x');os.close(w);time.sleep(600)\nelse:\n os.close(w);assert os.read(r,1)==b'x';os.close(r);time.sleep(600)\n", True, 1),
]
def no_children():
    try:
        os.wait4(-1, os.WNOHANG)
    except ChildProcessError:
        return True
    raise AssertionError('actual child remains')

results = []
try:
    for label, source, must_fail, wall in cases:
        script = OUT / (label + '.py')
        script.write_text(source)
        failed = None
        try:
            state.run(label, script, cpu=2, wall=wall)
        except BaseException as exc:
            failed = {'class': type(exc).__name__, 'message': str(exc), 'notes': list(getattr(exc, '__notes__', []))}
        assert bool(failed) is must_fail, (label, failed)
        assert not state.live
        assert no_children()
        result = json.loads((OUT / 'processes' / label / 'process.json').read_bytes())
        if must_fail:
            assert result['status'] == 'FAIL' and result['residual_descendants']
        else:
            assert result['status'] == 'PASS' and result['residual_descendants'] == []
        results.append({'label': label, 'expected_rejection': must_fail, 'observed': failed,
                        'all_children_reaped': True, 'process': result})
    script = OUT / 'nonzero.py'
    script.write_text('raise SystemExit(7)\n')
    original = m.write_json
    def fail_receipt(path, value):
        if path.name == 'process.json':
            raise OSError('controlled receipt failure')
        return original(path, value)
    m.write_json = fail_receipt
    error = None
    try:
        state.run('primary-before-receipt', script, cpu=2, wall=3)
    except BaseException as exc:
        error = exc
    finally:
        m.write_json = original
    assert isinstance(error, AssertionError) and '7' in str(error)
    assert any('controlled receipt failure' in item for item in error.__notes__)
    assert not state.live and no_children()
    results.append({'label': 'primary-before-receipt', 'primary_class': type(error).__name__,
                    'primary_message': str(error), 'secondary_notes': error.__notes__, 'all_children_reaped': True})
    summary = {'schema': 'hia-selfbuild-ci-process-local-precheck-r2', 'status': 'PASS',
               'scope': 'ONLY_MECHANICAL_TOY_PROCESS_CONTROLS_NOT_HIA_QUALIFICATION',
               'subreaper': subreaper, 'cases': results, 'native_HIA_entries': 0, 'B3_calls': 0,
               'all_owned_children_reaped': True}
    m.write_json(OUT / 'summary.json', summary)
    print(json.dumps({k:v for k,v in summary.items() if k != 'cases'}, sort_keys=True), flush=True)
finally:
    for pid, proc in list(state.live.items()):
        try: os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError: pass
        try: os.wait4(pid, 0)
        except ChildProcessError: pass
        state.live.pop(pid, None)
    state.reap_residual(None)
