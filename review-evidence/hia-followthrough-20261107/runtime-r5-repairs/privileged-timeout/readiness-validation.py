import datetime, hashlib, json, os, re, subprocess, sys, time
from pathlib import Path
root = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
source = root / 'source/src/mcp/runtime/inspect.rs'
source_bytes = source.read_bytes()
assert hashlib.sha256(source_bytes).hexdigest() == 'be9416a05d0a48ae63665ff3d2cca6f84bb4fb7231e8159754dba0d66b396aa2'
code = re.search(r'const PRIVILEGED_CODE: &str = r#"(.*?)"#;', source_bytes.decode(), re.S).group(1)
bootstrap = '\nimport select, subprocess\nfixture_popen = subprocess.Popen\ndef launch_fixture_ready(*args, **kwargs):\n    child = fixture_popen(*args, **kwargs)\n    if not select.select([child.stdout], [], [], 10)[0]:\n        child.kill()\n        child.wait(timeout=5)\n        raise RuntimeError("fixture stdout was not ready within 10 seconds")\n    return child\nsubprocess.Popen = launch_fixture_ready\n'
owned = root / 'mac-privileged-readiness-validation-r1'
owned.mkdir(mode=0o700)
report = {'schema':'hia-privileged-readiness-validation-v1', 'production_source_sha256':hashlib.sha256(source_bytes).hexdigest(), 'test_bootstrap_sha256':hashlib.sha256(bootstrap.encode()).hexdigest(), 'production_code_modified':False, 'rust_test_executed':False, 'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'cases':[]}
fixtures = ["#!/bin/sh\nprintf 'started\\n'\nexec sleep 4\n", "#!/bin/sh\nprintf '\\377'\n"]
for index, fixture in enumerate(fixtures):
    case = owned / str(index)
    case.mkdir(mode=0o700)
    sudo = case / 'sudo'
    sudo.write_text(fixture)
    sudo.chmod(0o700)
    env = dict(os.environ)
    env['PATH'] = str(case) + ':' + env.get('PATH','')
    started = time.monotonic()
    completed = subprocess.run([sys.executable,'-c',bootstrap+'\n'+code], input=json.dumps({'executable':'/bin/true','timeout_seconds':1.0}).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=20)
    result = json.loads(completed.stdout)
    row = {'fixture_sha256':hashlib.sha256(fixture.encode()).hexdigest(), 'elapsed_seconds':time.monotonic()-started, 'exit_code':completed.returncode, 'stdout_hex':completed.stdout.hex(), 'stderr_hex':completed.stderr.hex(), 'result':result}
    assert completed.returncode == 0, row
    if index == 0:
        assert result['exit_code'] == 124 and result['timed_out'] is True, row
        assert result['exit_code_authoritative'] is False and result['process_exit_confirmed'] is True, row
        assert result['stdout'] == 'started\n' and result['stdout_bytes_seen'] == 8 and result['capture_error'] is None, row
    else:
        assert result['exit_code'] == 0 and result['stdout'] == '\ufffd', row
    row['assertions_passed'] = True
    report['cases'].append(row)
    print(json.dumps(row, sort_keys=True), flush=True)
assert source.read_bytes() == source_bytes
report['all_assertions_passed'] = True
destination = owned / 'report.json'
with destination.open('x') as f:
    json.dump(report,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'report':str(destination),'report_sha256':hashlib.sha256(destination.read_bytes()).hexdigest()}),flush=True)
