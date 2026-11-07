import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

root = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
source = root / 'source/src/mcp/runtime/inspect.rs'
source_bytes = source.read_bytes()
source_sha256 = hashlib.sha256(source_bytes).hexdigest()
assert source_sha256 == 'be9416a05d0a48ae63665ff3d2cca6f84bb4fb7231e8159754dba0d66b396aa2'
code = re.search(r'const PRIVILEGED_CODE: &str = r#"(.*?)"#;', source_bytes.decode(), re.S).group(1)
owned = root / 'mac-privileged-timeout-marker-r1'
owned.mkdir(mode=0o700)
report = {'schema': 'hia-privileged-timeout-marker-diagnostic-v1',
          'source_commit': '14dfb09aa3263ed35b4f88e8c301f8492d63fea7',
          'source_sha256': source_sha256,
          'code_sha256': hashlib.sha256(code.encode()).hexdigest(),
          'code_modified': False,
          'python': sys.version,
          'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'cases': []}
for index, timeout in enumerate((1.0, 3.0)):
    case = owned / str(index)
    case.mkdir(mode=0o700)
    marker = case / 'entered-shell'
    sudo = case / 'sudo'
    fixture = "#!/bin/sh\nprintf 'ready\\n' > '" + str(marker) + "'\nprintf 'started\\n'\nexec sleep 4\n"
    sudo.write_text(fixture)
    sudo.chmod(0o700)
    env = dict(os.environ)
    env['PATH'] = str(case) + ':' + env.get('PATH', '')
    begin_wall = time.time_ns()
    begin = time.monotonic()
    completed = subprocess.run([sys.executable, '-c', code],
        input=json.dumps({'executable': '/bin/true', 'timeout_seconds': timeout}).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=12)
    row = {'timeout_seconds': timeout,
           'fixture_sha256': hashlib.sha256(fixture.encode()).hexdigest(),
           'elapsed_seconds': time.monotonic() - begin,
           'exit_code': completed.returncode,
           'stdout_hex': completed.stdout.hex(),
           'stderr_hex': completed.stderr.hex(),
           'result': json.loads(completed.stdout),
           'marker_exists': marker.exists()}
    if marker.exists():
        row['marker_hex'] = marker.read_bytes().hex()
        row['marker_mtime_relative_seconds'] = (marker.stat().st_mtime_ns - begin_wall) / 1e9
    report['cases'].append(row)
    print(json.dumps(row, sort_keys=True), flush=True)
assert hashlib.sha256(source.read_bytes()).hexdigest() == source_sha256
destination = owned / 'report.json'
with destination.open('x') as f:
    json.dump(report, f, indent=2)
    f.write('\n')
    f.flush()
    os.fsync(f.fileno())
print(json.dumps({'report': str(destination), 'report_sha256': hashlib.sha256(destination.read_bytes()).hexdigest()}), flush=True)
