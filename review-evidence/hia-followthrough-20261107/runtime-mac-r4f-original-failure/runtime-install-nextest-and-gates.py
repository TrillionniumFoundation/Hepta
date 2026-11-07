"""Install one verified official pinned tool into an owned candidate, then qualify."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tarfile

root = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
archive = root / 'cargo-nextest-0.9.137-universal-apple-darwin.tar.gz'
expected_sha = '94e89c20b233c29c042683e885131d76abf95e795c355a4fe7d64d4b128b90be'
assert archive.stat().st_size == 16138422
assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected_sha
destination = root / 'tools/bin/cargo-nextest'
assert not destination.exists()
destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
assert destination.parent.resolve() == destination.parent
assert destination.parent.stat().st_uid == os.getuid()
with tarfile.open(archive, 'r:gz') as source:
    members = source.getmembers()
    assert len(members) == 1 and members[0].name == 'cargo-nextest' and members[0].isfile()
    assert members[0].size == 38919408
    binary = source.extractfile(members[0]).read()
assert len(binary) == 38919408
with destination.open('xb') as output:
    output.write(binary)
destination.chmod(0o755)
version = subprocess.check_output([str(destination), '--version'], text=True, timeout=30)
assert version.splitlines()[0].split()[1] == '0.9.137', version
receipt = {
    'schema': 'hepta-pinned-tool-install-verified-transfer-v1',
    'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'official_archive_url': 'https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.137/cargo-nextest-0.9.137-universal-apple-darwin.tar.gz',
    'archive_sha256': expected_sha, 'archive_bytes': archive.stat().st_size,
    'archive_path': str(archive), 'binary_path': str(destination),
    'binary_sha256': hashlib.sha256(binary).hexdigest(), 'binary_bytes': len(binary),
    'version': version, 'passed': True,
    'prior_source_install': {'job_id': '1a1b4c44faa-fc05-89c8', 'terminal_state': 'cancelled', 'exit_code': -15},
    'prior_direct_download': {'job_id': '1a1b4d4a92f-fc05-8a01', 'terminal_state': 'timed_out', 'exit_code': 124},
    'transfer': 'official archive downloaded and hash-verified in the workspace, then bounded h_binary_upload with total hash verification and create-only commit',
}
with (root / 'mac-nextest-0.9.137-transfer-install.json').open('x') as output:
    output.write(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt), flush=True)
command = [
    sys.executable, str(root / 'runtime-ci-gates-final.py'),
    '--root', str(root), '--cargo', '/opt/homebrew/opt/rustup/bin/cargo',
    '--cargo-home', '/Users/qianqi/work/hepta-runtime-mac-controller-20261103/cargo-home',
    '--manifest', 'runtime-mac-r4f-source.json', '--patch', 'runtime-mac-compatibility-r4f.patch',
    '--tag', 'mac-r4f-final', '--tmp-dir', '/private/tmp/hr372e7-m5',
    '--expected-targets', 'runtime-expected-targets.json',
    '--expected-projection', 'runtime-r4f-expected-input-projection.json',
    '--previous-receipt', 'mac-r3-gates.json',
    '--tool-bin', str(root / 'tools/bin'), '--tool-bin', '/opt/homebrew/bin', '--release',
]
raise SystemExit(subprocess.run(command).returncode)
