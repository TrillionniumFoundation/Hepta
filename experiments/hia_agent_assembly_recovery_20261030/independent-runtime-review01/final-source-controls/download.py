"""Pure fake HTTP/member-stream controls; no network/model/native execution."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
from unittest import mock

source = Path('/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_agent_assembly_recovery_20261030/run_recovery.py')
source_bytes = source.read_bytes()
spec = importlib.util.spec_from_file_location('recovery_download_review', source)
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
rows = []


class Response:
    def __init__(self, data, length=None, slow=False):
        self.payload = io.BytesIO(data)
        self.headers = {} if length is None else {'Content-Length': str(length)}
        self.read_sizes = []
        self.slow = slow

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        self.read_sizes.append(size)
        if self.slow:
            time.sleep(0.1)
        return self.payload.read(size)


with tempfile.TemporaryDirectory(prefix='hepta-recovery-download-review-') as folder:
    root = Path(folder)
    cases = [
        ('exact', b'abcd', 4, False, True),
        ('truncated', b'abc', 4, False, False),
        ('wrong_sha', b'abce', 4, False, False),
        ('oversize_without_length', b'abcdefghi', None, False, False),
        ('wrong_content_length', b'abcdef', 6, False, False),
        ('absolute_deadline', b'abcd', 4, True, False),
    ]
    for index, (name, body, length, slow, expected) in enumerate(cases):
        evidence = root / ('evidence-' + str(index)); evidence.mkdir()
        cache = root / ('cache-' + str(index)); cache.mkdir()
        response = Response(body, length, slow)
        opener = mock.Mock(); opener.open.return_value = response
        item = {'id': name, 'filename': 'asset.bin', 'url': 'https://example.test/fixed.bin',
                'bytes': 4, 'sha256': hashlib.sha256(b'abcd').hexdigest()}
        accepted, error = False, None
        with mock.patch.object(runner.urllib.request, 'build_opener', return_value=opener), \
                mock.patch.object(runner, 'MAX_DOWNLOAD_SECONDS', 0.01 if slow else 900):
            try:
                runner.download_fixed(evidence, cache, item)
                accepted = True
            except Exception as failure:
                error = {'type': type(failure).__name__, 'message': str(failure)}
        record = json.loads((evidence / ('DOWNLOAD_' + name + '.json')).read_text())
        partial = cache / 'asset.bin.partial'
        partial_bytes = partial.stat().st_size if partial.exists() else None
        rows.append({'case': name, 'accepted': accepted, 'expected_accepted': expected,
                     'error': error, 'read_sizes': response.read_sizes, 'partial_bytes': partial_bytes,
                     'target_published': (cache / 'asset.bin').exists(),
                     'wall_cost_retained': type(record['download_and_identity_wall_ns']) is int,
                     'passed': accepted is expected and record['passed'] is expected
                         and (cache / 'asset.bin').exists() is expected
                         and (partial_bytes is None or partial_bytes <= 4)})

    class Members:
        def __init__(self):
            self.yielded = 0
            self.extracted = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def __iter__(self):
            for i in range(2000):
                self.yielded += 1
                member = tarfile.TarInfo('entry-' + str(i))
                member.size = 0
                yield member

        def extractall(self, *args, **kwargs):
            self.extracted = True
            raise AssertionError('oversized input must never reach extraction')

    archive = root / 'synthetic.tar.gz'; archive.write_bytes(b'synthetic header iterator fixture')
    evidence = root / 'member-evidence'; evidence.mkdir()
    members, failure = Members(), None
    with mock.patch.object(runner.tarfile, 'open', return_value=members):
        try:
            runner.extract_runtime(archive, root / 'members-out', evidence)
        except Exception as error:
            failure = {'type': type(error).__name__, 'message': str(error)}
    rows.append({'case': 'member_stream_stops_before_514', 'yielded': members.yielded,
                 'extractall_called': members.extracted, 'failure': failure,
                 'passed': members.yielded == 513 and not members.extracted and failure is not None})

    refused = False
    try:
        runner.HTTPSOnlyRedirect().redirect_request(
            runner.urllib.request.Request('https://example.test/'), None, 302,
            'Found', {}, 'http://example.test/downgrade')
    except ValueError:
        refused = True
    rows.append({'case': 'HTTPS_redirect_downgrade_refused', 'passed': refused})

unchanged = source.read_bytes() == source_bytes
report = {'schema': 'hepta.agent.recovery.bounded-download-review.v1',
          'source_sha256': hashlib.sha256(source_bytes).hexdigest(), 'source_unchanged': unchanged,
          'rows': rows, 'passed': unchanged and all(r['passed'] for r in rows),
          'scope': {'network_requests': 0, 'model_calls': 0, 'native_program_runs': 0,
                    'performance_measurement': False, 'deadline_test_is_synthetic': True}}
out = Path('/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_agent_assembly_recovery_20261030/independent-runtime-review01/final-source-controls/download.json')
with out.open('x') as stream:
    json.dump(report, stream, indent=2, sort_keys=True); stream.write('\n')
print(json.dumps({'passed': report['passed'], 'controls': len(rows), 'source_unchanged': unchanged,
                  'failed': [r['case'] for r in rows if not r['passed']], 'report': str(out)}))
