from pathlib import Path
import hashlib
import importlib.util
import json
import os
import signal
import sys
import tempfile
import types
from unittest.mock import patch

repo = Path('/workspace/scratch/5e5f40464be2/Hepta')
sys.path.insert(0, str(repo))
source = (repo / 'hepta/apps/quota.py').read_bytes()
output = Path('/workspace/scratch/5e5f40464be2/quota-independent-review')
(output / 'quota-source-snapshot.py').write_bytes(source)
q = types.ModuleType('quota_audit_snapshot')
q.__file__ = str(repo / 'hepta/apps/quota.py')
exec(compile(source, q.__file__, 'exec'), q.__dict__)
report = {'source_sha256': hashlib.sha256(source).hexdigest(), 'results': []}

def add(name, result):
    report['results'].append({'name': name, **result})

with tempfile.TemporaryDirectory(prefix='hia-quota-review-') as directory:
    base = Path(directory)
    with q.QuotaLedger(base / 'post-read', initial=100) as ledger:
        original = ledger._reload
        calls = 0
        def fail_post_commit_read():
            global calls
            calls += 1
            if calls == 2:
                raise OSError('injected committed-record read error')
            return original()
        error = None
        with patch.object(ledger, '_reload', side_effect=fail_post_commit_read):
            try:
                ledger.apply('read-failure', 1, 10)
            except BaseException as exc:
                error = type(exc).__name__
        retry = ledger.apply('read-failure', 1, 10)
        add('post_publication_read_failure', {'raised': error, 'retry': retry, 'snapshot': ledger.snapshot()})

    with q.QuotaLedger(base / 'interrupt', initial=100) as ledger:
        original = os.link
        def interrupted_ack(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt('injected interrupt after successful link')
        error = None
        with patch.object(q.os, 'link', side_effect=interrupted_ack):
            try:
                ledger.apply('interrupted', 1, 10)
            except BaseException as exc:
                error = type(exc).__name__
        retry = ledger.apply('interrupted', 1, 10)
        add('interrupt_after_publication', {'raised': error, 'retry': retry, 'snapshot': ledger.snapshot()})

    class BypassTarget(str):
        def __ne__(self, other):
            return False
    with q.QuotaLedger(base / 'target-type', initial=100) as ledger:
        error = None
        try:
            ledger.upgrade('bad-target', BypassTarget('v1'))
        except BaseException as exc:
            error = {'type': type(exc).__name__, 'message': str(exc)}
        committed = sorted(p.name for p in (base / 'target-type').glob('*.json'))
        failure = None
        try:
            ledger.apply('after-reject', 1, 1)
        except BaseException as exc:
            failure = {'type': type(exc).__name__, 'message': str(exc)}
        add('non_exact_upgrade_target', {'raised': error, 'committed_record_names': committed, 'next_request_failure': failure})

    # Fork before either process holds the in-process RLock; both retain one
    # flock open-description. The parent pauses only after its own commit.
    with q.QuotaLedger(base / 'fork', initial=100) as ledger:
        go_read, go_write = os.pipe()
        done_read, done_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(go_write)
                os.close(done_read)
                signal.alarm(15)
                os.read(go_read, 1)
                try:
                    child = {'receipt': ledger.apply('child-request', 1, 10)}
                except BaseException as exc:
                    child = {'raised': type(exc).__name__, 'message': str(exc)}
                os.write(done_write, json.dumps(child).encode())
                os._exit(0)
            except BaseException:
                os._exit(98)
        os.close(go_read)
        os.close(done_write)
        original_reload = ledger._reload
        calls = 0
        child_result = None
        def post_commit_wait_for_child():
            global calls, child_result
            calls += 1
            if calls == 2:
                os.write(go_write, b'x')
                child_result = json.loads(os.read(done_read, 8192))
            return original_reload()
        signal.alarm(20)
        with patch.object(ledger, '_reload', side_effect=post_commit_wait_for_child):
            parent = ledger.apply('parent-request', 1, 20)
        signal.alarm(0)
        _, status = os.waitpid(pid, 0)
        os.close(go_write)
        os.close(done_read)
        target = json.loads((base / 'fork' / f'{parent["sequence"]:08d}.json').read_text())
        add('fork_inherited_instance', {'child_exit_status': status, 'child': child_result, 'parent_receipt': parent,
            'actual_record_request_at_parent_receipt_sequence': target['event']['request_id'], 'snapshot': ledger.snapshot()})

(output / 'findings.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
for result in report['results']:
    print(json.dumps(result, sort_keys=True))
print('source_sha256=' + report['source_sha256'])
