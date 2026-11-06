from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile
import types
from unittest.mock import patch

repo = Path('/workspace/scratch/5e5f40464be2/Hepta')
sys.path.insert(0, str(repo))
source = (repo / 'hepta/apps/quota.py').read_bytes()
output = Path('/workspace/scratch/5e5f40464be2/quota-independent-review')
(output / 'quota-source-engine-probes.py').write_bytes(source)
q = types.ModuleType('quota_audit_engine_snapshot')
q.__file__ = str(repo / 'hepta/apps/quota.py')
exec(compile(source, q.__file__, 'exec'), q.__dict__)
report = {'source_sha256': hashlib.sha256(source).hexdigest(), 'results': []}

def caught(call):
    try:
        result = call()
    except BaseException as exc:
        return {'type': type(exc).__name__, 'message': str(exc)}
    return {'returned': result}

with tempfile.TemporaryDirectory(prefix='hia-quota-engine-review-') as directory:
    base = Path(directory)
    with q.HIAEngine() as engine, q.QuotaLedger(base / 'typed-result', initial=100, engine=engine) as ledger:
        original = engine.transition
        def faulty_live(version, state, amount, operation, *, replay=False):
            value = original(version, state, amount, operation, replay=replay)
            return value if replay else value ^ 1
        with patch.object(engine, 'transition', side_effect=faulty_live):
            first = caught(lambda: ledger.apply('backend-result-fault', 1, 10))
        retried = caught(lambda: ledger.apply('backend-result-fault', 1, 10))
        record = json.loads((base / 'typed-result' / '00000001.json').read_text())
        report['results'].append({'name': 'well_typed_wrong_backend_result', 'first': first, 'retry_after_restoring_engine': retried,
            'committed_after': record['event']['after'], 'expected_after': {'available':90,'held':10}})

    with q.HIAEngine() as engine, q.QuotaLedger(base / 'bad-type', initial=100, engine=engine) as ledger:
        original = engine.transition
        rows = []
        for bad_value in (True, -1, 1 << 64, 0.5, None, {}):
            def bad_live(version, state, amount, operation, *, replay=False):
                return original(version, state, amount, operation, replay=True) if replay else bad_value
            with patch.object(engine, 'transition', side_effect=bad_live):
                error = caught(lambda: ledger.apply('malformed-result', 1, 10))
            rows.append({'input_type': type(bad_value).__name__, 'error': error})
        report['results'].append({'name': 'malformed_backend_results', 'outcomes': rows, 'snapshot': ledger.snapshot()})

    with q.QuotaLedger(base / 'cleanup', initial=100) as ledger:
        original = os.unlink
        def cleanup_interrupt(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt('interrupt during stage cleanup')
        with patch.object(q.os, 'unlink', side_effect=cleanup_interrupt):
            first = caught(lambda: ledger.apply('cleanup-interrupt', 1, 10))
        retry = ledger.apply('cleanup-interrupt', 1, 10)
        report['results'].append({'name': 'stage_cleanup_interrupt', 'first': first, 'retry': retry, 'snapshot': ledger.snapshot()})

    with q.HIAEngine() as engine:
        original = engine.transition
        def faulty_genesis(version, state, amount, operation, *, replay=False):
            value = original(version, state, amount, operation, replay=replay)
            return value if replay else value ^ 1
        with patch.object(engine, 'transition', side_effect=faulty_genesis):
            first = caught(lambda: q.QuotaLedger(base / 'genesis-result', initial=100, engine=engine))
        reopened = caught(lambda: q.QuotaLedger(base / 'genesis-result', engine=engine))
        report['results'].append({'name': 'wrong_genesis_backend_result', 'first': first, 'reopen_after_restoring_engine': reopened,
            'committed_record_names': sorted(p.name for p in (base / 'genesis-result').glob('*.json'))})

(output / 'engine-findings.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
