from pathlib import Path
from hashlib import sha256
import json
import sys
from unittest.mock import patch

ROOT = Path('/tmp/hepta-evaluation-capture-recovery-589c')
OUT = Path('/tmp/runtime-evaluation-capture-order-before-589c')
OUT.mkdir(mode=0o700)
sys.path.insert(0, str(ROOT))
from tests.test_hia_agent_native_tools import AgentToolCase

case = AgentToolCase()
case.setUp()
try:
    workload = {'schema': 'hepta.hia.agent.workload.v1',
                'cases': [{'function': 'transform', 'arguments': [250]}],
                'warmup_iterations': 0, 'repetitions': 1}
    _base, _candidate, baseline, build, receipts = case.build_pair(workload=workload)
    candidate = build['native_artifact']
    path = case.state_root / 'artifacts' / candidate['sha256']
    original = path.read_bytes()
    path.chmod(0o600)
    path.write_bytes(original + b'corrupt-original-candidate')
    wrong_receipt = baseline['native_artifact']
    calls = []
    actual_get = case.service.store.get
    def traced_get(reference, **options):
        calls.append({'id': reference['id'], 'kind': options.get('kind')})
        return actual_get(reference, **options)
    results = {}
    with patch.object(case.service.store, 'get', new=traced_get):
        for name, function in (
                ('original_candidate_then_receipt', lambda: (
                    case.service._native(candidate, case.session.context),
                    case.service._build_receipt(wrong_receipt, case.session.context, candidate))),
                ('premature_combined_build_inputs', lambda: case.service._build_inputs(
                    wrong_receipt, case.session.context, candidate))):
            calls.clear()
            try:
                function()
            except BaseException as error:
                results[name] = {'exception_type': type(error).__name__, 'message': str(error),
                                 'code': getattr(error, 'code', None), 'calls': list(calls)}
            else:
                raise AssertionError('combined invalid inputs were admitted')
    record = {'schema': 'hepta.hia.evaluation-capture-order-before.v1',
              'source_commit': '06d21f6032d7b3a946b1d6581a13c5cfd5fa4375',
              'candidate_original_sha256': sha256(original).hexdigest(),
              'candidate_changed_sha256': sha256(path.read_bytes()).hexdigest(),
              'results': results, 'whole_stack_rewritten_in_hia': False}
    (OUT / 'receipt.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps(record, sort_keys=True))
finally:
    case.tearDown()
