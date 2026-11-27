from hashlib import sha256
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path('/tmp/hepta-evaluation-capture-recovery-589c')
OUT = Path('/tmp/runtime-evaluation-capture-provider-before-589c')
OUT.mkdir(mode=0o700)
sys.path.insert(0, str(ROOT))
from hepta import hia_agent_service as api
from tests.test_hia_agent_native_tools import AgentToolCase
from tests.hia_evaluation_oracle import reference_method

source = (ROOT / 'hepta/hia_agent_service.py').read_bytes()
oracle = reference_method(ROOT / 'tests/fixtures/hia_evaluate_19065.py.txt', api,
                          ROOT / 'tests/fixtures/hia_evaluation_value_19065.py.txt')
case = AgentToolCase()
case.setUp()
try:
    workload = {'schema': 'hepta.hia.agent.workload.v1',
                'cases': [{'function': 'transform', 'arguments': [250]}],
                'warmup_iterations': 0, 'repetitions': 1}
    _base, _candidate, baseline, build, receipts = case.build_pair(workload=workload)
    args = case.session.arguments(baseline_artifact=baseline['native_artifact'],
        candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
        verification_receipts=receipts)
    observed = []
    def dynamic_receipt(*_args):
        observed.append('dynamic_build_receipt')
        raise ValueError('original-dynamic-build-receipt-refusal')
    def claims(*_args):
        observed.append('claims')
        raise ValueError('claims-reached-before-dynamic-build-receipt')
    class Dynamic(api.HIAAgentService):
        def __getattribute__(self, name):
            if name == '_build_receipt':
                return dynamic_receipt
            return object.__getattribute__(self, name)
    case.service.__class__ = Dynamic
    results = []
    with patch.object(case.service, '_required_claims', new=claims):
        for name, function in (('frozen_original', lambda: oracle(case.service, args)),
                               ('unguarded_capture_successor', lambda: case.service._hia_evaluate(args))):
            observed.clear()
            try:
                function()
            except BaseException as error:
                results.append({'case': 'dynamic_getattribute', 'route': name,
                                'exception': type(error).__name__, 'message': str(error), 'effects': list(observed)})
            else:
                raise AssertionError('expected controlled original provider refusal')
    case.service.__class__ = api.HIAAgentService
    class Items(dict):
        def items(self):
            observed.append('unexpected_ref_items')
            raise ValueError('new-reference-items-effect')
    exotic = dict(args, candidate_artifact=Items(args['candidate_artifact']))
    provider = case.service._native
    def original_provider(ref, context=None):
        return provider(dict(ref), context)
    with patch.object(case.service, '_native', new=original_provider), \
            patch.object(case.service, '_required_claims', new=claims):
        for name, function in (('frozen_original', lambda: oracle(case.service, exotic)),
                               ('unguarded_capture_successor', lambda: case.service._hia_evaluate(exotic)),
                               ('public_object_boundary', lambda: case.service.call('hia_evaluate', exotic))):
            observed.clear()
            try:
                value = function()
            except BaseException as error:
                results.append({'case': 'dict_subclass_items', 'route': name,
                                'exception': type(error).__name__, 'message': str(error), 'effects': list(observed)})
            else:
                results.append({'case': 'dict_subclass_items', 'route': name,
                                'returned': value, 'effects': list(observed)})
    receipt = {'schema': 'hepta.hia.evaluation-capture-provider-before.v1', 'results': results,
        'source': {'bytes': len(source), 'sha256': sha256(source).hexdigest()},
        'source_unchanged': (ROOT / 'hepta/hia_agent_service.py').read_bytes() == source,
        'scope': 'real stored build pair and unchanged original oracle; explicit foreign provider controls',
        'whole_stack_rewritten_in_hia': False}
    (OUT / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps(receipt, sort_keys=True))
finally:
    case.service.__class__ = api.HIAAgentService
    case.tearDown()
