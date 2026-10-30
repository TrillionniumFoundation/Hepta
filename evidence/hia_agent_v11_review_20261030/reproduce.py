"""Zero-model controls for pre-fix V11 finalization and runtime identity review.

Run with PYTHONPATH pointing at the reviewed checkout and a NEW output path.
The engine is an explicit test double. No result is a model qualification.
"""
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import argparse
import json
import os
import sys
import time
from tools import qualify_hia_agent_tool_capacity_v11 as capacity
from experiments.hia_agent_toolstudy_v11_20261030 import support


class FinalIdentityFailure:
    def __init__(self, **kwargs):
        self.output = Path(kwargs['output_dir'])
        self.output.mkdir()
        self.process = SimpleNamespace(poll=lambda: 0)
        self.generation_count = 0
        self.service_calls = []
        self.closed = False

    def verify_final_identity(self):
        raise RuntimeError('review_injected_final_identity_failure')

    def close(self):
        self.closed = True


def run(output, source_sha):
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False)
    source_head = source_sha
    model = {'sha256': 'test-only', 'file': {'path': 'test-only-model', 'bytes': 0, 'sha256': 'test-only'}}
    started = time.monotonic_ns()
    with patch.dict(os.environ, {'LLAMA_ARG_REPACK': '0'}), \
         patch.object(support, 'clean_committed_source', return_value=(source_head, {})), \
         patch.object(support, 'check_model', return_value=model), \
         patch.object(support, 'tool_identities', return_value={}), \
         patch.object(support, 'prompt_bindings', return_value={}), \
         patch.object(support, 'snapshot'), patch.object(support, 'cells', return_value=[]), \
         patch.object(capacity, 'runtime_preflight', return_value={'test_double': True}), \
         patch.object(capacity, 'ToolStudyEngine', FinalIdentityFailure):
        try:
            capacity.run(output=root / 'identity-failure', binary='unused', tokenizer='unused',
                         model='unused', clang='unused', rustc='unused')
        except Exception as error:
            observed = {'type': type(error).__name__, 'message': str(error)}
        else:
            observed = None
    record = {'schema': 'hepta.p7-independent-control-review.v1', 'reviewed_source_commit': source_head,
        'actual_model_loads': 0, 'actual_model_requests': 0, 'engine_is_test_double': True,
        'test_purpose': 'final identity exception preserves or loses terminal capacity evidence',
        'observed_exception': observed, 'plan_retained': (root / 'identity-failure/PLAN.json').is_file(),
        'terminal_capacity_report_retained': (root / 'identity-failure/CAPACITY.json').is_file(),
        'service_cost_report_retained': (root / 'identity-failure/TOKENIZER_SERVICE_CALLS.json').is_file(),
        'wall_ns': time.monotonic_ns() - started}
    (root / 'capacity-finalizer-repro.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
    try:
        identities = support.tool_identities(sys.executable, sys.executable, sys.executable, sys.executable)
    except Exception as error:
        identity_record = {'helper_accepted_all_python_executable_identities': False,
                           'error': {'type': type(error).__name__, 'message': str(error)}}
    else:
        identity_record = {'helper_accepted_all_python_executable_identities': True,
                           'tool_identity_count': len(identities), 'binary_sha256': identities['binary']['sha256']}
    identity_record.update(schema='hepta.p7-runtime-pin-inspection.v1', reviewed_source_commit=source_head,
        expected_runtime_is_llama_cpp=True, actual_capacity_or_generation_attempted=False,
        scope='identity helper comparison only; not proof an arbitrary executable can pass real capacity')
    (root / 'runtime-pin-inspection.json').write_text(json.dumps(identity_record, indent=2) + '\n')
    print(json.dumps(identity_record))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--source-sha', required=True)
    args = parser.parse_args()
    run(args.output, args.source_sha)
