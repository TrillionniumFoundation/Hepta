from __future__ import annotations
import ast
from hashlib import sha256
import inspect
import json
from pathlib import Path
import sys
import textwrap
import unittest

ROOT = Path('/tmp/hepta-evaluation-capture-recovery-589c')
OUT = Path('/tmp/runtime-evaluation-capture-before-589c')
OUT.mkdir(mode=0o700)
sys.path.insert(0, str(ROOT))
from tests import test_hia_agent_native_tools as original_callers

historical_path = Path('/tmp/runtime-kernel-frontier-review-589c/f587bda2/tests/test_hia_agent_native_tools.py')
historical = historical_path.read_bytes()
module = ast.parse(historical)
method = next(node for group in module.body if isinstance(group, ast.ClassDef)
              for node in group.body if isinstance(node, ast.FunctionDef)
              and node.name == 'test_evaluation_candidate_uses_exact_build_bound_native_observation')
source = textwrap.dedent(ast.get_source_segment(historical.decode(), method)) + '\n'
# Only the predecessor-to-successor method names differ. All original business
# assertions and the public freeze/import/verify/emit/evaluate caller remain.
source = source.replace('if owner == "_hia_evaluate"',
    'if owner in ("_hia_evaluate_reference", "_hia_evaluate_with_components")')
source = source.replace('("_build_inputs", build["native_artifact"])',
    '("_build_inputs_with_components", build["native_artifact"])')
namespace = dict(vars(original_callers))
exec(compile(source, str(OUT / 'original-caller-successor.py'), 'exec'), namespace)
method = namespace[method.name]
case = type('OriginalEvaluationCaptureCaller', (original_callers.AgentToolCase,), {method.__name__: method})
names = ('hepta/hia_agent_service.py', 'hepta/hia_evaluation_native.py',
         'tests/test_hia_agent_native_tools.py', 'tests/fixtures/hia_evaluate_19065.py.txt',
         'tests/fixtures/hia_evaluation_value_19065.py.txt')
captured = {name: (ROOT / name).read_bytes() for name in names}
(OUT / 'original-caller-successor.py').write_text(source)
with (OUT / 'unittest.stderr').open('w') as stream:
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.TestSuite([case(method.__name__)]))
receipt = {
    'schema': 'hepta.hia.evaluation-capture-before.v1',
    'source_commit': '06d21f6032d7b3a946b1d6581a13c5cfd5fa4375',
    'historical_commit': 'f587bda212423ae0ad6c4bf238ba32c855c3885a',
    'historical_module': {'bytes': len(historical), 'sha256': sha256(historical).hexdigest()},
    'adaptations': ['successor evaluation method names', 'successor build-input method name'],
    'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
    'skipped': len(result.skipped), 'success': result.wasSuccessful(),
    'sources': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                     'terminal_reread_identical': (ROOT / name).read_bytes() == raw}
                for name, raw in captured.items()},
    'whole_stack_rewritten_in_hia': False,
}
(OUT / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps(receipt, sort_keys=True))
sys.exit(0 if result.wasSuccessful() else 1)
