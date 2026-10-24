"""Native oracle qualification; does not invoke or imitate an AI model."""
from __future__ import annotations

import datetime
from pathlib import Path
import tempfile

from ._private.solutions import HEPTA, RUST
from .fixtures.adapters import FIXTURE_MODEL, write_fixture
from .harness import Budget, evaluate, evaluator_hash
from .sandbox import probe_sandbox
from .scoring import compiler_identity
from .tasks import TASK_IDS, LANGUAGES, verify_manifest


def qualify_fixtures(rustc=None):
    budget = Budget(input_tokens=0, output_tokens=0, total_tokens=0,
                    wall_seconds=30.0, tool_calls=1)
    reports = []
    for task in TASK_IDS:
        for language in LANGUAGES:
            with tempfile.TemporaryDirectory(prefix='hepta-oracle-adapter-') as temporary:
                directory = Path(temporary)
                body = (HEPTA if language == 'hepta' else RUST)[task]
                command = write_fixture(directory, body, 'public_test')
                reports.append(evaluate(task, language, directory, command, FIXTURE_MODEL,
                                        kind='fixture', fixture_qualification=True,
                                        budget=budget, rustc=rustc))
    return {'schema': 'hepta.agent_fixture_qualification.v1',
            'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status': 'qualified_fixtures_only' if all(r['status'] == 'fixture_scored' and r['score']['ok']
                                                     for r in reports) else 'qualification_failed',
            'taskset_sha256': verify_manifest()['taskset_sha256'],
            'evaluator_sha256': evaluator_hash(), 'compiler': compiler_identity(rustc),
            'actual_ai_model_runs': 0, 'provider_tokens': 0,
            'oracle_fixture_runs': len(reports), 'ai_comparison_eligible': False,
            'environment': probe_sandbox(),
            'provider_qualification_blockers': ['No external metered provider adapter/model identities supplied.'] +
                ([] if probe_sandbox()['available'] else ['Namespace sandbox is unavailable; provider mode fails closed.']),
            'claims': {'measured_ai_productivity': False, 'hepta_advantage_established': False,
                       'strict_hidden_test_isolation_exercised': False},
            'runs': reports}
