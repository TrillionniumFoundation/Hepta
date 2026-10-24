"""Real native fixture qualification, with zero model calls and zero AI claims."""
from __future__ import annotations

import datetime
from pathlib import Path
import tempfile

from experiments.agent_eval.harness import Budget
from experiments.agent_eval.sandbox import probe_sandbox

from .fixtures.adapters import FIXTURE_MODEL, write_fixture
from .plan import evaluator_hash
from .records import seal_record
from .runner import evaluate
from .scoring import check_candidate, compiler_identity, score_candidate
from .tasks import ARMS, LANGUAGES, TASK_IDS, task_request, trusted_reference, verify_manifest


def qualify_fixtures(rustc=None):
    budget = Budget(input_tokens=0, output_tokens=0, total_tokens=0, wall_seconds=40.0, tool_calls=4)
    starters, runs = [], []
    for task in TASK_IDS:
        for language in LANGUAGES:
            request = task_request(task, language)
            original = check_candidate(request, request['files'], rustc=rustc, fixture=True, contracts=False)
            broken = score_candidate(request, request['files'], rustc=rustc, fixture=True, native_timeout=1.0)
            starters.append({'task_id': task, 'language': language, 'starter_compiles_without_new_contract': original,
                             'starter_fails_target_oracle': not broken['ok'], 'target_score': broken})
        for arm, profile in ARMS.items():
            request = task_request(task, profile['language'])
            reference = trusted_reference(task, profile['language'])
            with tempfile.TemporaryDirectory(prefix='hepta-crossfile-fixture-') as temporary:
                directory = Path(temporary)
                command = write_fixture(directory, request, reference)
                runs.append(evaluate(task, arm, directory, command, FIXTURE_MODEL, kind='fixture',
                                     fixture_qualification=True, budget=budget, rustc=rustc))
    qualified = (all(s['starter_compiles_without_new_contract']['ok'] and s['starter_fails_target_oracle'] for s in starters)
                 and all(r['status'] == 'fixture_scored' and r['score']['ok'] for r in runs))
    sandbox = probe_sandbox()
    return seal_record({'schema': 'hepta.crossfile_fixture_qualification.v1',
                        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'status': 'qualified_fixtures_only' if qualified else 'qualification_failed',
                        'taskset_sha256': verify_manifest()['taskset_sha256'], 'evaluator_sha256': evaluator_hash(),
                        'compiler': compiler_identity(rustc), 'actual_ai_model_runs': 0, 'provider_tokens': 0,
                        'fixture_runs': len(runs), 'starter_runs': len(starters),
                        'hidden_native_cases_passed': sum(r['score']['passed'] for r in runs if r.get('score')),
                        'ai_comparison_eligible': False, 'human_seconds': None, 'monetary_cost_usd': None,
                        'environment': sandbox,
                        'provider_qualification_blockers': ['No external metered provider adapter and exact model revisions supplied.'] +
                            ([] if sandbox['available'] else ['Namespace isolation probe failed: ' + sandbox['reason']]),
                        'claims': {'measured_ai_productivity': False, 'hepta_advantage_established': False,
                                   'strict_hidden_test_namespace_isolation_exercised': False,
                                   'production_workspace_v4_exercised': False},
                        'starters': starters, 'runs': runs})
