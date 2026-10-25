"""Preregister the complete language by tools matrix and exact implementation IDs."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import random

from experiments.agent_eval.harness import Budget, model_id as base_model_id
from .adapter_binding import FIELDS, validate_config
from .scoring import compiler_identity
from .tasks import ARMS, ROOT, TASK_IDS, canonical, digest, verify_manifest

SCHEDULE_SEED = 2026102411


def model_id(model):
    identity = base_model_id(model)
    if model['revision'].strip().lower() in {'latest', 'stable', 'current', 'default', 'auto'}:
        raise ValueError('E_MODEL_REVISION: a moving alias is not an exact provider revision')
    return identity


def default_budget():
    return Budget(input_tokens=32000, output_tokens=12000, total_tokens=44000,
                  wall_seconds=300.0, tool_calls=32)


def evaluator_hash():
    records = []
    for root in (ROOT, ROOT.parent / 'agent_eval'):
        records += [(str(path.relative_to(ROOT.parent)), digest(path.read_bytes()))
                    for path in sorted(root.rglob('*.py')) if '__pycache__' not in path.parts]
    return digest(canonical(records))


def sample_id(plan, model, task, arm, replicate):
    return digest(canonical({'plan': plan['plan_sha256'], 'model': model_id(model),
                             'task': task, 'arm': arm, 'replicate': replicate}))


def adapter_configs_for(models, configs):
    if configs is None: return []
    if not isinstance(configs, list) or len(configs) != len(models):
        raise ValueError('E_ADAPTER_CONFIG: configure every planned model exactly once')
    actual = []
    for value in configs:
        if not isinstance(value, dict) or set(value) != FIELDS | {'model'}:
            raise ValueError('E_ADAPTER_CONFIG: exact model plus adapter fields required')
        identity = model_id(value['model'])
        validate_config({k: value[k] for k in FIELDS})
        actual.append(identity)
    if len(set(actual)) != len(actual) or set(actual) != {model_id(m) for m in models}:
        raise ValueError('E_ADAPTER_CONFIG: model adapter mapping is incomplete or duplicated')
    return [next(v for v in configs if v['model'] == model) for model in models]


def make_plan(models, budget=None, replicates=1, *, rustc=None, adapter_configs=None):
    budget = budget or default_budget()
    identities = [model_id(model) for model in models]
    if len(identities) < 2 or len(set(identities)) != len(identities):
        raise ValueError('E_PLAN: at least two distinct exact provider model identities are required')
    if type(replicates) is not int or replicates < 1:
        raise ValueError('E_PLAN: positive integer replicates required')
    schedule = [{'model_index': i, 'task': task, 'arm': arm, 'replicate': replica}
                for i in range(len(models)) for task in TASK_IDS for arm in ARMS for replica in range(replicates)]
    random.Random(SCHEDULE_SEED).shuffle(schedule)
    configured = adapter_configs_for(models, adapter_configs)
    plan = {'schema': 'hepta.crossfile_plan.v2', 'models': models, 'tasks': list(TASK_IDS),
            'arms': ARMS, 'replicates': replicates, 'budget': asdict(budget),
            'taskset_sha256': verify_manifest()['taskset_sha256'], 'evaluator_sha256': evaluator_hash(),
            'compiler': compiler_identity(rustc), 'schedule_seed': SCHEDULE_SEED, 'schedule': schedule,
            'design': 'paired_task_language_by_semantic_tool_2x2_same_nominal_budgets_fresh_sessions',
            'missing_policy': 'all_planned_cells_in_denominator_failures_timeouts_missing_not_dropped',
            'usage_policy': 'exact_revision_provider_receipts_adapter_attested_not_independently_verified',
            'inference_scope': 'five_task_systems_pilot_no_general_productivity_advantage_claim',
            'protocol': 'hepta.crossfile_study.v2',
            'adapter_configs': configured, 'provider_ready': bool(configured),
            'production_workspace_v4_required_for_hepta_protocol': True,
            'production_workspace_v4_exercised': False}
    plan['plan_sha256'] = digest(canonical(plan))
    return plan


def verify_plan(plan, *, rustc=None, current_environment=False):
    if not isinstance(plan, dict) or plan.get('schema') != 'hepta.crossfile_plan.v2':
        raise ValueError('E_PLAN: unknown schema')
    if digest(canonical({k: v for k, v in plan.items() if k != 'plan_sha256'})) != plan.get('plan_sha256'):
        raise ValueError('E_PLAN_STALE: plan identity changed')
    if plan.get('taskset_sha256') != verify_manifest()['taskset_sha256'] or plan.get('evaluator_sha256') != evaluator_hash():
        raise ValueError('E_PLAN_STALE: taskset or evaluator implementation changed')
    if plan.get('tasks') != list(TASK_IDS) or plan.get('arms') != ARMS or plan.get('schedule_seed') != SCHEDULE_SEED:
        raise ValueError('E_PLAN: full frozen 2 by 2 matrix is required')
    identities = [model_id(model) for model in plan['models']]
    if len(identities) < 2 or len(set(identities)) != len(identities):
        raise ValueError('E_PLAN: distinct exact models are required')
    configs = plan.get('adapter_configs')
    normalized = adapter_configs_for(plan['models'], configs if configs else None)
    if (configs != normalized or plan.get('provider_ready') is not bool(normalized)
            or plan.get('protocol') != 'hepta.crossfile_study.v2'
            or plan.get('production_workspace_v4_required_for_hepta_protocol') is not True):
        raise ValueError('E_PLAN: frozen protocol or adapter configuration changed')
    replicas = plan.get('replicates')
    if type(replicas) is not int or replicas < 1: raise ValueError('E_PLAN: invalid replicate count')
    Budget(**plan['budget'])
    expected = {(i, task, arm, r) for i in range(len(identities)) for task in TASK_IDS for arm in ARMS for r in range(replicas)}
    try:
        actual = [(v['model_index'], v['task'], v['arm'], v['replicate']) for v in plan['schedule']]
        if any(set(v) != {'model_index', 'task', 'arm', 'replicate'} for v in plan['schedule']): raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ValueError('E_PLAN: malformed schedule') from None
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError('E_PLAN: every planned cell must occur exactly once')
    if not isinstance(plan.get('compiler'), dict): raise ValueError('E_PLAN: frozen compiler identity required')
    if current_environment and plan['compiler'] != compiler_identity(rustc):
        raise ValueError('E_PLAN_STALE: actual compiler/toolchain differs from the plan')
    return plan
