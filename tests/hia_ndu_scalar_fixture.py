"""Authored scalar-wire test fixtures; never evidence of actual native NDU use."""
from hashlib import sha256
import json


def scalar_request(costs=(100, 50, 50), *, resources=None, hard=None, cap=1000):
    ids = ('abstain', 'beta', 'alpha')
    resources = resources or [0] * len(costs)
    hard = hard or [False] * len(costs)
    return {'schema': 'hepta.hia.ndu-request.v1', 'objective_sha256': '1' * 64,
        'generation': 1, 'resource_cap_q32': cap,
        'candidates': [{'id': cid, 'cost_q32': cost, 'uncertainty_q32': 0,
            'resource_q32': resource, 'hard_violation': violation, 'support_sha256': '2' * 64}
            for cid, cost, resource, violation in zip(ids, costs, resources, hard)]}


def fixture_response(request):
    """Only for patched process boundaries; contains an explicit fixture label."""
    feasible = [row for row in request['candidates']
        if not row['hard_violation'] and row['resource_q32'] <= request['resource_cap_q32']]
    minimum = min(row['cost_q32'] for row in feasible)
    frontier = sorted(row['id'] for row in feasible if row['cost_q32'] == minimum)
    if len(feasible) == 1 and feasible[0]['id'] == 'abstain':
        disposition, selected = 'InfeasibleExplicitAbstain', 'abstain'
    elif len(frontier) == 1:
        disposition, selected = 'UniqueParetoRecommendation', frontier[0]
    else:
        disposition, selected = 'ParetoSetRequiresSlowPath', None
    return {'authored_test_fixture': True,
        'request_sha256': sha256(json.dumps(request, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest(),
        'objective_sha256': request['objective_sha256'], 'generation': request['generation'],
        'advisory_recommendation': selected, 'disposition': disposition,
        'pareto_frontier': frontier,
        'rejected': [{'id': row['id'], 'reasons': '[TestFixtureRejection]'}
            for row in sorted(request['candidates'], key=lambda r: r['id']) if row not in feasible]}


def fixture_rank(bridge, request, *, timeout_s, **kwargs):
    return fixture_response(request), {'authored_test_fixture': True}
