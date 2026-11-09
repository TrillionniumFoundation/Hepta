"""Paid information before macro selection; a finite research model only.

The caller supplies a public probability model and paid observation history,
never a realized hidden regime or future signal. All advice is DENY_ALL.
"""
from dataclasses import dataclass
from fractions import Fraction
from itertools import product
import time

from .model import Q32, FeedbackError, digest, scalar_backend


@dataclass(frozen=True)
class Probe:
    name: str
    cost: int
    zero_given_0: Fraction
    zero_given_1: Fraction


@dataclass(frozen=True)
class Problem:
    name: str
    prior0: Fraction
    budget: int
    terminals: tuple[tuple[str, int, int], ...]
    probes: tuple[Probe, ...]

    def __post_init__(self):
        def name_ok(x):
            return type(x) is str and 1 <= len(x) <= 64 and all(c.isascii() and (c.isalnum() or c in '-_.') for c in x)
        def prob_ok(x):
            return type(x) is Fraction and 0 <= x <= 1 and x.denominator <= 1000000
        if not name_ok(self.name) or not prob_ok(self.prior0):
            raise FeedbackError('paid information name or exact prior')
        if type(self.budget) is not int or not 0 <= self.budget <= 10000:
            raise FeedbackError('paid information budget')
        if type(self.terminals) is not tuple or not 1 <= len(self.terminals) <= 4:
            raise FeedbackError('terminal inventory')
        names = []
        for row in self.terminals:
            if (type(row) is not tuple or len(row) != 3 or not name_ok(row[0])
                    or any(type(v) is not int or abs(v) > 10000 for v in row[1:])):
                raise FeedbackError('terminal declared utility')
            names.append(row[0])
        if 'abstain' not in names or type(self.probes) is not tuple or len(self.probes) > 2:
            raise FeedbackError('incumbent abstention and at most two probes required')
        for p in self.probes:
            if (type(p) is not Probe or not name_ok(p.name) or type(p.cost) is not int
                    or not 1 <= p.cost <= 10000 or not prob_ok(p.zero_given_0) or not prob_ok(p.zero_given_1)):
                raise FeedbackError('probe identity, positive cost or likelihood')
            names.append(p.name)
        if len(set(names)) != len(names):
            raise FeedbackError('actions must have unique identities')

    def public(self):
        def ratio(p):
            return [p.numerator, p.denominator]
        return dict(name=self.name, prior0=ratio(self.prior0), budget=self.budget, terminals=self.terminals,
                    probes=[dict(name=p.name, cost=p.cost, zero_given_0=ratio(p.zero_given_0),
                                 zero_given_1=ratio(p.zero_given_1)) for p in self.probes],
                    objective='expected terminal utility minus each probe cost; Q32 ties-even per backup',
                    assumptions='conditionally independent signals given one episode-constant latent regime')


@dataclass(frozen=True)
class State:
    history: tuple[tuple[str, int], ...]
    remaining_budget: int


def belief(problem, state):
    if type(problem) is not Problem or type(state) is not State or type(state.history) is not tuple:
        raise FeedbackError('plain immutable public problem and observed history required')
    if type(state.remaining_budget) is not int or not 0 <= state.remaining_budget <= problem.budget:
        raise FeedbackError('remaining observation budget')
    sensors = {p.name: p for p in problem.probes}
    masses, seen, paid = [problem.prior0, 1-problem.prior0], set(), 0
    for row in state.history:
        if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
                or row[0] not in sensors or row[0] in seen or type(row[1]) is not int or row[1] not in (0, 1)):
            raise FeedbackError('unique consumed probes and binary observations required')
        p, signal = sensors[row[0]], row[1]
        for z, likelihood in enumerate((p.zero_given_0, p.zero_given_1)):
            masses[z] *= likelihood if signal == 0 else 1-likelihood
        seen.add(row[0])
        paid += p.cost
    if paid+state.remaining_budget != problem.budget or not sum(masses):
        raise FeedbackError('unpaid history or impossible observation')
    return masses[0]/sum(masses)


def observe(problem, state, probe, signal):
    belief(problem, state)
    sensor = next((p for p in problem.probes if p.name == probe), None)
    if sensor is None or probe in {name for name, _ in state.history} or sensor.cost > state.remaining_budget:
        raise FeedbackError('unavailable paid observation')
    after = State(state.history+((probe, signal),), state.remaining_budget-sensor.cost)
    belief(problem, after)
    return after


def plan(problem, state, *, backend=None, require_native=False, depth=None, max_states=1000):
    """Use depth=1 for myopic VOI, otherwise the full paid-information horizon.

    A native backend evaluates every backup before selection. Identical-model
    direct arithmetic is the strong ordinary control, not a different objective.
    """
    belief(problem, state)
    remaining = len(problem.probes)-len(state.history)
    depth = remaining if depth is None else depth
    if type(depth) is not int or not 0 <= depth <= remaining:
        raise FeedbackError('paid information horizon')
    if type(require_native) is not bool or (require_native and backend is None):
        raise FeedbackError('explicit native backend required')
    from .native import NativeValueBackend
    original_backend = type(backend) is NativeValueBackend
    if require_native and not original_backend:
        raise FeedbackError('original receipt-checking native backend required')
    if type(max_states) is not int or not 1 <= max_states <= 1000:
        raise FeedbackError('search budget')
    started = time.perf_counter_ns()
    evaluator = scalar_backend if backend is None else getattr(backend, 'evaluate', backend)
    memo, trace, active = {}, [], set()
    objective = digest(problem.public())

    def solve(current, horizon):
        key = current, horizon
        if key in memo:
            return memo[key]
        if len(memo)+len(active) >= max_states:
            raise FeedbackError('search budget exhausted; no partial advice')
        active.add(key)
        p0 = belief(problem, current)
        rows = [dict(id=name, instant_q32=round((p0*u0+(1-p0)*u1)*Q32), terminal_q32=0,
                     discount_q32=Q32, feasible=True, resource_q32=0, risk_q32=0)
                for name, u0, u1 in problem.terminals]
        if horizon:
            for sensor in problem.probes:
                if sensor.name in {name for name, _ in current.history}:
                    continue
                feasible = sensor.cost <= current.remaining_budget
                future = Fraction(0)
                if feasible:
                    pzero = p0*sensor.zero_given_0+(1-p0)*sensor.zero_given_1
                    for signal, mass in ((0, pzero), (1, 1-pzero)):
                        if mass:
                            after = observe(problem, current, sensor.name, signal)
                            future += mass*solve(after, horizon-1)['value_q32']
                rows.append(dict(id=sensor.name, instant_q32=-sensor.cost*Q32,
                                 terminal_q32=round(future), discount_q32=Q32, feasible=feasible,
                                 resource_q32=sensor.cost*Q32, risk_q32=0))
        public_state = dict(history=current.history, remaining_budget=current.remaining_budget,
                            belief=[p0.numerator, p0.denominator], horizon=horizon)
        request = dict(state_digest=digest(public_state), preference_digest=digest({'price': 1, 'discount': 1}),
                       objective_digest=objective, resource_budget_q32=current.remaining_budget*Q32,
                       risk_ceiling_q32=Q32)
        response = evaluator(rows, **request)
        expected = scalar_backend(rows, **request)
        values, winners = response.get('values'), response.get('winners')
        if (type(values) is not dict or any(type(v) is not int for v in values.values())
                or values != expected['values'] or winners != expected['winners']):
            raise FeedbackError('backend values or full winner relation differ')
        def retained_digest(value):
            return type(value) is str and len(value) == 64 and value != '0'*64 and set(value) <= set('0123456789abcdef')
        native = (original_backend and response.get('native') is True
                  and retained_digest(response.get('request_sha256'))
                  and retained_digest(response.get('evaluation_digest')))
        if require_native and not native:
            raise FeedbackError('native evidence absent; no reference substitution')
        result = dict(selected_action=winners[0], value_q32=values[winners[0]], candidate_values_q32=values)
        trace.append(dict(state=public_state, state_sha256=request['state_digest'], candidates=rows,
                          native=native, request_sha256=response.get('request_sha256'),
                          evaluation_digest=response.get('evaluation_digest'), **result))
        memo[key] = result
        active.remove(key)
        return result

    try:
        result = solve(state, depth)
    except Exception as error:
        error.controller_wall_ns = time.perf_counter_ns()-started
        error.completed_backups = len(trace)
        raise
    return dict(schema='hepta.hia.paid-information-plan.v1', **result, objective_sha256=objective,
                trace=trace, backups=len(trace), search_complete=depth == remaining,
                native_backend_used=bool(trace) and all(r['native'] for r in trace),
                controller_wall_ns=time.perf_counter_ns()-started, authority='DENY_ALL',
                production_activation=False, economic_benefit_established=False)


def independent_policy_oracle(problem, state):
    """Exhaust all contingent policy trees using separately encoded inference.

    The oracle has the same public model and information; no realized-future
    access. Two one-use sensors bound the complete policy enumeration.
    """
    belief(problem, state)  # admission only
    count = [0]

    def enumerate_policies(history, budget):
        masses = [problem.prior0, 1-problem.prior0]
        used = {name for name, _ in history}
        for name, signal in history:
            sensor = next(p for p in problem.probes if p.name == name)
            masses[0] *= sensor.zero_given_0 if signal == 0 else 1-sensor.zero_given_0
            masses[1] *= sensor.zero_given_1 if signal == 0 else 1-sensor.zero_given_1
        p0 = masses[0]/sum(masses)
        rows = [(name, round((p0*a+(1-p0)*b)*Q32)) for name, a, b in problem.terminals]
        for sensor in problem.probes:
            if sensor.name in used or sensor.cost > budget:
                continue
            q = p0*sensor.zero_given_0+(1-p0)*sensor.zero_given_1
            left = enumerate_policies(history+((sensor.name, 0),), budget-sensor.cost) if q else [('unreachable', 0)]
            right = enumerate_policies(history+((sensor.name, 1),), budget-sensor.cost) if q != 1 else [('unreachable', 0)]
            for (_, v0), (_, v1) in product(left, right):
                rows.append((sensor.name, -sensor.cost*Q32+round(q*v0+(1-q)*v1)))
        count[0] += len(rows)
        return rows

    rows = enumerate_policies(state.history, state.remaining_budget)
    maximum = max(v for _, v in rows)
    winners = sorted({name for name, value in rows if value == maximum})
    return dict(selected_action=winners[0], value_q32=maximum, winners=winners,
                enumerated_policies=count[0], realized_future_access=False)


def witness_problems():
    terminal = (('abstain', 0, 0), ('select-0', 20, -20), ('select-1', -20, 20))
    return (
        Problem('paid-information', Fraction(1, 2), 30, terminal,
                (Probe('read', 1, Fraction(1), Fraction(0)),)),
        Problem('expensive-information', Fraction(1, 2), 30, terminal,
                (Probe('read', 21, Fraction(1), Fraction(0)),)),
        Problem('uninformative-read', Fraction(1, 2), 30, terminal,
                (Probe('read', 1, Fraction(1, 2), Fraction(1, 2)),)),
        Problem('prepare-then-benefit', Fraction(1, 2), 2,
                (('abstain', 60, 60), ('select-0', 100, -100), ('select-1', -100, 100)),
                (Probe('read-a', 1, Fraction(7, 10), Fraction(3, 10)),
                 Probe('read-b', 1, Fraction(7, 10), Fraction(3, 10)))),
    )
