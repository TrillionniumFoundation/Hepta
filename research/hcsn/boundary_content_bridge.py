"""Research-only decision-level boundary/content/physical READ bridge.

This is a deliberately SMALL finite-horizon partially observed classification
problem, not a faithful He--Xiong financial model or a foundation encoder.
It closes a *toy execution-interface* gap: a public free-boundary decision now
actually prevents paid content reads, rather than being calculated after decode.

Independent Bayes model: y in {-1,+1}, public posterior p=P(y=+1), hidden
binary observation z has known accuracy q=P(z=y), observation costs c, and
at most `remaining` observations. STOP rewards 1{prediction==y}; READ costs c.
Bellman value is the task-specific optimal stopping value, not HX equity.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
from functools import lru_cache
import hashlib
import json
import math
import random
import time
from typing import Callable


@dataclass(frozen=True)
class PublicState:
    p: float
    q: float
    cost: float
    remaining: int

    def __post_init__(self):
        if (not all(math.isfinite(v) for v in (self.p, self.q, self.cost))
            or not 0.0 < self.p < 1.0 or not 0.5 <= self.q < 1.0
            or not 0.0 <= self.cost < 1.0
            or isinstance(self.remaining, bool)
            or not isinstance(self.remaining, int)
            or not 0 <= self.remaining <= 12):
            raise ValueError('Invalid finite-horizon public state')


def predict_positive(p: float) -> bool:
    return p >= .5


def posterior(p: float, q: float, z: int) -> float:
    """Stable Bayes update with binary channel, z is +1 or -1."""
    if z not in (-1, 1):
        raise ValueError('Invalid binary observation')
    prob = p * q + (1 - p) * (1 - q)
    if z == 1:
        return p * q / prob
    return p * (1 - q) / (1 - prob)


def observation_plus_probability(p: float, q: float) -> float:
    return p * q + (1 - p) * (1 - q)


@lru_cache(maxsize=200000)
def value(p: float, q: float, cost: float, remaining: int) -> float:
    """Exact finite-horizon expected value by Bayesian Bellman recursion.

    Complexity O(2**remaining), not an SSM or a continuous-time QVI.
    """
    stop = max(p, 1-p)
    if remaining == 0:
        return stop
    zprob = observation_plus_probability(p,q)
    read = (-cost + zprob * value(posterior(p,q,1),q,cost,remaining-1)
            + (1-zprob)*value(posterior(p,q,-1),q,cost,remaining-1))
    return max(stop, read)


def advantage(s: PublicState) -> float:
    """READ minus STOP, not a gradient of financial E(V) or a probability."""
    if s.remaining == 0:
        return -1.0
    a = observation_plus_probability(s.p,s.q)
    read = -s.cost + a*value(posterior(s.p,s.q,1),s.q,s.cost,s.remaining-1)
    read += (1-a)*value(posterior(s.p,s.q,-1),s.q,s.cost,s.remaining-1)
    return read - max(s.p,1-s.p)


def oracle(s: PublicState) -> bool:
    return advantage(s) > 1e-12


def ordinary_one_step(s: PublicState) -> bool:
    """Strong analytic one-look ordinary control, using the exact one-look VOI."""
    return s.remaining>0 and (s.q-max(s.p,1-s.p))>s.cost+1e-12


def boundary_intervention(offset: float) -> Callable[[PublicState],bool]:
    """Positive offset makes READ less likely; must influence real decoder calls."""
    if not math.isfinite(offset):
        raise ValueError('Nonfinite boundary intervention')
    return lambda s: s.remaining > 0 and advantage(s) > offset + 1e-12


def policy_value(s: PublicState, policy: Callable[[PublicState],bool]) -> float:
    """Independent expected utility of deterministic public-state policy."""
    if not policy(s) or s.remaining==0:
        return max(s.p,1-s.p)
    a=observation_plus_probability(s.p,s.q)
    return (-s.cost
            + a*policy_value(PublicState(posterior(s.p,s.q,1),s.q,s.cost,s.remaining-1),policy)
            + (1-a)*policy_value(PublicState(posterior(s.p,s.q,-1),s.q,s.cost,s.remaining-1),policy))


def _as_tuples(x):
    return tuple(_as_tuples(v) for v in x) if isinstance(x,list) else x


class SealedEpisode:
    """Private truth/observation RNG never reaches the public-policy API.

    The READ operation draws an observation *only when called*. Checkpoint
    includes private state and must stay inside the owner; SHA256 is an
    integrity digest, NOT a signature or protection against hostile rewriting.
    """
    def __init__(self, prior: PublicState, truth: int, private_seed: int):
        if truth not in (-1,1) or isinstance(private_seed,bool) or not isinstance(private_seed,int):
            raise ValueError('Invalid private state')
        self.state=prior
        self._truth=truth
        self._rng=random.Random(private_seed)
        self.read_calls=0
        self.total_cost=0.
        self.journal=[]
        self.done=False

    def read(self) -> int:
        if self.done or self.state.remaining==0:
            raise RuntimeError('READ rejected by terminal/budget fence')
        # Hidden observation is created only inside the physical READ.
        z=self._truth if self._rng.random()<self.state.q else -self._truth
        old=self.state
        self.state=PublicState(posterior(old.p,old.q,z),old.q,old.cost,old.remaining-1)
        self.read_calls+=1
        self.total_cost+=old.cost
        self.journal.append({'action':'READ','z':z,'remaining':self.state.remaining})
        return z

    def stop(self) -> dict:
        if self.done:
            raise RuntimeError('Duplicate terminal FIRE rejected')
        self.done=True
        prediction=1 if predict_positive(self.state.p) else -1
        correct=int(prediction==self._truth)
        self.journal.append({'action':'FIRE','prediction':prediction})
        return {'correct':correct,'utility':correct-self.total_cost,
                'reads':self.read_calls,'paid_cost':self.total_cost,
                'journal':list(self.journal)}

    def checkpoint(self) -> str:
        payload={'version':1,'public':asdict(self.state),'truth':self._truth,
                 'rng':self._rng.getstate(),'reads':self.read_calls,
                 'cost':self.total_cost,'journal':self.journal,'done':self.done}
        raw=json.dumps(payload,sort_keys=True,separators=(',',':'))
        wrapped={'payload':payload,'sha256':hashlib.sha256(raw.encode()).hexdigest()}
        return json.dumps(wrapped,sort_keys=True,separators=(',',':'))

    @classmethod
    def restore(cls,checkpoint: str) -> 'SealedEpisode':
        wrapper=json.loads(checkpoint)
        payload=wrapper['payload']
        raw=json.dumps(payload,sort_keys=True,separators=(',',':'))
        if hashlib.sha256(raw.encode()).hexdigest()!=wrapper['sha256']:
            raise ValueError('Corrupted checkpoint')
        if payload['version']!=1 or payload['reads']<0 or payload['cost']<0:
            raise ValueError('Invalid checkpoint contract')
        out=cls(PublicState(**payload['public']),payload['truth'],0)
        out._rng.setstate(_as_tuples(payload['rng']))
        out.read_calls=payload['reads'];out.total_cost=payload['cost']
        out.journal=payload['journal'];out.done=payload['done']
        if out.read_calls!=sum(item['action']=='READ' for item in out.journal):
            raise ValueError('Inconsistent checkpoint journal')
        return out


def execute(ep: SealedEpisode, policy: Callable[[PublicState],bool]) -> dict:
    # No future observation, true class or private RNG is exposed to policy.
    start=time.process_time_ns()
    while ep.state.remaining>0 and policy(ep.state):
        ep.read()
    result=ep.stop()
    result['process_cpu_ns']=time.process_time_ns()-start
    return result


def sample_public(rng:random.Random, *, ood:bool=False)->PublicState:
    if ood:
        p=rng.uniform(.5,.995);q=rng.uniform(.53,.99)
        cost=rng.uniform(0.,.20);remaining=rng.choice((1,2,3,4,5))
    else:
        p=rng.uniform(.5,.90);q=rng.uniform(.60,.95)
        cost=rng.uniform(.005,.13);remaining=rng.choice((1,2,3,4))
    return PublicState(p,q,cost,remaining)


def _episode_seed(seed:int,i:int)->tuple[int,int]:
    data=hashlib.sha256(f'hcsn-value-bridge-v1:{seed}:{i}'.encode()).digest()
    return int.from_bytes(data[:8],'big'),int.from_bytes(data[8:16],'big')


def run_panel(n:int=500,seed:int=29,ood:bool=False)->dict:
    """Actual paid READs, shared sealed episodes and independent policy regret."""
    if not 1<=n<=50000:
        raise ValueError('n outside audit range')
    rng=random.Random(seed+int(ood)*100000)
    cases=[]
    for i in range(n):
        public=sample_public(rng,ood=ood)
        a,b=_episode_seed(seed,i)
        truth=1 if random.Random(a).random()<public.p else -1
        cases.append((public,truth,b))
    policies={'oracle':oracle,'ordinary_one_step':ordinary_one_step,
              'boundary_tight':boundary_intervention(.025),
              'boundary_loose':boundary_intervention(-.025),
              'never_read':lambda s:False}
    rows={}
    for name,policy in policies.items():
        readings,quality,utility,regret,cpu=0,0.,0.,0.,0
        for public,truth,private_seed in cases:
            r=execute(SealedEpisode(public,truth,private_seed),policy)
            readings+=r['reads'];quality+=r['correct'];utility+=r['utility']
            cpu+=r['process_cpu_ns']
            delta=value(public.p,public.q,public.cost,public.remaining)-policy_value(public,policy)
            if delta < -1e-9:
                raise ArithmeticError('Policy beats exact optimal Bellman value')
            regret+=max(0.,delta)
        rows[name]={'episodes':n,'actual_read_calls':readings,
                    'mean_reads':readings/n,'quality':quality/n,
                    'mean_utility':utility/n,'mean_exact_regret':regret/n,
                    'process_cpu_ns_total':cpu,
                    'energy_joules':None}
    return {'protocol':'hcsn.boundary-content-task.v1',
            'method':'research exploratory; no heldout public preregistration',
            'seed':seed,'ood':ood,'results':rows,
            'scope':'synthetic Bayesian binary observations, not financial HX or real multimodal encoder',
            'production_activation':False,'all_p0_p6_closed':False}
