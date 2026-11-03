"""Finite, full-cost advisory planning with a real no-invocation path.

The v2 profile is deliberately small: at most two optional native artifacts and
four remaining batches.  Optimality is with respect to the supplied integer
cost model, never a theorem about measured wall time or arbitrary programs.
The existing v1 stateful model and its historical qualification stay unchanged.

Every batch pays the gate cost.  An invoke additionally pays search, native
evaluation, transport, response validation and (once) session startup.  A
prepared artifact pays proof and loading; resident artifacts pay holding, and
eviction or invalidation pays retirement.  Session cleanup is a terminal cost.
The memoized recurrence keeps session/artifact residency and batch position;
its nonnegative scalar minimum is filtered by the remaining budget at the root.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import itertools
import json
import time

from .hia_ndu import Q32, REQUEST_SCHEMA, candidate, event, NduBridgeError

SCHEMA = "hepta.hia.ndu.full-cost.v2"
MAX_NS = 1_000_000_000_000
_MODEL_FIELDS = {"schema", "objective_digest", "generation", "baseline", "variants",
                 "ready", "memory_budget_bytes", "budget_ns", "sunk_cost_ns",
                 "completion_value_ns", "decision", "session_ready", "observation_sha256"}
_VARIANT_FIELDS = {"id", "source_sha256", "verification_sha256", "support_sha256",
                   "status", "valid", "prepare_ns", "proof_ns", "retire_ns",
                   "holding_ns", "resident_bytes", "latency_ns"}
_DECISION_FIELDS = {"gate_ns", "search_ns", "native_ns", "transport_ns",
                    "validation_ns", "startup_ns", "close_ns"}


class CostModelError(ValueError):
    pass


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


def _require(ok, reason):
    if not ok:
        raise CostModelError("full-cost v2: " + reason)


def _model_snapshot(raw):
    """Detach the finite schema before validation without a JSON round trip.

    Every container has a schema-bound field/element limit, checked before
    copying or visiting children. Exact builtin types exclude conversion hooks.
    All leaves are subsequently checked by validate_model; no caller-owned
    mutable object can survive a successful return. The former JSON conversion
    accepted tuples as arrays, so that compatibility is retained explicitly.
    Textual JSON still goes through the normal bounded decoder at its boundary.
    """
    def record(value, fields, name):
        _require(type(value) is dict and len(value) == len(fields), name + " fields")
        # Cap the snapshot itself: another thread may grow caller-owned data
        # after the initial length check. Do not copy the entire dictionary.
        try:
            entries = list(itertools.islice(value.items(), len(fields) + 1))
        except RuntimeError as error:
            raise CostModelError("full-cost v2: " + name + " changed during snapshot") from error
        _require(len(entries) == len(fields) and len(value) == len(fields)
                 and all(type(k) is str and len(k) <= 32 for k, _ in entries)
                 and {k for k, _ in entries} == fields, name + " fields")
        # The old serializer sorted object keys. Retain that observable order
        # as well as values without encoding or decoding the bounded records.
        return dict(sorted(entries))

    def sequence(value, maximum, name):
        _require(type(value) in (list, tuple) and len(value) <= maximum, name + " bound")
        snapshot = list(value[:maximum + 1])
        _require(len(snapshot) <= maximum, name + " bound")
        return snapshot

    model = record(raw, _MODEL_FIELDS, "model")
    model["baseline"] = record(model["baseline"], {"source_sha256", "verification_sha256", "latency_ns"}, "baseline")
    model["baseline"]["latency_ns"] = sequence(model["baseline"]["latency_ns"], 4, "baseline horizon")
    model["decision"] = record(model["decision"], _DECISION_FIELDS, "decision cost")
    model["ready"] = sequence(model["ready"], 2, "initial residency")
    model["variants"] = sequence(model["variants"], 2, "variants")
    for index, value in enumerate(model["variants"]):
        variant = record(value, _VARIANT_FIELDS, "variant")
        variant["valid"] = sequence(variant["valid"], 4, "validity horizon")
        variant["latency_ns"] = sequence(variant["latency_ns"], 4, "latency horizon")
        model["variants"][index] = variant
    return model


def validate_model(raw):
    """Detach bounded input before search; exact fields prevent implicit costs."""
    model = _model_snapshot(raw)
    _require(type(model) is dict and set(model) == _MODEL_FIELDS, "model fields")
    _require(type(model["schema"]) is str and model["schema"] == SCHEMA, "schema")

    def integer(value, name, maximum=MAX_NS):
        _require(type(value) is int and 0 <= value <= maximum, name)

    def hash_value(value):
        _require(type(value) is str and len(value) == 64 and value != "0" * 64
                 and all(c in "0123456789abcdef" for c in value), "SHA-256 binding")

    for key in ("objective_digest", "observation_sha256"):
        hash_value(model[key])
    integer(model["generation"], "generation", (1 << 32) - 1)
    _require(model["generation"] > 0, "nonzero generation")
    for key in ("memory_budget_bytes", "budget_ns", "sunk_cost_ns", "completion_value_ns"):
        integer(model[key], key)
    _require(type(model["session_ready"]) is bool, "session residency")
    base = model["baseline"]
    _require(type(base) is dict and set(base) == {"source_sha256", "verification_sha256", "latency_ns"}, "baseline fields")
    for key in ("source_sha256", "verification_sha256"):
        hash_value(base[key])
    _require(type(base["latency_ns"]) is list and 1 <= len(base["latency_ns"]) <= 4, "horizon 1..4")
    horizon = len(base["latency_ns"])
    for cost in base["latency_ns"]:
        integer(cost, "baseline latency")
    variants = model["variants"]
    _require(type(variants) is list and 1 <= len(variants) <= 2, "one or two optional artifacts")
    names = set()
    for row in variants:
        _require(type(row) is dict and set(row) == _VARIANT_FIELDS, "variant fields")
        name = row["id"]
        _require(type(name) is str and 1 <= len(name) <= 32 and name != "baseline"
                 and all(c in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in name)
                 and name not in names, "unique artifact name")
        names.add(name)
        for key in ("source_sha256", "verification_sha256", "support_sha256"):
            hash_value(row[key])
        _require(type(row["status"]) is str and len(row["status"]) <= 8
                 and row["status"] in {"verified", "unknown", "rejected", "timeout"}, "verification status")
        _require(type(row["valid"]) is list and len(row["valid"]) == horizon
                 and all(type(v) is bool for v in row["valid"]), "validity horizon")
        _require(type(row["latency_ns"]) is list and len(row["latency_ns"]) == horizon, "latency horizon")
        for cost in row["latency_ns"]:
            integer(cost, "variant latency")
        for key in ("prepare_ns", "proof_ns", "retire_ns", "holding_ns", "resident_bytes"):
            integer(row[key], key)
    ready = model["ready"]
    _require(type(ready) is list and all(type(v) is str and len(v) <= 32 for v in ready)
             and len(set(ready)) == len(ready) and set(ready) <= names, "initial residency")
    # Invalid initial artifacts are admitted only as objects to retire. They
    # cannot be dispatched, including on the no-native-call path.
    _require(sum(v["resident_bytes"] for v in variants if v["id"] in ready)
             <= model["memory_budget_bytes"], "initial resident quota")
    decision = model["decision"]
    _require(type(decision) is dict and set(decision) == _DECISION_FIELDS, "decision cost fields")
    for value in decision.values():
        integer(value, "decision cost")
    # Prevent Q32 signed overflow even before infeasible plans are discarded.
    bound = (max(base["latency_ns"] + [c for v in variants for c in v["latency_ns"]])
             + sum(decision.values())
             + sum(sum(v[k] for k in ("prepare_ns", "proof_ns", "retire_ns", "holding_ns")) for v in variants)) * horizon
    _require(bound <= MAX_NS, "whole-path cost bound")
    return model


def _parts(model):
    variants = {v["id"]: v for v in model["variants"]}
    names = tuple(sorted(variants))
    sets = tuple(tuple(s) for n in range(len(names) + 1)
                 for s in itertools.combinations(names, n)
                 if sum(variants[x]["resident_bytes"] for x in s) <= model["memory_budget_bytes"])
    return variants, sets, len(model["baseline"]["latency_ns"])


def _live(variants, ready, batch):
    return tuple(n for n in ready if variants[n]["status"] == "verified" and variants[n]["valid"][batch])


def _action(model, variants, ready, batch, session_ready, mode, target=None):
    live = _live(variants, ready, batch)
    target = live if mode == "skip" else target
    if target is None or any(n not in _live(variants, target, batch) for n in target):
        return None
    removed = tuple(sorted(set(ready) - set(target)))
    acquired = tuple(sorted(set(target) - set(live)))
    decision = model["decision"]
    costs = {"gate_ns": decision["gate_ns"], "search_ns": 0, "native_ns": 0,
             "transport_ns": 0, "validation_ns": 0, "startup_ns": 0,
             "retire_ns": sum(variants[n]["retire_ns"] for n in removed),
             "prepare_ns": sum(variants[n]["prepare_ns"] for n in acquired),
             "proof_ns": sum(variants[n]["proof_ns"] for n in acquired),
             "holding_ns": sum(variants[n]["holding_ns"] for n in target)}
    if mode == "invoke":
        for k in ("search_ns", "native_ns", "transport_ns", "validation_ns"):
            costs[k] = decision[k]
        costs["startup_ns"] = 0 if session_ready else decision["startup_ns"]
    choices = [(model["baseline"]["latency_ns"][batch], "baseline")]
    choices += [(variants[n]["latency_ns"][batch], n) for n in target]
    costs["execution_ns"], dispatch = min(choices)
    return {"mode": mode, "batch": batch, "ready_before": list(ready),
            "ready_after": list(target), "acquired": list(acquired), "retired": list(removed),
            "invalidated": sorted(set(ready) - set(live)), "dispatch": dispatch,
            "costs": costs, "total_ns": sum(costs.values()),
            "session_after": session_ready or mode == "invoke"}


def _skip_schedule(model):
    variants, _, horizon = _parts(model)
    ready = tuple(sorted(model["ready"]))
    actions = []
    for batch in range(horizon):
        action = _action(model, variants, ready, batch, model["session_ready"], "skip")
        actions.append(action)
        ready = tuple(action["ready_after"])
    close = model["decision"]["close_ns"] if model["session_ready"] else 0
    total = sum(a["total_ns"] for a in actions) + close
    return {"actions": actions, "close_ns": close, "total_ns": total,
            "feasible": total <= model["budget_ns"]}


def skip_schedule(raw):
    return _skip_schedule(validate_model(raw))


def _gate(model):
    variants, _, horizon = _parts(model)
    skip = _skip_schedule(model)
    # Optimistic: ignore all preparation, proof, holding, memory and retirement.
    # Their nonnegativity makes this a lower bound for any delivery plan.
    execution_lower = sum(min([model["baseline"]["latency_ns"][b]] +
                             [v["latency_ns"][b] for v in variants.values()
                              if v["status"] == "verified" and v["valid"][b]]) for b in range(horizon))
    decision = model["decision"]
    call_floor = sum(decision[k] for k in ("search_ns", "native_ns", "transport_ns", "validation_ns"))
    call_floor += 0 if model["session_ready"] else decision["startup_ns"]
    common_gate = horizon * decision["gate_ns"]
    # A newly started native session must also be closed, once.
    invocation_lower = execution_lower + common_gate + call_floor + decision["close_ns"]
    saving_upper = skip["total_ns"] - (execution_lower + common_gate)
    if invocation_lower > model["budget_ns"]:
        mode, reason = ("skip", "invocation cannot fit even optimistic budget") if skip["feasible"] else ("refuse", "delivery cannot fit registered optimistic model bounds")
    elif skip["feasible"] and invocation_lower >= skip["total_ns"]:
        mode, reason = "skip", "optimistic saving cannot pay for invocation"
    else:
        mode, reason = "consider", "a cost-feasible improvement is not ruled out"
    return {"mode": mode, "reason": reason, "skip": skip,
            "saving_upper_ns": saving_upper, "invocation_lower_ns": invocation_lower,
            "bound_scope": "supplied finite integer model; measured estimates are not physical guarantees"}


def invocation_gate(raw):
    return _gate(validate_model(raw))


class _Planner:
    """One immutable-model planner with an exact budget-free continuation cache.

    All edge and terminal costs are nonnegative, and budget is only a scalar
    upper bound on that same total. A minimum-cost continuation fits iff any
    continuation fits. Thus remaining budget does not distinguish continuation
    subproblems. Status, validity, resident set, session state and batch do.
    The original budget is still applied to every complete first-action witness.
    See formal/HiaNduBudgetErasure.lean for the finite-tree model theorem.
    """
    def __init__(self, model):
        self.model = model
        self.variants, self.sets, self.horizon = _parts(model)
        self.counters = {"states": 0, "actions": 0}
        self._continuations = {}

    def solve(self, batch, ready, session_ready):
        key = batch, ready, session_ready
        if key not in self._continuations:
            self._continuations[key] = self._solve(batch, ready, session_ready)
        return self._continuations[key]

    def _choices(self):
        return [("skip", None)] + [("invoke", value) for value in self.sets]

    def _solve(self, batch, ready, session_ready):
        self.counters["states"] += 1
        if batch == self.horizon:
            close = self.model["decision"]["close_ns"] if session_ready else 0
            return close, (), close
        best = None
        for mode, target in self._choices():
            action = _action(self.model, self.variants, ready, batch,
                             session_ready, mode, target)
            self.counters["actions"] += 1
            if action is None:
                continue
            tail = self.solve(batch + 1, tuple(action["ready_after"]),
                              action["session_after"])
            if tail is None:
                continue
            value = action["total_ns"] + tail[0], (action,) + tail[1], tail[2]
            # The same ordered choices preserve skip-first/lexical ties.
            if best is None or value[0] < best[0]:
                best = value
        return best

    def frontier(self, *, committed_call_ns=None):
        """Complete least-cost first-action frontier, optionally after a call.

        A committed first skip has already opened the session and incurred the
        current call, even though its artifact state does not change. The same
        continuation cache covers that state; no second exact search is needed.
        """
        ready = tuple(sorted(self.model["ready"]))
        witnesses = []
        for mode, target in self._choices():
            committed_skip = committed_call_ns is not None and mode == "skip"
            session_ready = True if committed_skip else self.model["session_ready"]
            action = _action(self.model, self.variants, ready, 0,
                             session_ready, mode, target)
            if action is None:
                continue
            extra = committed_call_ns if committed_skip else 0
            if action["total_ns"] + extra > self.model["budget_ns"]:
                continue
            tail = self.solve(1, tuple(action["ready_after"]), action["session_after"])
            if tail is None:
                continue
            total = action["total_ns"] + tail[0] + extra
            if total > self.model["budget_ns"]:
                continue
            plan = {"actions": [action, *tail[1]], "close_ns": tail[2], "total_ns": total}
            if committed_call_ns is not None:
                plan["current_committed_ns"] = extra
            witnesses.append(plan)
        return witnesses

    def exact(self):
        witnesses = self.frontier()
        best = min(witnesses, key=lambda p: p["total_ns"], default=None)
        return {"best": best, "witnesses": witnesses, "search": dict(self.counters),
                "scope": "exact within v2 finite deterministic cost model",
                "native_evaluation": False, "authority": "DENY_ALL", "safety_certificate": False}


def _exact(model):
    return _Planner(model).exact()


def exact_control(raw):
    return _exact(validate_model(raw))


def lightweight_control(raw):
    """One-batch greedy control; no hidden future work or native call."""
    model = validate_model(raw)
    variants, sets, _ = _parts(model)
    ready = tuple(sorted(model["ready"]))
    actions = [_action(model, variants, ready, 0, model["session_ready"], "skip")]
    actions += [_action(model, variants, ready, 0, model["session_ready"], "invoke", s) for s in sets]
    valid = [a for a in actions if a is not None and a["total_ns"] <= model["budget_ns"]]
    return min(valid, key=lambda a: a["total_ns"], default=None)


def build_request(raw):
    """Bind exact witnesses to original Rust NDU. This grants no authority.

    The current invocation is already committed when evaluating this request.
    Therefore it is charged to EVERY candidate (including the first skip),
    once, before adding future invocation costs. Otherwise a fictitious free
    skip could undercut a physically incurred native call.
    """
    return _build_request(validate_model(raw))


def _build_request(model, planner=None):
    # Internal callers pass only this request's detached validated model and
    # planner. No mutable caller cache or cross-request plan is accepted.
    planner = _Planner(model) if planner is None else planner
    original_session = model["session_ready"]
    decision = model["decision"]
    current_charge = sum(decision[k] for k in ("search_ns", "native_ns", "transport_ns", "validation_ns"))
    current_charge += 0 if original_session else decision["startup_ns"]
    support = {"model": model, "recurrence": "batch,resident-set,session-ready,remaining-budget",
               "scope": "scalar completion-minus-total-cost; zero risk and uncertainty",
               "compaction": "one minimum-cost witness per first action; complete first-action frontier",
               "verification": "independent caller admission, not authenticated by model digests"}
    candidates, mapping = [], {}
    for witness in planner.frontier(committed_call_ns=current_charge):
        plan = deepcopy(witness)
        identity = "cost-" + digest(plan)[:24]
        mapping[identity] = plan
    # The native protocol requires literal abstain to have exactly zero effect
    # and zero incremental cost. The already-committed call and unavoidable
    # session close are common costs, reserved BEFORE this advisory request.
    # They stay in each full plan and the actual ledger; they are never erased.
    common_charge = current_charge + decision["close_ns"]
    support["committed_and_reserved_ns"] = common_charge
    support["native_resource_budget_ns"] = max(0, model["budget_ns"] - common_charge)
    support["plans"] = mapping
    support_hash = digest(support)
    for identity, plan in mapping.items():
        candidates.append(candidate(candidate_id=identity, verified=True,
            verification_digest=digest([model["baseline"]["verification_sha256"],
                                        [v["verification_sha256"] for v in model["variants"]]]),
            support_digest=support_hash,
            events=[event(identity=identity+support_hash, instant_q32=-((plan["total_ns"] - common_charge) * Q32 // 1_000_000),
                          preference_digest=model["objective_digest"])],
            terminal_q32=model["completion_value_ns"] * Q32 // 1_000_000,
            resource_cost_q32=(plan["total_ns"] - common_charge) * Q32 // 1000))
    candidates.append(candidate(candidate_id="abstain", verified=True,
        verification_digest=digest("literal-no-delivery"), support_digest=support_hash,
        events=[event(identity="abstain"+support_hash, instant_q32=0,
                      preference_digest=model["objective_digest"])], terminal_q32=0))
    request = {"schema": REQUEST_SCHEMA, "objective_digest": model["objective_digest"],
               "snapshot_digest": digest(model), "generation": model["generation"],
               "utility_unit": "completion-minus-wall-milliseconds", "resource_unit": "microseconds",
               "risk_unit": "probability", "risk_ceiling_q32": Q32,
               "resource_budget_q32": max(0, model["budget_ns"] - common_charge) * Q32 // 1000,
               "candidates": candidates}
    return {"request": request, "plans": mapping, "support": support,
            "search_complete": True, "authority": "DENY_ALL", "safety_certificate": False}


def project_advice(bundle, response):
    _require(response.get("authority") == "DENY_ALL" and response.get("safety_certificate") is False,
             "native authority must remain denied")
    ids = response.get("pareto_candidate_ids", [])
    _require(type(ids) is list and bool(ids), "empty native frontier")
    if "abstain" in ids:
        return None
    _require(all(i in bundle["plans"] for i in ids), "unknown native plan")
    first = [bundle["plans"][i]["actions"][0] for i in ids]
    keys = {(tuple(a["ready_after"]), a["dispatch"]) for a in first}
    if len(keys) != 1:
        return None
    return first[0]


class AdvisoryController:
    """Lazy real bridge invocation; skip never constructs the session.

    session_factory must return an identity-checking NduSession, not a Python
    surrogate in native qualification.  prepare/retire/execute remain owned by
    the caller, which independently checks the artifact before execution.
    """
    def __init__(self, session_factory):
        self._factory = session_factory
        self.session = None
        self.ledger = []
        self._closed = False

    def decide(self, raw):
        start = time.monotonic_ns()
        _require(not self._closed, "controller is closed")
        model = validate_model(raw)
        _require(model["session_ready"] == (self.session is not None), "session state drift")
        gate = _gate(model)
        row = {"gate": gate, "native_invoked": False, "startup_ns": 0,
               "request_ns": 0, "search_ns": 0, "response_projection_ns": 0}
        action = gate["skip"]["actions"][0] if gate["mode"] == "skip" else None
        if gate["mode"] == "consider":
            searched = time.monotonic_ns()
            planner = _Planner(model)
            exact = planner.exact()
            row["search_ns"] = time.monotonic_ns() - searched
            if exact["best"] is None:
                row["reason"] = "no budget-feasible plan"
            elif exact["best"]["actions"][0]["mode"] == "skip":
                action = exact["best"]["actions"][0]
                row["reason"] = "exact continuation chooses skip now"
            else:
                # Real wall-budget guard before launching a process; no launch
                # after the request/model work consumed the available budget.
                elapsed = time.monotonic_ns() - start
                if elapsed + gate["invocation_lower_ns"] > model["budget_ns"]:
                    row["reason"] = "actual planning cost exhausted optional budget"
                    action = gate["skip"]["actions"][0] if gate["skip"]["feasible"] else None
                else:
                    built = time.monotonic_ns()
                    bundle = _build_request(model, planner)
                    row["search_ns"] += time.monotonic_ns() - built
                    if time.monotonic_ns() - start + gate["invocation_lower_ns"] > model["budget_ns"]:
                        row["reason"] = "actual request construction exhausted optional budget"
                        action = gate["skip"]["actions"][0] if gate["skip"]["feasible"] else None
                    else:
                        try:
                            if self.session is None:
                                opened = time.monotonic_ns()
                                self.session = self._factory()
                                row["startup_ns"] = time.monotonic_ns() - opened
                            # Startup is measured, not assumed to fit its estimate.
                            reserved = model["decision"]["transport_ns"] + model["decision"]["native_ns"]
                            reserved += model["decision"]["validation_ns"] + model["decision"]["close_ns"]
                            if time.monotonic_ns() - start + reserved > model["budget_ns"]:
                                row["reason"] = "actual session startup exhausted optional budget"
                                action = gate["skip"]["actions"][0] if gate["skip"]["feasible"] else None
                            else:
                                invoked = time.monotonic_ns()
                                row["native_invoked"] = True
                                response = self.session.evaluate(bundle["request"])
                                row["request_ns"] = time.monotonic_ns() - invoked
                                projected = time.monotonic_ns()
                                action = project_advice(bundle, response)
                                frontier = response["pareto_candidate_ids"]
                                model_minimum = min((p["total_ns"] for p in bundle["plans"].values()), default=None)
                                row["same_information_exact_minimum_ns"] = model_minimum
                                row["native_matches_exact_model"] = bool(frontier) and all(
                                    i in bundle["plans"] and bundle["plans"][i]["total_ns"] == model_minimum
                                    for i in frontier)
                                row["response_projection_ns"] = time.monotonic_ns() - projected
                                row["bundle"], row["response"] = bundle, response
                                row["reason"] = "native unanimous first-action projection" if action else "native abstention or conflicting first actions"
                        except NduBridgeError as error:
                            row["reason"], row["native_error"] = "native refusal; retain admitted incumbent", str(error)
                            action = gate["skip"]["actions"][0] if gate["skip"]["feasible"] else None
                            if self.session is not None:
                                self.session.close()
                                self.session = None
        row["reason"] = row.get("reason", gate["reason"])
        row["wall_ns"] = time.monotonic_ns() - start
        # Native evaluation and projection can outlive their estimates. A
        # response is evidence, not permission to begin optional work after
        # this decision's remaining wall budget has already been consumed.
        # Preserve its receipt, but fall back to the already-admitted incumbent
        # (or refusal). This does not guarantee that delivery can meet a deadline.
        if (action is not None and action["mode"] == "invoke"
                and row["wall_ns"] >= model["budget_ns"]):
            row["reason_before_budget_guard"] = row["reason"]
            row["reason"] = "actual decision cost exhausted optional budget"
            row["optional_action_withheld"] = True
            action = gate["skip"]["actions"][0] if gate["skip"]["feasible"] else None
        row["action"] = action
        self.ledger.append(row)
        return action, row

    def close(self):
        started = time.monotonic_ns()
        if self.session is not None:
            self.session.close()
        self._closed = True
        return time.monotonic_ns() - started
