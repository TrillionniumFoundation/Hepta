"""Identical-request finite-path generators and distinct native control sessions.

This module contains no formal input generation at import time. The original
NDU entry point is admitted only through its unchanged pinned stream profile.
"""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import time

from hepta.hia_ndu import (MAX_REQUEST_BYTES, Q32, NduBridgeError, _read_json,
                          _validate_response, finite_plan_request)
from hepta.hia_ndu_session import NduSession, STREAM_SOURCE_PIN

CONTROL_SCHEMA = "hepta.hia.native-control.response.v1"
CONTROL_SCOPES = {"native-exact-dp": "bounded-supplied-candidate-paths-only",
                  "native-myopic": "bounded-first-batch-surrogate-only"}
ARMS = ("native-ndu", "native-exact-dp", "native-myopic")
SEEDS = {"development": 12648430, "formal": 2366149847}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return sha256(canonical(value)).hexdigest()


def next_word(seed, index, label):
    return int.from_bytes(sha256(f"{seed}:{index}:{label}".encode()).digest()[:8], "little")


def fields(index, *, seed, phase, permit_formal=False):
    if (phase not in SEEDS or type(seed) is not int or seed != SEEDS[phase]
            or type(index) is not int or not 0 <= index < 4096
            or phase == "formal" and (permit_formal is not True or index >= 2048)):
        raise ValueError("exact phase/seed/index and published formal preregistration required")
    regime = index % 3
    count = (2, 4, 8)[regime]
    horizon = 4
    names = [f"state{i}" for i in range(count)]
    states = {name: {"source_sha256": digest(["fixture-source", name]),
                    "verification_sha256": digest(["fixture-verdict", name]),
                    "status": "verified" if i != count-1 or index % 7 else "rejected"}
              for i,name in enumerate(names)}
    initial = names[index % max(1,count-1)]
    states[initial]["status"] = "verified"
    costs, transitions = {}, []
    for i,name in enumerate(names):
        noise = next_word(seed,index,f"cost:{i}") % 10007
        if regime == 0:
            costs[name] = [350000 + 90000*i + noise + b*137 for b in range(horizon)]
        elif regime == 1:
            # The immediately cheap state becomes expensive; planning can matter.
            costs[name] = [(60000 if i == 0 and b == 0 else 1800000 if i == 0 else
                            260000 + i*90000) + noise + b*271 for b in range(horizon)]
        else:
            costs[name] = [120000 + ((i-b-index) % count)*170000 + noise + b*389
                           for b in range(horizon)]
        targets = sorted({names[(i+1)%count], names[(i+2)%count]} - {name})
        for target in targets:
            setup = 130000 + next_word(seed,index,f"edge:{name}:{target}") % 350000
            transitions.append({"id": f"to-{target}-from-{name}", "source": name, "target": target,
                "setup_ns": setup, "status": states[target]["status"],
                "verification_sha256": states[target]["verification_sha256"],
                "support_sha256": digest(["edge-support",phase,index,name,target])})
    budget = (1800000, 3300000, 6000000)[index % 3]
    return {"objective_digest": digest(["common-profile",phase,seed]),
            "snapshot_digest": digest(["common-matrix",phase,seed,index]),
            "generation": index+1, "initial_state": initial, "states": states,
            "transitions": transitions, "batch_costs_ns": costs,
            "remaining_budget_ns": budget, "completion_value_ns": 10000000,
            "decision_cost_ns": 1000 + index%31, "observations": [],
            "max_paths": 127}


def packet(index, *, seed, phase, permit_formal=False):
    source = fields(index,seed=seed,phase=phase,permit_formal=permit_formal)
    bundle = finite_plan_request(**source)
    raw = json.dumps(bundle["request"],sort_keys=True,separators=(",",":"),
                     ensure_ascii=True,allow_nan=False).encode()
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("shared native wire input exceeded its unchanged bound")
    return {"index": index, "phase": phase, "fields": source, "bundle": bundle,
            "request_sha256": sha256(raw).hexdigest(), "request_bytes": len(raw),
            "canonical_request": raw.decode(),
            "authority": "DENY_ALL", "safety_certificate": False}


def python_oracle(request, *, myopic=False):
    """Independent tiny exhaustive recurrence; never used as native timing."""
    values, scores, rejected, evaluated = {}, {}, [], []
    for candidate in request["candidates"]:
        sequence = [candidate["terminal_q32"]]
        for event in reversed(candidate["events"]):
            if event["discount_q32"] != Q32:
                raise ValueError("oracle covers the registered unit-discount profile")
            sequence.insert(0, event["instant_q32"] + sequence[0])
        values[candidate["id"]] = sequence
        allowed = (candidate["verified"]
                   and candidate["resource_cost_q32"] <= request["resource_budget_q32"]
                   and candidate["risk_q32"] <= request["risk_ceiling_q32"])
        if not allowed:
            rejected.append(candidate["id"])
            continue
        evaluated.append(candidate["id"])
        scores[candidate["id"]] = (candidate["terminal_q32"] +
            sum(event["instant_q32"] for event in candidate["events"][:2])
            if myopic else sequence[0])
    maximum = max(scores.values())
    frontier = sorted(name for name,value in scores.items() if value == maximum)
    return {"values_q32": values, "frontier": frontier, "evaluated": sorted(evaluated),
            "rejected": sorted(rejected), "selected": frontier[0] if len(frontier)==1 else None,
            "full_optimum_q32": max(values[name][0] for name in evaluated)}


def compare_receipt(response, request, *, arm):
    expected = python_oracle(request,myopic=arm=="native-myopic")
    actual_values = {row["id"]:row["values_q32"] for row in response["paths"]}
    if (actual_values != expected["values_q32"]
            or sorted(response["pareto_candidate_ids"]) != expected["frontier"]
            or sorted(response["evaluated_candidate_ids"]) != expected["evaluated"]
            or sorted(row["id"] for row in response["rejected"]) != expected["rejected"]
            or response["advisory_candidate_id"] != expected["selected"]):
        raise ValueError("actual native advice differs from independent exhaustive oracle")
    chosen = response["advisory_candidate_id"]
    # Unresolved ties do not secretly receive an arbitrary execution choice.
    selected_utility = None if chosen is None else actual_values[chosen][0]
    regrets = [expected["full_optimum_q32"] - actual_values[name][0] for name in expected["frontier"]]
    return {"frontier": expected["frontier"], "selected": chosen,
            "selected_full_path_utility_q32": selected_utility,
            "optimal_full_path_utility_q32": expected["full_optimum_q32"],
            "full_path_regret_q32": None if selected_utility is None else expected["full_optimum_q32"]-selected_utility,
            "unresolved_frontier": chosen is None,
            "frontier_regret_min_q32": min(regrets), "frontier_regret_max_q32": max(regrets),
            "independent_oracle_agrees": True,
            "authority": "DENY_ALL", "safety_certificate": False}


class ControlSession(NduSession):
    """Same sealed process/stream implementation; separate control semantics.

    Schema normalization below is ONLY a copy for existing structural/provenance
    checks. Raw responses remain separately named control records. In particular
    a myopic frontier is never represented as an exact full-path NDU frontier.
    Original NDU admission and its original pin are not changed.
    """
    def __init__(self, executable, manifest, *, arm, timeout=10.0):
        if arm not in CONTROL_SCOPES:
            raise NduBridgeError("unknown separate native control")
        self.arm = arm
        self.host_control_admission_costs_ns = []
        super().__init__(executable,manifest,timeout=timeout)
        identity = self.manifest.get("identity",{})
        expected_algorithm = "hepta.control." + ("exact-suffix-dp" if arm=="native-exact-dp" else "myopic-first-batch")
        if (identity.get("schema") != "hepta.hia.native-control.identity.v1"
                or identity.get("source_commit") == STREAM_SOURCE_PIN
                or identity.get("algorithms") != [expected_algorithm]):
            self.close()
            raise NduBridgeError("control identity must remain separate from original native NDU")

    def evaluate(self, request):
        with self._lock:
            if self._closed:
                raise NduBridgeError("closed control session")
            started = time.monotonic_ns()
            try:
                payload = json.dumps(request,sort_keys=True,separators=(",",":"),
                                     ensure_ascii=True,allow_nan=False).encode()
                if len(payload) > MAX_REQUEST_BYTES:
                    raise NduBridgeError("request exceeds unchanged 1 MiB bound")
                frozen = _read_json(payload)
                self._verify_binary()
                response = self._invoke([],payload)
                before_admission = time.monotonic_ns()
                if (response.get("schema") != CONTROL_SCHEMA
                        or response.get("optimality_scope") != CONTROL_SCOPES[self.arm]):
                    raise NduBridgeError("control advice schema/scope mismatch")
                structural = deepcopy(response)
                structural["schema"] = "hepta.hia.ndu.response.v1"
                structural["optimality_scope"] = "bounded-supplied-candidate-paths-only"
                _validate_response(structural,frozen,payload,self.manifest)
                self.host_control_admission_costs_ns.append(time.monotonic_ns()-before_admission)
                self._verify_binary()
                return response
            except BaseException:
                self._close_after_failure()
                raise
            finally:
                self._request_costs_ns.append(time.monotonic_ns()-started)

    def snapshot(self):
        value = super().snapshot()
        value["control_arm"] = self.arm
        value["host_control_structural_admission_costs_ns"] = list(self.host_control_admission_costs_ns)
        value["control_schema"] = CONTROL_SCHEMA
        value["control_scope"] = CONTROL_SCOPES[self.arm]
        value["native_ndu_evaluation_claim"] = False
        return value
