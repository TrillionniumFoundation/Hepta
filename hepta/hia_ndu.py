"""Call the original Rust NDU algorithms; all returned decisions are advisory.

The compiler's independent verifier must establish candidate legality. Neither a
``verified`` input nor a digest authenticates that fact, and this module never
issues safety or deployment credentials. Costs and continuation values are
supplied measurements/estimates with a declared scope, not performance proofs.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any

Q32 = 1 << 32
REQUEST_SCHEMA = "hepta.hia.ndu.request.v1"
MAX_REQUEST_BYTES = 1_048_576


class NduBridgeError(ValueError):
    """Invalid input, mismatched executable identity or rejected native request."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NduBridgeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(raw: bytes) -> dict[str, Any]:
    try:
        result = json.loads(raw, object_pairs_hook=_unique_object,
                            parse_constant=lambda value: (_ for _ in ()).throw(
                                NduBridgeError(f"non-finite JSON value: {value}")))
    except (ValueError, UnicodeError) as error:
        raise NduBridgeError(str(error)) from error
    if not isinstance(result, dict):
        raise NduBridgeError("expected a JSON object")
    return result


def _sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def event(*, identity: str, instant_q32: int, discount_q32: int = Q32,
          preference_digest: str) -> dict[str, Any]:
    """Describe one actual/modeled continuation step, including refused work.

    Use a distinct identity for each physical step. A refusal still has its real
    negative cost; a stop step has no invented future improvement. The native
    implementation checks sequence, duplicate identities and discount bounds.
    """
    return {"event_digest": hashlib.sha256(identity.encode()).hexdigest(),
            "preference_digest": preference_digest, "instant_q32": instant_q32,
            "discount_q32": discount_q32}


def candidate(*, candidate_id: str, verified: bool, verification_digest: str,
              support_digest: str, events: list[dict[str, Any]], terminal_q32: int,
              resource_cost_q32: int = 0, risk_q32: int = 0,
              uncertainty_q32: int = 0) -> dict[str, Any]:
    """Bind an upstream decision to a value path without minting any authority."""
    return {"id": candidate_id, "verified": verified,
            "verification_digest": verification_digest, "support_digest": support_digest,
            "events": events, "terminal_q32": terminal_q32,
            "resource_cost_q32": resource_cost_q32, "risk_q32": risk_q32,
            "uncertainty_q32": uncertainty_q32}


def finite_plan_request(*, objective_digest: str, snapshot_digest: str, generation: int,
                        initial_state: str, states: dict[str, dict[str, Any]],
                        transitions: list[dict[str, Any]], batch_costs_ns: dict[str, list[int]],
                        remaining_budget_ns: int, completion_value_ns: int,
                        decision_cost_ns: int, observations: list[dict[str, Any]],
                        max_paths: int = 127) -> dict[str, Any]:
    """Enumerate an explicitly bounded graph and ask native NDU to rank paths.

    Each state binds a source and upstream verification digest. Each transition
    binds its actual proposal/proof support and a measured cost estimate. Values
    are future increments only; past observations bind the support without being
    charged again against literal abstention. A stop path closes optimization
    while still delivering every remaining batch. Other paths execute only their
    first action before the caller measures and replans.

    This is enumeration/transport, not proof verification or a learned cost
    model. The caller must independently verify any chosen code before loading
    its sealed native artifact. Exceeding the path bound rejects the whole plan;
    an incomplete search is never silently described as complete.
    """
    def fail(message: str) -> None:
        raise NduBridgeError(f"finite graph: {message}")

    def bounded_int(value: Any, name: str, maximum: int = 1_000_000_000_000) -> int:
        if type(value) is not int or not 0 <= value <= maximum:
            fail(f"{name} must be a bounded nonnegative integer")
        return value

    def valid_digest(value: Any, name: str) -> str:
        if (not isinstance(value, str) or len(value) != 64 or value == "0" * 64
                or any(ch not in "0123456789abcdef" for ch in value)):
            fail(f"{name} must be a nonzero lowercase SHA-256")
        return value

    def stable_id(value: Any) -> None:
        if (not isinstance(value, str) or not 1 <= len(value) <= 64
                or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for ch in value)):
            fail("state/transition identity is invalid")

    def sha(value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                         allow_nan=False).encode()).hexdigest()

    valid_digest(objective_digest, "objective")
    valid_digest(snapshot_digest, "snapshot")
    bounded_int(generation, "generation", (1 << 32) - 1)
    if generation == 0:
        fail("generation must be nonzero")
    bounded_int(remaining_budget_ns, "remaining budget")
    bounded_int(completion_value_ns, "completion value")
    bounded_int(decision_cost_ns, "future decision cost")
    if type(max_paths) is not int or not 1 <= max_paths <= 127:
        fail("max_paths must reserve one native slot for abstention")
    stable_id(initial_state)
    if not isinstance(states, dict) or not 1 <= len(states) <= 8 or initial_state not in states:
        fail("one to eight states including the current state are required")
    if not isinstance(batch_costs_ns, dict) or set(batch_costs_ns) != set(states):
        fail("every state must have costs for the same future batches")
    if not all(isinstance(value, list) for value in batch_costs_ns.values()):
        fail("each state's future batch costs must be a list")
    if (not isinstance(observations, list) or len(observations) > 128
            or not all(isinstance(value, dict) for value in observations)):
        fail("at most 128 explicit past observations may be supplied")
    horizon = len(batch_costs_ns[initial_state])
    if not 1 <= horizon <= 4:
        fail("the finite horizon must contain one to four remaining batches")
    states, transitions, batch_costs_ns = deepcopy((states, transitions, batch_costs_ns))
    for state_id, state in states.items():
        stable_id(state_id)
        if not isinstance(state, dict) or set(state) != {"source_sha256", "verification_sha256", "status"}:
            fail("unknown or missing state fields")
        valid_digest(state["source_sha256"], "state source")
        valid_digest(state["verification_sha256"], "state verification")
        if state["status"] not in {"verified", "rejected", "unknown", "timeout"}:
            fail("unknown verification status")
        if len(batch_costs_ns[state_id]) != horizon:
            fail("cost horizon mismatch")
        for value in batch_costs_ns[state_id]:
            bounded_int(value, "batch execution cost")
    if states[initial_state]["status"] != "verified":
        fail("the current executable state must have upstream verification")
    if not isinstance(transitions, list) or len(transitions) > 32:
        fail("at most 32 transitions may be supplied")
    outgoing: dict[str, list[dict[str, Any]]] = {key: [] for key in states}
    ids: set[str] = set()
    for transition in transitions:
        if not isinstance(transition, dict) or set(transition) != {"id", "source", "target", "setup_ns", "status",
                              "verification_sha256", "support_sha256"}:
            fail("unknown or missing transition fields")
        stable_id(transition["id"])
        if transition["id"] in ids or transition["id"] in {"hold", "stop"}:
            fail("transition IDs must be unique and not reserved")
        ids.add(transition["id"])
        if (transition["source"] not in states or transition["target"] not in states
                or transition["source"] == transition["target"]):
            fail("transition endpoints must be distinct existing states")
        bounded_int(transition["setup_ns"], "transition setup cost")
        if transition["status"] not in {"verified", "rejected", "unknown", "timeout"}:
            fail("unknown transition verification status")
        valid_digest(transition["verification_sha256"], "transition verification")
        valid_digest(transition["support_sha256"], "transition support")
        outgoing[transition["source"]].append(transition)

    graph = {"schema": "hepta.hia.ndu.finite-graph.v1", "initial_state": initial_state,
             "states": states, "transitions": transitions, "batch_costs_ns": batch_costs_ns,
             "horizon": horizon, "future_decision_cost_ns": decision_cost_ns}
    support = {"graph": graph, "observations": deepcopy(observations),
               "sunk_cost_policy": "retained in actual ledger, excluded from future increments"}
    try:
        encoded_support = json.dumps(support, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()
    except (TypeError, ValueError, UnicodeError) as error:
        raise NduBridgeError(f"finite graph: invalid support evidence: {error}") from error
    if len(encoded_support) > MAX_REQUEST_BYTES:
        fail("support evidence exceeds 1 MiB")
    support_digest = hashlib.sha256(encoded_support).hexdigest()
    plans: dict[str, dict[str, Any]] = {}

    def add(actions: list[dict[str, Any]]) -> None:
        if len(plans) >= max_paths:
            fail("complete enumeration exceeds the registered path budget")
        identity = "plan-" + sha(actions)[:24]
        verified = all(states[action["target"]]["status"] == "verified"
                       and action["status"] == "verified" for action in actions)
        proof = sha([{"state": states[action["target"]]["verification_sha256"],
                      "transition": action["verification_sha256"]} for action in actions])
        plans[identity] = {"id": identity, "actions": actions, "verified": verified,
                           "verification_sha256": proof,
                           "estimated_cost_ns": sum(action["setup_ns"] + action["decision_ns"]
                                                    + action["execution_ns"] for action in actions)}

    def walk(state_id: str, batch: int, prefix: list[dict[str, Any]]) -> None:
        if batch == horizon:
            add(prefix)
            return
        # Stopping optimization is an executable remaining-delivery plan.
        stopped = [{"id": "stop", "mode": "stop" if i == batch else "stopped",
                    "source": state_id, "target": state_id, "batch": i,
                    "setup_ns": 0, "decision_ns": decision_cost_ns if i == batch and i else 0,
                    "execution_ns": batch_costs_ns[state_id][i], "status": "verified",
                    "verification_sha256": states[state_id]["verification_sha256"]}
                   for i in range(batch, horizon)]
        add(prefix + stopped)
        options = list(outgoing[state_id])
        # At the final batch, hold and stop have identical effects, so hold is
        # omitted as a duplicate executable plan rather than a value tie-break.
        if batch + 1 < horizon:
            options.append({"id": "hold", "source": state_id, "target": state_id,
                            "setup_ns": 0, "status": "verified",
                            "verification_sha256": states[state_id]["verification_sha256"]})
        for edge in options:
            action = {"id": edge["id"], "mode": "hold" if edge["id"] == "hold" else "transition",
                      "source": state_id, "target": edge["target"], "batch": batch,
                      "setup_ns": edge["setup_ns"], "decision_ns": decision_cost_ns if batch else 0,
                      "execution_ns": batch_costs_ns[edge["target"]][batch], "status": edge["status"],
                      "verification_sha256": edge["verification_sha256"]}
            walk(edge["target"], batch + 1, prefix + [action])

    walk(initial_state, 0, [])
    candidates = []
    for plan in plans.values():
        events = []
        for action in plan["actions"]:
            for phase, cost in (("transition", action["setup_ns"] + action["decision_ns"]),
                                ("execution", action["execution_ns"])):
                events.append(event(identity=f"{snapshot_digest}:{plan['id']}:{action['batch']}:{phase}",
                    instant_q32=-(cost * Q32 // 1_000_000), preference_digest=objective_digest))
        candidates.append(candidate(candidate_id=plan["id"], verified=plan["verified"],
            verification_digest=plan["verification_sha256"], support_digest=support_digest,
            events=events, terminal_q32=completion_value_ns * Q32 // 1_000_000,
            resource_cost_q32=plan["estimated_cost_ns"] * Q32 // 1000))
    candidates.append(candidate(candidate_id="abstain", verified=True,
        verification_digest=sha("literal-no-effect"), support_digest=support_digest,
        events=[event(identity=f"{snapshot_digest}:abstain", instant_q32=0,
                      preference_digest=objective_digest)], terminal_q32=0))
    request = {"schema": REQUEST_SCHEMA, "objective_digest": objective_digest,
               "snapshot_digest": snapshot_digest, "generation": generation,
               "utility_unit": "completion-minus-wall-milliseconds", "resource_unit": "microseconds",
               "risk_unit": "probability", "risk_ceiling_q32": Q32,
               "resource_budget_q32": remaining_budget_ns * Q32 // 1000, "candidates": candidates}
    return {"request": request, "plans": plans, "support_evidence": support,
            "graph_sha256": sha(graph), "enumeration_complete": True,
            "authority": "DENY_ALL", "safety_certificate": False}


class NduBridge:
    """Identity-checked subprocess transport for the bounded original NDU CLI.

    The identity manifest is a locally trusted build input. Hash checks detect
    drift; they do not provide remote attestation or defend a hostile build host.
    """

    def __init__(self, executable: str | os.PathLike[str],
                 identity_manifest: str | os.PathLike[str], *, timeout: float = 10.0):
        self.executable = Path(executable).resolve(strict=True)
        self.identity_manifest = Path(identity_manifest).resolve(strict=True)
        self.timeout = timeout
        self.manifest = _read_json(self.identity_manifest.read_bytes())
        if self.manifest.get("schema") != "hepta.hia.ndu.build.v1":
            raise NduBridgeError("unsupported build identity schema")
        if not 0 < timeout <= 120:
            raise NduBridgeError("timeout must be in (0, 120] seconds")
        self._verify_binary()
        observed = self._invoke(["--identity"], b"")
        if observed != self.manifest.get("identity"):
            raise NduBridgeError("native source identity does not match build manifest")

    def _verify_binary(self) -> None:
        if _sha256_file(self.executable) != self.manifest.get("binary_sha256"):
            raise NduBridgeError("native executable digest mismatch")

    def _invoke(self, arguments: list[str], payload: bytes) -> dict[str, Any]:
        try:
            completed = subprocess.run([str(self.executable), *arguments], input=payload,
                                       capture_output=True, timeout=self.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise NduBridgeError(f"native NDU execution failed: {error}") from error
        if len(completed.stdout) > 4 * MAX_REQUEST_BYTES:
            raise NduBridgeError("native response exceeds bound")
        result = _read_json(completed.stdout)
        if completed.returncode != 0 or result.get("status") == "error":
            raise NduBridgeError(str(result.get("error", "native NDU failed")))
        if result.get("authority") != "DENY_ALL" or result.get("safety_certificate") is not False:
            raise NduBridgeError("native transport attempted to confer authority")
        return result

    def evaluate(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return original native recursion and feasibility/Pareto receipts.

        Missing/invalid/unknown inputs fail closed in the Rust typed protocol.
        A caller must independently reverify the chosen code before deployment.
        """
        try:
            payload = json.dumps(request, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False).encode()
        except (ValueError, TypeError) as error:
            raise NduBridgeError(str(error)) from error
        if len(payload) > MAX_REQUEST_BYTES:
            raise NduBridgeError("request exceeds 1 MiB")
        self._verify_binary()
        response = self._invoke([], payload)
        if response.get("schema") != "hepta.hia.ndu.response.v1" or response.get("status") != "advisory":
            raise NduBridgeError("unsupported native response")
        expected = {"objective_digest": request.get("objective_digest"),
                    "snapshot_digest": request.get("snapshot_digest"),
                    "generation": request.get("generation"),
                    "request_digest": hashlib.sha256(payload).hexdigest(),
                    "identity": self.manifest["identity"]}
        if any(response.get(key) != value for key, value in expected.items()):
            raise NduBridgeError("native response has stale or foreign bindings")
        candidates = {row["id"] for row in request.get("candidates", [])}
        if response.get("advisory_candidate_id") not in candidates | {None}:
            raise NduBridgeError("native response names an unknown candidate")
        return response
