#!/usr/bin/env python3
"""Independent, read-only reconstruction of the 54-profile policy campaign.

No production planner, graph, evaluator, runner or model helper is imported.
The only inputs are the published protocol, frozen scenarios and raw artifacts.
All probabilistic calculations use fractions; round(Fraction) is ties-to-even.
The native-wire cryptographic audit is a separate reviewer artifact. This file
binds every native request, in postorder, to an independently computed backup.
"""
from collections import Counter, defaultdict
from fractions import Fraction as F
from hashlib import sha256
from itertools import product
from pathlib import Path
import argparse
import gzip
import json
import subprocess
import time

Q = 1 << 32
COMMIT = "a07c5ecae52436234af370779cc440686dbe4139"
TREE = "273e7c458713ede9593c03267245a5bf756fc4f7"
BASE = Path("/workspace/scratch/22f6defbc03d")
REPO = BASE / "hepta-ndu-next"
DATA = BASE / "policy-final-v1"
REG = BASE / "policy-registration-final-v1.json.gz"
ARMS = ("fixed-direct", "fixed-cache-0", "fixed-cache-1", "state-greedy",
        "ordinary-mpc", "same-objective", "fixed-preference-ndu", "dynamic-ndu",
        "wrong-forecast", "prior-belief-only", "no-adaptation", "exact-oracle")
NATIVE = ("fixed-preference-ndu", "dynamic-ndu")
FIXED = {"fixed-direct": -1, "fixed-cache-0": 0, "fixed-cache-1": 1}
LABEL = {-1: "direct", 0: "cache-0", 1: "cache-1", None: "abstain"}
FIELDS = ("step", "request", "signal", "resident", "budget", "deadline", "belief_num", "belief_den")
checks, failures, failed_counts, totals = Counter(), [], Counter(), Counter()
started = time.perf_counter_ns()


def check(name, ok, context=None):
    checks[name] += 1
    if not ok:
        failed_counts[name] += 1
        if len(failures) < 100:
            failures.append({"check": name, "context": context})


def load(path):
    path = Path(path)
    with (gzip.open if path.suffix == ".gz" else open)(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def identity(path):
    path = Path(path)
    raw = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def frac(value):
    return [value.numerator, value.denominator]


def obs_dict(state):
    return dict(zip(FIELDS, state))


def obs_tuple(observation):
    return tuple(observation[k] for k in FIELDS)


def scenario_inventory():
    """The unchanged 54 natural profiles, encoded without importing production."""
    for i, (name, resident, resources, load_cost) in enumerate(product(
            ("adaptive", "fixed", "misleading"), (-1, 0, 1),
            ((12, 24), (24, 12), (24, 24)), (4, 8))):
        s = dict(name=name, horizon=3, request_p0_z0_num=9, request_p0_z0_den=10,
            request_p0_z1_num=1, request_p0_z1_den=10, signal_correct_num=4,
            signal_correct_den=5, prior0_num=1, prior0_den=2, direct_cost=6,
            hot_cost=1, load_cost=load_cost, retire_cost=0, holding_cost=0,
            initial_resident=resident, initial_budget=resources[0], initial_deadline=resources[1],
            cost_unit=1, completion_reward_q32=20*Q, miss_penalty_q32=30*Q,
            discount_q32=15*Q//16, risk_aversion_q32=Q//4, dynamic_preferences=True,
            cost_unit_label="declared model cost units")
        if name == "fixed":
            s.update(request_p0_z0_num=99, request_p0_z0_den=100,
                request_p0_z1_num=99, request_p0_z1_den=100,
                signal_correct_num=1, signal_correct_den=2)
        if name == "misleading":
            s.update(signal_correct_num=1)
        yield f"natural-profile-{i:02}", s


class Reference:
    def __init__(self, scenario):
        self.s = scenario
        self.law_cache = {}
        self.backup_cache = {}
        self.postorder_cache = {}
        self.scenario_digest = digest(scenario)

    def events(self, numerator, denominator):
        key = (numerator, denominator)
        if key not in self.law_cache:
            s = self.s
            prior = F(numerator, denominator)
            q = (F(s["request_p0_z0_num"], s["request_p0_z0_den"]),
                 F(s["request_p0_z1_num"], s["request_p0_z1_den"]))
            sensor = F(s["signal_correct_num"], s["signal_correct_den"])
            law = []
            for request, signal in product((0, 1), repeat=2):
                joint = []
                for z, mass in enumerate((prior, 1-prior)):
                    p_signal0 = sensor if z == 0 else 1-sensor
                    joint.append(mass*(q[z] if request == 0 else 1-q[z]) *
                        (p_signal0 if signal == 0 else 1-p_signal0))
                probability = sum(joint, F(0))
                if probability:
                    posterior = joint[0]/probability
                    law.append((probability, request, signal, posterior.numerator, posterior.denominator))
            if sum(p for p, *_ in law) != 1:
                raise ArithmeticError("independent probability law is not normalized")
            self.law_cache[key] = law
        return self.law_cache[key]

    def cost(self, state, action):
        _, request, _, resident, *_ = state
        s = self.s
        return ((s["hot_cost"] if request == action else s["direct_cost"])
            + s["load_cost"]*int(action >= 0 and action != resident)
            + s["retire_cost"]*int(resident >= 0 and action != resident)
            + s["holding_cost"]*int(action >= 0))

    def pref(self, state, mode="dynamic"):
        s = self.s
        if mode == "ordinary":
            return dict(price_q32=Q, discount_q32=Q, risk_q32=0, scarcity_num=0, scarcity_den=1)
        if not s["dynamic_preferences"]:
            scarcity = F(0)
        elif mode == "fixed":
            scarcity = max(F(0), 1-F(min(s["initial_budget"], s["initial_deadline"]),
                max(s["cost_unit"], s["horizon"]*s["direct_cost"])))
        else:
            scarcity = max(F(0), 1-F(min(state[4:6]),
                max(s["cost_unit"], (s["horizon"]-state[0])*s["direct_cost"])))
        return dict(price_q32=round((1+scarcity)*Q), discount_q32=s["discount_q32"],
            risk_q32=min(Q, s["risk_aversion_q32"]+round(scarcity*Q/4)),
            scarcity_num=scarcity.numerator, scarcity_den=scarcity.denominator)

    @staticmethod
    def ce(weighted, risk):
        mean = sum((p*v for p, v in weighted), F(0))
        downside = sum((p*max(F(0), mean-v) for p, v in weighted), F(0))
        return round(mean-F(risk, Q)*downside)

    def child_states(self, state, action):
        cost = self.cost(state, action)
        return [(p, (state[0]+1, request, signal, action, state[4]-cost, state[5]-cost, num, den))
            for p, request, signal, num, den in self.events(state[6], state[7])]

    def graph(self):
        s = self.s
        roots = [(p, (0, req, sig, s["initial_resident"], s["initial_budget"], s["initial_deadline"], n, d))
            for p, req, sig, n, d in self.events(s["prior0_num"], s["prior0_den"])]
        nodes, frontier = {}, [state for p, state in roots]
        while frontier:
            state = frontier.pop()
            if state in nodes:
                continue
            actions = {None: []}
            for action in (-1, 0, 1):
                if self.cost(state, action) > min(state[4:6]):
                    continue
                successors = self.child_states(state, action) if state[0]+1 < s["horizon"] else []
                actions[action] = successors
                frontier.extend(child for p, child in successors)
            nodes[state] = actions
        ids = {state: digest({"scenario": self.scenario_digest, "observation": obs_dict(state)}) for state in nodes}
        raw = {"scenario_digest": self.scenario_digest,
            "roots": [{"probability": frac(p), "state_id": ids[state]} for p, state in roots],
            "edges": sum(len(children) for actions in nodes.values() for children in actions.values()),
            "nodes": [{"id": ids[state], "observation": obs_dict(state), "actions": {
                LABEL[a]: [{"probability": frac(p), "state_id": ids[child]} for p, child in successors]
                for a, successors in nodes[state].items()}} for state in sorted(nodes, key=ids.get)]}
        return roots, nodes, ids, raw

    def backup(self, mode, state, depth):
        key = (mode, state, depth)
        if key in self.backup_cache:
            return self.backup_cache[key]
        s, pref = self.s, self.pref(state, mode)
        candidates, dependencies = [], []
        for action in (-1, 0, 1):
            cost = self.cost(state, action)
            legal = cost <= min(state[4:6])
            continuation = []
            if legal and depth > 1:
                for p, child in self.child_states(state, action):
                    child_key = (mode, child, depth-1)
                    dependencies.append(child_key)
                    continuation.append((p, self.backup(*child_key)["value"]))
            raw_cost = round(F(cost*Q, s["cost_unit"]))
            immediate = -raw_cost if mode == "ordinary" else s["completion_reward_q32"]-round(F(pref["price_q32"]*raw_cost, Q))
            candidates.append(dict(id=LABEL[action], instant_q32=immediate,
                terminal_q32=self.ce(continuation, pref["risk_q32"]),
                discount_q32=pref["discount_q32"], feasible=legal, resource_q32=raw_cost, risk_q32=0))
        candidates.append(dict(id="abstain", instant_q32=-s["miss_penalty_q32"]*(s["horizon"]-state[0]),
            terminal_q32=0, discount_q32=Q, feasible=True, resource_q32=0, risk_q32=0))
        values = {c["id"]: c["instant_q32"]+round(F(c["discount_q32"]*c["terminal_q32"], Q)) for c in candidates}
        eligible = [c["id"] for c in candidates if c["feasible"]]
        selected = min(eligible, key=lambda name: (-values[name], name))
        result = dict(value=values[selected], selected=selected, values=values, pref=pref,
            candidates=candidates, dependencies=dependencies)
        self.backup_cache[key] = result
        return result

    def postorder(self, key, oracle=False):
        cache_key = (key, oracle)
        if cache_key in self.postorder_cache:
            return self.postorder_cache[cache_key]
        seen, order = set(), []
        def visit(current):
            mode, state, depth = current
            unique = (mode, state[:2]+state[3:], depth) if oracle else current
            if unique in seen:
                return
            seen.add(unique)
            node = self.backup(*current)
            for dependency in node["dependencies"]:
                visit(dependency)
            order.append(current)
        visit(key)
        self.postorder_cache[cache_key] = order
        return order

    def decision(self, state, arm):
        planned = state
        if arm in ("prior-belief-only", "no-adaptation"):
            planned = state[:6]+(self.s["prior0_num"], self.s["prior0_den"])
        elif arm == "wrong-forecast":
            planned = state[:6]+(state[7]-state[6], state[7])
        mode = "fixed" if arm in ("fixed-preference-ndu", "no-adaptation") else "ordinary" if arm == "ordinary-mpc" else "dynamic"
        depth = 1 if arm in FIXED or arm == "state-greedy" else self.s["horizon"]-state[0]
        key = (mode, planned, depth)
        result = self.backup(*key)
        selected = result["selected"]
        if arm in FIXED:
            desired = LABEL[FIXED[arm]]
            feasible = [c for c in result["candidates"] if c["feasible"] and c["id"] != "abstain"]
            if any(c["id"] == desired for c in feasible):
                selected = desired
            else:
                selected = min(feasible, key=lambda c: (c["resource_q32"], c["id"]))["id"] if feasible else "abstain"
        order = self.postorder(key, oracle=arm == "exact-oracle")
        n = len(order)
        return {"status": "completed", "arm": arm, "action": next(a for a, label in LABEL.items() if label == selected),
            "selected_action": selected, "planned_value_q32": result["values"][selected],
            "candidate_values_q32": result["values"], "preference": result["pref"],
            "original_observation": obs_dict(state), "planning_observation": obs_dict(planned),
            "planning_belief": list(planned[6:]), "search": {
                "states": n, "backups": n, "transitions": 4*n, "backend_calls": n if arm in NATIVE else 0},
            "native_backend_used": arm in NATIVE}, order

    def whole_policy(self, roots, nodes, actions):
        values, delivered, costs = {}, {}, {}
        for state in sorted(nodes, key=lambda x: x[0], reverse=True):
            a = actions[state]
            if a is None:
                values[state] = -self.s["miss_penalty_q32"]*(self.s["horizon"]-state[0])
                delivered[state], costs[state] = F(0), F(0)
                continue
            pref, cost = self.pref(state), self.cost(state, a)
            successors = nodes[state][a]
            continuation = self.ce([(p, values[child]) for p, child in successors], pref["risk_q32"])
            values[state] = self.s["completion_reward_q32"]-round(F(pref["price_q32"]*round(F(cost*Q, self.s["cost_unit"])), Q))
            values[state] += round(F(self.s["discount_q32"]*continuation, Q))
            delivered[state] = 1+sum((p*delivered[child] for p, child in successors), F(0))
            costs[state] = cost+sum((p*costs[child] for p, child in successors), F(0))
        summary = {"status": "completed", "value_q32": round(sum((p*values[state] for p, state in roots), F(0))),
            "expected_delivered": frac(sum((p*delivered[state] for p, state in roots), F(0))),
            "expected_cost": frac(sum((p*costs[state] for p, state in roots), F(0)))}
        return summary, values


def factorial(values):
    names = ("dynamic-ndu", "prior-belief-only", "fixed-preference-ndu", "no-adaptation")
    d, p, f, j = [values[a] for a in names]
    return {"status": "completed", "policy_values_q32": {a: values[a] for a in names},
        "belief_gain_with_dynamic_preferences_q32": d-p,
        "belief_gain_with_fixed_preferences_q32": f-j,
        "preference_gain_with_current_belief_q32": d-f,
        "preference_gain_with_prior_belief_q32": p-j, "interaction_q32": d-p-f+j,
        "historical_no_adaptation_scope": "joint belief and numerical-preference intervention"}


def audit_source(frozen, result):
    source = frozen["source"]
    check("source_commit_tree", source["commit"] == COMMIT and source["tree"] == TREE)
    check("result_frozen_source", result["source"] == source)
    check("current_head", subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO).decode().strip() == COMMIT)
    check("working_tree_clean", not subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO).strip())
    for name, expected in source["files"].items():
        raw = (REPO/name).read_bytes()
        committed = subprocess.check_output(["git", "--no-replace-objects", "cat-file", "blob", f"{COMMIT}:{name}"], cwd=REPO)
        check("source_file_hash_git_binding", sha256(raw).hexdigest() == expected and raw == committed, name)
    protocol = REPO/"benchmarks/hia_ndu_feedback_state_coverage/POLICY_PROTOCOL.json"
    check("protocol_bytes_and_semantics", sha256(protocol.read_bytes()).hexdigest() == frozen["protocol_sha256"] and load(protocol) == frozen["protocol"])
    check("base_model_unchanged", source["files"]["experiments/hia_ndu_feedback_20261106/model.py"] ==
        "56b335e5a7fc205e4ad955faf3eece2a63d43c097f71d5fb4af6d84ee1081b79")
    check("native_registration_identity", result["registration"] == identity(REG))
    check("frozen_registration_copy", load(DATA/"REGISTRATION.json.gz") == frozen)
    for name, item in frozen["inputs"].items():
        check("native_input_hash", identity(item["path"]) == item, name)
    manifest = load(frozen["inputs"]["value_manifest"]["path"])
    check("native_build_manifest_preserved", manifest == frozen["build_receipt"])
    check("native_build_binary_binding", manifest["binary_sha256"] == frozen["inputs"]["value_binary"]["sha256"])
    check("native_upstream_commit", manifest["upstream"]["commit"] == "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d")
    snapshots = {}
    for stage in ("before", "after"):
        p = BASE/"native-final"/f"source-{stage}.json"
        if p.exists():
            actual = load(p)
            snapshots[stage] = actual
            check("outer_native_source_snapshot", actual["head"] == actual["expected_head"] == COMMIT and
                actual["clean"] is True and actual["matches_expected_head"] is True and
                actual["status_porcelain"] == "" and actual["production_activation"] is False and
                all(actual["files"].get(name, {}).get("sha256") == expected
                    for name, expected in source["files"].items()), stage)
            totals["source_snapshot_files"] += 1
    check("full_source_snapshots_before_after_equal", len(snapshots) == 2 and
        snapshots["before"]["files"] == snapshots["after"]["files"] and
        snapshots["after"]["matches_before"] is True)
    totals["outer_source_snapshot_paths"] = len(snapshots["before"]["files"])
    totals["source_files"] = len(source["files"])


def audit_native(directory, arm, rows, reference, expected_orders, frozen, cost):
    path = directory/(arm+".jsonl")
    with path.open() as stream:
        hello = json.loads(next(stream))
        check("native_session_first_hello", hello["event"] == "hello", str(path))
        check("native_session_input_binding", hello["binary_sha256"] == frozen["inputs"]["value_binary"]["sha256"] and
            hello["manifest_sha256"] == frozen["inputs"]["value_manifest"]["sha256"], str(path))
        sequence, total_call_ns = 0, 0
        for row in rows:
            cell = row["arms"][arm]
            order = expected_orders[row["id"]][arm]
            check("native_state_call_range", cell["native_call_range"] == [sequence+1, sequence+len(order)], [directory.name, row["id"], arm])
            for key in order:
                sequence += 1
                mode, state, depth = key
                computed = reference.backup(*key)
                exchange, validated = json.loads(next(stream)), json.loads(next(stream))
                request, response = json.loads(exchange["request"]), json.loads(exchange["response"])
                expected = {"schema": "hepta.hia.ndu.value.request.v1", "sequence": sequence, "generation": 1,
                    "state_digest": digest(obs_dict(state)), "preference_digest": digest(computed["pref"]),
                    "objective_digest": digest({"rule": "state-price-plus-discounted-mean-downside-v1", "scenario": reference.s}),
                    "resource_budget_q32": round(F(min(state[4:6])*Q, reference.s["cost_unit"])),
                    "risk_ceiling_q32": Q, "candidates": computed["candidates"]}
                context = [directory.name, arm, row["id"], sequence]
                check("native_request_complete_independent_backup_binding", request == expected, context)
                check("native_session_exact_event_order", exchange["event"] == "exchange" and validated["event"] == "validated" and
                    exchange["sequence"] == validated["sequence"] == sequence, context)
                eligible = [c["id"] for c in computed["candidates"] if c["feasible"]]
                best = max(computed["values"][name] for name in eligible)
                winners = sorted(name for name in eligible if computed["values"][name] == best)
                check("native_response_consumed_independent_values", response["values_q32"] == computed["values"] and
                    response["winners"] == winners and response["chosen_id"] == winners[0] and
                    validated["values_q32"] == computed["values"] and validated["winners"] == winners, context)
                check("native_wire_frame_hashes", sha256(exchange["request"].encode()).hexdigest() == exchange["request_sha256"] and
                    sha256(exchange["response"].encode()).hexdigest() == exchange["response_sha256"], context)
                check("native_timing_nesting", 0 <= response["native_evaluation_ns"] <= exchange["wire_roundtrip_ns"] <= validated["outer_call_ns"], context)
                total_call_ns += validated["outer_call_ns"]
            check("native_root_action_consumed", response["chosen_id"] == cell["selected_action"] and
                response["values_q32"][response["chosen_id"]] == cell["planned_value_q32"], [directory.name, row["id"], arm])
        close = json.loads(next(stream))
        check("native_session_exact_eof", not stream.read().strip(), str(path))
    check("native_clean_close", close["event"] == "close" and close["reaped"] is True and close["returncode"] == 0
        and close["killed"] is False and close["stderr"] == "" and close["stderr_over_bound"] is False, str(path))
    check("native_close_counts", close["calls"] == sequence and close["total_call_ns"] == total_call_ns, str(path))
    check("native_cost_close_binding", cost["native_close"] == {"started": True, "calls": sequence,
        "startup_ns": hello["startup_ns"], "close_ns": close["close_ns"], "returncode": 0, "call_wall_ns": total_call_ns}, str(path))
    check("native_cost_nesting", hello["startup_ns"]+close["close_ns"]+total_call_ns <= cost["planning_wall_including_native_cleanup_ns"], str(path))
    totals["native_sessions"] += 1
    totals["native_calls"] += sequence
    totals["native_candidate_backups_bound"] += 4*sequence


def statistics():
    return Counter(states=0, first_action_positive=0, whole_policy_positive=0,
        first_zero_whole_positive=0, whole_regret_sum_q32=0, whole_regret_max_q32=0)


def add_regret(bucket, first, whole):
    bucket["states"] += 1
    bucket["first_action_positive"] += first > 0
    bucket["whole_policy_positive"] += whole > 0
    bucket["first_zero_whole_positive"] += first == 0 and whole > 0
    bucket["whole_regret_sum_q32"] += whole
    bucket["whole_regret_max_q32"] = max(bucket["whole_regret_max_q32"], whole)


def main():
    frozen, result = load(REG), load(DATA/"RESULT.json")
    audit_source(frozen, result)
    check("protocol_arms", tuple(frozen["protocol"]["arms"]) == ARMS)
    check("frozen_no_policy_decisions", frozen["freeze_command_policy_decisions"] == 0)
    expected_profiles = list(scenario_inventory())
    check("profile_identifiers_order", [p["id"] for p in frozen["profiles"]] == [p[0] for p in expected_profiles])
    check("result_profile_identifiers_order", [p["id"] for p in result["profiles"]] == [p[0] for p in expected_profiles])
    ledgers = {arm: Counter(transitions=0, planning_wall_ns=0, policy_evaluation_wall_ns=0, completed=0, failed=0, not_run=0) for arm in ARMS}
    regret_stats = {arm: statistics() for arm in (*ARMS, "model-optimal-fixed")}
    by_environment = {env: {arm: statistics() for arm in (*ARMS, "model-optimal-fixed")} for env in ("adaptive", "fixed", "misleading")}
    effects = Counter()
    example_cases = defaultdict(list)
    profile_rows = []
    total_graph_edges = maximum_states = maximum_edges = 0
    total_nested_wall = total_profiles_wall = 0
    artifact_files = set()
    for index, (pid, scenario) in enumerate(expected_profiles):
        item = frozen["profiles"][index]
        directory = DATA/pid
        context = pid
        check("unchanged_scenario_profiles", item["scenario"] == scenario, pid)
        reference = Reference(scenario)
        roots, nodes, ids, graph = reference.graph()
        reverse = {sid: state for state, sid in ids.items()}
        check("complete_all_action_graph_frozen", graph == item["graph"] and digest(graph) == item["graph_sha256"], pid)
        check("complete_all_action_graph_artifact", graph == load(directory/"GRAPH.json.gz"), pid)
        check("profile_graph_denominators", item["states"] == len(nodes) and item["edges"] == graph["edges"], pid)
        total_graph_edges += graph["edges"]
        maximum_states, maximum_edges = max(maximum_states, len(nodes)), max(maximum_edges, graph["edges"])
        rows = load(directory/"STATE_RESULTS.json.gz")
        summary = load(directory/"SUMMARY.json")
        check("summary_result_equality", summary == result["profiles"][index], pid)
        check("state_inventory_complete_sorted", [row["id"] for row in rows] == sorted(ids.values()), pid)
        check("summary_complete_counts", summary["planned_states"] == summary["retained_states"] == len(nodes) and
            summary["planned_cells"] == len(nodes)*len(ARMS) and summary["cell_status_counts"] == {"completed": len(nodes)*len(ARMS)}, pid)
        check("summary_pass_not_substituted", summary["status"] == "passed" and not summary["errors"] and
            all(v is True for v in summary["checks"].values()), pid)
        expected_artifacts = {p.name for p in directory.iterdir() if p.is_file()}-{"SUMMARY.json"}
        check("artifact_inventory_complete", {Path(a["path"]).name for a in summary["artifacts"]} == expected_artifacts, pid)
        for artifact in summary["artifacts"]:
            check("artifact_size_hash_binding", identity(artifact["path"]) == artifact, artifact["path"])
            artifact_files.add(artifact["path"])
        decisions, expected_orders = {}, {}
        for row in rows:
            sid, state = row["id"], reverse[row["id"]]
            check("row_observation_legal_actions", row["observation"] == obs_dict(state) and
                row["legal_actions"] == sorted(LABEL[a] for a in nodes[state]), [pid, sid])
            check("all_arms_retained", set(row["arms"]) == set(ARMS), [pid, sid])
            decisions[sid], expected_orders[sid] = {}, {}
            for arm in ARMS:
                computed, order = reference.decision(state, arm)
                decisions[sid][arm], expected_orders[sid][arm] = computed, order
                cell = row["arms"][arm]
                check("complete_independent_plan", all(cell.get(k) == v for k, v in computed.items()), [pid, sid, arm])
                check("decision_budget_and_time_bounds", computed["search"]["transitions"] <= 20000 and
                    type(cell["controller_wall_ns"]) is int and 0 <= cell["controller_wall_ns"] <= cell["observed_planning_wall_ns"], [pid, sid, arm])
                ledger = ledgers[arm]
                ledger["transitions"] += computed["search"]["transitions"]
                ledger["planning_wall_ns"] += cell["observed_planning_wall_ns"]
                ledger["completed"] += 1
                totals["decision_cells"] += 1
        full, values = {}, {}
        for arm in ARMS:
            full[arm], values[arm] = reference.whole_policy(roots, nodes,
                {state: decisions[ids[state]][arm]["action"] for state in nodes})
            check("whole_policy_ex_ante_and_physical_expectations", full[arm] == summary["policies"][arm], [pid, arm])
            cost = summary["costs"][arm]
            disk_cost = load(directory/(arm+".cost.json"))
            check("arm_cost_artifact_binding", all(cost[k] == v for k, v in disk_cost.items()) and
                set(cost)-set(disk_cost) == {"policy_evaluation_wall_ns", "policy_evaluation_state_visits"}, [pid, arm])
            check("arm_cost_transitions", cost["search_transitions"] == sum(decisions[r["id"]][arm]["search"]["transitions"] for r in rows), [pid, arm])
            check("arm_planning_cost_nesting", cost["planning_wall_including_native_cleanup_ns"] >=
                sum(row["arms"][arm]["observed_planning_wall_ns"] for row in rows), [pid, arm])
            check("whole_policy_denominator_timing", cost["policy_evaluation_state_visits"] == len(nodes) and cost["policy_evaluation_wall_ns"] >= 0, [pid, arm])
            ledgers[arm]["policy_evaluation_wall_ns"] += cost["policy_evaluation_wall_ns"]
            journal = [json.loads(line) for line in (directory/(arm+".attempts.jsonl")).read_text().splitlines()]
            check("attempt_journal_full_order", [j["state_id"] for j in journal] == [row["id"] for row in rows], [pid, arm])
            for row, attempt in zip(rows, journal):
                expected_cell = {k: v for k, v in row["arms"][arm].items() if k not in {
                    "whole_policy_value_q32", "whole_policy_regret_q32", "first_action_conditional_regret_q32"}}
                check("attempt_journal_exact_retention", attempt == {"state_id": row["id"], **expected_cell}, [pid, arm, row["id"]])
                totals["journal_cells"] += 1
            if arm in NATIVE:
                audit_native(directory, arm, rows, reference, expected_orders, frozen, cost)
            else:
                check("scalar_arm_not_represented_native", cost["native_close"] is None and not (directory/(arm+".jsonl")).exists(), [pid, arm])
        profile_values = {arm: full[arm]["value_q32"] for arm in ARMS}
        pf = factorial(profile_values)
        check("profile_factorial_independent", summary["factorial"] == pf, pid)
        best_fixed = min(FIXED, key=lambda arm: (-profile_values[arm], FIXED[arm]))
        fixed = summary["model_optimal_fixed"]
        check("single_ex_ante_strongest_fixed", fixed["arm"] == best_fixed and fixed["fixed_action"] == FIXED[best_fixed]
            and all(fixed[k] == v for k, v in full[best_fixed].items()) and
            fixed["all_candidate_values_q32"] == {arm: profile_values[arm] for arm in FIXED}, pid)
        check("strongest_fixed_all_candidate_costs", fixed["all_candidate_planning_wall_ns"] ==
            sum(summary["costs"][a]["planning_wall_including_native_cleanup_ns"] for a in FIXED) and
            fixed["all_candidate_evaluation_wall_ns"] == sum(summary["costs"][a]["policy_evaluation_wall_ns"] for a in FIXED), pid)
        profile_nested = sum(c["planning_wall_including_native_cleanup_ns"]+c["policy_evaluation_wall_ns"] for c in summary["costs"].values())+fixed["selection_wall_ns"]
        check("profile_costs_nested_not_added_twice", 0 <= profile_nested <= summary["profile_wall_before_manifest_ns"], pid)
        total_nested_wall += profile_nested
        total_profiles_wall += summary["profile_wall_before_manifest_ns"]
        profile_regrets = {arm: profile_values["exact-oracle"]-profile_values[arm] for arm in ARMS}
        profile_regrets["model-optimal-fixed"] = profile_values["exact-oracle"]-profile_values[best_fixed]
        check("profile_ex_ante_regrets_nonnegative", min(profile_regrets.values()) >= 0, pid)
        profile_rows.append(dict(id=pid, environment=scenario["name"], scenario=scenario,
            states=len(nodes), edges=graph["edges"], policies=full, model_optimal_fixed=best_fixed,
            ex_ante_regrets_q32=profile_regrets, factorial=pf))
        for row in rows:
            sid, state = row["id"], reverse[row["id"]]
            oracle = decisions[sid]["exact-oracle"]
            state_values = {arm: values[arm][state] for arm in ARMS}
            check("state_factorial_independent", row["whole_policy_factorial"] == factorial(state_values), [pid, sid])
            for arm in (*ARMS, "model-optimal-fixed"):
                target = best_fixed if arm == "model-optimal-fixed" else arm
                plan = decisions[sid][target]
                first = oracle["planned_value_q32"]-oracle["candidate_values_q32"][plan["selected_action"]]
                whole = oracle["planned_value_q32"]-values[target][state]
                if arm != "model-optimal-fixed":
                    cell = row["arms"][arm]
                    check("first_action_and_whole_policy_independent", cell["first_action_conditional_regret_q32"] == first
                        and cell["whole_policy_regret_q32"] == whole and cell["whole_policy_value_q32"] == values[arm][state], [pid, sid, arm])
                    check("regrets_nonnegative_independent", first >= 0 and whole >= 0, [pid, sid, arm])
                add_regret(regret_stats[arm], first, whole)
                add_regret(by_environment[scenario["name"]][arm], first, whole)
                if first == 0 and whole > 0 and len(example_cases[arm]) < 5:
                    example_cases[arm].append(dict(profile=pid, state_id=sid, observation=obs_dict(state),
                        policy=target, first_action=plan["selected_action"], optimal_first_action=oracle["selected_action"],
                        first_action_conditional_regret_q32=first, whole_policy_regret_q32=whole,
                        optimal_value_q32=oracle["planned_value_q32"], whole_policy_value_q32=values[target][state]))
            d, f = decisions[sid]["dynamic-ndu"], decisions[sid]["fixed-preference-ndu"]
            p, j = decisions[sid]["prior-belief-only"], decisions[sid]["no-adaptation"]
            effects["states"] += 1
            effects["dynamic_vs_fixed_preference_numeric_changes"] += d["preference"] != f["preference"]
            effects["dynamic_vs_fixed_candidate_value_changes"] += d["candidate_values_q32"] != f["candidate_values_q32"]
            effects["dynamic_vs_fixed_preference_action_changes"] += d["action"] != f["action"]
            effects["dynamic_vs_fixed_whole_policy_changes"] += state_values["dynamic-ndu"] != state_values["fixed-preference-ndu"]
            effects["pure_prior_vs_joint_action_changes"] += p["action"] != j["action"]
            effects["pure_prior_vs_joint_whole_policy_changes"] += state_values["prior-belief-only"] != state_values["no-adaptation"]
            effects["ordinary_mpc_candidate_changes"] += d["candidate_values_q32"] != decisions[sid]["ordinary-mpc"]["candidate_values_q32"]
            effects["ordinary_mpc_action_changes"] += d["action"] != decisions[sid]["ordinary-mpc"]["action"]
            effects["ordinary_mpc_whole_policy_changes"] += state_values["dynamic-ndu"] != state_values["ordinary-mpc"]
            check("pure_belief_keeps_dynamic_numeric_preference", p["preference"] == d["preference"] and
                p["planning_observation"] == {**obs_dict(state), "belief_num": scenario["prior0_num"], "belief_den": scenario["prior0_den"]}, [pid, sid])
            if F(state[6], state[7]) == F(scenario["prior0_num"], scenario["prior0_den"]):
                effects["current_belief_equals_prior_states"] += 1
                check("current_equals_prior_same_dynamic_decision", all(d[k] == p[k] for k in ("action", "candidate_values_q32", "preference", "planned_value_q32")), [pid, sid])
            totals["states"] += 1
            totals[f"step_{state[0]}_states"] += 1
        totals["profiles"] += 1
        print(json.dumps({"independent_profile": pid, "states": len(nodes), "failed_checks": sum(failed_counts.values())}), flush=True)
    expected_inventory = dict(profiles=54, states=totals["states"], edges=total_graph_edges,
        maximum_profile_states=maximum_states, maximum_profile_edges=maximum_edges)
    check("global_graph_inventory_independent", frozen["inventory"] == expected_inventory and
        expected_inventory == dict(profiles=54, states=10224, edges=18624, maximum_profile_states=376, maximum_profile_edges=624))
    for arm in ARMS:
        check("global_ledger_from_all_decisions", dict(ledgers[arm]) == result["per_arm_ledgers"][arm], arm)
        check("global_arm_cap_independent", ledgers[arm]["transitions"] <= 20000000, arm)
    check("global_complete_denominator", result["planned_profiles"] == result["retained_profiles"] == totals["profiles"] == 54
        and result["planned_states"] == result["retained_states"] == totals["states"] == 10224
        and result["planned_cells"] == totals["decision_cells"] == totals["journal_cells"] == 122688)
    check("global_no_suppressed_failures", result["status"] == "passed" and result["missing_profiles"] == [] and
        result["fatal_error"] is None and result["postflight_errors"] == [] and all(result["checks"].values()))
    check("global_cost_nesting", total_nested_wall <= total_profiles_wall <= result["wall_before_report_ns"])
    check("scope_no_unsupported_advantage", all(result[k] is False for k in ("native_timing_is_advantage_endpoint",
        "full_lifecycle_cost_known", "ndu_exclusive_advantage_established", "production_activation")) and result["authority"] == "DENY_ALL")
    profile_aggregates = {}
    for arm in (*ARMS, "model-optimal-fixed"):
        regrets = [p["ex_ante_regrets_q32"][arm] for p in profile_rows]
        profile_aggregates[arm] = dict(profiles=len(regrets), positive_regret_profiles=sum(v > 0 for v in regrets),
            zero_regret_profiles=sum(v == 0 for v in regrets), negative_regret_profiles=sum(v < 0 for v in regrets),
            regret_sum_q32=sum(regrets), regret_max_q32=max(regrets))
    totals["artifact_hash_files"] = len(artifact_files)
    report = dict(schema="hepta.hia.ndu.independent-policy-audit.v1", status="passed" if not failed_counts else "failed",
        method="Independent Fraction law, all legal action-prefix graph, exact scalar backups, each arm's own complete continuation, root probability mean, fixed ex-ante selection, factorial arithmetic, journals and native request/postorder binding. No production helper imports or native process reruns.",
        source_commit=COMMIT, source_tree=TREE, source_files=frozen["source"]["files"],
        reviewer_correction="Initial draft compared differently scoped source schemas directly and reported two false negatives. Corrected check verifies the frozen 230-file subset, HEAD/clean metadata, and unchanged full 9,105-file before/after inventory; no production or evidence bytes were changed. Draft report/script/log retained separately.",
        audit_script=identity(__file__), registration=identity(REG), result=identity(DATA/"RESULT.json"),
        checks=dict(checks), failed_checks=dict(failed_counts), failures=failures, counts=dict(totals),
        inventory=expected_inventory, state_regret_statistics=regret_stats, state_regrets_by_environment=by_environment,
        preference_belief_effects=dict(effects), ex_ante_profile_statistics=profile_aggregates,
        first_zero_whole_positive_examples=dict(example_cases), profiles=profile_rows,
        cost_verification=dict(arm_ledgers=ledgers, nested_arm_and_selection_wall_ns=total_nested_wall,
            profile_wall_ns=total_profiles_wall, campaign_wall_before_report_ns=result["wall_before_report_ns"],
            freeze_wall_ns=frozen["freeze_wall_ns"], nested_costs_must_not_be_added_again=True),
        limitations=["This is a complete finite declared-model audit, not a new physical execution cohort.",
            "All-action-prefix states are structural units; action alternatives have no probability measure and are not IID samples.",
            "Ex-ante values are rounded probability means of conditional nested-risk root values, without a second CE.",
            "The separate raw-native review recomputes native recursive and selection evidence digests.",
            "Known emission law is available to all planning arms; misleading sensor is known anticorrelation, not unknown model shift.",
            "No unique NDU advantage, gradient/training result, general FBSDE result or full-lifecycle monetary benefit is established."],
        wall_ns=time.perf_counter_ns()-started)
    output = BASE/"independent-policy-review.json"
    with output.open("w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "failed_checks": dict(failed_counts), "counts": dict(totals),
        "effects": dict(effects), "output": str(output)}), flush=True)
    return 0 if not failed_counts else 1


if __name__ == "__main__":
    raise SystemExit(main())
