"""Original-receipt four-arm HIA macro continuation campaign.

This executes real native artifacts and the original native NDU evaluator, but
its bundled task author is a deterministic fixture, never an Agent. Receipt
integrity, measured lifecycle cost and real-Agent economic qualification are
separate outcomes. No successful invocation can close P1.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_macro_policy import (ARMS, COMPARISON_SCHEMA, PHASES,
    STATE_SCHEMA, advise_macro, advise_ordinary, ordinary_plan_selection, assess_macro_comparison, digest, ledger_totals, wire)
from tools.hia_agent_native_qualification import (Session, ToolClient,
    add_program, exhaustive_u8_workload)

SCHEMA = "hepta.hia.agent.macro-campaign.v1"
EVENT_SCHEMA = "hepta.hia.agent.macro-campaign-event.v1"
RESULT_SCHEMA = "hepta.hia.agent.macro-campaign-result.v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
ARM_ORDER = ("fixed", "greedy", "ordinary", "ndu")
MAX_OBJECT_BYTES = 8 * 1024 * 1024
MAX_OBJECTS = 16384
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
SOURCE_FILES = ("tools/qualify_hia_macro_campaign.py", "tools/hia_agent_native_qualification.py",
    "hepta/hia_agent_macro_policy.py", "hepta/hia_ndu_optimizer.py",
    "hepta/hia_agent_runner.py", "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json",
    "tools/build_hia_ndu_bridge.py", "rust/hia-ndu-bridge/Cargo.toml",
    "rust/hia-ndu-bridge/Cargo.lock", "rust/hia-ndu-bridge/upstream.json",
    "rust/hia-ndu-bridge/src/main.rs")
CONTROL_DESCRIPTIONS = {
    "fixed": "search and evaluate the registered proposal; adopt only when the tool objective permits",
    "greedy": "compare only the observed import cost with incumbent use; ignore the remaining search pipeline",
    "ordinary": "ordinary deterministic argmin of the same complete conservative continuation costs",
    "ndu": "rank those identical supplied costs with the source-bound original native NDU value ABI",
}


class CampaignRejected(ValueError):
    pass


class CampaignBudgetExceeded(CampaignRejected):
    pass


def _require(condition, reason):
    if not condition:
        raise CampaignRejected(reason)


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(CampaignRejected("nonfinite JSON")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CampaignRejected("invalid receipt JSON") from exc


def _read_regular(path, maximum=MAX_OBJECT_BYTES, *, allow_hardlinks=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and (allow_hardlinks or before.st_nlink == 1),
                 "receipt must be a single-link regular file")
        _require(before.st_size <= maximum, "receipt byte bound exceeded")
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            _require(size <= maximum, "receipt grew beyond byte bound")
        after = os.fstat(fd)
        _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                  after.st_mtime_ns, after.st_ctime_ns), "receipt changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _new_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


class Evidence:
    """Content-addressed original bytes; no executable or uploaded receipts."""
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        (self.root / "objects").mkdir(mode=0o700)
        self.inventory = {}
        self.byte_size = 0

    def put(self, value, *, binary=False):
        raw = value if binary else wire(value)
        _require(type(raw) is bytes and len(raw) <= MAX_OBJECT_BYTES, "object byte bound exceeded")
        identity = sha256(raw).hexdigest()
        if identity not in self.inventory:
            _require(len(self.inventory) < MAX_OBJECTS, "object count bound exceeded")
            _require(self.byte_size + len(raw) <= MAX_BUNDLE_BYTES, "bundle byte bound exceeded")
            _new_file(self.root / "objects" / identity, raw)
            self.inventory[identity] = {"sha256": identity, "byte_size": len(raw)}
            self.byte_size += len(raw)
        return identity

    def named(self, name, value):
        _new_file(self.root / name, wire(value) + b"\n")


class CapturingSession(Session):
    """Retain actual hia_read bytes, including receipt dependency closure."""
    def __init__(self, client, evidence, *, prefix):
        self.evidence = evidence
        self.captured = set()
        super().__init__(client, prefix=prefix)

    def read(self, artifact, **kwargs):
        raw = super().read(artifact, **kwargs)
        self.evidence.put(raw, binary=True)
        self.captured.add(artifact["sha256"])
        return raw

    def harvest(self, value):
        queue = [value]
        while queue:
            item = queue.pop()
            if type(item) is dict:
                if set(item) == {"id", "sha256", "uri"} and item["sha256"] not in self.captured:
                    raw = self.read(item)
                    try:
                        queue.append(_json(raw))
                    except CampaignRejected:
                        pass  # Native artifacts are retained as original bytes.
                else:
                    queue.extend(item.values())
            elif type(item) is list:
                queue.extend(item)


class Journal:
    """One contiguous outer wall interval per attempt, including evidence work.

    Serialization after one attempt is charged to the following interval. The
    final close event sets the measurement endpoint. Exporting that final event
    and verdict is outside the endpoint and separately reported at campaign
    level. Nested tool/native timings are evidence, never extra charge entries.
    """
    def __init__(self, evidence, arm, task, budget, *, clock=time.monotonic_ns):
        self.evidence, self.arm, self.task, self.budget = evidence, arm, task, budget
        self.clock = clock
        self.origin = self.cursor = clock()
        self.entries = []
        self.client = self.session = None
        self.closed = False

    def run(self, phase, label, operation, *, expected_status="completed", cleanup=False, model=False):
        _require(not self.closed, "journal already closed")
        operation_start = self.clock()
        start = self.cursor
        record_start = len(self.client.records) if self.client else 0
        value, failure, status = None, None, expected_status
        try:
            if not cleanup and operation_start - self.origin >= self.budget["wall_ns"]:
                raise CampaignBudgetExceeded("original task wall allowance exhausted")
            value = operation()
            if self.session is not None:
                self.session.harvest(value)
                self.session.harvest(self.client.records[record_start:])
        except Exception as exc:
            failure = {"type": type(exc).__name__, "message": str(exc)[:2048]}
            status = "failed"
        if model and value is not None and value.get("status") != "completed":
            status = "failed"
            failure = failure or {"type": "ProviderIncomplete", "message": value.get("reason", value.get("error") or value["status"])}
        end = self.clock()
        records = deepcopy(self.client.records[record_start:]) if self.client else []
        event = {"schema": EVENT_SCHEMA, "arm": self.arm, "task_id": self.task,
            "id": f"event.{len(self.entries):04d}", "phase": phase, "label": label,
            "status": status, "start_offset_ns": start - self.origin,
            "operation_start_offset_ns": operation_start - self.origin,
            "end_offset_ns": end - self.origin, "wall_ns": end - start,
            "model_tokens": ((value.get("charged_model_tokens") if value is not None else None) if model else 0),
            "output": value, "failure": failure, "tool_records": records,
            "nested_tool_costs_charged_separately": False}
        receipt = self.evidence.put(event)
        self.entries.append({key: event[key] for key in ("id", "phase", "status", "wall_ns", "model_tokens")}
                            | {"receipt_sha256": receipt})
        self.cursor = end
        if failure:
            raise CampaignRejected(f"{phase}/{label}: {failure['type']}: {failure['message']}")
        return value

    def close(self, operation=lambda: None):
        try:
            self.run("controller", "close measurement interval", operation, cleanup=True)
        finally:
            self.closed = True

    def phase_inventory(self):
        return {phase: {"performed": any(entry["phase"] == phase for entry in self.entries),
            "receipt_sha256": self.evidence.put({"schema": "hepta.hia.agent.macro-phase.v1",
                "arm": self.arm, "task_id": self.task, "phase": phase,
                "event_receipts": [entry["receipt_sha256"] for entry in self.entries if entry["phase"] == phase],
                "not_performed_reason": (None if any(entry["phase"] == phase for entry in self.entries)
                    else "not invoked by this deterministic fixture; no Agent/provider cost is inferred")})}
            for phase in sorted(PHASES)}


def _source_inventory(evidence):
    return {name: evidence.put(_read_regular(ROOT / name), binary=True) for name in SOURCE_FILES}


def _worker_sources(evidence):
    from hepta.hia_agent_contract import DISCOVERY_FILES
    paths = sorted((ROOT / "hepta").rglob("*.py"))
    paths += [ROOT / "docs" / name for name in DISCOVERY_FILES]
    return {str(path.relative_to(ROOT)): evidence.put(_read_regular(path), binary=True) for path in paths}


def _task_documents():
    for index, increment in enumerate((1, 7, 19, 127, 128, 191, 250, 255)):
        yield {"id": f"wrapping.{index:02d}", "specification": {
            "function": "transform", "input_domain": "all 256 u8 values",
            "output": "(x + increment) modulo 256", "increment": increment},
            "baseline": add_program(increment=increment, redundant_additions=index * 4),
            "candidate": add_program(optimized=True, increment=increment),
            "workload": exhaustive_u8_workload(increment)}


def _decision(state, strategy, bridge):
    if strategy == "ndu":
        advice = advise_macro(wire(state), bridge=bridge)
        return {"selected_id": advice["selected_id"], "advice": advice,
                "status": advice["status"], "selection_basis": CONTROL_DESCRIPTIONS[strategy]}
    if strategy == "ordinary":
        bounded_state = {key: value for key, value in state.items() if key != "fixture_one_step_cost_ns"}
        advice = advise_ordinary(wire(bounded_state))
        return {"selected_id": advice["selected_id"], "advice": None,
                "ordinary_advice": advice, "status": advice["status"],
                "selection_basis": CONTROL_DESCRIPTIONS[strategy]}
    plan = state["plans"][0]
    if strategy == "fixed":
        selected = plan["id"]
    elif strategy == "greedy":
        selected = plan["id"] if state["fixture_one_step_cost_ns"] < state["stop_remaining_ns"] else "abstain"
    else:
        selected = plan["id"] if plan["remaining_cost_ns"] + plan["uncertainty_ns"] < state["stop_remaining_ns"] else "abstain"

    return {"selected_id": selected, "advice": None, "status": "ADVISORY",
            "selection_basis": CONTROL_DESCRIPTIONS[strategy]}


def _native_result_correct(use, task, artifact_sha):
    report = use.get("report") or {}
    observations = report.get("observations")
    cases = task["workload"]["cases"]
    return (use.get("status") == "returned" and use.get("termination_confirmed") is True
        and use.get("started") is True and use.get("returncode") == 0
        and report.get("schema") == "hepta.hia.agent.native-observation.v1"
        and report.get("artifact_sha256") == artifact_sha and report.get("complete") is True
        and report.get("planned_cases") == report.get("completed_cases") == len(cases)
        and report.get("repetitions") == 1 and report.get("warmup") == 0
        and report.get("measured_calls") == len(cases)
        and type(observations) is list and len(observations) == len(cases)
        and all(type(row) is dict and row.get("mismatch") is False
            and {key: row.get(key) for key in ("status", "values")} == case["expected"]
            for row, case in zip(observations, cases)))


def _run_task(evidence, task, item, arm, registration, objective, bridge, state_parent, worker_sha256, provider=None):
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_agent_runner import run_native_batch
    journal = Journal(evidence, arm, task["id"], registration["budget"])
    service = None
    native_receipts, detail, state_receipt, provider_receipt = [], {}, None, None
    correct, status = False, "failed"
    try:
        def setup():
            nonlocal service
            service = HIAAgentService(state_parent / f"{task['id']}-{arm}")
            _require(service.identities["worker_sha256"] == worker_sha256, "installed worker changed after registration")
            journal.client = ToolClient(service.call)
            return {"implementation": service.identities, "catalog_sha256": service.catalog_sha256}
        journal.run("setup", "initialize isolated worker", setup)
        def discover():
            journal.session = CapturingSession(journal.client, evidence, prefix=f"macro/{task['id']}/{arm}")
            return journal.session.discovery
        journal.run("discovery", "read installed manifest and profiles", discover)
        session = journal.session
        journal.run("setup", "freeze initial workload", lambda: session.freeze(task["workload"]))
        baseline = journal.run("search", "import baseline", lambda: session.import_program(task["baseline"]))
        journal.run("setup", "freeze incumbent and objective", lambda: session.freeze(task["workload"],
            baseline=baseline, objective=objective, budget={"max_total_wall_ms": max(1, registration["budget"]["wall_ns"] // 1_000_000)}))
        def rejected_search():
            malformed = deepcopy(task["candidate"])
            malformed["functions"][0]["blocks"][0]["term"]["values"] = ["undefined_result"]
            source = session.artifact(malformed)
            return session.client.call("hia_candidate", session.arguments(change={
                "kind": "import", "format": "core-json", "source": source}), expected_status="rejected")
        journal.run("search", "retain one rejected search attempt", rejected_search, expected_status="rejected")
        base_check = journal.run("verification", "verify baseline", lambda: session.verify(baseline))
        base_build = journal.run("emission", "emit baseline", lambda: session.emit(baseline,
            receipts=[base_check["verification_receipt"]]))
        def execute(build):
            artifact = session.read(build["native_artifact"])
            remaining = registration["budget"]["wall_ns"] - (time.monotonic_ns() - journal.origin)
            return run_native_batch(artifact, {"transform": {"params": ["u8"], "returns": ["u8"]}},
                task["workload"]["cases"], timeout_ms=max(0, min(10000, remaining // 1_000_000)),
                memory_bytes=512 * 1024 * 1024)
        incumbent_probe = journal.run("evaluation", "measure incumbent on complete domain", lambda: execute(base_build))
        _require(_native_result_correct(incumbent_probe, task, base_build["native_artifact"]["sha256"]),
                 "incumbent does not satisfy frozen task")
        probe_receipt = journal.entries[-1]["receipt_sha256"]
        # Actual prior stage receipts provide a reproducible forecast basis.
        # A subsequent candidate can be cheaper or more expensive. This simple
        # extrapolator is explicitly a fixture, not a learned Agent cost model.
        phase_cost = ledger_totals(journal.entries)["phases"]
        one_step_ns = next(entry["wall_ns"] for entry in journal.entries
                           if entry["phase"] == "search" and entry["status"] == "completed")
        baseline_ns = int(incumbent_probe["wall_ns"])
        search_forecast = one_step_ns + phase_cost["verification"]["wall_ns"] + phase_cost["emission"]["wall_ns"]
        transition = 2_000_000
        support = evidence.put({"schema": "hepta.hia.agent.macro-forecast-support.v1",
            "incumbent_probe_receipt_sha256": probe_receipt,
            "observed_baseline_batch_wall_ns": baseline_ns, "one_step_import_ns": one_step_ns,
            "search_pipeline_forecast_ns": search_forecast, "candidate_use_forecast_ns": baseline_ns,
            "transition_forecast_ns": transition, "uncertainty_ns": 10_000_000,
            "search_basis": "extrapolate observed baseline import, proof and emission; model/equivalence costs remain uncalibrated",
            "transition_basis": "explicit uncalibrated fixture estimate; adoption and rollback measured if invoked",
            "candidate_evaluated_before_decision": False,
            "future_observations_available_before_decision": False})
        installation = {name: service.identities[name] for name in ("worker_sha256", "backend_sha256")}
        installation["catalog_sha256"] = session.catalog_sha256
        state = {"schema": STATE_SCHEMA, "context_sha256": session.context["sha256"],
            "objective_sha256": registration["objective_sha256"], "agent_sha256": registration["agent_sha256"],
            "installation": installation, "generation": 1, "budget": registration["budget"],
            "ledger": deepcopy(journal.entries), "stop_remaining_ns": baseline_ns,
            "plans": [{"id": "candidate", "actions": ["propose", "verify", "emit", "evaluate", "adopt", "use", "rollback", "stop"],
                "remaining_cost_ns": search_forecast + baseline_ns + transition,
                "uncertainty_ns": 10_000_000, "model_tokens": 0, "support_sha256": support}]}
        proposal = task["candidate"]
        ordinary_choice = None
        if provider is not None:
            def generate():
                nonlocal provider_receipt
                observed = ledger_totals(journal.entries)
                provider_receipt = provider.invoke(task, state, evidence,
                    evidence.root / ("provider-" + task["id"] + "-" + arm),
                    remaining_wall_ns=max(0, registration["budget"]["wall_ns"] - (time.monotonic_ns() - journal.origin)),
                    remaining_tokens=registration["budget"]["model_tokens"] - observed["observed_model_tokens"])
                return provider_receipt
            generated = journal.run("model", "generate proposal and ordinary macro advice", generate, model=True)
            proposal, ordinary_choice = generated["answer"]["candidate"], generated["answer"]["selected_id"]
            # The actual model phase is now sunk. Every policy sees the same
            # prior measured phases and pays its own complete provider usage.
            state["ledger"] = deepcopy(journal.entries)
        state_receipt = evidence.put(state)
        def choose():
            if arm == "ordinary" and provider is not None:
                return {"selected_id": ordinary_choice, "advice": None, "status": "ADVISORY",
                    "selection_basis": "original same-model ordinary advice on the disclosed complete cost state"}
            decision_state = deepcopy(state)
            if arm != "ndu":
                decision_state["fixture_one_step_cost_ns"] = one_step_ns
            return _decision(decision_state, arm, bridge)
        decision = journal.run("controller", "choose before candidate search", choose)
        advice = decision["advice"]
        if advice is not None:
            native_receipts.append(evidence.put(advice))
        searched = decision["selected_id"] == "candidate"
        chosen, allowed, adoption, evaluation, check, encoding = False, False, None, None, None, None
        selected = base_build
        if searched:
            candidate = journal.run("search", "import same proposed candidate", lambda: session.import_program(proposal))
            check = journal.run("verification", "prove full u8 equivalence", lambda: session.verify(candidate,
                base=baseline, claims=["core_admission", "behavior_equivalence"]))
            _require(all(c["status"] == "proved" for c in check["checks"]), "candidate proof incomplete")
            build = journal.run("emission", "emit candidate", lambda: session.emit(candidate,
                receipts=[check["verification_receipt"]]))
            encoding = journal.run("verification", "check emitted encoding", lambda: session.encoding(candidate, build))
            receipts = [check["verification_receipt"], encoding["verification_receipt"]]
            evaluation = journal.run("evaluation", "evaluate every planned input", lambda: session.evaluate(base_build, build, receipts=receipts))
            _require(evaluation["planned_workload_complete"], "planned workload incomplete")
            allowed = evaluation["outcome"] in {"improved", "unchanged"}
            if allowed:
                adoption = journal.run("adoption", "adopt checked artifact", lambda: session.client.result("hia_adopt", session.arguments(
                    target_slot="macro", expected_current={"generation": "0", "epoch": "0"},
                    candidate_artifact=build["native_artifact"], evaluation_receipt=evaluation["evaluation_receipt"],
                    verification_receipts=receipts)))
                chosen, selected = True, build
        use = journal.run("future_use", "execute selected native artifact on complete domain", lambda: execute(selected))
        correct = _native_result_correct(use, task, selected["native_artifact"]["sha256"])
        if adoption is not None:
            journal.run("rollback", "restore retained incumbent", lambda: session.client.result("hia_rollback", session.arguments(
                target_slot="macro", expected_current=adoption["current"],
                retained_generation=adoption["previous"]["generation"], reason="macro continuation fixture complete")), cleanup=True)
        detail = {"state_sha256": state_receipt, "decision": decision,
            "decision_before_candidate_search": True, "candidate_search_performed": searched,
            "selected_artifact": selected["native_artifact"], "selected_candidate": chosen,
            "tool_objective_permitted_candidate": allowed, "native_use": use,
            "incumbent_probe": incumbent_probe, "evaluation": evaluation,
            "proof": check, "encoding": encoding}
        status = "completed" if correct else "failed"
    except Exception as exc:
        detail["failure"] = {"type": type(exc).__name__, "message": str(exc)[:2048]}
    finally:
        try:
            journal.session = None  # no artifact reads are needed after close
            journal.close(service.close if service is not None else lambda: None)
        except Exception as exc:
            detail["close_failure"] = {"type": type(exc).__name__, "message": str(exc)[:2048]}
            status, correct = "failed", False
    if ledger_totals(journal.entries)["observed_wall_ns"] > registration["budget"]["wall_ns"]:
        status, correct = "failed", False
        detail["budget_exceeded"] = True
    result = {"schema": RESULT_SCHEMA, "arm": arm, "task_id": task["id"],
        "input_sha256": item["input_sha256"], "status": status, "correct": correct,
        "driver_kind": "codex_cli" if provider is not None else "deterministic_fixture",
        "provider_receipt": provider_receipt,
        "real_agent_model_cost_known": False, "scope": "native macro continuation mechanism; tasks remain synthetic",
        "measurement_endpoint_ns": journal.cursor - journal.origin,
        "ledger_receipts": [entry["receipt_sha256"] for entry in journal.entries], "detail": detail}
    return {"task_id": task["id"], "input_sha256": item["input_sha256"],
        "qualification_receipt_sha256": item["qualification_receipt_sha256"],
        "status": status, "correct": correct, "result_receipt_sha256": evidence.put(result),
        "ledger": journal.entries, "phase_inventory": journal.phase_inventory(),
        "native_ndu_receipts": native_receipts}


def run_campaign(output, *, bridge=None, wall_ns=60_000_000_000, provider=None, model_tokens=0):
    _require(type(wall_ns) is int and 1 <= wall_ns <= 1_000_000_000_000_000, "invalid original wall allowance")
    _require(type(model_tokens) is int and (0 <= model_tokens <= 100_000_000), "invalid model allowance")
    _require((provider is None and model_tokens == 0) or (provider is not None and model_tokens > 0),
             "actual provider and positive original model allowance must be supplied together")
    campaign_start = time.monotonic_ns()
    evidence = Evidence(output)
    source_before = _source_inventory(evidence)
    worker_before = _worker_sources(evidence)
    native_bridge = None
    if bridge is not None:
        native_bridge = {"binary_sha256": evidence.put(_read_regular(bridge["binary"], allow_hardlinks=True), binary=True),
            "build_receipt_sha256": evidence.put(_read_regular(bridge["build_receipt"]), binary=True)}
    driver = {"schema": "hepta.hia.agent.macro-driver.v1", "kind": "deterministic_fixture",
        "source_inventory": source_before, "worker_sha256": digest(worker_before), "provider": None, "model": None,
        "prompt": None, "controls": CONTROL_DESCRIPTIONS,
        "candidate_generation": "same checked-in constructor and input for all arms",
        "strong_model_controller_baseline_present": False}
    if provider is not None:
        driver.update(kind="codex_cli", provider=provider.description(evidence), model=provider.model,
            prompt="source-bound macro provider instruction and one shared public proposal/ordinary-choice prompt builder",
            candidate_generation="one fresh same-model provider request per arm; no answer repair",
            strong_model_controller_baseline_present=True,
            controls={**CONTROL_DESCRIPTIONS, "ordinary": "original ordinary advice supplied by the same model"})
    agent_sha = evidence.put(driver)
    objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
        "required_claims": ["core_admission", "behavior_equivalence", "encoding_check"],
        "allow_unchanged": True, "min_improvement_ratio": 0.0}
    objective_sha = evidence.put({"tool_objective": objective,
        "campaign_objective": "complete correct native tasks with minimum total observed lifecycle wall cost",
        "forecast_future_savings_counted": False, "future_batches_per_task": 1})
    tasks = list(_task_documents())
    inventory = []
    for task in tasks:
        task_sha = evidence.put(task)
        qualification = evidence.put({"schema": "hepta.hia.agent.macro-task-qualification.v1",
            "task_id": task["id"], "input_sha256": task_sha, "kind": "synthetic_fixture",
            "real_user_demand": False, "independent_task_judge": None,
            "reason": "finite wrapping-u8 fixtures authored by this same runner"})
        inventory.append({"id": task["id"], "input_sha256": task_sha,
            "qualification": "synthetic_fixture", "qualification_receipt_sha256": qualification})
    registration = {"agent_sha256": agent_sha, "objective_sha256": objective_sha,
        "budget": {"wall_ns": wall_ns, "model_tokens": model_tokens}, "task_inventory": inventory,
        "minimum_gain_ns": 1_000_000}
    registration_sha = evidence.put(registration)
    evidence.named("registration.json", registration)
    arms = {name: {"strategy": name, "agent_sha256": agent_sha, "registration_sha256": registration_sha,
        "budget": registration["budget"], "observations": []} for name in ARM_ORDER}
    order = []
    with tempfile.TemporaryDirectory(prefix="macro-workers-", dir=evidence.root) as temporary:
        for index, (task, item) in enumerate(zip(tasks, inventory)):
            # Fixed preregistered rotation, not runtime cherry-picking.
            for arm in ARM_ORDER[index % 4:] + ARM_ORDER[:index % 4]:
                order.append({"task_id": task["id"], "arm": arm})
                row = _run_task(evidence, task, item, arm, registration, objective, bridge, Path(temporary), digest(worker_before), provider)
                arms[arm]["observations"].append(row)
                print(json.dumps({"task": task["id"], "arm": arm, "status": row["status"],
                    "correct": row["correct"], "wall_ns": ledger_totals(row["ledger"])["observed_wall_ns"]}), flush=True)
    comparison = {"schema": COMPARISON_SCHEMA, **registration, "registration_sha256": registration_sha,
                  "arms": [arms[name] for name in ARM_ORDER]}
    comparison_sha = evidence.put(comparison)
    source_after = _source_inventory(evidence)
    worker_after = _worker_sources(evidence)
    measured_total = sum(ledger_totals(row["ledger"])["observed_wall_ns"]
        for arm in arms.values() for row in arm["observations"])
    campaign_end = time.monotonic_ns()
    manifest = {"schema": SCHEMA, "registration_sha256": registration_sha,
        "comparison_sha256": comparison_sha, "driver_sha256": agent_sha,
        "source_before": source_before, "source_after": source_after,
        "worker_source_before": worker_before, "worker_source_after": worker_after,
        "execution_order": order, "objects": sorted(evidence.inventory.values(), key=lambda x: x["sha256"]),
        "measurement": {"campaign_wall_ns_to_manifest": campaign_end - campaign_start,
            "charged_task_wall_ns": measured_total,
            "campaign_setup_export_and_cleanup_ns": campaign_end - campaign_start - measured_total,
            "final_manifest_and_verdict_export_included": False,
            "native_nested_times_added_again": False},
        "transport": "in_process_HIAAgentService", "driver_kind": driver["kind"],
        "provider_usage_receipts": [entry["receipt_sha256"] for arm in arms.values()
            for row in arm["observations"] for entry in row["ledger"] if entry["phase"] == "model"],
        "native_bridge": native_bridge,
        "external_cost_scope": {"real_agent_model_tokens": None, "real_agent_provider_cost": None,
            "module_imports_before_campaign_clock_measured": False,
            "bridge_provisioning": "reused original build; historical receipt retained, not current-budget spend",
            "complete_real_agent_economics": False}, "economic_benefit_established": False,
        "p1_acceptance": "HOLD"}
    evidence.named("campaign.json", manifest)
    verdict = verify_campaign(evidence.root)
    evidence.named("verdict.json", verdict)
    return verdict


def verify_campaign(root):
    """Verify original local bytes and causal/accounting bindings, not authorship."""
    root = Path(root)
    _require(stat.S_ISDIR(root.lstat().st_mode), "bundle root must be a directory, not a symlink")
    _require(stat.S_ISDIR((root / "objects").lstat().st_mode), "object directory must not be a symlink")
    manifest = _json(_read_regular(root / "campaign.json"))
    _require(manifest.get("schema") == SCHEMA, "unsupported campaign")
    objects = manifest.get("objects")
    _require(type(objects) is list and 1 <= len(objects) <= MAX_OBJECTS, "invalid object inventory")
    originals = {}
    declared_bytes = 0
    for item in objects:
        _require(type(item) is dict and set(item) == {"sha256", "byte_size"}, "invalid object declaration")
        identity = item["sha256"]
        _require(type(identity) is str and SHA.fullmatch(identity) is not None and identity not in originals,
                 "invalid or repeated original object")
        _require(type(item["byte_size"]) is int and 0 <= item["byte_size"] <= MAX_OBJECT_BYTES,
                 "invalid object byte declaration")
        declared_bytes += item["byte_size"]
        _require(declared_bytes <= MAX_BUNDLE_BYTES, "bundle byte bound exceeded")
        raw = _read_regular(root / "objects" / identity)
        _require(type(item["byte_size"]) is int and len(raw) == item["byte_size"]
            and sha256(raw).hexdigest() == identity, "original object bytes do not match digest and length")
        originals[identity] = raw
    def obj(identity):
        _require(identity in originals, "referenced original receipt missing")
        return _json(originals[identity])
    registration = obj(manifest["registration_sha256"])
    _require(_json(_read_regular(root / "registration.json")) == registration, "frozen registration drift")
    comparison = obj(manifest["comparison_sha256"])
    _require(comparison["registration_sha256"] == digest(registration)
        and {key: comparison[key] for key in registration} == registration, "comparison registration drift")
    verdict = assess_macro_comparison(wire(comparison))
    driver = obj(manifest["driver_sha256"])
    _require(manifest["driver_sha256"] == registration["agent_sha256"]
        and driver["kind"] == manifest["driver_kind"]
        and driver["kind"] in {"deterministic_fixture", "codex_cli"}, "driver provenance changed")
    provider_enabled = driver["kind"] == "codex_cli"
    _require(driver["source_inventory"] == manifest["source_before"], "driver source identity drift")
    if not provider_enabled:
        _require(driver["provider"] is None and driver["model"] is None and driver["prompt"] is None
            and driver["strong_model_controller_baseline_present"] is False
            and driver["controls"] == CONTROL_DESCRIPTIONS, "fixture controller/provider provenance changed")
    else:
        from tools.hia_macro_codex_provider import SOURCE_FILES as PROVIDER_FILES, INSTRUCTION, verify_receipt
        _require(driver["provider"]["kind"] == "codex_cli" and driver["model"] == driver["provider"]["requested_model"]
            and driver["strong_model_controller_baseline_present"] is True
            and driver["controls"] == {**CONTROL_DESCRIPTIONS, "ordinary": "original ordinary advice supplied by the same model"},
            "provider controller provenance mismatch")
        _require(set(driver["provider"]["source_inventory"]) == set(PROVIDER_FILES)
            and all(value in originals for value in driver["provider"]["source_inventory"].values())
            and originals[driver["provider"]["prompt_instruction_sha256"]] == INSTRUCTION.encode(),
            "provider sources or prompt original missing")
    scope = manifest["external_cost_scope"]
    _require(scope["real_agent_model_tokens"] is None and scope["real_agent_provider_cost"] is None
        and scope["complete_real_agent_economics"] is False, "unknown external costs cannot become free complete costs")
    for inventory in (manifest["source_before"], manifest["source_after"]):
        _require(set(inventory) == set(SOURCE_FILES), "source coverage missing")
        for identity in inventory.values():
            _require(identity in originals, "source original missing")
    _require(manifest["source_before"] == manifest["source_after"], "source changed during campaign")
    _require(manifest["worker_source_before"] == manifest["worker_source_after"]
        and digest(manifest["worker_source_before"]) == driver["worker_sha256"], "installed worker source drift")
    for identity in manifest["worker_source_before"].values():
        _require(identity in originals, "worker source original missing")
    expected_provider = [entry["receipt_sha256"] for arm in comparison["arms"]
        for row in arm["observations"] for entry in row["ledger"] if entry["phase"] == "model"]
    _require(manifest["provider_usage_receipts"] == expected_provider
        and (provider_enabled or expected_provider == []) and manifest["economic_benefit_established"] is False
        and manifest["p1_acceptance"] == "HOLD", "fixture cannot claim provider use or economic acceptance")
    native_bridge = manifest["native_bridge"]
    if native_bridge is not None:
        _require(set(native_bridge) == {"binary_sha256", "build_receipt_sha256"}
            and native_bridge["binary_sha256"] in originals, "native executable original missing")
        build_receipt = obj(native_bridge["build_receipt_sha256"])
        _require(build_receipt["binary_sha256"] == native_bridge["binary_sha256"]
            and build_receipt["upstream"] == obj(manifest["source_before"]["rust/hia-ndu-bridge/upstream.json"])
            and build_receipt["builder_sha256"] == manifest["source_before"]["tools/build_hia_ndu_bridge.py"],
            "native source/build original binding mismatch")
        for filename, identity in build_receipt["adapter_files"].items():
            _require(manifest["source_before"].get("rust/hia-ndu-bridge/" + filename) == identity,
                     "native adapter source original missing")
    expected_order = []
    for index, task in enumerate(registration["task_inventory"]):
        original = obj(task["input_sha256"])
        qualification = obj(task["qualification_receipt_sha256"])
        _require(original["id"] == qualification["task_id"] == task["id"]
            and qualification["input_sha256"] == task["input_sha256"]
            and qualification["kind"] == task["qualification"] == "synthetic_fixture"
            and qualification["real_user_demand"] is False, "task qualification provenance mismatch")
        for arm in ARM_ORDER[index % 4:] + ARM_ORDER[:index % 4]:
            expected_order.append({"task_id": task["id"], "arm": arm})
    _require(manifest["execution_order"] == expected_order, "counterbalanced execution order drift")
    events_count = native_count = correct_count = failed_attempts = total_wall = provider_calls = provider_completions = 0
    for arm in comparison["arms"]:
        for row in arm["observations"]:
            result = obj(row["result_receipt_sha256"])
            _require(result["schema"] == RESULT_SCHEMA and result["arm"] == arm["strategy"]
                and result["task_id"] == row["task_id"] and result["input_sha256"] == row["input_sha256"]
                and result["status"] == row["status"] and result["correct"] == row["correct"], "task result mismatch")
            _require(result["driver_kind"] == driver["kind"]
                and (provider_enabled or result["provider_receipt"] is None)
                and result["real_agent_model_cost_known"] is False, "model cost provenance mismatch")
            _require(result["ledger_receipts"] == [entry["receipt_sha256"] for entry in row["ledger"]], "result ledger drift")
            previous = 0
            events = []
            for entry in row["ledger"]:
                event = obj(entry["receipt_sha256"])
                events.append(event)
                _require(event["schema"] == EVENT_SCHEMA and event["arm"] == arm["strategy"]
                    and event["task_id"] == row["task_id"], "event ownership mismatch")
                _require(all(type(event[key]) is type(entry[key]) and event[key] == entry[key]
                    for key in ("id", "phase", "status", "wall_ns", "model_tokens")), "event cost binding mismatch")
                _require(all(type(event[key]) is int for key in ("start_offset_ns", "operation_start_offset_ns", "end_offset_ns"))
                    and event["start_offset_ns"] == previous <= event["operation_start_offset_ns"] <= event["end_offset_ns"]
                    and event["wall_ns"] == event["end_offset_ns"] - previous, "gap, overlap or forged interval cost")
                _require(event["nested_tool_costs_charged_separately"] is False
                    and (event["phase"] == "model" and provider_enabled or event["model_tokens"] == 0),
                    "fixture charged invented model or duplicated nested cost")
                if event["phase"] == "model":
                    receipt = event["output"]
                    if receipt is not None:
                        request = verify_receipt(receipt, originals, driver["provider"])
                        _require(request["task_id"] == row["task_id"]
                            and request["task_input_sha256"] == row["input_sha256"]
                            and request["state"]["ledger"] == row["ledger"][:len(events)-1]
                            and request["state"]["budget"] == registration["budget"]
                            and request["state"]["agent_sha256"] == registration["agent_sha256"]
                            and receipt == result["provider_receipt"]
                            and receipt["charged_model_tokens"] == event["model_tokens"],
                            "provider request or usage does not bind preceding state")
                        _require(receipt["remaining_tokens"] == registration["budget"]["model_tokens"]
                            and 0 <= receipt["remaining_wall_ns"] <= registration["budget"]["wall_ns"] - event["operation_start_offset_ns"],
                            "provider original remaining allowance changed")
                        if receipt["process"] is not None:
                            _require(receipt["process"]["wall_ns"] <= event["wall_ns"], "provider duration exceeds charged phase")
                            provider_calls += 1
                        provider_completions += receipt["status"] == "completed"
                    else:
                        _require(event["status"] == "failed" and event["model_tokens"] is None,
                                 "failed model call without receipt must retain unknown usage")
                previous = event["end_offset_ns"]
                for call in event["tool_records"]:
                    _require(type(call) is dict and set(call) == {"tool", "arguments", "response", "elapsed_ns"}
                        and type(call["tool"]) is str and call["tool"].startswith("hia_")
                        and type(call["elapsed_ns"]) is str and call["elapsed_ns"].isdigit()
                        and len(call["elapsed_ns"]) <= 16 and 0 <= int(call["elapsed_ns"]) <= event["wall_ns"],
                        "invalid original tool receipt")
                if event["status"] in {"failed", "rejected"}:
                    failed_attempts += 1
                events_count += 1
            _require(previous == result["measurement_endpoint_ns"], "measurement endpoint mismatch")
            total_wall += previous
            for phase, declaration in row["phase_inventory"].items():
                original = obj(declaration["receipt_sha256"])
                expected = [entry["receipt_sha256"] for entry in row["ledger"] if entry["phase"] == phase]
                _require(original["phase"] == phase and original["arm"] == arm["strategy"]
                    and original["task_id"] == row["task_id"] and original["event_receipts"] == expected,
                    "phase declaration does not resolve to charged events")
            detail = result["detail"]
            if "decision" in detail:
                decision_indexes = [i for i, event in enumerate(events) if event["label"] == "choose before candidate search"]
                _require(len(decision_indexes) == 1, "macro decision event missing or repeated")
                at = decision_indexes[0]
                state = obj(detail["state_sha256"])
                _require(state["ledger"] == row["ledger"][:at]
                    and state["agent_sha256"] == registration["agent_sha256"]
                    and state["objective_sha256"] == registration["objective_sha256"]
                    and state["budget"] == registration["budget"]
                    and state["installation"]["worker_sha256"] == driver["worker_sha256"],
                    "decision does not consume the exact preceding ledger and installation")
                _require(events[at]["output"] == detail["decision"], "executed decision differs from original event")
                ordinary = detail["decision"].get("ordinary_advice")
                if ordinary is not None:
                    _require(arm["strategy"] == "ordinary" and not provider_enabled
                        and ordinary["state_sha256"] == digest(state)
                        and type(ordinary["controller_wall_ns"]) is int
                        and type(ordinary["decision_elapsed_ns"]) is int
                        and 0 <= ordinary["decision_elapsed_ns"] <= ordinary["controller_wall_ns"] <= events[at]["wall_ns"],
                        "ordinary control must bind its original state and charged interval")
                    expected = ordinary_plan_selection(state, elapsed_ns=ordinary["decision_elapsed_ns"])
                    _require(all(ordinary[key] == value for key, value in expected.items())
                        and detail["decision"]["selected_id"] == ordinary["selected_id"]
                        and ordinary["policy"] == "full_budget_argmin"
                        and ordinary["authority"] == "DENY_ALL"
                        and ordinary["execution_authorized"] is False
                        and ordinary["native_ndu_evaluated"] is False,
                        "ordinary control changed the complete-cost or original-budget rule")
                if provider_enabled:
                    receipt = result["provider_receipt"]
                    _require(receipt is not None and receipt["status"] == "completed", "decision lacks original complete provider")
                    if arm["strategy"] == "ordinary":
                        _require(detail["decision"]["selected_id"] == receipt["answer"]["selected_id"],
                                 "ordinary controller did not execute original model advice")
                candidate_indexes = [i for i, event in enumerate(events) if event["label"] == "import same proposed candidate"]
                searched = detail["decision"]["selected_id"] == "candidate"
                _require(detail["decision_before_candidate_search"] is True
                    and detail["candidate_search_performed"] == searched
                    and (len(candidate_indexes) == 1 and candidate_indexes[0] > at if searched else not candidate_indexes),
                    "search occurred outside the admitted macro continuation")
                support = obj(state["plans"][0]["support_sha256"])
                probe = obj(support["incumbent_probe_receipt_sha256"])
                _require(support["candidate_evaluated_before_decision"] is False
                    and support["future_observations_available_before_decision"] is False
                    and probe in events[:at] and probe["output"] == detail["incumbent_probe"]
                    and support["observed_baseline_batch_wall_ns"] == int(detail["incumbent_probe"]["wall_ns"]),
                    "forecast basis is not a preceding original observation")
            for receipt in row["native_ndu_receipts"]:
                advice = obj(receipt)
                _require(result["detail"]["decision"]["advice"] == advice,
                         "native advice differs from executed decision")
                _require(advice["authority"] == "DENY_ALL" and advice["execution_authorized"] is False,
                         "advice cannot grant execution authority")
                if advice["native_ndu_evaluated"]:
                    request, response = advice["native_request"], advice["native_response"]
                    _require(response["request_sha256"] == digest(request)
                        and response["objective_sha256"] == request["objective_sha256"]
                        and response["authority"] == "ADVISORY_ONLY", "native receipt request binding mismatch")
                    state = obj(result["detail"]["state_sha256"])
                    _require(advice["state_sha256"] == digest(state), "advice state binding mismatch")
                    _require(native_bridge is not None and advice["native_identity"] is not None
                        and all(advice["native_identity"][key] == native_bridge[key] for key in native_bridge),
                        "native executable/build identity differs from retained originals")
                    native_count += 1
            if row["correct"]:
                use = result["detail"]["native_use"]
                task = obj(row["input_sha256"])
                _require(_native_result_correct(use, task, result["detail"]["selected_artifact"]["sha256"]),
                    "successful result lacks correct complete native execution")
                _require(result["detail"]["selected_artifact"]["sha256"] in originals, "selected native original missing")
                correct_count += 1
    measurement = manifest["measurement"]
    _require(type(measurement["charged_task_wall_ns"]) is int and measurement["charged_task_wall_ns"] == total_wall
        and type(measurement["campaign_setup_export_and_cleanup_ns"]) is int
        and measurement["campaign_setup_export_and_cleanup_ns"] >= 0
        and measurement["campaign_wall_ns_to_manifest"] == total_wall + measurement["campaign_setup_export_and_cleanup_ns"]
        and measurement["native_nested_times_added_again"] is False, "campaign cost reconciliation failed")
    return {"schema": "hepta.hia.agent.macro-campaign-verdict.v1", "original_receipt_integrity": "verified",
        "registration_sha256": manifest["registration_sha256"], "objects_verified": len(originals),
        "events_verified": events_count, "planned_task_arms": len(expected_order),
        "correct_native_task_arms": correct_count, "native_ndu_evaluations": native_count,
        "provider_processes_observed": provider_calls, "complete_provider_turns": provider_completions,
        "failed_or_rejected_attempts_retained": failed_attempts, "measurement": measurement,
        "native_mechanism_complete": correct_count == len(expected_order)
            and native_count == len(registration["task_inventory"])
            and (not provider_enabled or provider_completions == len(expected_order)),
        "comparison": verdict, "observed_scope_positive": False,
        "economic_benefit_established": False, "p1_acceptance": "HOLD",
        "original_receipts_authenticated": False,
        "remaining_gates": ["real qualified tasks and independent task judge", "actual same-Agent provider invocation and original usage receipts",
            "provider monetary and complete Agent costs", "strong ordinary model controller baseline",
            "calibrated forecasts covering actual Agent and search costs", "repeat runs with uncertainty and workload representativeness",
            "measured advantage over every control within frozen budget", "independent provenance authentication"],
        "scope": "local original-byte integrity and actual native mechanism measurements; deterministic task and controller fixtures"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--output", required=True)
    run.add_argument("--native-binary")
    run.add_argument("--native-build-receipt")
    run.add_argument("--wall-ns", type=int, default=60_000_000_000)
    run.add_argument("--codex")
    run.add_argument("--model")
    run.add_argument("--model-tokens", type=int, default=0)
    run.add_argument("--registered-warnings", help="JSON array from an independently observed preflight; never guessed")
    verify = sub.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            _require(bool(args.native_binary) == bool(args.native_build_receipt), "native executable and build receipt are a pair")
            bridge = ({"binary": args.native_binary, "build_receipt": args.native_build_receipt}
                      if args.native_binary else None)
            _require(bool(args.codex) == bool(args.model), "explicit Codex executable and model must be supplied together")
            provider = None
            if args.codex:
                from tools.hia_macro_codex_provider import CodexMacroProvider
                warnings = _json(_read_regular(args.registered_warnings)) if args.registered_warnings else []
                provider = CodexMacroProvider(args.codex, args.model, warnings=warnings)
            result = run_campaign(args.output, bridge=bridge, wall_ns=args.wall_ns,
                                  provider=provider, model_tokens=args.model_tokens)
        else:
            result = verify_campaign(args.bundle)
        summary = {key: result[key] for key in ("schema", "original_receipt_integrity", "planned_task_arms",
            "correct_native_task_arms", "native_ndu_evaluations", "events_verified", "objects_verified",
            "failed_or_rejected_attempts_retained", "native_mechanism_complete", "p1_acceptance", "economic_benefit_established") }
        summary["arm_wall_ns"] = result["comparison"]["arm_wall_ns"]
        comparison = result["comparison"]
        summary["completed_comparison"] = comparison["completed_comparison"]
        summary["ndu_saving_ns"] = comparison["completed_comparison"]["ndu_saving_ns"]
        summary["raw_lowest_cost_control"] = comparison["raw_lowest_cost_control"]
        summary["raw_ndu_wall_difference_ns"] = comparison["raw_ndu_wall_difference_ns"]
        print(json.dumps(summary, sort_keys=True, indent=2))
        # Run success requires the actual native mechanism, never P1 acceptance.
        # Offline verify success means only internally consistent original bytes.
        return 0 if args.command == "verify" or result["native_mechanism_complete"] else 2
    except (CampaignRejected, OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc), "p1_acceptance": "HOLD"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
