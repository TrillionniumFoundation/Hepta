"""Discoverable guidance for the explicit caller-side HIA macro controller."""
from __future__ import annotations

from copy import deepcopy

from .hia_agent_macro_policy import ACTIONS, COMPARISON_SCHEMA, PHASES, STATE_SCHEMA


def macro_policy_guidance(installation):
    """Return content for hia_describe/hia_read, without registering a new tool.

    The installation is the server's own source identity, never a caller's
    permission. The example deliberately contains unknown model costs and
    cannot be admitted as a completed measured experiment.
    """
    return {
        "schema": "hepta.hia.agent.macro-policy-guidance.v1",
        "installation": deepcopy(installation),
        "entrypoint": "python tools/hia_agent_macro_policy.py advise --input STATE --output ADVICE --native-binary BINARY --native-build-receipt RECEIPT",
        "scope": "explicit caller-side macro advice; actual tool owners recheck every operation",
        "mcp_tool_registered": False,
        "implicit_compiler_optimization": False,
        "native_profile": {
            "adapter": "rust/hia-ndu-bridge",
            "source_commit": "d3c2d760eca5065fc966820379c35c6e8d56e855",
            "entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
            "input_profile": "hepta.hia.ndu-request.v1",
            "utility": "minimize caller-supplied full remaining cost with uncertainty",
            "recursive_utility_evaluated": False,
            "learned_macro_dynamics": False,
            "missing_bridge_behavior": "BLOCKED; no substitute evaluator",
        },
        "state_schema": STATE_SCHEMA,
        "comparison_schema": COMPARISON_SCHEMA,
        "macro_actions": sorted(ACTIONS),
        "action_owners": {
            "discover": "hia_describe / hia_read", "propose": "hia_candidate",
            "verify": "hia_verify", "emit": "hia_emit", "evaluate": "hia_evaluate",
            "adopt": "hia_adopt", "rollback": "hia_rollback",
            "use": "authorized runtime consumer acquire_slot/invoke_lease/release_slot",
            "stop": "retain incumbent; no further controller action",
            "keep_existing": "retain the admitted incumbent; actual use remains separately owned",
            "no_adopt": "discard the candidate for adoption; keep all search costs",
        },
        "cost_phases": sorted(PHASES),
        "cost_rules": [
            "charge each disjoint attempt once, including failed/rejected search and unknown completion",
            "model tokens and elapsed time come from actual provider receipts",
            "unknown costs remain null and block advice",
            "continue from returned next_state; original budget is not renewed",
            "actual future use is distinct from forecast expected invocations",
            "hia_evaluate v1 ledger is a prefix; model/adoption/use costs require external receipts",
        ],
        "example_is_an_observation": False,
        "state_example": {
            "schema": STATE_SCHEMA, "context_sha256": "1" * 64,
            "objective_sha256": "2" * 64, "agent_sha256": "3" * 64,
            "installation": deepcopy(installation), "generation": 1,
            "budget": {"wall_ns": 60_000_000_000, "model_tokens": 4096},
            "ledger": [{"id": "model.call.1", "phase": "model", "status": "unknown",
                        "wall_ns": None, "model_tokens": None, "receipt_sha256": None}],
            "stop_remaining_ns": 0,
            "plans": [{"id": "verify_then_measure", "actions": ["verify", "emit", "evaluate", "stop"],
                       "remaining_cost_ns": 1_000_000_000, "uncertainty_ns": 100_000_000,
                       "model_tokens": 0, "support_sha256": "4" * 64}],
        },
        "qualification": {
            "arms": ["fixed", "greedy", "ordinary", "ndu"],
            "requires": "same Agent, original budgets and every registered real task; complete actual costs and downstream use",
            "hash_only_assessor": "reported arithmetic only; P1 HOLD until original receipts and task outcomes are independently checked",
            "successful_ndu_call_is_benefit": False,
            "ordinary_baseline": "python tools/hia_agent_macro_policy.py ordinary --input STATE --output ADVICE",
            "ordinary_profile": "all supplied finite plans, complete robust cost, original wall/token budgets, incumbent wins ties",
            "legal_no_change_outcomes": ["keep_existing", "stop", "no_adopt"],
        },
        "authority": "DENY_ALL", "execution_authorized": False,
    }
