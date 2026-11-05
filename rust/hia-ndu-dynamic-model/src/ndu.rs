//! Original, unchanged NDU APIs over separately generated dynamic-cache witnesses.
//! Adapter semantics follow upstream bridge 8e52e118; the original crates are
//! linked unchanged. Digests and `verified` fields never prove program safety.
use crate::{
    digest,
    model::{Model, sum},
    planner::Plan,
};
use codex_hepta_ndu::{
    AggregationOperator, AxisAggregationRule, AxisDirection, AxisLimit, AxisValue, ContributionSet,
    EvaluationPolicyV1, FeasibilityPosture, RecursiveUtilityPath, RequiredOrganSet,
    UtilityContribution, UtilityEvent, UtilityProfile, evaluate_candidates_with_policy,
    evaluate_recursive_utility,
};
use codex_hepta_types::{Digest32, FixedQ32, Generation, StableId};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const Q32: i64 = 1_i64 << 32;
const UTILITY_LIMIT: i64 = 1_000_000 * Q32;

pub fn scaled(value: u64, divisor: u64) -> Result<i64, String> {
    let product = (value as u128)
        .checked_mul(Q32 as u128)
        .ok_or("Q32 product overflow")?;
    i64::try_from(product / divisor as u128).map_err(|_| "Q32 signed overflow".into())
}

fn parse(value: &str) -> Result<Digest32, String> {
    value.parse().map_err(|e| format!("{e}"))
}
fn id(value: &str) -> Result<StableId, String> {
    StableId::new(value).map_err(|e| e.to_string())
}
fn axis(name: &str, raw: i64) -> Result<AxisValue, String> {
    Ok(AxisValue {
        axis: id(name)?,
        value: FixedQ32::from_raw(raw),
    })
}
fn rule(name: &str) -> Result<AxisAggregationRule, String> {
    Ok(AxisAggregationRule {
        axis: id(name)?,
        operator: AggregationOperator::RequireEqual,
    })
}

#[derive(Serialize)]
pub struct Event {
    event_digest: String,
    preference_digest: String,
    instant_q32: i64,
    discount_q32: i64,
}

#[derive(Serialize)]
pub struct Candidate {
    id: String,
    verified: bool,
    verification_digest: String,
    support_digest: String,
    events: Vec<Event>,
    terminal_q32: i64,
    resource_cost_q32: i64,
    risk_q32: i64,
    uncertainty_q32: i64,
}

#[derive(Serialize)]
pub struct Request {
    schema: &'static str,
    objective_digest: String,
    snapshot_digest: String,
    generation: u64,
    utility_unit: &'static str,
    resource_unit: &'static str,
    risk_unit: &'static str,
    risk_ceiling_q32: i64,
    resource_budget_q32: i64,
    candidates: Vec<Candidate>,
}

#[derive(Serialize)]
pub struct Bundle {
    pub request: Request,
    pub plans: BTreeMap<String, Plan>,
    pub support: Value,
    search_complete: bool,
    authority: &'static str,
    safety_certificate: bool,
}

pub fn bundle(model: &Model, frontier: Vec<Plan>, complete: bool) -> Result<Bundle, String> {
    let common = sum([model.decision.call(model.session_ready)?, model.decision.close_ns])?;
    let mut plans = BTreeMap::new();
    for plan in frontier {
        let name = format!("dynamic-{}", &digest(&plan)?[..24]);
        plans.entry(name).or_insert(plan);
    }
    let support = json!({"model":model,"plans":plans,"search_complete":complete,
        "scope":"supplied finite cache model; forecast times; no program safety or elapsed-time theorem",
        "authority":"DENY_ALL","safety_certificate":false});
    let support_hash = digest(&support)?;
    let verification = digest(&json!([model.workload_sha256, model.observation_digest]))?;
    let mut candidates = Vec::new();
    for (name, plan) in &plans {
        let variable = plan.total_ns.checked_sub(common).ok_or("missing current/close cost")?;
        candidates.push(Candidate {
            id:name.clone(),verified:true,verification_digest:verification.clone(),support_digest:support_hash.clone(),
            events:vec![Event {event_digest:Digest32::of_bytes(format!("{name}{support_hash}").as_bytes()).to_string(),
                preference_digest:model.objective_digest.clone(),instant_q32:-scaled(variable,1_000_000)?,discount_q32:Q32}],
            terminal_q32:scaled(model.completion_value_ns,1_000_000)?,resource_cost_q32:scaled(variable,1000)?,
            risk_q32:0,uncertainty_q32:0,
        });
    }
    candidates.push(Candidate {id:"abstain".into(),verified:true,
        verification_digest:digest(&json!("literal-no-delivery"))?,support_digest:support_hash.clone(),
        events:vec![Event {event_digest:Digest32::of_bytes(format!("abstain{support_hash}").as_bytes()).to_string(),
            preference_digest:model.objective_digest.clone(),instant_q32:0,discount_q32:Q32}],
        terminal_q32:0,resource_cost_q32:0,risk_q32:0,uncertainty_q32:0});
    Ok(Bundle {request:Request {schema:"hepta.hia.ndu.request.v1",objective_digest:model.objective_digest.clone(),
        snapshot_digest:digest(model)?,generation:model.generation as u64,
        utility_unit:"completion-minus-wall-milliseconds",resource_unit:"microseconds",risk_unit:"probability",
        risk_ceiling_q32:Q32,resource_budget_q32:scaled(model.budget_ns.saturating_sub(common),1000)?,candidates},
        plans,support,search_complete:complete,authority:"DENY_ALL",safety_certificate:false})
}

pub fn exact_winners(bundle: &Bundle) -> Result<Vec<String>, String> {
    // Independent scalar reference, with the original floor conversions and
    // literal abstain. This arm never invokes the NDU library.
    let mut maximum = i64::MIN;
    let mut winners = Vec::new();
    for c in &bundle.request.candidates {
        let value = c
            .terminal_q32
            .checked_add(c.events[0].instant_q32)
            .ok_or("utility overflow")?;
        if value > maximum {
            maximum = value;
            winners.clear();
        }
        if value == maximum {
            winners.push(c.id.clone());
        }
    }
    winners.sort();
    Ok(winners)
}

pub fn original_ndu(bundle: &Bundle) -> Result<(Vec<String>, Value), String> {
    let r = &bundle.request;
    let objective = parse(&r.objective_digest)?;
    let snapshot = parse(&r.snapshot_digest)?;
    let generation = Generation::new(r.generation).map_err(|e| e.to_string())?;
    let units = parse(&digest(
        &json!({"utility":r.utility_unit,"resource":r.resource_unit,
        "risk":r.risk_unit,"fixed_point":"signed-Q32-nearest-ties-even"}),
    )?)?;
    let request_digest = parse(&digest(r)?)?;
    let mut contributions = Vec::new();
    let mut values = Vec::new();
    for c in &r.candidates {
        let events = c
            .events
            .iter()
            .enumerate()
            .map(|(i, e)| {
                Ok(UtilityEvent {
                    sequence: i as u64 + 1,
                    event_digest: parse(&e.event_digest)?,
                    preference_digest: parse(&e.preference_digest)?,
                    instant: FixedQ32::from_raw(e.instant_q32),
                    discount: FixedQ32::from_raw(e.discount_q32),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let path = RecursiveUtilityPath {
            objective_digest: objective,
            episode_digest: Digest32::of_parts(&[snapshot.as_array(), c.id.as_bytes()]),
            coefficient_digest: Digest32::of_bytes(b"hia.ndu.discounted-path.q32.v1"),
            units_digest: units,
            terminal_outcome_digest: parse(&c.support_digest)?,
            terminal: FixedQ32::from_raw(c.terminal_q32),
            lower: FixedQ32::from_raw(-UTILITY_LIMIT),
            upper: FixedQ32::from_raw(UTILITY_LIMIT),
            events,
        };
        let evaluated = evaluate_recursive_utility(&path).map_err(|e| e.to_string())?;
        if evaluated.projection_count != 0 {
            return Err("unsupported utility projection".into());
        }
        let verification = parse(&c.verification_digest)?;
        let support = parse(&c.support_digest)?;
        contributions.push(UtilityContribution {
            candidate_id: id(&c.id)?,
            organ_id: id("hia.compiler")?,
            objective_digest: objective,
            generation,
            feasibility: FeasibilityPosture::Feasible,
            utility: vec![axis("utility.net", evaluated.values[0].raw())?],
            risk: vec![axis("risk.tail", 0)?],
            resource: vec![axis("resource.optimization", c.resource_cost_q32)?],
            uncertainty: vec![axis("utility.net", 0)?],
            support_digest: Digest32::of_parts(&[
                b"hia.ndu.compiler-candidate.v1\0",
                request_digest.as_array(),
                snapshot.as_array(),
                verification.as_array(),
                support.as_array(),
                evaluated.evidence_digest.as_array(),
            ]),
        });
        values.push(json!({"id":c.id,"value_q32":evaluated.values[0].raw(),"recursive_evidence_digest":evaluated.evidence_digest.to_string()}));
    }
    let profile = UtilityProfile {
        profile_id: id("hia.compiler.v1")?,
        axis_registry_digest: Digest32::of_bytes(b"utility.net/risk.tail/resource.optimization.v1"),
        normalization_manifest_digest: units,
        dimensions: vec![(id("utility.net")?, AxisDirection::Maximize)],
        risk_ceilings: vec![AxisLimit {
            axis: id("risk.tail")?,
            maximum: FixedQ32::from_raw(Q32),
        }],
        resource_ceilings: vec![AxisLimit {
            axis: id("resource.optimization")?,
            maximum: FixedQ32::from_raw(r.resource_budget_q32),
        }],
        required_organs: RequiredOrganSet {
            organ_ids: vec![id("hia.compiler")?],
        },
    };
    let policy = EvaluationPolicyV1 {
        policy_id: id("hia.compiler.complete-path.v1")?,
        utility_rules: vec![rule("utility.net")?],
        risk_rules: vec![rule("risk.tail")?],
        resource_rules: vec![rule("resource.optimization")?],
        uncertainty_rules: vec![rule("utility.net")?],
        pareto_absolute_tolerances: vec![axis("utility.net", 0)?],
    };
    let result = evaluate_candidates_with_policy(
        ContributionSet {
            objective_digest: objective,
            generation,
            contributions,
        },
        profile,
        None,
        policy,
    )
    .map_err(|e| e.to_string())?;
    let winners = result
        .base
        .pareto_frontier
        .iter()
        .map(|c| c.candidate_id.to_string())
        .collect();
    Ok((
        winners,
        json!({"entry_points":["codex_hepta_ndu::evaluate_recursive_utility","codex_hepta_ndu::evaluate_candidates_with_policy"],
        "evaluation_digest":result.evaluation_digest_v2.to_string(),"paths":values,
        "advisory_candidate_id":result.base.advisory_recommendation.map(|v| v.to_string()),
        "authority":"DENY_ALL","safety_certificate":false}),
    ))
}

pub fn first_action(bundle: &Bundle, winners: &[String]) -> Result<Value, String> {
    if winners.is_empty() || winners.iter().any(|v| v == "abstain") {
        return Ok(Value::Null);
    }
    let first = &bundle
        .plans
        .get(&winners[0])
        .ok_or("unknown winner")?
        .actions[0];
    for name in winners {
        let action = &bundle.plans.get(name).ok_or("unknown winner")?.actions[0];
        if action.ready_after != first.ready_after || action.dispatch != first.dispatch {
            return Ok(Value::Null);
        }
    }
    serde_json::to_value(first).map_err(|e| e.to_string())
}
