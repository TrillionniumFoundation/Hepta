//! Bounded JSON transport into the existing, pinned NDU evaluator.
//! This executable is advisory only. HIA independently proves candidates.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::str::FromStr;

use codex_hepta_ndu::{
    AggregationOperator, AxisAggregationRule, AxisDirection, AxisLimit, AxisValue, ContributionSet,
    EvaluationPolicyV1, FeasibilityPosture, RequiredOrganSet, UtilityContribution, UtilityProfile,
    evaluate_candidates_with_policy,
};
use codex_hepta_types::{Digest32, FixedQ32, Generation, StableId};
use serde::Deserialize;
use serde_json::{Value, json};

const MAX_BYTES: u64 = 1024 * 1024;
const UPSTREAM: &str = "d3c2d760eca5065fc966820379c35c6e8d56e855";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    id: String,
    cost_q32: i64,
    uncertainty_q32: i64,
    resource_q32: i64,
    hard_violation: bool,
    support_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    objective_sha256: String,
    generation: u64,
    resource_cap_q32: i64,
    candidates: Vec<Candidate>,
}

fn id(raw: &str) -> Result<StableId, String> {
    StableId::new(raw).map_err(|e| e.to_string())
}

fn axis(name: &str, raw: i64) -> Result<AxisValue, String> {
    Ok(AxisValue {
        axis: id(name)?,
        value: FixedQ32::from_raw(raw),
    })
}

fn evaluate(request: Request) -> Result<Value, String> {
    if request.schema != "hepta.hia.ndu-request.v1"
        || !(1..=128).contains(&request.candidates.len())
        || request.resource_cap_q32 < 0
    {
        return Err("invalid schema, candidate count or resource cap".into());
    }
    let objective = Digest32::from_str(&request.objective_sha256).map_err(|e| e.to_string())?;
    let generation = Generation::new(request.generation).map_err(|e| e.to_string())?;
    let mut seen = BTreeSet::new();
    let mut contributions = Vec::new();
    for candidate in request.candidates {
        if !seen.insert(candidate.id.clone())
            || candidate.cost_q32 < 0
            || candidate.resource_q32 < 0
            || candidate.uncertainty_q32 < 0
        {
            return Err("duplicate candidate or negative cost".into());
        }
        contributions.push(UtilityContribution {
            candidate_id: id(&candidate.id)?,
            organ_id: id("hia-compiler")?,
            objective_digest: objective,
            generation,
            feasibility: if candidate.hard_violation {
                FeasibilityPosture::HardConstraintViolation
            } else {
                FeasibilityPosture::Feasible
            },
            utility: vec![axis("total-ms", candidate.cost_q32)?],
            risk: Vec::new(),
            resource: vec![axis("search-ms", candidate.resource_q32)?],
            uncertainty: vec![axis("total-ms", candidate.uncertainty_q32)?],
            support_digest: Digest32::from_str(&candidate.support_sha256)
                .map_err(|e| e.to_string())?,
        });
    }
    if !seen.contains("abstain") {
        return Err("baseline abstain candidate is required".into());
    }
    let profile = UtilityProfile {
        profile_id: id("hia-total-cost-ms-v1")?,
        axis_registry_digest: Digest32::of_bytes(b"total-ms:minimize;search-ms:ceiling"),
        normalization_manifest_digest: Digest32::of_bytes(
            b"nanoseconds-to-ms-q32;nearest-ties-even;no-clipping",
        ),
        dimensions: vec![(id("total-ms")?, AxisDirection::Minimize)],
        risk_ceilings: Vec::new(),
        resource_ceilings: vec![AxisLimit {
            axis: id("search-ms")?,
            maximum: FixedQ32::from_raw(request.resource_cap_q32),
        }],
        required_organs: RequiredOrganSet {
            organ_ids: vec![id("hia-compiler")?],
        },
    };
    let policy = EvaluationPolicyV1 {
        policy_id: id("hia-single-owner-no-shared-cost-v1")?,
        utility_rules: vec![AxisAggregationRule {
            axis: id("total-ms")?,
            operator: AggregationOperator::RequireEqual,
        }],
        risk_rules: Vec::new(),
        resource_rules: vec![AxisAggregationRule {
            axis: id("search-ms")?,
            operator: AggregationOperator::RequireEqual,
        }],
        uncertainty_rules: vec![AxisAggregationRule {
            axis: id("total-ms")?,
            operator: AggregationOperator::Maximum,
        }],
        pareto_absolute_tolerances: vec![axis("total-ms", 0)?],
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
    Ok(json!({
        "schema": "hepta.hia.ndu-response.v1", "upstream_commit": UPSTREAM,
        "entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
        "objective_sha256": request.objective_sha256, "generation": request.generation,
        "advisory_recommendation": result.base.advisory_recommendation.map(|v| v.to_string()),
        "disposition": format!("{:?}", result.base.disposition),
        "evaluation_digest_v2": result.evaluation_digest_v2.to_string(),
        "evaluation_policy_digest": result.evaluation_policy_digest.to_string(),
        "utility_profile_digest": result.base.utility_profile_digest.to_string(),
        "pareto_frontier": result.base.pareto_frontier.iter().map(|c| c.candidate_id.to_string()).collect::<Vec<_>>(),
        "rejected": result.base.rejected_candidates.iter().map(|c| json!({"id":c.candidate_id.to_string(),"reasons":format!("{:?}",c.reasons)})).collect::<Vec<_>>(),
        "authority": "ADVISORY_ONLY", "proves_program_safety": false,
        "global_optimality_established": false
    }))
}

fn main() {
    let result = (|| -> Result<Value, String> {
        let mut input = Vec::new();
        io::stdin()
            .take(MAX_BYTES + 1)
            .read_to_end(&mut input)
            .map_err(|e| e.to_string())?;
        if input.len() as u64 > MAX_BYTES {
            return Err("request exceeds byte limit".into());
        }
        let request = serde_json::from_slice(&input).map_err(|e| e.to_string())?;
        let mut response = evaluate(request)?;
        response
            .as_object_mut()
            .ok_or("response must be an object")?
            .insert(
                "request_sha256".into(),
                json!(Digest32::of_bytes(&input).to_string()),
            );
        Ok(response)
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!(
                "{}",
                json!({"schema":"hepta.hia.ndu-error.v1","error":error,"authority":"NONE"})
            );
            std::process::exit(2);
        }
    }
}
