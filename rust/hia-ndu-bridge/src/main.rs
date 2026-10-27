//! Thin, authority-free JSON adapter to the actual pinned NDU evaluator.
//! Compiler legality and measurement authenticity belong to the host pipeline.
#![forbid(unsafe_code)]

use std::io::{self, Read};
use std::str::FromStr;

use codex_hepta_ndu::{
    AggregationOperator, AxisAggregationRule, AxisDirection, AxisLimit, AxisValue,
    ContributionSet, EvaluationPolicyV1, FeasibilityPosture, RequiredOrganSet,
    UtilityContribution, UtilityProfile, evaluate_candidates_with_policy,
};
use codex_hepta_types::{Digest32, FixedQ32, Generation, StableId};
use serde::Deserialize;
use serde_json::{Value, json};

const UPSTREAM: &str = "f8c9419df6ddeb36ff8b522a50219981fb8d9345";
const MAX_INPUT: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    id: String,
    core_sha256: String,
    artifact_sha256: String,
    evidence_sha256: String,
    feasible: bool,
    projected_total_ns: u64,
    peak_live_bytes: u64,
    artifact_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    objective_sha256: String,
    generation: u64,
    maximum_live_bytes: u64,
    maximum_artifact_bytes: u64,
    candidates: Vec<Candidate>,
}

fn id(text: &str) -> Result<StableId, String> {
    StableId::new(text).map_err(|e| e.to_string())
}

fn digest(text: &str) -> Result<Digest32, String> {
    let value = Digest32::from_str(text).map_err(|e| e.to_string())?;
    if value.is_zero() { return Err("empty digest".into()); }
    Ok(value)
}

fn scaled(value: u64, denominator: u64) -> Result<FixedQ32, String> {
    let raw = u128::from(value) * (1_u128 << 32) / u128::from(denominator);
    let raw = i64::try_from(raw).map_err(|_| "Q32 range exceeded")?;
    Ok(FixedQ32::from_raw(raw))
}

fn value(axis: &str, value: FixedQ32) -> Result<AxisValue, String> {
    Ok(AxisValue { axis: id(axis)?, value })
}

fn rule(axis: &str, operator: AggregationOperator) -> Result<AxisAggregationRule, String> {
    Ok(AxisAggregationRule { axis: id(axis)?, operator })
}

fn evaluate(request: Request) -> Result<Value, String> {
    if request.schema != "hepta.hia.ndu-request.v1"
        || !(1..=16).contains(&request.candidates.len())
        || request.maximum_live_bytes > 1024 * 1024 * 1024
        || request.maximum_artifact_bytes > 64 * 1024 * 1024 {
        return Err("request outside registered compiler profile".into());
    }
    let objective = digest(&request.objective_sha256)?;
    let generation = Generation::new(request.generation).map_err(|e| e.to_string())?;
    let profile = UtilityProfile {
        profile_id: id("hia.compiler.cost.v1")?,
        axis_registry_digest: Digest32::of_bytes(b"hia.compiler.axes.v1:total_seconds,min;live_mib,max;artifact_bytes,max"),
        normalization_manifest_digest: Digest32::of_bytes(b"hia.compiler.units.v1:ns/1e9;bytes/1048576;bytes;Q32-truncate"),
        dimensions: vec![(id("total_seconds")?, AxisDirection::Minimize)],
        risk_ceilings: vec![],
        resource_ceilings: vec![
            AxisLimit { axis: id("live_mib")?, maximum: scaled(request.maximum_live_bytes, 1 << 20)? },
            AxisLimit { axis: id("artifact_bytes")?, maximum: scaled(request.maximum_artifact_bytes, 1)? },
        ],
        required_organs: RequiredOrganSet { organ_ids: vec![id("compiler_measurement")?] },
    };
    let policy = EvaluationPolicyV1 {
        policy_id: id("hia.compiler.explicit-policy.v1")?,
        utility_rules: vec![rule("total_seconds", AggregationOperator::Sum)?],
        risk_rules: vec![],
        resource_rules: vec![rule("live_mib", AggregationOperator::Maximum)?,
                             rule("artifact_bytes", AggregationOperator::Maximum)?],
        uncertainty_rules: vec![rule("total_seconds", AggregationOperator::Maximum)?],
        pareto_absolute_tolerances: vec![value("total_seconds", FixedQ32::ZERO)?],
    };
    let mut contributions = Vec::new();
    let mut bindings = Vec::new();
    for candidate in request.candidates {
        let core = digest(&candidate.core_sha256)?;
        let artifact = digest(&candidate.artifact_sha256)?;
        let evidence = digest(&candidate.evidence_sha256)?;
        let support = Digest32::of_parts(&[b"hia.compiler.support.v1", core.as_array(), artifact.as_array(), evidence.as_array()]);
        bindings.push(json!({"id": candidate.id, "core_sha256": core.to_string(),
            "artifact_sha256": artifact.to_string(), "evidence_sha256": evidence.to_string(),
            "support_sha256": support.to_string()}));
        contributions.push(UtilityContribution {
            candidate_id: id(&candidate.id)?, organ_id: id("compiler_measurement")?,
            objective_digest: objective, generation,
            feasibility: if candidate.feasible { FeasibilityPosture::Feasible }
                         else { FeasibilityPosture::HardConstraintViolation },
            utility: vec![value("total_seconds", scaled(candidate.projected_total_ns, 1_000_000_000)?)?],
            risk: vec![],
            resource: vec![value("live_mib", scaled(candidate.peak_live_bytes, 1 << 20)?)?,
                           value("artifact_bytes", scaled(candidate.artifact_bytes, 1)?)?],
            uncertainty: vec![value("total_seconds", FixedQ32::ZERO)?],
            support_digest: support,
        });
    }
    let receipt = evaluate_candidates_with_policy(
        ContributionSet { objective_digest: objective, generation, contributions },
        profile, None, policy).map_err(|e| e.to_string())?;
    Ok(json!({
        "schema": "hepta.hia.ndu-response.v1", "ok": true,
        "upstream_commit": UPSTREAM, "objective_sha256": objective.to_string(),
        "generation": request.generation, "authority": "DENY_ALL",
        "advisory_recommendation": receipt.base.advisory_recommendation.as_ref().map(StableId::as_str),
        "disposition": format!("{:?}", receipt.base.disposition),
        "evaluation_sha256": receipt.evaluation_digest_v2.to_string(),
        "evaluation_policy_sha256": receipt.evaluation_policy_digest.to_string(),
        "utility_profile_sha256": receipt.base.utility_profile_digest.to_string(),
        "bindings": bindings,
        "rejected": receipt.base.rejected_candidates.iter().map(|c| json!({
            "id": c.candidate_id.as_str(), "reasons": c.reasons.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
        "scope": "host-supplied bounded measurements; exact NDU V2 evaluator; no compiler proof or installation authority"
    }))
}

fn run() -> Result<Value, String> {
    let mut bytes = Vec::new();
    io::stdin().take(MAX_INPUT + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_INPUT { return Err("input byte budget".into()); }
    let request: Request = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    evaluate(request)
}

fn main() {
    match run() {
        Ok(response) => println!("{response}"),
        Err(error) => {
            println!("{}", json!({"schema":"hepta.hia.ndu-response.v1", "ok":false,
                "authority":"DENY_ALL", "error":error}));
            std::process::exit(2);
        }
    }
}
