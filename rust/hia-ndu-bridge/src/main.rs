//! Bounded JSON transport into the existing, pinned NDU evaluator.
//! This executable is advisory only. HIA independently proves candidates.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
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

const STREAM_PROFILE: &str = "hepta.hia.ndu-ranking-persistent-framed.v1";
const MAX_REQUESTS: usize = 256;
const MAX_SESSION_BYTES: usize = 8 * 1024 * 1024;
const FRAME_TAG_BYTES: usize = 4 + 64;

fn response(input: &[u8]) -> Result<Value, String> {
    if input.len() as u64 > MAX_BYTES {
        return Err("request exceeds byte limit".into());
    }
    let request = serde_json::from_slice(input).map_err(|e| e.to_string())?;
    let mut result = evaluate(request)?;
    result
        .as_object_mut()
        .ok_or("response must be an object")?
        .insert(
            "request_sha256".into(),
            json!(Digest32::of_bytes(input).to_string()),
        );
    Ok(result)
}

fn charge(total: &mut usize, amount: usize) -> Result<(), String> {
    let next = total.checked_add(amount).ok_or("session byte count overflow")?;
    if next > MAX_SESSION_BYTES {
        return Err("session byte allowance exhausted".into());
    }
    *total = next;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R, total: &mut usize) -> Result<Option<Vec<u8>>, String> {
    let mut header = [0u8; 4];
    match reader.read(&mut header[..1]).map_err(|e| e.to_string())? {
        0 => return Ok(None), // EOF at a frame boundary is a requested clean close.
        1 => (),
        _ => unreachable!(),
    }
    reader.read_exact(&mut header[1..]).map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(header) as usize;
    if !(FRAME_TAG_BYTES + 1..=FRAME_TAG_BYTES + MAX_BYTES as usize).contains(&length) {
        return Err("stream frame exceeds byte bounds".into());
    }
    charge(total, 4 + length)?;
    let mut frame = vec![0u8; length];
    reader.read_exact(&mut frame).map_err(|e| e.to_string())?;
    Ok(Some(frame))
}

fn write_frame<W: Write>(
    writer: &mut W, sequence: u32, session: &str, body: &[u8], total: &mut usize,
) -> Result<(), String> {
    if body.is_empty() || body.len() as u64 > MAX_BYTES {
        return Err("stream response exceeds byte bounds".into());
    }
    let length = FRAME_TAG_BYTES + body.len();
    charge(total, 4 + length)?;
    writer.write_all(&(length as u32).to_be_bytes()).map_err(|e| e.to_string())?;
    writer.write_all(&sequence.to_be_bytes()).map_err(|e| e.to_string())?;
    writer.write_all(session.as_bytes()).map_err(|e| e.to_string())?;
    writer.write_all(body).map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())
}

fn stream<R: Read, W: Write>(
    reader: &mut R, writer: &mut W, session: &str, maximum: usize,
) -> Result<(), String> {
    if session.len() != 64
        || !session.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !(1..=MAX_REQUESTS).contains(&maximum)
    {
        return Err("invalid stream session or request allowance".into());
    }
    let mut total = 0;
    let hello = json!({
        "schema": "hepta.hia.ndu-stream-hello.v1",
        "transport_profile": STREAM_PROFILE,
        "upstream_commit": UPSTREAM,
        "entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
        "max_requests": maximum,
        "max_frame_json_bytes": MAX_BYTES,
        "max_session_bytes": MAX_SESSION_BYTES,
        "authority": "ADVISORY_ONLY",
        "result_cache": false,
        "evaluates_each_request": true
    }).to_string();
    write_frame(writer, 0, session, hello.as_bytes(), &mut total)?;
    for sequence in 1..=maximum {
        let Some(frame) = read_frame(reader, &mut total)? else {
            return Ok(());
        };
        let supplied = u32::from_be_bytes(frame[..4].try_into().map_err(|_| "sequence bytes")?);
        if supplied != sequence as u32 || &frame[4..FRAME_TAG_BYTES] != session.as_bytes() {
            return Err("stream sequence or session mismatch".into());
        }
        // Every accepted frame constructs a fresh request and invokes the
        // original pinned evaluator. Only the transport process is retained.
        let value = response(&frame[FRAME_TAG_BYTES..])?;
        let mut output = value.to_string().into_bytes();
        output.push(b'\n'); // Exactly the same native JSON bytes as one-shot mode.
        write_frame(writer, sequence as u32, session, &output, &mut total)?;
    }
    Ok(()) // The process cannot evaluate more than its startup allowance.
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        let result = (|| -> Result<Value, String> {
            let mut input = Vec::new();
            io::stdin()
                .take(MAX_BYTES + 1)
                .read_to_end(&mut input)
                .map_err(|e| e.to_string())?;
            response(&input)
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
        return;
    }
    let result = (|| -> Result<(), String> {
        if args.len() != 4 || args[1] != "--stream-v1" {
            return Err("expected --stream-v1 SESSION_HEX MAX_REQUESTS".into());
        }
        let maximum = args[3].parse::<usize>().map_err(|e| e.to_string())?;
        stream(&mut io::stdin().lock(), &mut io::stdout().lock(), &args[2], maximum)
    })();
    if let Err(error) = result {
        let bounded: String = error.chars().take(2048).collect();
        eprintln!(
            "{}",
            json!({"schema":"hepta.hia.ndu-stream-error.v1","error":bounded,"authority":"NONE"})
        );
        std::process::exit(2);
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_bounds_and_partial_headers_refuse_before_unbounded_allocation() {
        for raw in [vec![0u8], vec![0, 0, 0, 1], vec![255, 255, 255, 255]] {
            assert!(read_frame(&mut Cursor::new(raw), &mut 0).is_err());
        }
        let mut total = MAX_SESSION_BYTES;
        let header = (FRAME_TAG_BYTES as u32 + 1).to_be_bytes();
        assert!(read_frame(&mut Cursor::new(header), &mut total).is_err());
    }

    #[test]
    fn clean_boundary_eof_is_distinct_from_a_partial_frame() {
        assert!(read_frame(&mut Cursor::new(Vec::<u8>::new()), &mut 0).unwrap().is_none());
        let mut raw = Vec::new();
        raw.extend_from_slice(&(FRAME_TAG_BYTES as u32 + 2).to_be_bytes());
        raw.extend_from_slice(&[1u8; 10]);
        assert!(read_frame(&mut Cursor::new(raw), &mut 0).is_err());
    }

    #[test]
    fn session_and_round_replay_refuse_before_json_evaluation() {
        let session = "1".repeat(64);
        for (sequence, token) in [(0u32, session.clone()), (2u32, session.clone()), (1u32, "2".repeat(64))] {
            let mut input = Vec::new();
            input.extend_from_slice(&((FRAME_TAG_BYTES + 2) as u32).to_be_bytes());
            input.extend_from_slice(&sequence.to_be_bytes());
            input.extend_from_slice(token.as_bytes());
            input.extend_from_slice(b"{}");
            let result = stream(&mut Cursor::new(input), &mut Vec::new(), &session, 1);
            assert_eq!(result.unwrap_err(), "stream sequence or session mismatch");
        }
    }
}
