//! Separate native controls for the prospective same-input finite-path study.
//! These are not the private NDU implementation and grant no authority.
#![forbid(unsafe_code)]
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read, Write};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAX_INPUT: u64 = 1_048_576;
const MAX_REQUESTS: usize = 256;
const Q32: i64 = 1_i64 << 32;
const UTILITY_LIMIT: i64 = 1_000_000 * Q32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event { event_digest: String, preference_digest: String, instant_q32: i64, discount_q32: i64 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    id: String, verified: bool, verification_digest: String, support_digest: String,
    resource_cost_q32: i64, risk_q32: i64, uncertainty_q32: i64,
    terminal_q32: i64, events: Vec<Event>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String, objective_digest: String, snapshot_digest: String, generation: u64,
    utility_unit: String, resource_unit: String, risk_unit: String,
    resource_budget_q32: i64, risk_ceiling_q32: i64, candidates: Vec<Candidate>,
}
fn hash(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
fn digest(v: &str) -> bool {
    v.len()==64 && v.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && v.bytes().any(|c| c!=b'0')
}
fn stable(v: &str) -> bool {
    !v.is_empty() && v.len()<=64
        && v.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}
fn identity() -> Value {
    json!({"schema":"hepta.hia.native-control.identity.v1",
        "source_commit":env!("CONTROL_SOURCE_COMMIT"),
        "source_digest":env!("CONTROL_SOURCE_DIGEST"),
        "bridge_digest":env!("CONTROL_SOURCE_DIGEST"),
        "rustc":env!("CONTROL_RUSTC"),
        "algorithms":[concat!("hepta.control.",env!("CONTROL_ALGORITHM"))],
        "authority":"DENY_ALL","safety_certificate":false})
}
fn validate(r: &Request) -> Result<(),String> {
    if r.schema!="hepta.hia.ndu.request.v1" || !(1..=128).contains(&r.candidates.len())
        || !digest(&r.objective_digest) || !digest(&r.snapshot_digest)
        || !(1..=u32::MAX as u64).contains(&r.generation) || !stable(&r.utility_unit)
        || !["nanoseconds","microseconds","bytes","modeled-work"].contains(&r.resource_unit.as_str())
        || r.risk_unit!="probability" || r.resource_budget_q32<0 || !(0..=Q32).contains(&r.risk_ceiling_q32) {
        return Err("request outside registered finite unit-discount control profile".into());
    }
    let mut ids=BTreeSet::new();
    for c in &r.candidates {
        if !stable(&c.id) || !ids.insert(c.id.clone()) || !digest(&c.verification_digest)
            || !digest(&c.support_digest) || c.resource_cost_q32<0
            || !(0..=Q32).contains(&c.risk_q32) || c.uncertainty_q32!=0
            || c.events.is_empty() || c.events.len()>8 || !(-UTILITY_LIMIT..=UTILITY_LIMIT).contains(&c.terminal_q32) {
            return Err("invalid finite candidate".into());
        }
        let mut event_ids=BTreeSet::new();
        for e in &c.events {
            if !digest(&e.event_digest) || !event_ids.insert(e.event_digest.clone())
                || !digest(&e.preference_digest) || e.preference_digest!=r.objective_digest
                || e.discount_q32!=Q32 || e.instant_q32>0 {
                return Err("control profile requires unit discounts and nonpositive cost events".into());
            }
        }
        if c.id=="abstain" && (!c.verified || c.resource_cost_q32!=0 || c.risk_q32!=0
            || c.terminal_q32!=0 || c.events.iter().any(|e|e.instant_q32!=0)) {
            return Err("abstain must retain exact zero effect".into());
        }
    }
    if !ids.contains("abstain") { return Err("explicit abstention required".into()); }
    Ok(())
}
fn values(c: &Candidate) -> Result<Vec<i64>,String> {
    // A linear suffix-DP table for each supplied path. Every suffix depends
    // only on the next one; a map or cloned suffix keys would add work here.
    // The complete table is required by the common response profile.
    let mut result=vec![0;c.events.len()+1];
    result[c.events.len()]=c.terminal_q32;
    for i in (0..c.events.len()).rev() {
        let value=c.events[i].instant_q32.checked_add(result[i+1])
            .ok_or("Q32 arithmetic overflow")?;
        if !(-UTILITY_LIMIT..=UTILITY_LIMIT).contains(&value) {
            return Err("projected utility is outside control profile".into());
        }
        result[i]=value;
    }
    Ok(result)
}

fn evaluate(raw: &[u8]) -> Result<Value,String> {
    let r:Request=serde_json::from_slice(raw).map_err(|e|e.to_string())?;
    validate(&r)?;
    let algorithm=env!("CONTROL_ALGORITHM");
    if !["exact-suffix-dp","myopic-first-batch"].contains(&algorithm) {
        return Err("unknown compiled control algorithm".into());
    }
    let mut paths=Vec::new();
    let mut evaluated=Vec::new();
    let mut rejected=Vec::new();
    let mut scores=BTreeMap::new();
    for c in &r.candidates {
        let vals=values(c)?;
        let evidence=hash(&serde_json::to_vec(&json!({
            "kind":"independent-control-values-not-NDU-recursive-evidence",
            "candidate":c.id,"values":vals,"source":env!("CONTROL_SOURCE_DIGEST")
        })).map_err(|e|e.to_string())?);
        let mut reasons=Vec::new();
        if !c.verified {reasons.push("control:upstream-verification-not-admitted");}
        if c.resource_cost_q32>r.resource_budget_q32 {reasons.push("control:resource-ceiling");}
        if c.risk_q32>r.risk_ceiling_q32 {reasons.push("control:risk-ceiling");}
        if reasons.is_empty() {
            evaluated.push(c.id.clone());
            let score=if algorithm=="exact-suffix-dp" {vals[0]} else {
                // A disclosed heuristic objective, not a claimed full-path Pareto value.
                c.events.iter().take(2).try_fold(c.terminal_q32,
                    |v,e|v.checked_add(e.instant_q32).ok_or("myopic Q32 overflow"))?
            };
            scores.insert(c.id.clone(),score);
        } else {rejected.push(json!({"id":c.id,"reasons":reasons}));}
        paths.push(json!({"id":c.id,"verification_digest":c.verification_digest,
            "support_digest":c.support_digest,"values_q32":vals,
            "recursive_evidence_digest":evidence,"resource_cost_q32":c.resource_cost_q32,
            "risk_q32":c.risk_q32,"projection_count":0}));
    }
    let maximum=scores.values().max().ok_or("no explicit feasible abstention")?;
    let frontier:Vec<String>=scores.iter().filter(|(_,v)|*v==maximum).map(|(id,_)|id.clone()).collect();
    evaluated.sort();
    let chosen=if frontier.len()==1 {Some(frontier[0].clone())} else {None};
    let disposition=if evaluated==["abstain"] {"InfeasibleExplicitAbstain"}
        else if frontier.len()==1 {"UniqueParetoRecommendation"} else {"ParetoSetRequiresSlowPath"};
    let policy=hash(format!("control:{algorithm}:unit-discount:zero-risk:zero-uncertainty").as_bytes());
    let profile=hash(b"hepta.control.same-native-wire-profile.v1");
    let evaluation=hash(&serde_json::to_vec(&json!({"request":hash(raw),"algorithm":algorithm,
        "scores":scores,"frontier":frontier,"rejected":rejected})).map_err(|e|e.to_string())?);
    Ok(json!({"schema":"hepta.hia.native-control.response.v1","status":"advisory",
        "request_digest":hash(raw),"objective_digest":r.objective_digest,
        "snapshot_digest":r.snapshot_digest,"generation":r.generation,
        "identity":identity(),"authority":"DENY_ALL","safety_certificate":false,
        "optimality_scope":if algorithm=="exact-suffix-dp" {"bounded-supplied-candidate-paths-only"}
                           else {"bounded-first-batch-surrogate-only"},
        "disposition":disposition,"advisory_candidate_id":chosen,
        "evaluated_candidate_ids":evaluated,"pareto_candidate_ids":frontier,
        "rejected":rejected,"evaluation_digest":evaluation,"evaluation_policy_digest":policy,
        "utility_profile_digest":profile,"paths":paths}))
}
fn stream(mut input:impl BufRead, mut output:impl Write) -> Result<(),String> {
    // Same framing, serde_json codec and request cap as the original stream.
    writeln!(output,"{}",json!({"schema":"hepta.hia.ndu.stream.v1","identity":identity(),
        "max_requests":MAX_REQUESTS,"authority":"DENY_ALL","safety_certificate":false})).map_err(|e|e.to_string())?;
    output.flush().map_err(|e|e.to_string())?;
    for sequence in 1..=MAX_REQUESTS {
        let mut line=Vec::new();
        input.by_ref().take(MAX_INPUT+2).read_until(b'\n',&mut line).map_err(|e|e.to_string())?;
        if line.is_empty(){return Ok(());}
        if line.pop()!=Some(b'\n') || line.len() as u64>MAX_INPUT {
            return Err("one newline-terminated request of at most 1 MiB required".into());
        }
        let response=evaluate(&line)?;
        writeln!(output,"{}",json!({"schema":"hepta.hia.ndu.stream-response.v1","sequence":sequence,
            "response":response,"authority":"DENY_ALL","safety_certificate":false})).map_err(|e|e.to_string())?;
        output.flush().map_err(|e|e.to_string())?;
    }
    let mut extra=[0_u8;1];
    if input.read(&mut extra).map_err(|e|e.to_string())?!=0 {
        return Err("native request budget of 256 exhausted".into());
    }
    Ok(())
}
fn main() {
    let args:Vec<_>=std::env::args().skip(1).collect();
    let result=if args==["--identity"] {
        println!("{}",identity());Ok(())
    } else if args==["--stream"] {stream(std::io::stdin().lock(),std::io::stdout().lock())}
    else if args.is_empty() {
        let mut raw=Vec::new();
        let read=std::io::stdin().take(MAX_INPUT+1).read_to_end(&mut raw).map_err(|e|e.to_string());
        read.and_then(|_|if raw.len() as u64>MAX_INPUT {Err("request byte cap".into())}
            else {evaluate(&raw).map(|v|println!("{v}"))})
    } else {Err("only --identity, --stream or one request is supported".into())};
    if let Err(error)=result {eprintln!("{error}");std::process::exit(1);}
}
