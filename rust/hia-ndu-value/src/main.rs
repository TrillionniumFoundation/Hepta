//! Original scalar NDU at each live search backup. No workload execution.
#![forbid(unsafe_code)]
use codex_hepta_ndu::{
    AggregationOperator, AxisAggregationRule, AxisDirection, AxisLimit, AxisValue,
    ContributionSet, EvaluationPolicyV1, FeasibilityPosture, RecursiveUtilityPath,
    RequiredOrganSet, UtilityContribution, UtilityEvent, UtilityProfile,
    evaluate_candidates_with_policy, evaluate_recursive_utility,
};
use codex_hepta_types::{Digest32, FixedQ32, Generation, StableId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::time::Instant;

const UPSTREAM: &str = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d";
const Q32: i64 = 1_i64 << 32;
const LIMIT: i64 = 1_000_000 * Q32;
const MAX_FRAME: usize = 65536;
const MAX_REQUESTS: u64 = 1000000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    id: String,
    instant_q32: i64,
    terminal_q32: i64,
    discount_q32: i64,
    feasible: bool,
    resource_q32: i64,
    risk_q32: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    sequence: u64,
    generation: u64,
    state_digest: String,
    preference_digest: String,
    objective_digest: String,
    resource_budget_q32: i64,
    risk_ceiling_q32: i64,
    candidates: Vec<Candidate>,
}
fn hash(value: &[u8]) -> Digest32 { Digest32::of_bytes(value) }
fn parse(value: &str) -> Result<Digest32,String> {
    let digest: Digest32 = value.parse().map_err(|e|format!("{e}"))?;
    if digest.is_zero() { return Err("zero digest".into()); }
    Ok(digest)
}
fn id(value:&str)->Result<StableId,String>{ StableId::new(value).map_err(|e|e.to_string()) }
fn axis(name:&str,value:i64)->Result<AxisValue,String>{Ok(AxisValue{axis:id(name)?,value:FixedQ32::from_raw(value)})}
fn rule(name:&str)->Result<AxisAggregationRule,String>{Ok(AxisAggregationRule{axis:id(name)?,operator:AggregationOperator::RequireEqual})}
fn evaluate(bytes:&[u8], sequence:u64)->Result<Value,String>{
    let started=Instant::now();
    let r:Request=serde_json::from_slice(bytes).map_err(|e|e.to_string())?;
    if r.schema!="hepta.hia.ndu.value.request.v1" || r.sequence!=sequence {return Err("schema or sequence".into());}
    if !(1..=32).contains(&r.candidates.len()) || !(1..=u32::MAX as u64).contains(&r.generation) {
        return Err("candidate or generation bound".into());
    }
    if !(0..=LIMIT).contains(&r.resource_budget_q32) || !(0..=Q32).contains(&r.risk_ceiling_q32) {
        return Err("resource or risk bound".into());
    }
    let state=parse(&r.state_digest)?;
    let preference=parse(&r.preference_digest)?;
    let objective=parse(&r.objective_digest)?;
    let generation=Generation::new(r.generation).map_err(|e|e.to_string())?;
    let request_digest=hash(bytes);
    let units=hash(b"hia.value.scalar.q32.v1;instant-and-continuation-same-units;no-normalization");
    let mut names=BTreeSet::new();
    let mut contributions=Vec::new();
    let mut values=serde_json::Map::new();
    let mut path_receipts=Vec::new();
    let mut eligibility=serde_json::Map::new();
    for (index,c) in r.candidates.iter().enumerate(){
        if !names.insert(c.id.clone()) || c.id.len()>64 {return Err("duplicate or oversized candidate".into());}
        if !(-LIMIT..=LIMIT).contains(&c.instant_q32) || !(-LIMIT..=LIMIT).contains(&c.terminal_q32)
            || !(0..=Q32).contains(&c.discount_q32) || !(0..=LIMIT).contains(&c.resource_q32)
            || !(0..=Q32).contains(&c.risk_q32) {return Err("candidate numeric bound".into());}
        let candidate_id=id(&c.id)?;
        let path=RecursiveUtilityPath {
            objective_digest:objective,
            episode_digest:Digest32::of_parts(&[state.as_array(),c.id.as_bytes()]),
            coefficient_digest:hash(b"hia.value.backup.original.scalar.v1"),units_digest:units,
            terminal_outcome_digest:request_digest,terminal:FixedQ32::from_raw(c.terminal_q32),
            lower:FixedQ32::from_raw(-LIMIT),upper:FixedQ32::from_raw(LIMIT),
            events:vec![UtilityEvent{sequence:1,
                event_digest:Digest32::of_parts(&[request_digest.as_array(),&(index as u64).to_be_bytes()]),
                preference_digest:preference,instant:FixedQ32::from_raw(c.instant_q32),
                discount:FixedQ32::from_raw(c.discount_q32)}],
        };
        let result=evaluate_recursive_utility(&path).map_err(|e|e.to_string())?;
        if result.projection_count!=0 {return Err("utility clipping prohibited".into());}
        let value=result.values[0].raw();
        values.insert(c.id.clone(),json!(value));
        eligibility.insert(c.id.clone(),json!(c.feasible && c.resource_q32<=r.resource_budget_q32 && c.risk_q32<=r.risk_ceiling_q32));
        path_receipts.push(json!({"id":c.id,"recursive_evidence_digest":result.evidence_digest.to_string()}));
        contributions.push(UtilityContribution {
            candidate_id,organ_id:id("hia.control")?,objective_digest:objective,generation,
            feasibility:if c.feasible {FeasibilityPosture::Feasible} else {FeasibilityPosture::HardConstraintViolation},
            utility:vec![axis("utility.net",value)?],risk:vec![axis("risk.tail",c.risk_q32)?],
            resource:vec![axis("resource.optimization",c.resource_q32)?],uncertainty:vec![axis("utility.net",0)?],
            support_digest:Digest32::of_parts(&[request_digest.as_array(),result.evidence_digest.as_array()]),
        });
    }
    let profile=UtilityProfile {
        profile_id:id("hia.control.value.v1")?,axis_registry_digest:hash(b"utility.net/risk.tail/resource.optimization.v1"),
        normalization_manifest_digest:units,dimensions:vec![(id("utility.net")?,AxisDirection::Maximize)],
        risk_ceilings:vec![AxisLimit{axis:id("risk.tail")?,maximum:FixedQ32::from_raw(r.risk_ceiling_q32)}],
        resource_ceilings:vec![AxisLimit{axis:id("resource.optimization")?,maximum:FixedQ32::from_raw(r.resource_budget_q32)}],
        required_organs:RequiredOrganSet{organ_ids:vec![id("hia.control")?]},
    };
    let policy=EvaluationPolicyV1{policy_id:id("hia.control.original.backup.v1")?,
        utility_rules:vec![rule("utility.net")?],risk_rules:vec![rule("risk.tail")?],
        resource_rules:vec![rule("resource.optimization")?],uncertainty_rules:vec![rule("utility.net")?],
        pareto_absolute_tolerances:vec![axis("utility.net",0)?]};
    let result=evaluate_candidates_with_policy(ContributionSet{objective_digest:objective,generation,contributions},profile,None,policy).map_err(|e|e.to_string())?;
    let mut winners=result.base.pareto_frontier.iter().map(|c|c.candidate_id.to_string()).collect::<Vec<_>>();
    winners.sort();
    let rejected=result.base.rejected_candidates.iter().map(|c|json!({"id":c.candidate_id.to_string(),"reasons":c.reasons.iter().map(|r|format!("{r:?}")).collect::<Vec<_>>()})).collect::<Vec<_>>();
    Ok(json!({"schema":"hepta.hia.ndu.value.response.v1","sequence":sequence,
        "state_digest":r.state_digest,"preference_digest":r.preference_digest,"objective_digest":r.objective_digest,
        "generation":r.generation,"request_sha256":request_digest.to_string(),"upstream_commit":UPSTREAM,
        "values_q32":values,"eligible":eligibility,"winners":winners,"rejected":rejected,
        "chosen_id":winners.first(),"path_receipts":path_receipts,"projection_count":0,
        "evaluation_digest":result.evaluation_digest_v2.to_string(),"native_evaluation_ns":started.elapsed().as_nanos(),
        "entry_points":["codex_hepta_ndu::evaluate_recursive_utility","codex_hepta_ndu::evaluate_candidates_with_policy"],
        "authority":"DENY_ALL","safety_certificate":false,"execution_authorized":false}))
}
fn emit(output:&mut impl Write,value:&Value)->Result<(),String>{
    let bytes=serde_json::to_vec(value).map_err(|e|e.to_string())?;
    if bytes.len()>MAX_FRAME {return Err("output frame bound".into());}
    output.write_all(&bytes).and_then(|_|output.write_all(b"\n")).and_then(|_|output.flush()).map_err(|e|e.to_string())
}
fn identity()->Value{json!({"profile":"hepta.hia.ndu.value.v1","upstream_commit":UPSTREAM,
    "maximum_candidates":32,"maximum_requests":MAX_REQUESTS,"maximum_frame_bytes":MAX_FRAME,
    "scalar_recurrence":"instant + ties_even(discount * continuation / 2^32)","unsafe_code":"forbidden", "authority":"DENY_ALL"})}
fn run()->Result<(),String>{
    let args:Vec<_>=std::env::args().collect();
    let mut output=std::io::stdout().lock();
    if args.len()==2 && args[1]=="--identity" {return emit(&mut output,&identity());}
    if args.len()!=2 || args[1]!="--value-stream" {return Err("explicit value role required".into());}
    emit(&mut output,&json!({"schema":"hepta.hia.ndu.value.hello.v1","identity":identity(),"authority":"DENY_ALL","safety_certificate":false}))?;
    let mut input=std::io::stdin().lock();
    for sequence in 1..=MAX_REQUESTS {
        let mut bytes=Vec::new();
        let count=std::io::Read::take(&mut input,(MAX_FRAME+2) as u64).read_until(b'\n',&mut bytes).map_err(|e|e.to_string())?;
        if count==0{return Ok(());}
        if bytes.len()>MAX_FRAME+1 || bytes.last()!=Some(&b'\n'){return Err("input frame bound or missing delimiter".into());}
        bytes.pop();
        match evaluate(&bytes,sequence) {
            Ok(result)=>emit(&mut output,&result)?,
            Err(reason)=>{
                emit(&mut output,&json!({"schema":"hepta.hia.ndu.value.refusal.v1","sequence":sequence,"request_sha256":hash(&bytes).to_string(),"reason":reason,"authority":"DENY_ALL"}))?;
                return Err("request refused; session terminated".into());
            }
        }
    }
    Err("session request bound".into())
}
fn main(){if let Err(reason)=run(){eprintln!("{reason}");std::process::exit(2);}}
