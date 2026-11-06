//! Independent ordinary finite-horizon control for the registered kernel experiment.
//! No Hepta/NDU imports, linked code, state digests, or advice inputs.
//! All observations and already qualified image identities are caller supplied.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Read, Write};
use std::time::Instant;

const Q: i64 = 1_i64 << 32;
const BOUND: i64 = 1_000_000 * Q;
const TOLERANCE: i64 = 4096;
const FRAME: usize = 1_048_576;
const REQUESTS: usize = 256;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Axis { axis: String, value_q32: i64 }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preference {
    mode: String, previous_state: Option<Value>, genesis_values: Vec<Axis>,
    target: Vec<Axis>, eta_q32: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Image {
    id: String, backend: String, artifact_sha256: String, verification_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase {
    image_id: String, event_digest: String, support_digest: String,
    components: Vec<Axis>, cost_q32: i64, discount_q32: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    id: String, verified: bool, verification_digest: String, support_digest: String,
    resource_cost_q32: i64, risk_q32: i64, uncertainty_q32: i64, path: Vec<Phase>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String, objective_digest: String, snapshot_digest: String,
    action_registry_digest: String, generation: u64, horizon: usize,
    utility_unit: String, resource_unit: String, resource_budget_q32: i64,
    risk_ceiling_q32: i64, terminal_utility_q32: i64,
    preference: Preference, images: Vec<Image>, candidates: Vec<Candidate>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String, request: Box<RawValue>, previous_weights: Option<Vec<Axis>>,
}

fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn stable(text: &str) -> Result<(), String> {
    if text.is_empty() || text.len() > 128 || !text.bytes().all(
        |b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')) {
        return Err("identifier grammar or length".into());
    }
    Ok(())
}
fn support(text: &str) -> Result<(), String> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || text.bytes().all(|b| b == b'0') {
        return Err("nonzero lowercase SHA256 required".into());
    }
    Ok(())
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let v = serde_json::to_value(value).map_err(|e| e.to_string())?;
    serde_json::to_vec(&v).map_err(|e| e.to_string())
}
fn axes(input: &[Axis], bound: i64) -> Result<BTreeMap<String, i64>, String> {
    if input.is_empty() || input.len() > 16 {
        return Err("one to sixteen axes required".into());
    }
    let mut values = BTreeMap::new();
    for a in input {
        stable(&a.axis)?;
        if !(-bound..=bound).contains(&a.value_q32) ||
            values.insert(a.axis.clone(), a.value_q32).is_some() {
            return Err("axis duplicate or range".into());
        }
    }
    Ok(values)
}
fn wire_axes(values: &BTreeMap<String, i64>) -> Vec<Axis> {
    values.iter().map(|(axis, value)| Axis { axis:axis.clone(), value_q32:*value }).collect()
}
fn same_axes(a: &BTreeMap<String,i64>, b: &BTreeMap<String,i64>) -> Result<(),String> {
    if a.keys().ne(b.keys()) { return Err("axis dimension mismatch".into()); }
    Ok(())
}
// Independent integer implementation: signed magnitude, round nearest ties to even.
fn multiply(a: i64, b: i64) -> Result<i64, String> {
    let product = i128::from(a) * i128::from(b);
    let magnitude = product.abs();
    let mut whole = magnitude / i128::from(Q);
    let fraction = magnitude % i128::from(Q);
    if fraction > i128::from(Q / 2) || (fraction == i128::from(Q / 2) && whole % 2 != 0) {
        whole += 1;
    }
    let rounded = if product < 0 { -whole } else { whole };
    i64::try_from(rounded).map_err(|_| "Q32 multiplication overflow".into())
}
fn checked_utility(value: i128) -> Result<i64,String> {
    if !(-i128::from(BOUND)..=i128::from(BOUND)).contains(&value) {
        return Err("utility overflow or forbidden projection".into());
    }
    Ok(value as i64)
}
fn residual(current:&BTreeMap<String,i64>, target:&BTreeMap<String,i64>)->i64 {
    current.iter().map(|(k,v)| (target[k] - v).abs()).max().unwrap_or(0)
}
fn solve(p:&Preference, previous:Option<&[Axis]>)->Result<(BTreeMap<String,i64>,Value),String> {
    if p.previous_state.is_some() {
        return Err("native NDU state must never enter ordinary control".into());
    }
    if !matches!(p.mode.as_str(),"fixed"|"dynamic") || p.eta_q32 != Q/4 {
        return Err("unregistered preference mode or eta".into());
    }
    let genesis=axes(&p.genesis_values,Q)?;
    let registered_target=axes(&p.target,Q)?;
    same_axes(&genesis,&registered_target)?;
    let initial=if let Some(v)=previous { axes(v,Q)? } else { genesis.clone() };
    same_axes(&initial,&genesis)?;
    let target=if p.mode=="fixed" {initial.clone()} else {registered_target};
    let mut current=initial.clone();
    let maximum_residual=residual(&current,&target);
    let mut final_residual=maximum_residual;
    let mut iterations=Vec::new();
    if final_residual>TOLERANCE {
        for iteration in 1..=64 {
            let mut next=BTreeMap::new();
            for (axis,value) in &current {
                let delta=target[axis]-value;
                let step=multiply(delta,p.eta_q32)?;
                let updated=value.checked_add(step).ok_or("preference addition overflow")?;
                // Convex damping between bounded inputs cannot require projection.
                if !(-Q..=Q).contains(&updated) {return Err("preference projection forbidden".into());}
                next.insert(axis.clone(),updated);
            }
            current=next;
            final_residual=residual(&current,&target);
            iterations.push(json!({"iteration":iteration,"residual_raw":final_residual,
                "projection_count":0,"values":wire_axes(&current)}));
            if final_residual<=TOLERANCE {break;}
        }
    }
    if final_residual>TOLERANCE {return Err("preference iteration bound exhausted".into());}
    let result=json!({"entry_point":"independent_integer_damped_preference",
        "mode":p.mode,"initial_weights":wire_axes(&initial),"target":p.target,
        "effective_target":wire_axes(&target),"weights":wire_axes(&current),
        "eta_q32":p.eta_q32,"iterations":iterations,
        "termination":{"iterations":iterations.len(),"terminal_residual_raw":final_residual,
            "maximum_residual_raw":maximum_residual,"projection_count":0},
        "native_state_digests_created":false});
    Ok((current,result))
}
fn evaluate(input:&[u8])->Result<Value,String> {
    let started=Instant::now();
    let outer:Envelope=serde_json::from_slice(input).map_err(|e|e.to_string())?;
    if outer.schema!="hepta.hia.kernel-ordinary-control.request.v1" {
        return Err("ordinary envelope schema".into());
    }
    let raw_request=outer.request.get().as_bytes();
    let r:Request=serde_json::from_slice(raw_request).map_err(|e|e.to_string())?;
    if r.schema!="hepta.hia.kernel-ndu.request.v1" || !(1..=4).contains(&r.horizon)
        || r.images.len()!=3 || r.generation==0 {
        return Err("request schema, horizon, image count or generation".into());
    }
    if r.resource_budget_q32<0 || !(0..=Q).contains(&r.risk_ceiling_q32)
        || !(0..=BOUND).contains(&r.terminal_utility_q32)
        || !["nanoseconds","microseconds","bytes","modeled-work"].contains(&r.resource_unit.as_str()) {
        return Err("resource/risk/terminal bounds or unit".into());
    }
    stable(&r.utility_unit)?;
    support(&r.objective_digest)?;support(&r.snapshot_digest)?;
    support(&r.action_registry_digest)?;
    if sha(&canonical(&r.images)?)!=r.action_registry_digest {
        return Err("action registry digest mismatch".into());
    }
    let mut images=BTreeMap::new();
    let mut backends=BTreeSet::new();
    for image in &r.images {
        stable(&image.id)?;support(&image.artifact_sha256)?;support(&image.verification_digest)?;
        if !["O2","O3","Os"].contains(&image.backend.as_str())
            || !backends.insert(image.backend.clone()) || images.insert(image.id.clone(),image).is_some() {
            return Err("duplicate image/backend or unknown backend".into());
        }
    }
    let count=3_usize.pow(r.horizon as u32);
    if r.candidates.len()!=count+1 {return Err("complete paths plus abstain required".into());}
    let (weights,pref)=solve(&r.preference,outer.previous_weights.as_deref())?;
    let mut ids=BTreeSet::new();
    let mut sequences=BTreeSet::new();
    let mut paths=Vec::new();
    let mut eligible=BTreeMap::new();
    let mut first_by_id=BTreeMap::new();
    let mut seen_abstain=false;
    for candidate in &r.candidates {
        stable(&candidate.id)?;
        support(&candidate.verification_digest)?;support(&candidate.support_digest)?;
        if !ids.insert(candidate.id.clone()) || candidate.resource_cost_q32<0
            || !(0..=Q).contains(&candidate.risk_q32)
            || !(0..=Q).contains(&candidate.uncertainty_q32) {
            return Err("duplicate candidate or invalid bounded cost/risk/uncertainty".into());
        }
        let mut phases=Vec::new();
        let mut instants=Vec::new();
        let mut discounts=Vec::new();
        let terminal;
        if candidate.id=="abstain" {
            if seen_abstain || !candidate.path.is_empty() || !candidate.verified
                || candidate.resource_cost_q32!=0 || candidate.risk_q32!=0 || candidate.uncertainty_q32!=0 {
                return Err("abstain must be exact zero-effect search option".into());
            }
            seen_abstain=true;
            terminal=0;
            instants.push(0);discounts.push(Q);
        } else {
            if candidate.path.len()!=r.horizon {return Err("candidate horizon mismatch".into());}
            let sequence=candidate.path.iter().map(|p|p.image_id.clone()).collect::<Vec<_>>();
            if !sequences.insert(sequence) {return Err("duplicate image sequence".into());}
            terminal=r.terminal_utility_q32;
            first_by_id.insert(candidate.id.clone(),candidate.path[0].image_id.clone());
            for (index,phase) in candidate.path.iter().enumerate() {
                let image=images.get(&phase.image_id).ok_or("unregistered image")?;
                support(&phase.event_digest)?;support(&phase.support_digest)?;
                if !(0..=BOUND).contains(&phase.cost_q32) || !(0..=Q).contains(&phase.discount_q32) {
                    return Err("phase cost or discount outside bounds".into());
                }
                let components=axes(&phase.components,BOUND)?;
                same_axes(&weights,&components)?;
                let mut terms=Vec::new();
                let mut sum=0_i128;
                for (axis,weight) in &weights {
                    let component=components[axis];
                    let weighted=multiply(*weight,component)?;
                    sum+=i128::from(weighted);
                    terms.push(json!({"axis":axis,"weight_q32":weight,
                        "component_q32":component,"weighted_q32":weighted}));
                }
                let instant=checked_utility(sum-i128::from(phase.cost_q32))?;
                instants.push(instant);discounts.push(phase.discount_q32);
                phases.push(json!({"index":index,"image_id":phase.image_id,"backend":image.backend,
                    "artifact_sha256":image.artifact_sha256,"input_event_digest":phase.event_digest,
                    "support_digest":phase.support_digest,"terms":terms,
                    "instant_q32":instant,"cost_q32":phase.cost_q32,"discount_q32":phase.discount_q32}));
            }
        }
        // Independent backward finite-horizon dynamic programming over each supplied path.
        let mut values=vec![0_i64;instants.len()+1];
        values[instants.len()]=terminal;
        for k in (0..instants.len()).rev() {
            values[k]=checked_utility(i128::from(instants[k])
                +i128::from(multiply(discounts[k],values[k+1])?))?;
        }
        let mut reasons=Vec::new();
        if !candidate.verified {reasons.push("unverified");}
        if candidate.resource_cost_q32>r.resource_budget_q32 {reasons.push("resource_budget");}
        if candidate.risk_q32>r.risk_ceiling_q32 {reasons.push("risk_ceiling");}
        let feasible=reasons.is_empty();
        if feasible {eligible.insert(candidate.id.clone(),values[0]);}
        paths.push(json!({"id":candidate.id,"verified":candidate.verified,"feasible":feasible,
            "rejection_reasons":reasons,"phases":phases,"terminal_q32":terminal,
            "values_q32":values,"resource_cost_q32":candidate.resource_cost_q32,
            "risk_q32":candidate.risk_q32,"uncertainty_q32":candidate.uncertainty_q32,
            "projection_count":0}));
    }
    if !seen_abstain || sequences.len()!=count {return Err("incomplete path inventory".into());}
    let maximum=*eligible.values().max().ok_or("no feasible candidate")?;
    let frontier=eligible.iter().filter(|(_,v)|**v==maximum).map(|(k,_)|k.clone()).collect::<Vec<_>>();
    let firsts=frontier.iter().filter_map(|k|first_by_id.get(k)).cloned().collect::<BTreeSet<_>>();
    let selected=if !frontier.iter().any(|id|id=="abstain") && firsts.len()==1 {
        firsts.iter().next().cloned()
    } else {None};
    Ok(json!({"schema":"hepta.hia.kernel-ordinary-control.response.v1","status":"advisory",
        "input_sha256":sha(input),"request_sha256":sha(raw_request),
        "objective_digest":r.objective_digest,"snapshot_digest":r.snapshot_digest,
        "action_registry_digest":r.action_registry_digest,"generation":r.generation,
        "entry_points":["independent_integer_damped_preference",
            "independent_backward_path_recursion","independent_exact_scalar_frontier"],
        "preference":pref,"paths":paths,"complete_image_paths":count,
        "pareto_candidate_ids":frontier,"selected_first_image_id":selected,
        "first_action_policy":"only-common-across-entire-feasible-frontier",
        "service_before_output_ns":started.elapsed().as_nanos(),
        "implementation":"independent-rust-integer-control",
        "native_ndu_linked_or_called":false,"native_state_digests_created":false,
        "measurements_created":false,"kernel_image_verified_by_adapter":false,
        "authority":"DENY_ALL","production_activation_allowed":false}))
}
fn emit(out:&mut impl Write,value:&Value)->Result<(),String>{
    let bytes=serde_json::to_vec(value).map_err(|e|e.to_string())?;
    if bytes.len()>FRAME {return Err("response frame bound".into());}
    out.write_all(&bytes).and_then(|_|out.write_all(b"\n")).and_then(|_|out.flush()).map_err(|e|e.to_string())
}
fn run()->Result<(),String>{
    let args=std::env::args().collect::<Vec<_>>();
    let mut out=io::stdout().lock();
    if args.len()==2 && args[1]=="--identity" {
        return emit(&mut out,&json!({"profile":"hepta.hia.kernel-ordinary-control.v1",
            "implementation":"independent-rust-integer-control","native_ndu_linked_or_called":false,
            "preference_modes":["fixed","dynamic"],"maximum_horizon":4,
            "image_backends":["O2","O3","Os"],"eta_q32":Q/4,
            "residual_tolerance_raw":TOLERANCE,"maximum_preference_iterations":64,
            "numeric_profile":"signed-Q32-nearest-ties-even","authority":"DENY_ALL",
            "measurements_created":false,"production_activation_allowed":false}));
    }
    if args.len()==2 && args[1]=="--stream" {
        emit(&mut out,&json!({"schema":"hepta.hia.kernel-ordinary-control.hello.v1",
            "max_frame_bytes":FRAME,"max_requests":REQUESTS,"authority":"DENY_ALL"}))?;
        let mut input=io::stdin().lock();
        for sequence in 1..=REQUESTS {
            let mut bytes=Vec::new();
            let n=std::io::Read::take(&mut input,(FRAME+2) as u64).read_until(b'\n',&mut bytes).map_err(|e|e.to_string())?;
            if n==0 {return Ok(());}
            if bytes.len()>FRAME+1 || bytes.last()!=Some(&b'\n') {return Err("input frame or delimiter".into());}
            bytes.pop();
            let response=match evaluate(&bytes){
                Ok(mut value)=>{value["stream_sequence"]=json!(sequence);value},
                Err(reason)=>json!({"schema":"hepta.hia.kernel-ordinary-control.refusal.v1",
                    "sequence":sequence,"input_sha256":sha(&bytes),"reason":reason,"authority":"DENY_ALL"}),
            };
            emit(&mut out,&response)?;
        }
        return Err("stream request bound exhausted".into());
    }
    if args.len()!=1 {return Err("usage: hia-kernel-ordinary-control [--identity|--stream]".into());}
    let mut input=Vec::new();
    io::stdin().take((FRAME+1) as u64).read_to_end(&mut input).map_err(|e|e.to_string())?;
    if input.len()>FRAME {return Err("input frame bound".into());}
    emit(&mut out,&evaluate(&input)?)
}
fn main(){if let Err(reason)=run(){eprintln!("HIA_KERNEL_ORDINARY_REJECT: {reason}");std::process::exit(2);}}
