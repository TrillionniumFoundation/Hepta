//! Native whole-kernel path evaluation against unchanged pinned NDU crates.
//! No workload command, compiler, measurement generator, or activation API.
#![forbid(unsafe_code)]

use codex_hepta_ndu::{
    AggregationOperator, AxisAggregationRule, AxisDirection, AxisLimit, AxisValue,
    ContributionSet, EvaluationPolicyV1, FeasibilityPosture, PreferenceState,
    RecursiveUtilityPath, RequiredOrganSet, SubjectClass, UtilityContribution,
    UtilityEvent, UtilityProfile, evaluate_candidates_with_policy,
    evaluate_recursive_utility, mul_q32_ties_even, solve_preference_target,
};
use codex_hepta_types::{Digest32, FixedQ32, Generation, Revision, StableId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Read, Write};
use std::time::Instant;

const UPSTREAM: &str = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d";
const SCHEMA: &str = "hepta.hia.kernel-ndu.request.v1";
const Q32: i64 = 1_i64 << 32;
const LIMIT: i64 = 1_000_000 * Q32;
const MAX_FRAME: usize = 1_048_576;
const MAX_REQUESTS: usize = 256;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Axis { axis: String, value_q32: i64 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    revision: u64, predecessor_digest: String, state_digest: String,
    values: Vec<Axis>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preference {
    mode: String, previous_state: Option<State>, genesis_values: Vec<Axis>,
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
fn digest(s: &str) -> Result<Digest32,String> {
    let d: Digest32 = s.parse().map_err(|e|format!("{e}"))?;
    if d.is_zero() { return Err("zero digest is not support".into()); }
    Ok(d)
}
fn stable(s: &str) -> Result<StableId,String> {
    StableId::new(s).map_err(|e|e.to_string())
}
fn hash(v: &impl Serialize) -> Result<Digest32,String> {
    let value=serde_json::to_value(v).map_err(|e|e.to_string())?;
    Ok(Digest32::of_bytes(&serde_json::to_vec(&value).map_err(|e|e.to_string())?))
}
fn axis(s: &str, n: i64) -> Result<AxisValue,String> {
    Ok(AxisValue{axis:stable(s)?,value:FixedQ32::from_raw(n)})
}
fn axes(v: &[Axis], preference: bool) -> Result<Vec<AxisValue>,String> {
    if v.is_empty() || v.len()>16 {return Err("one to sixteen component axes required".into());}
    let mut seen=BTreeSet::new();
    let mut result=Vec::new();
    for a in v {
        let bound=if preference {Q32} else {LIMIT};
        if a.value_q32 < -bound || a.value_q32 > bound || !seen.insert(a.axis.clone()) {
            return Err("component axis duplicate or out of range".into());
        }
        result.push(axis(&a.axis,a.value_q32)?);
    }
    result.sort();
    Ok(result)
}
fn state_json(s: &PreferenceState)->Value {
    json!({"subject_id":s.subject_id.to_string(),"subject_class":"System",
        "revision":s.revision.get(),"predecessor_digest":s.predecessor_digest.to_string(),
        "state_digest":s.state_digest.to_string(),
        "values":s.values.iter().map(|v|json!({"axis":v.axis.to_string(),"value_q32":v.value.raw()})).collect::<Vec<_>>()})
}
fn wire_state_json(s: &PreferenceState)->Value {
    json!({"revision":s.revision.get(),"predecessor_digest":s.predecessor_digest.to_string(),
        "state_digest":s.state_digest.to_string(),
        "values":s.values.iter().map(|v|json!({"axis":v.axis.to_string(),"value_q32":v.value.raw()})).collect::<Vec<_>>()})
}
fn preference(p: &Preference)->Result<(PreferenceState,Value),String> {
    if !matches!(p.mode.as_str(),"fixed"|"dynamic") || p.eta_q32 != Q32/4 {
        return Err("preference mode or registered eta (1/4)".into());
    }
    let initial=if let Some(s)=&p.previous_state {
        if !p.genesis_values.is_empty() {return Err("genesis values and prior state are exclusive".into());}
        let predecessor: Digest32=s.predecessor_digest.parse().map_err(|e|format!("{e}"))?;
        PreferenceState{
            subject_id:stable("linux.kernel.system")?,subject_class:SubjectClass::System,
            revision:Revision::new(s.revision).map_err(|e|e.to_string())?,
            predecessor_digest:predecessor,values:axes(&s.values,true)?,
            state_digest:digest(&s.state_digest)?,
        }
    } else {
        PreferenceState::genesis(stable("linux.kernel.system")?,SubjectClass::System,
            axes(&p.genesis_values,true)?).map_err(|e|e.to_string())?
    };
    let target=axes(&p.target,true)?;
    if initial.values.iter().map(|v|&v.axis).ne(target.iter().map(|v|&v.axis)) {
        return Err("target and state axes differ".into());
    }
    let original=state_json(&initial);
    // A zero-distance call validates all imported state-digest invariants in
    // the upstream owner. Fixed preference never advances a revision.
    let actual_target=if p.mode=="fixed" {initial.values.clone()} else {target};
    let started=Instant::now();
    let (next,termination,steps)=solve_preference_target(initial,actual_target,
        FixedQ32::from_raw(p.eta_q32)).map_err(|e|e.to_string())?;
    let solve_ns=started.elapsed().as_nanos();
    let receipts=steps.iter().map(|s|json!({
        "subject_id":s.subject_id().to_string(),"subject_class":"System",
        "iteration":s.iteration(),"predecessor_revision":s.predecessor_revision().get(),
        "next_revision":s.next_revision().get(),"residual_raw":s.residual_raw(),
        "projection_count":s.projection_count(),"state_digest":s.state_digest().to_string()
    })).collect::<Vec<_>>();
    let report=json!({"entry_point":"codex_hepta_ndu::solve_preference_target",
        "mode":p.mode,"initial":original,"target":p.target,"eta_q32":p.eta_q32,
        "state":state_json(&next),"next_request_state":wire_state_json(&next),
        "termination":{"disposition":"Converged","iterations":termination.iterations,
            "terminal_residual_raw":termination.terminal_residual_raw,
            "maximum_residual_raw":termination.maximum_residual_raw,
            "projection_count":termination.projection_count,
            "predecessor_digest":termination.predecessor_digest.to_string(),
            "terminal_state_digest":termination.terminal_state_digest.to_string()},
        "iterations":receipts,"solve_ns":solve_ns,
        "scope":"bounded native damping toward the supplied registered target; no learned target or independent convergence certificate"});
    Ok((next,report))
}
fn rule(s:&str)->Result<AxisAggregationRule,String>{
    Ok(AxisAggregationRule{axis:stable(s)?,operator:AggregationOperator::RequireEqual})
}
fn evaluate(input:&[u8])->Result<Value,String>{
    let started=Instant::now();
    let r:Request=serde_json::from_slice(input).map_err(|e|e.to_string())?;
    if r.schema!=SCHEMA || !(1..=4).contains(&r.horizon) || r.images.len()!=3 {
        return Err("kernel request schema, horizon, or image registry".into());
    }
    if r.resource_budget_q32<0 || !(0..=Q32).contains(&r.risk_ceiling_q32)
        || !(0..=LIMIT).contains(&r.terminal_utility_q32)
        || !["nanoseconds","microseconds","bytes","modeled-work"].contains(&r.resource_unit.as_str()) {
        return Err("budget, terminal, risk, or resource units".into());
    }
    stable(&r.utility_unit)?;
    let objective=digest(&r.objective_digest)?;
    let snapshot=digest(&r.snapshot_digest)?;
    let registry=digest(&r.action_registry_digest)?;
    if hash(&r.images)? != registry {return Err("action registry digest mismatch".into());}
    let generation=Generation::new(r.generation).map_err(|e|e.to_string())?;
    let mut images=BTreeMap::new();
    let mut backends=BTreeSet::new();
    for image in &r.images {
        stable(&image.id)?;
        digest(&image.artifact_sha256)?;digest(&image.verification_digest)?;
        if !["O2","O3","Os"].contains(&image.backend.as_str()) ||
            !backends.insert(image.backend.clone()) || images.insert(image.id.clone(),image).is_some() {
            return Err("image identifiers and backend recipes must be unique".into());
        }
    }
    let count=3_usize.pow(r.horizon as u32);
    if r.candidates.len()!=count+1 {return Err("complete 3^horizon image-path inventory plus abstain required".into());}
    let (weights,pref_receipt)=preference(&r.preference)?;
    let units=hash(&json!({"utility":r.utility_unit,"resource":r.resource_unit,
        "risk":"probability","fixed_point":"signed-Q32-nearest-ties-even"}))?;
    let request_digest=Digest32::of_bytes(input);
    let mut ids=BTreeSet::new();
    let mut sequences=BTreeSet::new();
    let mut contributions=Vec::new();
    let mut paths=Vec::new();
    let mut seen_abstain=false;
    for c in &r.candidates {
        let cid=stable(&c.id)?;
        if !ids.insert(c.id.clone()) || c.resource_cost_q32<0 ||
            !(0..=Q32).contains(&c.risk_q32) || !(0..=Q32).contains(&c.uncertainty_q32) {
            return Err("duplicate candidate or invalid bounded cost/risk/uncertainty".into());
        }
        let verification=digest(&c.verification_digest)?;
        let support=digest(&c.support_digest)?;
        let mut events=Vec::new();
        let mut phases=Vec::new();
        let terminal;
        if c.id=="abstain" {
            if seen_abstain || !c.path.is_empty() || !c.verified ||
                c.resource_cost_q32!=0 || c.risk_q32!=0 || c.uncertainty_q32!=0 {
                return Err("abstain must be exactly zero effect and zero cost".into());
            }
            seen_abstain=true;terminal=0;
            events.push(UtilityEvent{sequence:1,event_digest:hash(&json!([r.snapshot_digest,"abstain"]))?,
                preference_digest:weights.state_digest,instant:FixedQ32::ZERO,discount:FixedQ32::ONE});
        } else {
            if c.path.len()!=r.horizon {return Err("incomplete candidate path".into());}
            let sequence=c.path.iter().map(|p|p.image_id.clone()).collect::<Vec<_>>();
            if !sequences.insert(sequence) {return Err("duplicate image path".into());}
            terminal=r.terminal_utility_q32;
            for (index,p) in c.path.iter().enumerate() {
                let image=images.get(&p.image_id).ok_or("unregistered image")?;
                if !(0..=LIMIT).contains(&p.cost_q32) || !(0..=Q32).contains(&p.discount_q32) {
                    return Err("phase cost or discount outside contract".into());
                }
                let components=axes(&p.components,false)?;
                if components.iter().map(|v|&v.axis).ne(weights.values.iter().map(|v|&v.axis)) {
                    return Err("phase and preference axes differ".into());
                }
                let mut terms=Vec::new();
                let mut total=0_i128;
                for (weight,component) in weights.values.iter().zip(&components) {
                    let term=mul_q32_ties_even(weight.value,component.value).map_err(|e|e.to_string())?;
                    total+=i128::from(term.raw());
                    terms.push(json!({"axis":weight.axis.to_string(),"weight_q32":weight.value.raw(),
                        "component_q32":component.value.raw(),"weighted_q32":term.raw()}));
                }
                total-=i128::from(p.cost_q32);
                let instant=i64::try_from(total).map_err(|_|"instant utility overflow")?;
                if !(-LIMIT..=LIMIT).contains(&instant) {return Err("instant utility outside no-projection bound".into());}
                let phase_support=digest(&p.support_digest)?;
                let event_id=digest(&p.event_digest)?;
                let bound_event=Digest32::of_parts(&[event_id.as_array(),phase_support.as_array(),
                    digest(&image.artifact_sha256)?.as_array(),request_digest.as_array()]);
                events.push(UtilityEvent{sequence:index as u64+1,event_digest:bound_event,
                    preference_digest:weights.state_digest,instant:FixedQ32::from_raw(instant),
                    discount:FixedQ32::from_raw(p.discount_q32)});
                phases.push(json!({"index":index,"image_id":p.image_id,"backend":image.backend,
                    "artifact_sha256":image.artifact_sha256,"input_event_digest":p.event_digest,
                    "bound_event_digest":bound_event.to_string(),"support_digest":p.support_digest,
                    "terms":terms,"cost_q32":p.cost_q32,"instant_q32":instant,
                    "discount_q32":p.discount_q32,"preference_digest":weights.state_digest.to_string()}));
            }
        }
        let recursive=evaluate_recursive_utility(&RecursiveUtilityPath{
            objective_digest:objective,episode_digest:Digest32::of_parts(&[snapshot.as_array(),c.id.as_bytes()]),
            coefficient_digest:Digest32::of_bytes(b"hia.kernel.ndu.q32.v1"),units_digest:units,
            terminal_outcome_digest:support,terminal:FixedQ32::from_raw(terminal),
            lower:FixedQ32::from_raw(-LIMIT),upper:FixedQ32::from_raw(LIMIT),events,
        }).map_err(|e|e.to_string())?;
        if recursive.projection_count!=0 {return Err("recursive clipping is forbidden in this profile".into());}
        let value=recursive.values[0].raw();
        contributions.push(UtilityContribution{
            candidate_id:cid,organ_id:stable("hia.kernel.system")?,objective_digest:objective,generation,
            feasibility:if c.verified {FeasibilityPosture::Feasible} else {FeasibilityPosture::HardConstraintViolation},
            utility:vec![axis("utility.net",value)?],risk:vec![axis("risk.tail",c.risk_q32)?],
            resource:vec![axis("resource.kernel",c.resource_cost_q32)?],
            uncertainty:vec![axis("utility.net",c.uncertainty_q32)?],
            support_digest:Digest32::of_parts(&[request_digest.as_array(),registry.as_array(),
                verification.as_array(),support.as_array(),recursive.evidence_digest.as_array(),weights.state_digest.as_array()]),
        });
        paths.push(json!({"id":c.id,"verified":c.verified,"verification_digest":c.verification_digest,
            "support_digest":c.support_digest,"phases":phases,"terminal_q32":terminal,
            "values_q32":recursive.values.iter().map(|v|v.raw()).collect::<Vec<_>>(),
            "recursive_evidence_digest":recursive.evidence_digest.to_string(),
            "resource_cost_q32":c.resource_cost_q32,"risk_q32":c.risk_q32,
            "uncertainty_q32":c.uncertainty_q32,"projection_count":recursive.projection_count}));
    }
    if !seen_abstain || sequences.len()!=count {return Err("complete path inventory absent".into());}
    let evaluated=evaluate_candidates_with_policy(ContributionSet{objective_digest:objective,generation,contributions},
        UtilityProfile{
            profile_id:stable("hia.kernel.system.v1")?,
            axis_registry_digest:Digest32::of_bytes(b"utility.net:risk.tail:resource.kernel:v1"),
            normalization_manifest_digest:units,
            dimensions:vec![(stable("utility.net")?,AxisDirection::Maximize)],
            risk_ceilings:vec![AxisLimit{axis:stable("risk.tail")?,maximum:FixedQ32::from_raw(r.risk_ceiling_q32)}],
            resource_ceilings:vec![AxisLimit{axis:stable("resource.kernel")?,maximum:FixedQ32::from_raw(r.resource_budget_q32)}],
            required_organs:RequiredOrganSet{organ_ids:vec![stable("hia.kernel.system")?]},
        },None,EvaluationPolicyV1{
            policy_id:stable("hia.kernel.complete-path.v1")?,
            utility_rules:vec![rule("utility.net")?],risk_rules:vec![rule("risk.tail")?],
            resource_rules:vec![rule("resource.kernel")?],uncertainty_rules:vec![rule("utility.net")?],
            pareto_absolute_tolerances:vec![axis("utility.net",0)?],
        }).map_err(|e|e.to_string())?;
    let chosen=evaluated.base.advisory_recommendation.as_ref().map(|v|v.to_string());
    let mut first_images=BTreeSet::new();
    let mut frontier_abstain=false;
    for member in &evaluated.base.pareto_frontier {
        let id=member.candidate_id.to_string();
        if id=="abstain" {frontier_abstain=true;continue;}
        let candidate=r.candidates.iter().find(|c|c.id==id).ok_or("unknown native frontier")?;
        first_images.insert(candidate.path[0].image_id.clone());
    }
    let selected_first_image=if !frontier_abstain && first_images.len()==1 {
        first_images.into_iter().next()
    } else {None};
    Ok(json!({"schema":"hepta.hia.kernel-ndu.response.v1","status":"advisory",
        "upstream_commit":UPSTREAM,"request_sha256":request_digest.to_string(),
        "objective_digest":r.objective_digest,"snapshot_digest":r.snapshot_digest,
        "action_registry_digest":r.action_registry_digest,"generation":r.generation,
        "entry_points":["codex_hepta_ndu::solve_preference_target",
            "codex_hepta_ndu::evaluate_recursive_utility","codex_hepta_ndu::evaluate_candidates_with_policy"],
        "preference":pref_receipt,"paths":paths,"complete_image_paths":count,
        "advisory_candidate_id":chosen,"selected_first_image_id":selected_first_image,
        "first_action_policy":"only-common-across-entire-native-frontier",
        "pareto_candidate_ids":evaluated.base.pareto_frontier.iter().map(|c|c.candidate_id.to_string()).collect::<Vec<_>>(),
        "rejected":evaluated.base.rejected_candidates.iter().map(|c|json!({"id":c.candidate_id.to_string(),"reasons":format!("{:?}",c.reasons)})).collect::<Vec<_>>(),
        "disposition":format!("{:?}",evaluated.base.disposition),
        "evaluation_digest":evaluated.evaluation_digest_v2.to_string(),
        "evaluation_policy_digest":evaluated.evaluation_policy_digest.to_string(),
        "utility_profile_digest":evaluated.base.utility_profile_digest.to_string(),
        "service_before_output_ns":started.elapsed().as_nanos(),
        "authority":"DENY_ALL","safety_certificate":false,"production_activation_allowed":false,
        "measurements_created":false,"kernel_image_verified_by_adapter":false,
        "search_scope":"complete supplied paths over exactly three qualified image identities; at most four stages"}))
}
fn emit(out:&mut impl Write,v:&Value)->Result<(),String>{
    let bytes=serde_json::to_vec(v).map_err(|e|e.to_string())?;
    if bytes.len()>MAX_FRAME {return Err("response exceeds frame bound".into());}
    out.write_all(&bytes).and_then(|_|out.write_all(b"\n")).and_then(|_|out.flush()).map_err(|e|e.to_string())
}
fn run()->Result<(),String>{
    let args=std::env::args().collect::<Vec<_>>();
    let mut output=io::stdout().lock();
    if args.len()==2 && args[1]=="--identity" {
        return emit(&mut output,&json!({"profile":"hepta.hia.kernel-ndu.v1","upstream_commit":UPSTREAM,
            "preference_modes":["fixed","dynamic"],"maximum_horizon":4,"image_backends":["O2","O3","Os"],
            "eta_q32":Q32/4,"authority":"DENY_ALL","safety_certificate":false,
            "measurements_created":false,"production_activation_allowed":false}));
    }
    if args.len()==2 && args[1]=="--stream" {
        emit(&mut output,&json!({"schema":"hepta.hia.kernel-ndu.hello.v1","upstream_commit":UPSTREAM,
            "max_frame_bytes":MAX_FRAME,"max_requests":MAX_REQUESTS,"authority":"DENY_ALL"}))?;
        let mut input=io::stdin().lock();
        for sequence in 1..=MAX_REQUESTS {
            let mut bytes=Vec::new();
            let n=std::io::Read::take(&mut input,(MAX_FRAME+2) as u64).read_until(b'\n',&mut bytes).map_err(|e|e.to_string())?;
            if n==0{return Ok(());}
            if bytes.len()>MAX_FRAME+1 || bytes.last()!=Some(&b'\n'){return Err("input frame bound or delimiter".into());}
            bytes.pop();
            let response=match evaluate(&bytes){
                Ok(mut v)=>{v["stream_sequence"]=json!(sequence);v},
                Err(e)=>json!({"schema":"hepta.hia.kernel-ndu.refusal.v1","sequence":sequence,
                    "request_sha256":Digest32::of_bytes(&bytes).to_string(),"reason":e,"authority":"DENY_ALL"}),
            };
            emit(&mut output,&response)?;
        }
        return Err("stream request bound exhausted".into());
    }
    if args.len()!=1 {return Err("usage: hia-ndu-bridge [--identity|--stream]".into());}
    let mut input=Vec::new();
    io::stdin().take((MAX_FRAME+1) as u64).read_to_end(&mut input).map_err(|e|e.to_string())?;
    if input.len()>MAX_FRAME {return Err("input frame bound".into());}
    emit(&mut output,&evaluate(&input)?)
}
fn main(){if let Err(e)=run(){eprintln!("HIA_KERNEL_NDU_REJECT: {e}");std::process::exit(2);}}
