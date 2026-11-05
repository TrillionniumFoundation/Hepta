//! Separate finite native experiment; NDU proposals never execute work.
#![forbid(unsafe_code)]
mod model;
mod ndu;
mod planner;
mod workload;

use codex_hepta_types::Digest32;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::time::Instant;

const UPSTREAM: &str = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d";
const MAX_FRAME: usize = 1_048_576;
const MAX_REQUESTS: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { schema: String, mode: String, model: model::Model }

pub fn digest(value: &impl Serialize) -> Result<String,String> {
    let value = serde_json::to_value(value).map_err(|e|e.to_string())?;
    Ok(Digest32::of_bytes(&serde_json::to_vec(&value).map_err(|e|e.to_string())?).to_string())
}

fn evaluate(input:&[u8]) -> Result<Value,String> {
    let started=Instant::now();
    let request:Request=serde_json::from_slice(input).map_err(|e|e.to_string())?;
    if request.schema!="hepta.hia.ndu.dynamic-cache.request.v1"
        || !matches!(request.mode.as_str(),"exact_dp"|"light"|"beam"|"beam_ndu") {
        return Err("dynamic request schema or mode".into());
    }
    request.model.validate()?;
    let search=Instant::now();
    let mut planner=planner::Planner::new(&request.model)?;
    let frontier=match request.mode.as_str() {
        "exact_dp"=>planner.exact()?, "light"=>planner.light()?, _=>planner.beam(4)?,
    };
    let search_ns=search.elapsed().as_nanos();
    let construction=Instant::now();
    let bundle=ndu::bundle(&request.model,frontier,request.mode=="exact_dp")?;
    let construction_ns=construction.elapsed().as_nanos();
    let evaluation=Instant::now();
    let (winners,native)=if request.mode=="beam_ndu" {
        let (w,n)=ndu::original_ndu(&bundle)?; (w,Some(n))
    } else { (ndu::exact_winners(&bundle)?,None) };
    let evaluation_ns=evaluation.elapsed().as_nanos();
    let selected=ndu::first_action(&bundle,&winners)?;
    Ok(json!({"schema":"hepta.hia.ndu.dynamic-cache.response.v1","mode":request.mode,
        "request_sha256":Digest32::of_bytes(input).to_string(),"model_sha256":digest(&request.model)?,
        "generation":request.model.generation,"upstream_commit":UPSTREAM,"bundle":bundle,
        "pareto_candidate_ids":winners,"selected_first_action":selected,"ndu_evaluation":native,
        "search":planner.stats,"search_ns":search_ns,"construction_ns":construction_ns,
        "evaluation_ns":evaluation_ns,"service_before_output_ns":started.elapsed().as_nanos(),
        "authority":"DENY_ALL","safety_certificate":false,"execution_authorized":false,
        "global_program_optimality":false,"hia_compiler_qualification":false}))
}

fn emit(output:&mut impl Write,value:&Value)->Result<(),String>{
    let bytes=serde_json::to_vec(value).map_err(|e|e.to_string())?;
    if bytes.len()>MAX_FRAME {return Err("output frame bound".into());}
    output.write_all(&bytes).and_then(|_|output.write_all(b"\n")).and_then(|_|output.flush()).map_err(|e|e.to_string())
}

fn run()->Result<(),String>{
    let args:Vec<_>=std::env::args().collect();
    let role=args.get(1).map(String::as_str).unwrap_or("");
    if args.len()!=2 || !matches!(role,"--identity"|"--planner-stream"|"--workload-stream") {
        return Err("explicit planner or workload role required".into());
    }
    let mut output=std::io::stdout().lock();
    if role=="--identity" {
        return emit(&mut output,&json!({"profile":"hepta.hia.ndu.dynamic-cache.v1","upstream_commit":UPSTREAM,
            "modes":["exact_dp","light","beam","beam_ndu"],"beam_width":4,
            "maximum_artifacts":model::MAX_ARTIFACTS,"maximum_horizon":model::MAX_HORIZON,
            "unsafe_code":"forbidden","hia_compiler_qualification":false}));
    }
    emit(&mut output,&json!({"schema":"hepta.hia.ndu.dynamic-cache.hello.v1","role":role,
        "upstream_commit":UPSTREAM,"max_frame_bytes":MAX_FRAME,"max_requests":MAX_REQUESTS,
        "authority":"DENY_ALL","safety_certificate":false}))?;
    let mut input=std::io::stdin().lock();
    let mut state=workload::Workload::default();
    for _ in 0..MAX_REQUESTS {
        let mut bytes=Vec::new();
        let length=std::io::Read::take(&mut input,(MAX_FRAME+2) as u64).read_until(b'\n',&mut bytes).map_err(|e|e.to_string())?;
        if length==0{return Ok(());}
        if bytes.len()>MAX_FRAME+1 || bytes.last()!=Some(&b'\n'){return Err("input frame bound or missing delimiter".into());}
        bytes.pop();
        let result=if role=="--planner-stream" {evaluate(&bytes)} else {
            serde_json::from_slice(&bytes).map_err(|e|e.to_string()).and_then(|c|state.execute(c))
        };
        // A rejected command leaves the stream available, but does not grant
        // a fallback or silently reinterpret malformed optimizer input.
        let response=match result {Ok(v)=>v,Err(e)=>json!({"schema":"hepta.hia.ndu.dynamic-cache.refusal.v1",
            "reason":e,"authority":"DENY_ALL","safety_certificate":false,"execution_authorized":false})};
        emit(&mut output,&response)?;
    }
    Err("session request bound".into())
}

fn main(){if let Err(error)=run(){eprintln!("{error}");std::process::exit(2);}}
