//! A separate, advisory raw-model profile. No Python continuation is accepted.
#![forbid(unsafe_code)]
mod model;
mod ndu;
mod planner;

use codex_hepta_types::Digest32;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};
use std::time::Instant;

const UPSTREAM: &str = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d";
const MAX_BYTES: u64 = 1_048_576;
const MAX_REQUESTS: u64 = 256;

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    ExactDp,
    Ndu,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    mode: Mode,
    model: model::Model,
}

pub fn digest(value: &impl Serialize) -> Result<String, String> {
    // serde_json::Value uses sorted map keys; all schema strings are ASCII.
    let value = serde_json::to_value(value).map_err(|e| e.to_string())?;
    Ok(Digest32::of_bytes(&serde_json::to_vec(&value).map_err(|e| e.to_string())?).to_string())
}

fn evaluate(input: &[u8]) -> Result<Value, String> {
    let started = Instant::now();
    let request: Request = serde_json::from_slice(input).map_err(|e| e.to_string())?;
    if request.schema != "hepta.hia.ndu.raw-model.request.v1" {
        return Err("unsupported raw-model schema".into());
    }
    request.model.validate()?;
    let model_digest = digest(&request.model)?;
    let search_start = Instant::now();
    let mut planner = planner::Planner::new(&request.model)?;
    let frontier = planner.frontier()?;
    let search_ns = search_start.elapsed().as_nanos();
    let bundle_start = Instant::now();
    let bundle = ndu::bundle(&request.model, frontier)?;
    let construction_ns = bundle_start.elapsed().as_nanos();
    let eval_start = Instant::now();
    let invoked = request.mode == Mode::Ndu;
    let (winners, original) = if invoked {
        ndu::original_ndu(&bundle)?
    } else {
        (ndu::exact_winners(&bundle)?, Value::Null)
    };
    let evaluation_ns = eval_start.elapsed().as_nanos();
    let action = ndu::first_action(&bundle, &winners)?;
    Ok(
        json!({"schema":"hepta.hia.ndu.raw-model.response.v1","mode":request.mode,
        "request_sha256":Digest32::of_bytes(input).to_string(),"model_sha256":model_digest,
        "generation":request.model.generation,"upstream_commit":UPSTREAM,
        "search":{"states":planner.states,"actions":planner.actions},
        "bundle":bundle,"pareto_candidate_ids":winners,"selected_first_action":action,
        "native_evaluation":invoked,"ndu_evaluation":original,
        "measured":{"search_ns":search_ns,"request_construction_ns":construction_ns,"evaluation_ns":evaluation_ns,
            "service_before_output_ns":started.elapsed().as_nanos()},
        "planning_scope":"complete first-action frontier within full-cost-v2; current native call committed",
        "python_search_performed":false,"global_program_optimality":false,
        "authority":"DENY_ALL","safety_certificate":false,"production_activation_allowed":false}),
    )
}

fn stream(reader: &mut impl BufRead, writer: &mut impl Write) -> Result<(), String> {
    let hello = json!({"schema":"hepta.hia.ndu.raw-model.stream.v1",
        "upstream_commit":UPSTREAM,"max_requests":MAX_REQUESTS,
        "modes":["exact_dp","ndu"],"authority":"DENY_ALL","safety_certificate":false});
    writeln!(writer, "{hello}").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    let mut sequence = 0;
    loop {
        let mut bytes = Vec::new();
        // Bound allocation while reading, before accepting the complete line.
        let count = (&mut *reader).take(MAX_BYTES + 2).read_until(b'\n', &mut bytes)
            .map_err(|e| e.to_string())?;
        if count == 0 { return Ok(()); }
        if bytes.last() != Some(&b'\n') || count as u64 > MAX_BYTES + 1 {
            return Err("stream requires a complete bounded newline frame".into());
        }
        bytes.pop();
        if sequence >= MAX_REQUESTS {
            return Err("stream request budget exhausted".into());
        }
        let response = evaluate(&bytes)?;
        sequence += 1;
        let envelope = json!({"schema":"hepta.hia.ndu.raw-model.stream-response.v1",
            "sequence":sequence,"response":response,
            "authority":"DENY_ALL","safety_certificate":false});
        writeln!(writer, "{envelope}").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
    }
}

fn main() {
    if std::env::args().skip(1).collect::<Vec<_>>() == ["--stream"] {
        let result = stream(&mut std::io::stdin().lock(), &mut std::io::stdout().lock());
        if let Err(error) = result {
            eprintln!("{}", json!({"schema":"hepta.hia.ndu.raw-model.error.v1",
                "error":error,"authority":"DENY_ALL"}));
            std::process::exit(2);
        }
        return;
    }
    let result = (|| {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args == ["--identity"] {
            return Ok(
                json!({"schema":"hepta.hia.ndu.raw-model.identity.v1","upstream_commit":UPSTREAM,
            "modes":["exact_dp","ndu"],"authority":"DENY_ALL","safety_certificate":false}),
            );
        }
        if !args.is_empty() {
            return Err("only --identity or one bounded request is supported".into());
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("raw request exceeds 1 MiB".into());
        }
        evaluate(&bytes)
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!(
                "{}",
                json!({"schema":"hepta.hia.ndu.raw-model.error.v1","error":error,"authority":"DENY_ALL"})
            );
            std::process::exit(2);
        }
    }
}
