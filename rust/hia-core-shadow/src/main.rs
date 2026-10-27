//! CLI wrapper: read a bounded HIA JSON program from stdin and print a JSON report.
#![forbid(unsafe_code)]
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut input = Vec::new();
    let read = io::stdin().take(hia_core_shadow::MAX_BYTES as u64 + 1).read_to_end(&mut input);
    if let Err(e) = read {
        eprintln!("E_HIA_FORMAT: cannot read input: {e}");
        return ExitCode::FAILURE;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [] => hia_core_shadow::verify(&input),
        [flag] if flag == "--owned-shadow" => hia_core_shadow::verify_owned(&input),
        [mode, function, arguments] | [mode, function, arguments, _]
            if mode == "--scalar-run" => {
            // One optional explicit step budget. Unknown/reordered flags reject.
            let max_steps = if args.len() == 4 {
                match args[3].parse::<u64>() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("E_HIA_BUDGET_POLICY: invalid numeric step limit");
                        return ExitCode::FAILURE;
                    }
                }
            } else { 100_000 };
            match serde_json::from_str::<Vec<serde_json::Value>>(arguments) {
                Ok(values) => hia_core_shadow::execute_scalar(
                    &input, function, &values, max_steps),
                Err(_) => {
                    eprintln!("E_HIA_INPUT: expected a JSON array of typed scalar arguments");
                    return ExitCode::FAILURE;
                }
            }
        },
        _ => {
            eprintln!("E_HIA_RUST_UNSUPPORTED: expected no args, --owned-shadow or --scalar-run FUNCTION JSON_ARGS [MAX_STEPS]");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
