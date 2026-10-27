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
        [mode, function, arguments] if mode == "--scalar-run" => {
            match serde_json::from_str::<Vec<serde_json::Value>>(arguments) {
                Ok(args) => hia_core_shadow::execute_scalar(&input, function, &args, 100_000),
                Err(_) => {
                    eprintln!("E_HIA_INPUT: expected a JSON array of typed scalar arguments");
                    return ExitCode::FAILURE;
                }
            }
        },
        _ => {
            eprintln!("E_HIA_RUST_UNSUPPORTED: expected no args or --owned-shadow");
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
