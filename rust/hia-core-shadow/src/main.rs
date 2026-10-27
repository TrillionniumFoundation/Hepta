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
        [mode, function, arguments] | [mode, function, arguments, _, _, _]
            if mode == "--owned-run" => {
            let policy = if args.len() == 6 {
                let steps = args[3].parse::<u64>();
                let heap = args[4].parse::<u64>();
                let failure = if args[5] == "none" { Ok(None) }
                              else { args[5].parse::<u64>().map(Some) };
                match (steps, heap, failure) {
                    (Ok(steps), Ok(heap), Ok(failure)) => (steps, heap, failure),
                    _ => {
                        eprintln!("E_HIA_BUDGET_POLICY: expected owned MAX_STEPS MAX_HEAP_BYTES FAIL_AT|none");
                        return ExitCode::FAILURE;
                    }
                }
            } else { (100_000, 1024 * 1024, None) };
            match hia_core_shadow::decode_scalar_arguments(arguments) {
                Ok(values) => hia_core_shadow::execute_owned(
                    &input, function, &values, policy.0, policy.1, policy.2),
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            }
        },
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
            match hia_core_shadow::decode_scalar_arguments(arguments) {
                Ok(values) => hia_core_shadow::execute_scalar(
                    &input, function, &values, max_steps),
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            }
        },
        _ => {
            eprintln!("E_HIA_RUST_UNSUPPORTED: expected no args, --owned-shadow, --scalar-run FUNCTION JSON_ARGS [MAX_STEPS], or --owned-run FUNCTION JSON_ARGS [MAX_STEPS MAX_HEAP_BYTES FAIL_AT|none]");
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
