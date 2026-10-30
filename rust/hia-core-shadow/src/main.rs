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
        [flag] if flag == "--owned-static-budget" => hia_core_shadow::analyze_static_budget(&input),
        [mode, function, arguments, heap_policy] if mode == "--owned-finite-heap" => {
            match hia_core_shadow::decode_scalar_arguments(arguments) {
                Ok(values) => hia_core_shadow::analyze_finite_entry_heap(
                    &input, function, &values, heap_policy.as_bytes()),
                Err(error) => { eprintln!("{error}"); return ExitCode::FAILURE; }
            }
        },
        [mode, function, arguments, static_policy, heap_policy, cleanup_policy, execution_policy]
            if mode == "--byte-dag-heap-cleanup-admit-run" => {
            match hia_core_shadow::decode_scalar_arguments(arguments) {
                Ok(values) => hia_core_shadow::admit_and_run_byte_dag_heap_cleanup(&input, function, &values,
                    static_policy.as_bytes(),heap_policy.as_bytes(),cleanup_policy.as_bytes(),execution_policy.as_bytes()),
                Err(error) => { eprintln!("{error}"); return ExitCode::FAILURE; }
            }
        },
        [mode, function, arguments, static_policy, heap_policy, execution_policy]
            if mode == "--byte-dag-heap-admit-run" => {
            match hia_core_shadow::decode_scalar_arguments(arguments) {
                Ok(values) => hia_core_shadow::admit_and_run_byte_dag_heap(&input, function, &values,
                    static_policy.as_bytes(), heap_policy.as_bytes(), execution_policy.as_bytes()),
                Err(error) => { eprintln!("{error}"); return ExitCode::FAILURE; }
            }
        },
        [mode, function, arguments, static_policy, execution_policy]
            if mode == "--byte-dag-admit-run" => {
            match hia_core_shadow::decode_scalar_arguments(arguments) {
                Ok(values) => hia_core_shadow::admit_and_run_byte_dag(
                    &input, function, &values, static_policy.as_bytes(), execution_policy.as_bytes()),
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            }
        },
        [mode, function, arguments, policy]
            if matches!(mode.as_str(), "--owned-run-bound-v2" | "--owned-run-bound-v3" | "--owned-run-bound-v4") => {
            match hia_core_shadow::decode_scalar_arguments(arguments) {
                Ok(values) => {
                    let execute = if mode == "--owned-run-bound-v4" {
                        hia_core_shadow::execute_owned_bound_v4
                    } else if mode == "--owned-run-bound-v3" {
                        hia_core_shadow::execute_owned_bound_v3
                    } else { hia_core_shadow::execute_owned_bound_v2 };
                    execute(&input, function, &values, policy.as_bytes())
                },
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            }
        },
        [mode, function, arguments] | [mode, function, arguments, _, _, _]
            if mode == "--owned-run" || mode == "--owned-run-bound" => {
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
                Ok(values) => {
                    let execute = if mode == "--owned-run-bound" {
                        hia_core_shadow::execute_owned_bound
                    } else { hia_core_shadow::execute_owned };
                    execute(&input, function, &values, policy.0, policy.1, policy.2)
                },
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
            eprintln!("E_HIA_RUST_UNSUPPORTED: expected no args, --owned-shadow, --owned-static-budget, --owned-finite-heap FUNCTION JSON_ARGS JSON_HEAP_POLICY, --byte-dag-admit-run FUNCTION JSON_ARGS JSON_STATIC_POLICY JSON_V4_POLICY, --byte-dag-heap-admit-run FUNCTION JSON_ARGS JSON_STATIC_POLICY JSON_HEAP_POLICY JSON_V4_POLICY, --scalar-run FUNCTION JSON_ARGS [MAX_STEPS], --owned-run/--owned-run-bound FUNCTION JSON_ARGS [MAX_STEPS MAX_HEAP_BYTES FAIL_AT|none], or --owned-run-bound-v2/v3/v4 FUNCTION JSON_ARGS JSON_POLICY");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(report) => {
            println!("{report}");
            if report["schema"] == "hepta.hia.rust-byte-dag-heap-cleanup-run.v1"
                && report["status"] == "cleanup_failed" {
                eprintln!("E_HIA_CLEANUP_INTERNAL: cleanup failed; original stop and cleanup prefix retained in stdout");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
