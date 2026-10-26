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
    match hia_core_shadow::verify(&input) {
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
