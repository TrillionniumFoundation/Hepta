//! Explicit raw-Core admission for one finite Rust interpreter profile.
//!
//! This route does not invoke Python, lower nominal/source programs, or grant
//! native use. A private snapshot binds whole-module static admission to the
//! exact canonical bytes consumed by the existing v4 Machine.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{analyze_static_budget, array, decode_hia, execute_owned_bound_v4,
            failure, object, R};

const PROFILE: &str = "raw-byte-dag-v1";
const MAX_STATIC_POLICY_BYTES: usize = 1024;
const METRICS: [&str; 3] = ["max_allocator_interactions", "max_vm_ticks", "max_call_depth"];

// No public constructor, deserializer, or report-to-admission conversion.
// The only constructor independently checks the complete raw module and all
// functions' limits. Execution takes this owned immutable snapshot, never a
// caller-provided certificate or a second source argument.
struct AdmittedByteDag {
    canonical_core: Vec<u8>,
    input_sha256: String,
    static_policy: Value,
    static_budget: Value,
}

impl AdmittedByteDag {
    fn admit(input: &[u8], static_policy_input: &[u8]) -> R<Self> {
        if static_policy_input.len() > MAX_STATIC_POLICY_BYTES {
            return failure("E_HIA_BUDGET_POLICY", "byte-DAG static policy exceeds 1024 bytes");
        }
        let (static_policy, _) = decode_hia(static_policy_input)?;
        let limits = object(&static_policy, &METRICS, "byte-DAG static policy")?;
        for metric in METRICS {
            if limits[metric].as_u64().is_none() {
                return failure("E_HIA_BUDGET_POLICY", "static limits require exact unsigned u64 integers");
            }
        }
        // Parsing the original bytes rejects duplicate fields, trailing JSON,
        // floats, oversized integers and excessive structure before a snapshot
        // is retained. analyze_static_budget then invokes verify_owned itself.
        let (_, canonical_core) = decode_hia(input)?;
        let static_budget = analyze_static_budget(&canonical_core)?;
        for row in array(&static_budget["functions"], "static function bounds")? {
            for metric in METRICS {
                let bound = row[metric].as_u64().ok_or_else(|| super::VerifyError {
                    code: "E_HIA_BUDGET_GRAPH", detail: "missing independent static bound".into(),
                })?;
                if bound > limits[metric].as_u64().unwrap() {
                    return failure("E_HIA_BUDGET_EXCEEDED", format!(
                        "function {} exceeds {metric}", row["function"]));
                }
            }
        }
        Ok(Self { canonical_core, input_sha256: format!("{:x}", Sha256::digest(input)),
                  static_policy, static_budget })
    }

    fn run(self, function: &str, arguments: &[Value], execution_policy_input: &[u8]) -> R<Value> {
        // Preserve the complete v4 policy/parser/external scalar boundary and
        // runtime semantics, including early stops and retained resource ledgers.
        // Reverification here is deliberate: no unchecked Machine API is added.
        let runtime = execute_owned_bound_v4(
            &self.canonical_core, function, arguments, execution_policy_input)?;
        let request = json!({
            "schema": "hepta.hia.rust-byte-dag-request.v1", "profile": PROFILE,
            "input_sha256": self.input_sha256,
            "program_sha256": self.static_budget["program_sha256"],
            "function": function, "arguments": arguments,
            "static_policy": self.static_policy,
            "execution_policy": runtime["request"]["policy"],
        });
        let canonical_request = serde_json::to_vec(&request).map_err(|error| super::VerifyError {
            code: "E_HIA_INPUT", detail: error.to_string(),
        })?;
        Ok(json!({
            "schema": "hepta.hia.rust-byte-dag-run.v1", "profile": PROFILE,
            "status": "admitted_and_observed",
            "request_sha256": format!("{:x}", Sha256::digest(canonical_request)),
            "request": request, "static_budget": self.static_budget, "runtime": runtime,
            "claims": {
                "raw_primitive_core_admitted_by_rust": true,
                "all_functions_checked_before_execution": true,
                "static_limits_checked_before_execution": true,
                "single_immutable_core_snapshot_used": true,
                "python_verifier_required_for_this_mode": false,
                "rust_interpreter_admission_authority_for_this_profile": true,
                "default_production_admission_changed": false,
                "nominal_or_source_lowering_supported": false,
                "native_execution_authorized": false,
                "whole_language_soundness_proved": false,
                "native_backend_refinement_proved": false,
                "process_rss_or_native_time_bounded": false,
                "successful_return_or_cleanup_guaranteed": false,
            }
        }))
    }
}

/// Independently admit raw primitive byte-DAG Core and observe one invocation.
///
/// Static limits apply to EVERY function, including uncalled private helpers.
/// The runtime policy is the exact existing v4 policy. A smaller runtime budget
/// may intentionally stop execution; static admission is not a success promise.
/// Only this opt-in Rust interpreter route is authorized, never default/native
/// or nominal/source compilation. No imported receipt can construct admission.
pub fn admit_and_run_byte_dag(input: &[u8], function: &str, arguments: &[Value],
                             static_policy_input: &[u8], execution_policy_input: &[u8]) -> R<Value> {
    AdmittedByteDag::admit(input, static_policy_input)?.run(
        function, arguments, execution_policy_input)
}
