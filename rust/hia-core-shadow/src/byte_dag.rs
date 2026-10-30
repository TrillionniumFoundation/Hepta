//! Explicit raw-Core admission for one finite Rust interpreter profile.
//!
//! This route does not invoke Python, lower nominal/source programs, or grant
//! native use. A private snapshot binds whole-module static admission to the
//! exact canonical bytes consumed by the existing v4 Machine.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{analyze_finite_entry_heap, analyze_static_budget, array, decode_hia, execute_owned_bound_v4,
            failure, object, R};

const PROFILE: &str = "raw-byte-dag-v1";
const HEAP_PROFILE: &str = "raw-byte-dag-finite-heap-v1";
const CLEANUP_PROFILE: &str = "raw-byte-dag-finite-heap-cleanup-v1";
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
    heap_bound: Option<Value>,
    cleanup_bound: Option<Value>,
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
                  static_policy, static_budget, heap_bound: None, cleanup_bound: None })
    }

    fn admit_heap(mut self, function: &str, arguments: &[Value], policy: &[u8]) -> R<Self> {
        // No observation supplies this bound. The independent abstract pass
        // rechecks the same immutable whole Core and every finite graph.
        self.heap_bound = Some(analyze_finite_entry_heap(
            &self.canonical_core, function, arguments, policy)?);
        Ok(self)
    }

    fn admit_cleanup(mut self, policy: &[u8]) -> R<Self> {
        if policy.len() > MAX_STATIC_POLICY_BYTES {
            return failure("E_HIA_CLEANUP_POLICY", "cleanup policy exceeds 1024 bytes");
        }
        let (policy, _) = decode_hia(policy)?;
        let fields = object(&policy, &["max_cleanup_actions"], "cleanup policy")?;
        let limit = fields["max_cleanup_actions"].as_u64().ok_or_else(||super::VerifyError {
            code:"E_HIA_CLEANUP_POLICY",detail:"cleanup actions require an exact unsigned integer".into(),
        })?;
        if limit > super::scalar_vm::MAX_ABORT_CLEANUP_ACTIONS {
            return failure("E_HIA_CLEANUP_POLICY", "cleanup action limit exceeds finite profile");
        }
        let Some(heap) = self.heap_bound.as_ref() else {
            return failure("E_HIA_CLEANUP_PROFILE", "cleanup requires independent finite entry heap admission");
        };
        let (core, _) = decode_hia(&self.canonical_core)?;
        let max_formals = array(&core["functions"],"cleanup functions")?.iter()
            .map(|f|f["params"].as_array().unwrap().iter()
                .filter(|p|matches!(p["type"].as_str(),Some("readbuf"|"mutbuf"))).count() as u64)
            .max().unwrap_or(0);
        let ticks = heap["max_vm_ticks"].as_u64().unwrap();
        let allocator = heap["max_allocator_interactions"].as_u64().unwrap();
        // Every new/try_new produces at most one owner, including empty failed
        // owners. Every source borrow consumes a tick. Every call-entry tick
        // creates at most max_formals extra witnesses. Returned loans rebind
        // existing witnesses; they do not allocate a new runtime identity.
        let bound = max_formals.checked_add(1).and_then(|n|n.checked_mul(ticks))
            .and_then(|n|n.checked_add(allocator)).ok_or_else(||super::VerifyError {
                code:"E_HIA_CLEANUP_BOUND",detail:"static cleanup action bound overflows u64".into(),
            })?;
        if bound > limit {
            return failure("E_HIA_CLEANUP_EXCEEDED", "cleanup reservation does not cover every admitted execution prefix");
        }
        self.cleanup_bound = Some(json!({
            "schema":"hepta.hia.scoped-abort-cleanup-bound.v1",
            "program_sha256":self.static_budget["program_sha256"],
            "function":heap["function"], "arguments":heap["arguments"],
            "max_allocator_interactions":allocator, "max_vm_ticks":ticks,
            "max_borrowed_parameters":max_formals,
            "action_bound":bound, "limit_actions":limit,
            "fixed_action_limit":super::scalar_vm::MAX_ABORT_CLEANUP_ACTIONS,
            "claims":{
                "independent_static_reservation_before_execution":true,
                "every_allocator_outcome_including_empty_owner_counted":true,
                "call_formal_witnesses_counted_separately":true,
                "runtime_observation_used_to_establish_bound":false,
                "process_rss_or_cpu_bound_proved":false,
            }
        }));
        Ok(self)
    }

    fn run(self, function: &str, arguments: &[Value], execution_policy_input: &[u8]) -> R<Value> {
        if let Some(heap) = &self.heap_bound {
            if heap["function"] != function || heap["arguments"] != json!(arguments) {
                return failure("E_HIA_INPUT", "finite heap admission belongs to a different invocation");
            }
        }
        // Preserve the complete v4 policy/parser/external scalar boundary and
        // runtime semantics, including early stops and retained resource ledgers.
        // Reverification here is deliberate: no unchecked Machine API is added.
        let (runtime, cleanup) = if let Some(bound) = &self.cleanup_bound {
            let (runtime,cleanup) = super::scalar_vm::execute_owned_bound_v4_scoped(
                &self.canonical_core,function,arguments,execution_policy_input,
                bound["action_bound"].as_u64().unwrap())?;
            (runtime,Some(cleanup))
        } else {
            (execute_owned_bound_v4(&self.canonical_core, function, arguments,
                execution_policy_input)?,None)
        };
        let bounded_heap = self.heap_bound.is_some();
        let scoped_cleanup = self.cleanup_bound.is_some();
        let profile = if scoped_cleanup { CLEANUP_PROFILE } else if bounded_heap { HEAP_PROFILE } else { PROFILE };
        let mut request = json!({
            "schema": if scoped_cleanup { "hepta.hia.rust-byte-dag-heap-cleanup-request.v1" }
                      else if bounded_heap { "hepta.hia.rust-byte-dag-heap-request.v1" }
                      else { "hepta.hia.rust-byte-dag-request.v1" }, "profile": profile,
            "input_sha256": self.input_sha256,
            "program_sha256": self.static_budget["program_sha256"],
            "function": function, "arguments": arguments,
            "static_policy": self.static_policy,
            "execution_policy": runtime["request"]["policy"],
        });
        if let Some(heap) = &self.heap_bound {
            request["heap_policy"] = json!({"max_live_heap_bytes": heap["limit_bytes"]});
            if runtime["execution"]["resources"]["peak_bytes"].as_u64()
                .zip(heap["peak_bound_bytes"].as_u64()).is_none_or(|(actual,bound)| actual > bound) {
                return failure("E_HIA_BUDGET_GRAPH", "Machine prefix escaped finite heap admission");
            }
        }
        if let Some(bound) = &self.cleanup_bound {
            request["cleanup_policy"] = json!({"max_cleanup_actions":bound["limit_actions"]});
        }
        let canonical_request = serde_json::to_vec(&request).map_err(|error| super::VerifyError {
            code: "E_HIA_INPUT", detail: error.to_string(),
        })?;
        let mut report = json!({
            "schema": if scoped_cleanup { "hepta.hia.rust-byte-dag-heap-cleanup-run.v1" }
                      else if bounded_heap { "hepta.hia.rust-byte-dag-heap-run.v1" }
                      else { "hepta.hia.rust-byte-dag-run.v1" }, "profile": profile,
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
        });
        if let Some(heap) = self.heap_bound {
            report["heap_bound"] = heap;
            report["claims"]["finite_entry_live_payload_limit_checked_before_execution"] = json!(true);
        }
        if let (Some(bound),Some(cleanup)) = (self.cleanup_bound,cleanup) {
            let completed = cleanup["status"] == "completed" || cleanup["status"] == "not_needed";
            if !completed { report["status"] = json!("cleanup_failed"); }
            report["cleanup_bound"] = bound;
            report["cleanup"] = cleanup;
            report["claims"]["scoped_cleanup_reservation_checked_before_execution"] = json!(true);
            report["claims"]["scoped_cleanup_completed"] = json!(completed);
        }
        Ok(report)
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

/// Same snapshot/authority/Machine, with a separately versioned static heap gate.
/// Only the exact scalar invocation is heap-bounded; v1 remains unchanged.
pub fn admit_and_run_byte_dag_heap(input: &[u8], function: &str, arguments: &[Value],
    static_policy_input: &[u8], heap_policy_input: &[u8], execution_policy_input: &[u8]) -> R<Value> {
    AdmittedByteDag::admit(input, static_policy_input)?
        .admit_heap(function, arguments, heap_policy_input)?
        .run(function, arguments, execution_policy_input)
}

/// Explicit whole-invocation byte-owner cleanup on language trap/budget stop.
/// Original prefix observations and legacy profile semantics remain unchanged.
/// A cleanup-internal failure retains both ledgers/journal with cleanup_failed;
/// callers MUST check status, and the CLI returns nonzero for that report.
pub fn admit_and_run_byte_dag_heap_cleanup(input: &[u8], function: &str, arguments: &[Value],
    static_policy_input: &[u8], heap_policy_input: &[u8], cleanup_policy_input: &[u8],
    execution_policy_input: &[u8]) -> R<Value> {
    AdmittedByteDag::admit(input, static_policy_input)?
        .admit_heap(function, arguments, heap_policy_input)?
        .admit_cleanup(cleanup_policy_input)?
        .run(function, arguments, execution_policy_input)
}
