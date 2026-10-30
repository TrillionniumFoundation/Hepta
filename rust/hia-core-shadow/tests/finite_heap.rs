//! The optional independent heap gate composes with, rather than replaces, v4.
use hia_core_shadow::{admit_and_run_byte_dag, admit_and_run_byte_dag_heap,
    analyze_finite_entry_heap, analyze_static_budget, execute_owned_bound_v4};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};

fn wire(value:&Value)->Vec<u8> {serde_json::to_vec(value).unwrap()}
fn param(name:&str,ty:&str)->Value {json!({"name":name,"type":ty})}
fn owned()->Value {
    json!({"schema":"hepta.hia.program.v8","module":"finite_heap","exports":["allocate"],"functions":[{
        "name":"allocate","params":[param("n","usize")],"returns":["bool"],
        "effects":["alloc"],"entry":"entry","blocks":[{
            "id":"entry","params":[param("n","usize")],"ops":[
                {"op":"buffer.try_new","args":["n"],"out":[param("owner","buffer"),param("ok","bool")],"attrs":{}},
                {"op":"owner.drop","args":["owner"],"out":[],"attrs":{}}],
            "term":{"op":"ret","values":["ok"]}}]}]})
}
fn static_policy()->Value {json!({"max_vm_ticks":4,"max_allocator_interactions":2,"max_call_depth":1})}
fn runtime()->Value {json!({"max_steps":4,"max_heap_bytes":8,"max_call_depth":1,"allocation_fail_at":null})}

#[test]
fn analysis_only_proves_unexecuted_extent_and_refuses_smaller_policy_before_vm() {
    let source=wire(&owned());let size=1_u64<<40;let args=[json!(size)];
    let policy=wire(&json!({"max_live_heap_bytes":size}));
    let report=analyze_finite_entry_heap(&source,"allocate",&args,&policy).unwrap();
    assert_eq!(report["peak_bound_bytes"],size);
    assert!(report.get("runtime").is_none());
    assert_eq!(report["claims"]["execution_used_to_establish_bound"],false);
    let mut execution=runtime();execution["max_steps"]=json!(1);execution["max_heap_bytes"]=json!(0);
    let observed=admit_and_run_byte_dag_heap(&source,"allocate",&args,&wire(&static_policy()),&policy,&wire(&execution)).unwrap();
    assert_eq!(observed["runtime"]["execution"]["error"]["code"],"steps");
    assert_eq!(observed["runtime"]["execution"]["resources"]["peak_bytes"],0);
    let error=admit_and_run_byte_dag_heap(&source,"allocate",&args,&wire(&static_policy()),
        &wire(&json!({"max_live_heap_bytes":size-1})),&wire(&execution)).unwrap_err();
    assert_eq!(error.code,"E_HIA_BUDGET_EXCEEDED");
}

#[test]
fn optional_static_heap_preserves_full_v4_ledger_and_legacy_static_contract() {
    let source=wire(&owned());let bound=wire(&json!({"max_live_heap_bytes":3}));
    for fail in [Value::Null,json!("0x1"),json!("0x10000000000000001")] {
        for steps in 1..=4 {
            let mut selected=runtime();selected["allocation_fail_at"]=fail.clone();selected["max_steps"]=json!(steps);
            let result=admit_and_run_byte_dag_heap(&source,"allocate",&[json!(3)],&wire(&static_policy()),&bound,&wire(&selected)).unwrap();
            let ordinary=admit_and_run_byte_dag(&source,"allocate",&[json!(3)],&wire(&static_policy()),&wire(&selected)).unwrap();
            assert_eq!(result["runtime"],execute_owned_bound_v4(&source,"allocate",&[json!(3)],&wire(&selected)).unwrap());
            assert_eq!(result["runtime"],ordinary["runtime"]);
            assert_eq!(result["static_budget"],ordinary["static_budget"]);
            assert!(ordinary.get("heap_bound").is_none());
            assert_eq!(ordinary["profile"],"raw-byte-dag-v1");
            assert_eq!(result["heap_bound"]["peak_bound_bytes"],3);
            assert_eq!(result["heap_bound"]["claims"]["allocation_failure_index_specialized"],false);
            assert_eq!(result["claims"]["successful_return_or_cleanup_guaranteed"],false);
        }
    }
    let original=analyze_static_budget(&source).unwrap();
    assert_eq!(original["claims"]["live_heap_or_process_rss_bounded"],false);
}

#[test]
fn whole_snapshot_exact_arguments_and_all_three_policies_are_bound_to_request() {
    let source=owned();let raw=serde_json::to_vec_pretty(&source).unwrap();
    let mut policy=json!({"max_live_heap_bytes":3});
    let first=admit_and_run_byte_dag_heap(&raw,"allocate",&[json!(3)],&wire(&static_policy()),&wire(&policy),&wire(&runtime())).unwrap();
    assert_eq!(first["request"]["input_sha256"],format!("{:x}",Sha256::digest(&raw)));
    assert_eq!(first["request_sha256"],format!("{:x}",Sha256::digest(wire(&first["request"]))));
    assert_eq!(first["heap_bound"]["static_budget_sha256"],format!("{:x}",Sha256::digest(wire(&first["static_budget"]))));
    policy["max_live_heap_bytes"]=json!(4);
    let second=admit_and_run_byte_dag_heap(&raw,"allocate",&[json!(3)],&wire(&static_policy()),&wire(&policy),&wire(&runtime())).unwrap();
    assert_ne!(first["request_sha256"],second["request_sha256"]);
    assert_eq!(first["runtime"],second["runtime"]);
    let third=admit_and_run_byte_dag_heap(&raw,"allocate",&[json!(2)],&wire(&static_policy()),&wire(&policy),&wire(&runtime())).unwrap();
    assert_eq!(third["heap_bound"]["peak_bound_bytes"],2);
    assert_ne!(second["request_sha256"],third["request_sha256"]);
}

#[test]
fn invalid_limits_or_inexact_arguments_cannot_mint_a_heap_report() {
    let source=wire(&owned());
    for value in [json!(-1),json!(true),json!(1.0),json!(null),json!("3"),json!(1_u64<<63)] {
        assert!(analyze_finite_entry_heap(&source,"allocate",&[json!(3)],&wire(&json!({"max_live_heap_bytes":value}))).is_err());
    }
    let policy=wire(&json!({"max_live_heap_bytes":3}));
    for arg in [json!(-1),json!(true),json!(3.0),json!({"extent":3})] {
        assert_eq!(analyze_finite_entry_heap(&source,"allocate",&[arg],&policy).unwrap_err().code,"E_HIA_INPUT");
    }
    let duplicate=b"{\"max_live_heap_bytes\":3,\"max_live_heap_bytes\":3}";
    assert!(analyze_finite_entry_heap(&source,"allocate",&[json!(3)],duplicate).is_err());
    assert!(analyze_finite_entry_heap(&source,"allocate",&[json!(3)],&vec![b' ';1025]).is_err());
}
