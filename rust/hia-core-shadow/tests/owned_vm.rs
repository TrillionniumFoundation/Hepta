//! Actual execution of the finite byte-owner extension to the scalar Machine.
use hia_core_shadow::{execute_owned, execute_scalar, verify_owned};
use serde_json::{json, Value};

fn roundtrip() -> Value {
    json!({
        "schema":"hepta.hia.program.v1", "module":"byte_owner_vm",
        "functions":[{
            "name":"probe", "params":[{"name":"n","type":"usize"}],
            "returns":["u8"], "effects":["alloc","read","write","trap"], "entry":"entry",
            "blocks":[{"id":"entry","params":[{"name":"n","type":"usize"}],
                "ops":[
                    {"op":"buffer.new","args":["n"],"out":[{"name":"owner","type":"buffer"}],"attrs":{}},
                    {"op":"borrow.mut","args":["owner"],"out":[{"name":"view","type":"mutbuf"}],"attrs":{}},
                    {"op":"const","args":[],"out":[{"name":"index","type":"usize"}],"attrs":{"value":0}},
                    {"op":"const","args":[],"out":[{"name":"byte","type":"u8"}],"attrs":{"value":42}},
                    {"op":"buffer.store","args":["view","index","byte"],"out":[],"attrs":{}},
                    {"op":"buffer.load","args":["view","index"],"out":[{"name":"readback","type":"u8"}],"attrs":{}},
                    {"op":"loan.end","args":["view"],"out":[],"attrs":{}},
                    {"op":"owner.move","args":["owner"],"out":[{"name":"moved","type":"buffer"}],"attrs":{}},
                    {"op":"owner.drop","args":["moved"],"out":[],"attrs":{}}
                ], "term":{"op":"ret","values":["readback"]}}]
        }]
    })
}

fn run(source: &Value, args: Vec<Value>, steps: u64, heap: u64, fail: Option<u64>) -> Value {
    execute_owned(&serde_json::to_vec(source).unwrap(), "probe", &args, steps, heap, fail).unwrap()
}

#[test]
fn successful_roundtrip_has_exact_resource_ledger_and_no_authority_promotion() {
    let source = roundtrip();
    let raw = serde_json::to_vec(&source).unwrap();
    assert!(verify_owned(&raw).is_ok());
    assert!(execute_scalar(&raw, "probe", &[json!(3)], 100).is_err());
    let report = run(&source, vec![json!(3)], 100, 100, None);
    assert_eq!(report["schema"], "hepta.hia.rust-byte-owner-execution.v1");
    assert_eq!(report["status"], "returned");
    assert_eq!(report["values"], json!([42]));
    assert_eq!(report["steps"], 11);
    assert_eq!(report["resources"], json!({
        "allocations":1, "frees":1, "allocation_attempts":1,
        "owners_created":1, "owners_dropped":1, "live_owners":0,
        "live_bytes":0, "peak_bytes":3,
        "loans_started":1, "loans_ended":1, "live_local_loans":0
    }));
    assert_eq!(report["claims"]["production_admission_authorized"], false);
    assert_eq!(report["claims"]["general_resource_execution"], false);
    assert_eq!(report["claims"]["native_backend_refinement_proved"], false);
}

#[test]
fn heap_budget_is_not_allocation_failure_and_trap_does_not_claim_drop() {
    let heap = run(&roundtrip(), vec![json!(4)], 100, 3, Some(1));
    assert_eq!(heap["status"], "budget_exceeded");
    assert_eq!(heap["error"]["code"], "heap");
    assert_eq!(heap["resources"]["allocation_attempts"], 0);
    let failure = run(&roundtrip(), vec![json!(4)], 100, 4, Some(1));
    assert_eq!(failure["status"], "trapped");
    assert_eq!(failure["error"]["code"], "allocation");
    assert_eq!(failure["resources"]["allocation_attempts"], 1);
    assert_eq!(failure["resources"]["owners_created"], 0);
    let bounds = run(&roundtrip(), vec![json!(0)], 100, 0, Some(1));
    assert_eq!(bounds["status"], "trapped");
    assert_eq!(bounds["error"]["code"], "bounds");
    assert_eq!(bounds["resources"]["allocation_attempts"], 0);
    assert_eq!(bounds["resources"]["live_owners"], 1);
    assert_eq!(bounds["resources"]["live_local_loans"], 1);
    assert_eq!(bounds["resources"]["owners_dropped"], 0);
    let steps = run(&roundtrip(), vec![json!(4)], 3, 4, None);
    assert_eq!(steps["status"], "budget_exceeded");
    assert_eq!(steps["steps"], 4);
    assert_eq!(steps["resources"]["live_bytes"], 4);
    assert_eq!(steps["resources"]["live_local_loans"], 1);
    assert_eq!(steps["resources"]["frees"], 0);
}

#[test]
fn optional_failure_produces_real_empty_owner_and_zero_is_infallible() {
    let mut source = roundtrip();
    let function = &mut source["functions"][0];
    function["returns"] = json!(["usize","bool"]);
    function["effects"] = json!(["alloc"]);
    function["blocks"][0]["ops"] = json!([
        {"op":"buffer.try_new","args":["n"],"out":[{"name":"owner","type":"buffer"},{"name":"ok","type":"bool"}],"attrs":{}},
        {"op":"buffer.len","args":["owner"],"out":[{"name":"length","type":"usize"}],"attrs":{}},
        {"op":"owner.drop","args":["owner"],"out":[],"attrs":{}}
    ]);
    function["blocks"][0]["term"] = json!({"op":"ret","values":["length","ok"]});
    for (size, fail, expected, attempts) in [
        (0, Some(1), json!([0,true]), 0),
        (4, Some(1), json!([0,false]), 1),
        (4, None, json!([4,true]), 1),
        (u64::MAX, None, json!([0,false]), 0),
    ] {
        let report = run(&source, vec![json!(size)], 100, 100, fail);
        assert_eq!(report["values"], expected);
        assert_eq!(report["resources"]["owners_created"], 1);
        assert_eq!(report["resources"]["owners_dropped"], 1);
        assert_eq!(report["resources"]["allocation_attempts"], attempts);
        assert_eq!(report["resources"]["live_owners"], 0);
    }
}

#[test]
fn unsupported_suffix_rejects_before_a_hiding_allocator_failure() {
    let mut source = roundtrip();
    source["schema"] = json!("hepta.hia.program.v7");
    let ops = source["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap();
    ops.insert(4, json!({"op":"chain.empty","args":[],
        "out":[{"name":"unsupported","type":"chain"}],"attrs":{}}));
    ops.insert(5, json!({"op":"owner.drop","args":["unsupported"],"out":[],"attrs":{}}));
    let raw = serde_json::to_vec(&source).unwrap();
    assert!(verify_owned(&raw).is_ok());
    let error = execute_owned(&raw, "probe", &[json!(4)], 100, 100, Some(1)).unwrap_err();
    assert_eq!(error.code, "E_HIA_RUST_UNSUPPORTED");
    // The chain-typed result is rejected by the profile's type boundary
    // before the operation whitelist or an allocator can be reached.
    assert_eq!(error.detail, "Rust shadow checker only supports scalar values");
}

#[test]
fn scalar_entry_boundary_and_policy_are_not_capability_constructors() {
    let raw = serde_json::to_vec(&roundtrip()).unwrap();
    for argument in [json!(true), json!({"owner":1}), json!("4")] {
        assert!(execute_owned(&raw, "probe", &[argument], 100, 100, None).is_err());
    }
    for (steps, heap, fail) in [(0,100,None),(1_000_001,100,None),
                               (100,16*1024*1024+1,None),(100,100,Some(0))] {
        let error = execute_owned(&raw, "probe", &[json!(4)], steps, heap, fail).unwrap_err();
        assert_eq!(error.code, "E_HIA_BUDGET_POLICY");
    }
    let mut private = roundtrip();
    private["exports"] = json!([]);
    let error = execute_owned(&serde_json::to_vec(&private).unwrap(), "probe", &[json!(4)],
                              100, 100, None).unwrap_err();
    assert_eq!(error.code, "E_HIA_INPUT");
}
