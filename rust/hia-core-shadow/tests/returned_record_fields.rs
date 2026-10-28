//! A real source-lowered nested record selects one non-first borrowed field.
//! The Rust verifier receives only canonical Core, never a source certificate.
use hia_core_shadow::{execute_owned, verify_owned};
use serde_json::{json, Value};

fn program() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../examples/hia_returned_loans/returned_nested_field.json"
    )).unwrap()
}

#[test]
fn nested_nonfirst_field_and_mutable_scalar_writeback_execute() {
    let source = program();
    for function in source["functions"].as_array().unwrap().iter().take(2) {
        assert_eq!(function["return_origins"][0], function["params"][2]["name"]);
    }
    let wire = serde_json::to_vec(&source).unwrap();
    assert!(verify_owned(&wire).is_ok());
    for choose in [false, true] {
        for byte in [0_u8, 19, 255] {
            let report = execute_owned(&wire, "probe", &[json!(2), json!(byte), json!(choose)],
                                       1000, 100, None).unwrap();
            assert_eq!(report["status"], "returned");
            assert_eq!(report["values"], json!([byte ^ 90]));
            assert_eq!(report["steps"], 74);
            assert_eq!(report["resources"], json!({
                "allocations":2,"frees":2,"allocation_attempts":2,
                "owners_created":2,"owners_dropped":2,"live_owners":0,
                "live_bytes":0,"peak_bytes":4,
                "loans_started":13,"loans_ended":13,"live_local_loans":0,
                "chains_created":0,"chains_consumed":0,"live_chains":0,
                "chain_nodes_created":0,"chain_nodes_dropped":0,"live_chain_nodes":0
            }));
        }
    }
}

#[test]
fn interrupted_record_keeps_the_actual_unreleased_resources() {
    let wire = serde_json::to_vec(&program()).unwrap();
    let args = [json!(2), json!(19), json!(false)];
    for budget in 1..74 {
        let report = execute_owned(&wire, "probe", &args, budget, 100, None).unwrap();
        assert_eq!(report["status"], "budget_exceeded");
        assert_eq!(report["error"]["code"], "steps");
        assert_eq!(report["steps"], budget + 1);
    }
    let heap = execute_owned(&wire, "probe", &args, 1000, 3, None).unwrap();
    assert_eq!(heap["status"], "budget_exceeded");
    assert_eq!(heap["error"]["code"], "heap");
    assert_eq!(heap["resources"]["live_owners"], 1);
    assert_eq!(heap["resources"]["live_bytes"], 2);
    assert_eq!(heap["resources"]["frees"], 0);
    let failed_second = execute_owned(&wire, "probe", &args, 1000, 100, Some(2)).unwrap();
    assert_eq!(failed_second["status"], "trapped");
    assert_eq!(failed_second["error"]["code"], "allocation");
    assert_eq!(failed_second["resources"]["allocation_attempts"], 2);
    assert_eq!(failed_second["resources"]["live_owners"], 1);
    assert_eq!(failed_second["resources"]["live_bytes"], 2);
    assert_eq!(failed_second["resources"]["frees"], 0);
}

#[test]
fn sibling_or_scalar_origin_cannot_be_authorized_by_source_metadata() {
    for bad_index in [0, 1] {
        let mut source = program();
        source["functions"][0]["return_origins"][0] =
            source["functions"][0]["params"][bad_index]["name"].clone();
        let wire = serde_json::to_vec(&source).unwrap();
        assert!(verify_owned(&wire).is_err());
        assert!(execute_owned(&wire, "probe", &[json!(2), json!(19), json!(false)],
                              1, 0, Some(1)).is_err());
    }
}
