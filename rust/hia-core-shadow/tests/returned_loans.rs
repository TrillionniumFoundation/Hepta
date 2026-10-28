//! Actual Rust API admission/execution of the versioned v8 byte-loan profile.
use hia_core_shadow::{execute_owned, execute_scalar, verify, verify_owned};
use serde_json::{json, Value};

fn example() -> Value {
    serde_json::from_slice(include_bytes!("../../../examples/hia_program/parameter_loan_return_v8.hia")).unwrap()
}

#[test]
fn actual_recursive_example_returns_child_once_and_retains_parent_until_end() {
    let raw = serde_json::to_vec(&example()).unwrap();
    let verified = verify_owned(&raw).unwrap();
    assert_eq!(verified["schema"], "hepta.hia.rust-owner-shadow.v2");
    assert_eq!(verified["claims"]["v8_parameter_bound_loan_returns_checked"], true);
    assert_eq!(verified["claims"]["rust_is_production_admission_authority"], false);
    let report = execute_owned(&raw, "entry_mut_recursive", &[json!(17), json!(7)], 1000, 128, None).unwrap();
    assert_eq!(report["profile"], "bounded-cfg-byte-owner-loan-returns-v4");
    assert_eq!(report["values"], json!([12]));
    assert_eq!(report["resources"]["loans_started"], 3);
    assert_eq!(report["resources"]["loans_ended"], 3);
    assert_eq!(report["resources"]["allocations"], 1);
    assert_eq!(report["resources"]["frees"], 1);
    assert_eq!(report["resources"]["live_local_loans"], 0);
    assert_eq!(report["resources"]["live_bytes"], 0);
    assert!(verify(&raw).is_err());
    assert!(execute_scalar(&raw, "entry_mut_recursive", &[json!(17), json!(7)], 1000).is_err());
}

#[test]
fn v8_contract_is_required_and_never_backported_to_older_grammar() {
    for origin in [Value::Null, json!([]), json!([null]), json!(["depth"]), json!(["input", null])] {
        let mut doc = example();
        doc["functions"][0]["return_loans"] = origin;
        assert!(verify_owned(&serde_json::to_vec(&doc).unwrap()).is_err());
    }
    let mut doc = example();
    doc["functions"][0].as_object_mut().unwrap().remove("return_loans");
    assert!(verify_owned(&serde_json::to_vec(&doc).unwrap()).is_err());
    for version in 1..=7 {
        let mut doc = example();
        doc["schema"] = json!(format!("hepta.hia.program.v{version}"));
        assert!(verify_owned(&serde_json::to_vec(&doc).unwrap()).is_err());
    }
}

#[test]
fn stopped_recursive_borrow_keeps_the_actual_owner_and_caller_loan() {
    let mut doc = example();
    for instruction in doc["functions"][1]["blocks"][0]["ops"].as_array_mut().unwrap() {
        if instruction["op"] == "const" && instruction["out"][0]["name"] == "depth" {
            instruction["attrs"]["value"] = json!(100);
        }
    }
    let raw = serde_json::to_vec(&doc).unwrap();
    let report = execute_owned(&raw, "entry_mut_recursive", &[json!(17), json!(7)], 1000, 128, None).unwrap();
    assert_eq!(report["status"], "budget_exceeded");
    assert_eq!(report["error"]["code"], "calls");
    assert_eq!(report["resources"]["live_owners"], 1);
    assert_eq!(report["resources"]["live_local_loans"], 1);
    assert_eq!(report["resources"]["live_bytes"], 17);
    assert_eq!(report["resources"]["frees"], 0);
    assert_eq!(execute_owned(&raw, "return_mut_recursive", &[], 1, 0, Some(1)).unwrap_err().code,
               "E_HIA_INPUT");
}

// Source-lowering scenarios retained from the new base, using canonical v8.
fn source_frontend_example() -> Value {
    serde_json::from_slice(include_bytes!("../../../examples/hia_returned_loans/core_v8.json")).unwrap()
}

#[test]
fn returned_child_survives_two_call_returns_then_original_parent_resumes() {
    let source = serde_json::to_vec(&source_frontend_example()).unwrap();
    let admission = verify_owned(&source).unwrap();
    assert_eq!(admission["claims"]["v8_parameter_bound_loan_returns_checked"], true);
    let run = execute_owned(&source, "probe", &[json!(2), json!(19), json!(false)], 100, 100, None).unwrap();
    assert_eq!(run["profile"], "bounded-cfg-byte-owner-loan-returns-v4");
    assert_eq!(run["status"], "returned");
    assert_eq!(run["values"], json!([73]));
    assert_eq!(run["resources"], json!({
        "allocations":1,"frees":1,"allocation_attempts":1,
        "owners_created":1,"owners_dropped":1,"live_owners":0,
        "live_bytes":0,"peak_bytes":2,
        "loans_started":4,"loans_ended":4,"live_local_loans":0,
        "chains_created":0,"chains_consumed":0,"live_chains":0,
        "chain_nodes_created":0,"chain_nodes_dropped":0,"live_chain_nodes":0,
    }));
    assert!(execute_scalar(&source, "probe", &[json!(2), json!(19), json!(false)], 100).is_err());
    assert!(execute_owned(&source, "leaf", &[], 100, 100, None).is_err());
}

#[test]
fn old_version_labels_cannot_authorize_new_returned_loans() {
    for version in 1..=7 {
        let mut source = source_frontend_example();
        source["schema"] = json!(format!("hepta.hia.program.v{version}"));
        assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_err());
        for function in source["functions"].as_array_mut().unwrap() {
            function.as_object_mut().unwrap().remove("return_loans");
        }
        assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_err());
    }
}

#[test]
fn frozen_parent_and_hidden_illegal_helper_reject_before_budgets() {
    let mut source = source_frontend_example();
    let main = source["functions"].as_array_mut().unwrap().last_mut().unwrap();
    let ops = main["blocks"][0]["ops"].as_array_mut().unwrap();
    let after_call = ops.iter().position(|op| op["op"] == "call").unwrap() + 1;
    ops.insert(after_call, json!({"op":"loan.end","args":["parent"],"out":[],"attrs":{}}));
    assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_err());
    assert!(execute_owned(&serde_json::to_vec(&source).unwrap(), "probe",
                          &[json!(2),json!(19),json!(false)], 1, 0, Some(1)).is_err());
    let mut source = source_frontend_example();
    let mut unused = source["functions"][0].clone();
    unused["name"] = json!("uninvoked");
    unused["return_loans"] = json!(["choose"]);
    source["functions"].as_array_mut().unwrap().push(unused);
    assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_err());
    assert!(execute_owned(&serde_json::to_vec(&source).unwrap(), "probe",
                          &[json!(2),json!(19),json!(false)], 1, 0, Some(1)).is_err());
}


#[test]
fn alternate_return_origin_wire_is_rejected_before_execution_budgets() {
    // The independently-developed donor used a different spelling under v8.
    // Current source producers migrate explicitly; the checker accepts only
    // the published return_loans field, even when both spellings agree.
    for keep_canonical in [false, true] {
        let mut source = example();
        let function = source["functions"][0].as_object_mut().unwrap();
        let origins = function["return_loans"].clone();
        if !keep_canonical { function.remove("return_loans"); }
        function.insert("return_origins".into(), origins);
        let raw = serde_json::to_vec(&source).unwrap();
        assert_eq!(verify_owned(&raw).unwrap_err().code, "E_HIA_FORMAT");
        assert_eq!(execute_owned(&raw, "entry_mut_recursive", &[json!(17), json!(7)],
                                 1, 0, Some(1)).unwrap_err().code, "E_HIA_FORMAT");
    }
}
