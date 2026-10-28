//! Independent v8 admission and actual retained-parent/returned-child execution.
use hia_core_shadow::{execute_owned, execute_scalar, verify_owned};
use serde_json::{json, Value};

fn program() -> Value {
    serde_json::from_slice(include_bytes!("../../../examples/hia_returned_loans/core_v8.json")).unwrap()
}

#[test]
fn returned_child_survives_two_call_returns_then_original_parent_resumes() {
    let source = serde_json::to_vec(&program()).unwrap();
    let admission = verify_owned(&source).unwrap();
    assert_eq!(admission["claims"]["explicit_parameter_returned_loan_checked"], true);
    let run = execute_owned(&source, "probe", &[json!(2), json!(19), json!(false)], 100, 100, None).unwrap();
    assert_eq!(run["profile"], "bounded-cfg-returned-loan-v4");
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
        let mut source = program();
        source["schema"] = json!(format!("hepta.hia.program.v{version}"));
        assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_err());
        for function in source["functions"].as_array_mut().unwrap() {
            function.as_object_mut().unwrap().remove("return_origins");
        }
        assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_err());
    }
}

#[test]
fn frozen_parent_and_hidden_illegal_helper_reject_before_budgets() {
    let mut source = program();
    let main = source["functions"].as_array_mut().unwrap().last_mut().unwrap();
    let ops = main["blocks"][0]["ops"].as_array_mut().unwrap();
    let after_call = ops.iter().position(|op| op["op"] == "call").unwrap() + 1;
    ops.insert(after_call, json!({"op":"loan.end","args":["parent"],"out":[],"attrs":{}}));
    assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_err());
    assert!(execute_owned(&serde_json::to_vec(&source).unwrap(), "probe",
                          &[json!(2),json!(19),json!(false)], 1, 0, Some(1)).is_err());
    let mut source = program();
    let mut unused = source["functions"][0].clone();
    unused["name"] = json!("uninvoked");
    unused["return_origins"] = json!(["choose"]);
    source["functions"].as_array_mut().unwrap().push(unused);
    assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_err());
    assert!(execute_owned(&serde_json::to_vec(&source).unwrap(), "probe",
                          &[json!(2),json!(19),json!(false)], 1, 0, Some(1)).is_err());
}
