//! Raw Rust admission and execution; no Python receipt supplies authority.
use hia_core_shadow::{execute_owned, execute_scalar, verify_owned};
use serde_json::{json, Value};

fn document() -> Value {
    serde_json::from_slice(include_bytes!("../../../examples/hia_program/returned_loans_cross_target_v8.hia")).unwrap()
}

#[test]
fn chain_head_forward_and_child_use_versioned_single_machine_profile() {
    let raw = serde_json::to_vec(&document()).unwrap();
    assert_eq!(verify_owned(&raw).unwrap()["claims"]["v8_parameter_bound_loan_returns_checked"], true);
    for (entry, answer) in [("head_chain_mut_child", 42), ("head_chain_mut_forward", 84),
                           ("head_chain_read_child", 37), ("head_chain_read_forward", 74)] {
        let report = execute_owned(&raw, entry, &[json!(37)], 10000, 128, None).unwrap();
        assert_eq!(report["profile"], "bounded-cfg-owned-memory-v5");
        assert_eq!(report["values"], json!([answer]));
        assert_eq!(report["resources"]["allocations"], 2);
        assert_eq!(report["resources"]["frees"], 2);
        assert_eq!(report["resources"]["peak_bytes"], 25);
        assert_eq!(report["resources"]["live_local_loans"], 0);
        assert_eq!(report["resources"]["live_chains"], 0);
        assert_eq!(report["resources"]["live_chain_nodes"], 0);
        assert_eq!(report["claims"]["parameter_bound_returned_loans_execution"], true);
        assert_eq!(report["claims"]["production_admission_authorized"], false);
    }
    assert!(execute_scalar(&raw, "head_chain_read_child", &[json!(37)], 10000).is_err());
}

#[test]
fn failed_chain_header_retains_empty_chain_and_real_source_prefix() {
    let raw = serde_json::to_vec(&document()).unwrap();
    let stopped = execute_owned(&raw, "head_chain_read_child", &[json!(37)], 10000, 128, Some(2)).unwrap();
    assert_eq!(stopped["status"], "trapped");
    assert_eq!(stopped["error"]["code"], "bounds");
    assert_eq!(stopped["resources"]["allocation_attempts"], 2);
    assert_eq!(stopped["resources"]["allocations"], 1);
    assert_eq!(stopped["resources"]["frees"], 1);
    assert_eq!(stopped["resources"]["live_chains"], 1);
    assert_eq!(stopped["resources"]["live_chain_nodes"], 0);
    assert_eq!(stopped["resources"]["live_local_loans"], 0);
    assert_eq!(stopped["resources"]["live_bytes"], 0);
    let complete = execute_owned(&raw, "head_chain_mut_child", &[json!(37)], 10000, 128, None).unwrap();
    let limit = complete["steps"].as_u64().unwrap();
    let before_return = execute_owned(&raw, "head_chain_mut_child", &[json!(37)], limit - 1, 128, None).unwrap();
    assert_eq!(before_return["status"], "budget_exceeded");
    assert_eq!(before_return["resources"]["frees"], 2);
}

#[test]
fn uncalled_invalid_origin_and_live_chain_mutation_reject_before_budget() {
    for invalid in ["origin", "drop"] {
        let mut doc = document();
        if invalid == "origin" {
            let helper = doc["functions"].as_array_mut().unwrap().iter_mut()
                .find(|f| f["name"] == "head_return_mut_child").unwrap();
            helper["return_loans"] = json!(["absent"]);
        } else {
            let caller = doc["functions"].as_array_mut().unwrap().iter_mut()
                .find(|f| f["name"] == "head_chain_mut_child").unwrap();
            caller["blocks"][1]["ops"].as_array_mut().unwrap().insert(0,
                json!({"op":"owner.drop","args":["chain_again"],"out":[],"attrs":{}}));
        }
        let raw = serde_json::to_vec(&doc).unwrap();
        assert!(verify_owned(&raw).is_err());
        assert!(execute_owned(&raw, "head_chain_read_child", &[json!(37)], 1, 0, Some(1)).is_err());
    }
}
