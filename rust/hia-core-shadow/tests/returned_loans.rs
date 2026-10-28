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
