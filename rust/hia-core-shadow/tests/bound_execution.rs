//! The opt-in request envelope must wrap the existing Machine unchanged.
use hia_core_shadow::{execute_owned, execute_owned_bound};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn program() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "hepta.hia.program.v8", "module": "bound_execution",
        "functions": [{
            "name": "identity", "params": [{"name": "v", "type": "u64"}],
            "returns": ["u64"], "effects": [], "entry": "entry",
            "blocks": [{"id": "entry", "params": [{"name": "v", "type": "u64"}],
                        "ops": [], "term": {"op": "ret", "values": ["v"]}}]
        }]
    })).unwrap()
}

#[test]
fn request_binding_wraps_the_actual_legacy_execution() {
    let source = program();
    let args = [json!(u64::MAX)];
    let bound = execute_owned_bound(&source, "identity", &args, 20, 0, None).unwrap();
    assert_eq!(bound["execution"], execute_owned(&source, "identity", &args, 20, 0, None).unwrap());
    assert_eq!(bound["request"]["arguments"], json!(args));
    assert_eq!(bound["request"]["policy"]["max_call_depth"], 32);
    assert_eq!(bound["request_sha256"], format!("{:x}", Sha256::digest(
        serde_json::to_vec(&bound["request"]).unwrap())));
    let changed_args = execute_owned_bound(&source, "identity", &[json!(0)], 20, 0, None).unwrap();
    let changed_policy = execute_owned_bound(&source, "identity", &args, 21, 0, None).unwrap();
    assert_ne!(bound["request_sha256"], changed_args["request_sha256"]);
    assert_ne!(bound["request_sha256"], changed_policy["request_sha256"]);
}

#[test]
fn budget_stop_is_bound_but_invalid_module_never_gets_an_envelope() {
    let source = program();
    let stopped = execute_owned_bound(&source, "identity", &[json!(7)], 1, 0, None).unwrap();
    assert_eq!(stopped["execution"]["status"], "budget_exceeded");
    assert_eq!(stopped["execution"]["error"]["code"], "steps");
    assert_eq!(stopped["execution"]["steps"], 2);
    let mut invalid: Value = serde_json::from_slice(&source).unwrap();
    invalid["functions"][0]["blocks"][0]["term"]["values"] = json!(["missing"]);
    let rejected = execute_owned_bound(&serde_json::to_vec(&invalid).unwrap(),
                                       "identity", &[json!(7)], 1, 0, None);
    assert!(rejected.is_err());
    assert!(execute_owned_bound(&source, "identity", &[json!({"fake": 7})], 1, 0, None).is_err());
    assert!(execute_owned_bound(&source, "identity", &vec![json!(0); 8193], 1, 0, None).is_err());
}
