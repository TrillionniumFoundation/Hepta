//! Explicit depth changes only the policy of the existing Machine.
use hia_core_shadow::{execute_owned, execute_owned_bound, execute_owned_bound_v2};
use serde_json::{json, Value};

fn recursion() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "hepta.hia.program.v8", "module": "depth_v2",
        "functions": [{"name": "recur", "params": [], "returns": [],
            "effects": [], "entry": "entry", "blocks": [{
                "id": "entry", "params": [], "ops": [{"op": "call", "args": [],
                    "out": [], "attrs": {"function": "recur"}}],
                "term": {"op": "ret", "values": []}}]}]
    })).unwrap()
}

fn policy(depth: u32) -> Value {
    json!({"max_steps": 1000, "max_heap_bytes": 0,
           "allocation_fail_at": null, "max_call_depth": depth})
}

#[test]
fn every_explicit_depth_stops_before_the_next_frame_entry_tick() {
    let source = recursion();
    for depth in 1..=32 {
        let report = execute_owned_bound_v2(&source, "recur", &[],
            &serde_json::to_vec(&policy(depth)).unwrap()).unwrap();
        assert_eq!(report["schema"], "hepta.hia.rust-bound-execution.v2");
        assert_eq!(report["request"]["schema"], "hepta.hia.rust-execution-request.v2");
        assert_eq!(report["request"]["policy"], policy(depth));
        assert_eq!(report["execution"]["max_call_depth"], depth);
        assert_eq!(report["execution"]["steps"], 2 * depth);
        assert_eq!(report["execution"]["status"], "budget_exceeded");
        assert_eq!(report["execution"]["error"], json!({"code": "calls"}));
    }
}

#[test]
fn v2_does_not_change_or_relabel_legacy_execution_or_bound_v1() {
    let source = recursion();
    let _ = execute_owned_bound_v2(&source, "recur", &[],
        &serde_json::to_vec(&policy(1)).unwrap()).unwrap();
    let legacy = execute_owned(&source, "recur", &[], 1000, 0, None).unwrap();
    let v1 = execute_owned_bound(&source, "recur", &[], 1000, 0, None).unwrap();
    let v2 = execute_owned_bound_v2(&source, "recur", &[],
        &serde_json::to_vec(&policy(32)).unwrap()).unwrap();
    assert_eq!(legacy["max_call_depth"], 32);
    assert_eq!(legacy["steps"], 64);
    assert_eq!(v1["schema"], "hepta.hia.rust-bound-execution.v1");
    assert_eq!(v1["request"]["schema"], "hepta.hia.rust-execution-request.v1");
    assert_eq!(v1["execution"], legacy);
    assert_eq!(v2["execution"], legacy);
    assert_ne!(v1["request_sha256"], v2["request_sha256"]);
}

#[test]
fn raw_policy_rejects_missing_unknown_and_inexact_fields() {
    let source = recursion();
    for field in ["max_steps", "max_heap_bytes", "allocation_fail_at", "max_call_depth"] {
        let mut missing = policy(2);
        missing.as_object_mut().unwrap().remove(field);
        assert!(execute_owned_bound_v2(&source, "recur", &[],
            &serde_json::to_vec(&missing).unwrap()).is_err());
        for value in [json!(true), json!(false), json!("1"), json!([]), json!({})] {
            let mut changed = policy(2);
            changed[field] = value;
            assert!(execute_owned_bound_v2(&source, "recur", &[],
                &serde_json::to_vec(&changed).unwrap()).is_err());
        }
    }
    for (field, value) in [
        ("max_call_depth", json!(0)), ("max_call_depth", json!(33)),
        ("max_call_depth", json!(-1)), ("max_call_depth", Value::Null),
        ("max_steps", json!(0)), ("max_steps", json!(1_000_001)),
        ("max_heap_bytes", json!(16 * 1024 * 1024 + 1)),
        ("allocation_fail_at", json!(0)), ("unknown", json!(false)),
    ] {
        let mut changed = policy(2);
        changed[field] = value;
        assert!(execute_owned_bound_v2(&source, "recur", &[],
            &serde_json::to_vec(&changed).unwrap()).is_err());
    }
    for raw in [
        br#"{"max_steps":1000,"max_heap_bytes":0,"allocation_fail_at":null,"max_call_depth":2,"max_call_depth":2}"#.as_slice(),
        br#"{"max_steps":1000,"max_heap_bytes":0,"allocation_fail_at":null,"max_call_depth":2.0}"#.as_slice(),
        br#"{"max_steps":1000,"max_heap_bytes":0,"allocation_fail_at":null,"max_call_depth":2e0}"#.as_slice(),
        b"null".as_slice(), b"[]".as_slice(),
    ] {
        assert!(execute_owned_bound_v2(&source, "recur", &[], raw).is_err());
    }
    assert!(execute_owned_bound_v2(&source, "recur", &[], &vec![b' '; 1025]).is_err());
}

#[test]
fn a_small_depth_never_hides_a_bad_unused_function() {
    let mut source: Value = serde_json::from_slice(&recursion()).unwrap();
    let mut hidden = source["functions"][0].clone();
    hidden["name"] = json!("hidden");
    hidden["blocks"][0]["ops"][0]["op"] = json!("future.unsafe");
    source["functions"].as_array_mut().unwrap().push(hidden);
    assert!(execute_owned_bound_v2(&serde_json::to_vec(&source).unwrap(), "recur", &[],
        &serde_json::to_vec(&policy(1)).unwrap()).is_err());
}
