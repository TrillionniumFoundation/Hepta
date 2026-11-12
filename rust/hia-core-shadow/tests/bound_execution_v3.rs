//! Wider evaluator budgets retain the one Machine, including small host stacks.
use hia_core_shadow::{execute_owned, execute_owned_bound_v2, execute_owned_bound_v3};
use serde_json::{json, Value};

fn recursion() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "hepta.hia.program.v8", "module": "budget_v3",
        "functions": [{"name": "recur", "params": [], "returns": [],
            "effects": [], "entry": "entry", "blocks": [{
                "id": "entry", "params": [], "ops": [{"op": "call", "args": [],
                    "out": [], "attrs": {"function": "recur"}}],
                "term": {"op": "ret", "values": []}}]}]
    })).unwrap()
}

fn policy(depth: u32) -> Value {
    json!({"max_steps": 10_000_000, "max_heap_bytes": 1024 * 1024 * 1024,
           "allocation_fail_at": null, "max_call_depth": depth})
}

#[test]
fn all_256_language_depths_work_on_a_fixed_small_host_stack() {
    // This is an actual bounded-stack execution test, not a frame-count claim.
    // It covers the debug build too; no RUST_MIN_STACK override is required.
    std::thread::Builder::new().stack_size(512 * 1024).spawn(|| {
        let source = recursion();
        for depth in 1..=256 {
            let result = execute_owned_bound_v3(&source, "recur", &[],
                &serde_json::to_vec(&policy(depth)).unwrap()).unwrap();
            assert_eq!(result["schema"], "hepta.hia.rust-bound-execution.v3");
            assert_eq!(result["request"]["schema"], "hepta.hia.rust-execution-request.v3");
            assert_eq!(result["request"]["policy"], policy(depth));
            assert_eq!(result["execution"]["steps"], 2 * depth);
            assert_eq!(result["execution"]["error"], json!({"code": "calls"}));
            assert_eq!(result["execution"]["claims"]["production_admission_authorized"], false);
        }
    }).unwrap().join().unwrap();
}

#[test]
fn wider_step_budget_is_executed_and_old_protocols_still_reject_it() {
    let source = serde_json::to_vec(&json!({
        "schema": "hepta.hia.program.v8", "module": "steps_v3",
        "functions": [{"name": "looping", "params": [], "returns": [],
            "effects": [], "entry": "entry", "blocks": [
                {"id": "entry", "params": [], "ops": [],
                 "term": {"op": "jump", "target": "loop", "args": []}},
                {"id": "loop", "params": [], "ops": [],
                 "term": {"op": "jump", "target": "loop", "args": []}}]}]
    })).unwrap();
    let mut selected = policy(1);
    selected["max_steps"] = json!(1_000_001);
    selected["max_heap_bytes"] = json!(0);
    let encoded = serde_json::to_vec(&selected).unwrap();
    let result = execute_owned_bound_v3(&source, "looping", &[], &encoded).unwrap();
    assert_eq!(result["execution"]["steps"], 1_000_002);
    assert_eq!(result["execution"]["error"], json!({"code": "steps"}));
    assert!(execute_owned_bound_v2(&source, "looping", &[], &encoded).is_err());
    assert!(execute_owned(&source, "looping", &[], 1_000_001, 0, None).is_err());
    assert!(execute_owned(&source, "looping", &[], 1, 16 * 1024 * 1024 + 1, None).is_err());
}

#[test]
fn policy_shape_integer_tokens_and_new_upper_bounds_remain_strict() {
    let source = recursion();
    for field in ["max_steps", "max_heap_bytes", "max_call_depth", "allocation_fail_at"] {
        let mut missing = policy(1);
        missing.as_object_mut().unwrap().remove(field);
        assert!(execute_owned_bound_v3(&source, "recur", &[],
            &serde_json::to_vec(&missing).unwrap()).is_err());
        for value in [json!(true), json!(false), json!("1"), json!([]), json!({}), json!(1.0)] {
            let mut bad = policy(1);
            bad[field] = value;
            assert!(execute_owned_bound_v3(&source, "recur", &[],
                &serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
    for (field, value) in [
        ("max_call_depth", json!(0)), ("max_call_depth", json!(257)),
        ("max_steps", json!(0)), ("max_steps", json!(10_000_001)),
        ("max_heap_bytes", json!(1024_u64 * 1024 * 1024 + 1)),
        ("allocation_fail_at", json!(0)), ("unknown", json!(false)),
    ] {
        let mut bad = policy(1);
        bad[field] = value;
        assert!(execute_owned_bound_v3(&source, "recur", &[],
            &serde_json::to_vec(&bad).unwrap()).is_err());
    }
    for raw in [
        br#"{"max_steps":1,"max_heap_bytes":0,"allocation_fail_at":null,"max_call_depth":256,"max_call_depth":256}"#.as_slice(),
        br#"{"max_steps":1,"max_heap_bytes":0,"allocation_fail_at":null,"max_call_depth":256e0}"#.as_slice(),
        b"null".as_slice(), b"[]".as_slice(),
    ] {
        assert!(execute_owned_bound_v3(&source, "recur", &[], raw).is_err());
    }
    assert!(execute_owned_bound_v3(&source, "recur", &[], &vec![b' '; 1025]).is_err());
}

#[test]
fn early_stop_cannot_hide_an_invalid_unused_function() {
    let mut source: Value = serde_json::from_slice(&recursion()).unwrap();
    let mut hidden = source["functions"][0].clone();
    hidden["name"] = json!("hidden");
    hidden["blocks"][0]["ops"][0]["op"] = json!("future.unsafe");
    source["functions"].as_array_mut().unwrap().push(hidden);
    let mut selected = policy(256);
    selected["max_steps"] = json!(1);
    selected["allocation_fail_at"] = json!(1);
    assert!(execute_owned_bound_v3(&serde_json::to_vec(&source).unwrap(), "recur", &[],
        &serde_json::to_vec(&selected).unwrap()).is_err());
}
