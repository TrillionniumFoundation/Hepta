//! Versioned exact failure-index transport on the existing Machine.
use hia_core_shadow::{execute_owned_bound, execute_owned_bound_v2,
                      execute_owned_bound_v3, execute_owned_bound_v4};
use serde_json::{json, Value};

fn owned(version: u8) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": format!("hepta.hia.program.v{version}"), "module": "api_v4",
        "functions": [{"name": "allocate_release", "params": [{"name":"n", "type":"usize"}],
            "returns": [], "effects": ["alloc", "trap"], "entry":"entry", "blocks": [{
                "id":"entry", "params":[{"name":"n", "type":"usize"}], "ops":[
                    {"op":"buffer.new", "args":["n"], "out":[{"name":"owner", "type":"buffer"}], "attrs":{}},
                    {"op":"owner.drop", "args":["owner"], "out":[], "attrs":{}}],
                "term":{"op":"ret", "values":[]}}]}]
    })).unwrap()
}

fn policy(index: Value) -> Value {
    json!({"max_steps":100000, "max_heap_bytes":1048576,
           "allocation_fail_at":index, "max_call_depth":32})
}

#[test]
fn wide_indices_retain_every_digit_without_low_word_injection() {
    let source = owned(8);
    let mut previous = Value::Null;
    for encoded in ["0xffffffffffffffff".to_owned(), "0x10000000000000000".to_owned(),
                    "0x10000000000000001".to_owned(), format!("0x1{}1", "0".repeat(510))] {
        let result = execute_owned_bound_v4(&source, "allocate_release", &[json!(3)],
            &serde_json::to_vec(&policy(json!(encoded))).unwrap()).unwrap();
        assert_eq!(result["schema"], "hepta.hia.rust-bound-execution.v4");
        assert_eq!(result["request"]["policy"]["allocation_fail_at"], encoded);
        assert_eq!(result["execution"]["schema"], "hepta.hia.rust-byte-owner-execution.v2");
        assert_eq!(result["execution"]["allocation_fail_at"], encoded);
        assert_eq!(result["execution"]["status"], "returned");
        assert_eq!(result["execution"]["resources"]["allocation_attempts"], 1);
        assert_ne!(result["request_sha256"], previous);
        previous = result["request_sha256"].clone();
    }
}

#[test]
fn exact_small_indices_zero_owners_and_stops_keep_real_ledger() {
    let source = owned(8);
    for (index, size, status, attempts) in [
        ("0x1", 0, "returned", 0), ("0x1", 3, "trapped", 1),
        ("0x2", 3, "returned", 1), ("0x10000000000000001", 3, "returned", 1),
    ] {
        let result = execute_owned_bound_v4(&source, "allocate_release", &[json!(size)],
            &serde_json::to_vec(&policy(json!(index))).unwrap()).unwrap();
        assert_eq!(result["execution"]["status"], status);
        assert_eq!(result["execution"]["resources"]["allocation_attempts"], attempts);
        assert_eq!(result["execution"]["resources"]["live_owners"], 0);
    }
    let mut selected = policy(json!("0x10000000000000001"));
    selected["max_steps"] = json!(2);
    let stopped = execute_owned_bound_v4(&source, "allocate_release", &[json!(3)],
        &serde_json::to_vec(&selected).unwrap()).unwrap();
    assert_eq!(stopped["execution"]["error"], json!({"code":"steps"}));
    assert_eq!(stopped["execution"]["steps"], 3);
    assert_eq!(stopped["execution"]["resources"]["live_owners"], 1);
    assert_eq!(stopped["execution"]["resources"]["live_bytes"], 3);
}

#[test]
fn noncanonical_indices_ambiguous_json_and_exact_wire_overflow_reject() {
    let source = owned(8);
    for index in [json!(0), json!(1), json!(true), json!(false), json!(1.0),
                  json!([]), json!({}), json!(""), json!("1"), json!("0x"), json!("0x0"),
                  json!("0x00"), json!("0x01"), json!("0X1"), json!("0xA"), json!("+0x1"),
                  json!("-0x1"), json!("0x-1"), json!("0x1_0"), json!("0x1 "), json!(" 0x1"), json!("0xé")] {
        assert!(execute_owned_bound_v4(&source, "allocate_release", &[json!(3)],
            &serde_json::to_vec(&policy(index)).unwrap()).is_err());
    }
    let width = 1024 - serde_json::to_vec(&policy(Value::Null)).unwrap().len();
    let exact = policy(json!(format!("0x1{}", "0".repeat(width - 1))));
    let raw = serde_json::to_vec(&exact).unwrap();
    assert_eq!(raw.len(), 1024);
    assert!(execute_owned_bound_v4(&source, "allocate_release", &[json!(3)], &raw).is_ok());
    let mut oversized = raw.clone();
    oversized.push(b' ');
    assert!(execute_owned_bound_v4(&source, "allocate_release", &[json!(3)], &oversized).is_err());
    for raw in [
        br#"{"max_steps":1,"max_heap_bytes":0,"max_call_depth":32,"allocation_fail_at":"0x1","allocation_fail_at":"0x1"}"#.as_slice(),
        br#"{"max_steps":1,"max_heap_bytes":0,"max_call_depth":32,"allocation_fail_at":"0x1","allocation_fail\u005fat":"0x1"}"#.as_slice(),
        br#"{"max_steps":1e0,"max_heap_bytes":0,"max_call_depth":32,"allocation_fail_at":"0x1"}"#.as_slice(),
        br#"{"max_steps":1,"max_heap_bytes":0,"max_call_depth":32,"allocation_fail_at":"0x1"}{}"#.as_slice(),
    ] {
        assert!(execute_owned_bound_v4(&source, "allocate_release", &[json!(3)], raw).is_err());
    }
}

#[test]
fn all_legacy_versions_keep_their_original_report_types_and_policy_limits() {
    let zero_policy = serde_json::to_vec(&policy(json!(0))).unwrap();
    for (version, execute) in [(2, execute_owned_bound_v2 as fn(&[u8], &str, &[Value], &[u8]) -> _),
                               (3, execute_owned_bound_v3)] {
        let refused = execute(&owned(8), "allocate_release", &[json!(3)], &zero_policy).unwrap_err();
        assert_eq!(refused.code, "E_HIA_BUDGET_POLICY");
        assert_eq!(refused.detail, format!("bound v{version} policy outside existing finite limits"));
    }
    for version in 1..=8 {
        let source = owned(version);
        for fail in [None, Some(1), Some(2), Some(u64::MAX)] {
            let old = execute_owned_bound(&source, "allocate_release", &[json!(3)],
                                          100000, 1048576, fail).unwrap();
            let legacy_policy = serde_json::to_vec(&policy(json!(fail))).unwrap();
            let v2 = execute_owned_bound_v2(&source, "allocate_release", &[json!(3)], &legacy_policy).unwrap();
            let v3 = execute_owned_bound_v3(&source, "allocate_release", &[json!(3)], &legacy_policy).unwrap();
            assert_eq!(old["execution"], v2["execution"]);
            assert_eq!(old["execution"], v3["execution"]);
            let selected = policy(fail.map_or(Value::Null, |index| json!(format!("0x{index:x}"))));
            let mut v4 = execute_owned_bound_v4(&source, "allocate_release", &[json!(3)],
                &serde_json::to_vec(&selected).unwrap()).unwrap();
            v4["execution"]["schema"] = json!("hepta.hia.rust-byte-owner-execution.v1");
            v4["execution"]["allocation_fail_at"] = json!(fail);
            assert_eq!(old["execution"], v4["execution"]);
            assert!(execute_owned_bound_v3(&source, "allocate_release", &[json!(3)],
                &serde_json::to_vec(&policy(json!("0x10000000000000001"))).unwrap()).is_err());
        }
    }
}

#[test]
fn early_policy_stop_does_not_hide_invalid_unused_core() {
    let mut document: Value = serde_json::from_slice(&owned(8)).unwrap();
    let mut hidden = document["functions"][0].clone();
    hidden["name"] = json!("hidden");
    hidden["blocks"][0]["ops"][0]["op"] = json!("future.unsafe");
    document["functions"].as_array_mut().unwrap().push(hidden);
    let mut selected = policy(json!("0x10000000000000001"));
    selected["max_steps"] = json!(1);
    assert!(execute_owned_bound_v4(&serde_json::to_vec(&document).unwrap(), "allocate_release", &[json!(3)],
        &serde_json::to_vec(&selected).unwrap()).is_err());
}

