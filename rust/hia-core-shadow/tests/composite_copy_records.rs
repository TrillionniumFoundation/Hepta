//! Independent raw nominal intake must precede the existing primitive Machine.
use hia_core_shadow::{execute_composite_records_bound, execute_owned_bound_v4,
                      normalize_composite_records};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn record(name: &str, fields: Value) -> Value {
    json!({"name":name,"kind":"record","params":[],"fields":fields})
}

fn function(name: &str, params: Value, returns: Value, ops: Value, values: Value) -> Value {
    json!({"name":name,"params":params,"returns":returns,"effects":[],"entry":"entry",
        "blocks":[{"id":"entry","params":params,"ops":ops,"term":{"op":"ret","values":values}}]})
}

fn source() -> Value {
    json!({"schema":"hepta.hia.composite.v1","module":"raw_records",
        "types":[record("Packet",json!([{"name":"value","type":"u64"}]))],
        "functions":[
            function("helper",json!([{"name":"packet","type":"Packet"}]),json!(["Packet"]),json!([]),json!(["packet"])),
            function("entry",json!([{"name":"value","type":"u64"}]),json!(["u64"]),json!([
                {"op":"record.make","args":["value"],"out":[{"name":"made","type":"Packet"}],"attrs":{}},
                {"op":"call","args":["made"],"out":[{"name":"back","type":"Packet"}],"attrs":{"function":"helper"}},
                {"op":"record.get","args":["back"],"out":[{"name":"answer","type":"u64"}],"attrs":{"field":"value"}}
            ]),json!(["answer"]))]})
}

fn policy() -> Vec<u8> {
    serde_json::to_vec(&json!({"max_steps":100,"max_heap_bytes":1024,"max_call_depth":32,
        "allocation_fail_at":"0x10000000000000001"})).unwrap()
}

#[test]
fn raw_records_normalize_to_v6_and_execute_the_same_machine_with_bound_origin() {
    let raw = serde_json::to_vec(&source()).unwrap();
    let normalized = normalize_composite_records(&raw).unwrap();
    assert_eq!(normalized["core"]["schema"],"hepta.hia.program.v6");
    assert_eq!(normalized["core"]["exports"],json!(["entry"]));
    assert_eq!(normalized["input_sha256"],format!("{:x}",Sha256::digest(&raw)));
    let core = serde_json::to_vec(&normalized["core"]).unwrap();
    for value in [0,u64::MAX] {
        let result = execute_composite_records_bound(&raw,"entry",&[json!(value)],&policy()).unwrap();
        let primitive = execute_owned_bound_v4(&core,"entry",&[json!(value)],&policy()).unwrap();
        assert_eq!(result["execution"],primitive["execution"]);
        assert_eq!(result["execution"]["values"],json!([value]));
        assert_eq!(result["request"]["input_sha256"],normalized["input_sha256"]);
        assert_eq!(result["request_sha256"],format!("{:x}",Sha256::digest(
            serde_json::to_vec(&result["request"]).unwrap())));
        assert_eq!(result["claims"]["rust_is_production_admission_authority"],false);
    }
    assert!(execute_composite_records_bound(&raw,"helper",&[json!(7)],&policy()).is_err());
    assert!(execute_owned_bound_v4(&raw,"entry",&[json!(7)],&policy()).is_err());
}

#[test]
fn distinct_empty_nominal_values_do_not_become_interchangeable_or_public() {
    let mut document = json!({"schema":"hepta.hia.composite.v1","module":"empty_records",
        "types":[record("First",json!([])),record("Second",json!([]))],
        "functions":[function("hidden",json!([{"name":"input","type":"First"}]),
            json!(["First"]),json!([]),json!(["input"]))]});
    let raw = serde_json::to_vec(&document).unwrap();
    let normalized = normalize_composite_records(&raw).unwrap();
    assert_eq!(normalized["core"]["exports"],json!([]));
    assert_eq!(normalized["core"]["functions"][0]["params"],json!([]));
    assert!(execute_composite_records_bound(&raw,"hidden",&[],&policy()).is_err());
    document["functions"][0]["returns"] = json!(["Second"]);
    assert_eq!(normalize_composite_records(&serde_json::to_vec(&document).unwrap()).unwrap_err().code,"E_HIA_TYPE");
    document["functions"][0]["returns"] = json!(["First"]);
    document["functions"][0]["blocks"][0]["params"][0]["type"] = json!("Second");
    assert_eq!(normalize_composite_records(&serde_json::to_vec(&document).unwrap()).unwrap_err().code,"E_HIA_CFG");
}

#[test]
fn unsupported_unused_types_and_small_raw_wide_result_fanout_refuse() {
    for ty in [record("Forbidden",json!([{"name":"field","type":"buffer"}])),
               record("Forbidden",json!([{"name":"field","type":"Forbidden"}]))] {
        let mut document = source();
        document["types"].as_array_mut().unwrap().push(ty);
        assert!(normalize_composite_records(&serde_json::to_vec(&document).unwrap()).is_err());
    }
    let leaf = record("Leaf",json!((0..64).map(|n|json!({"name":format!("f{n}"),"type":"u8"})).collect::<Vec<_>>()));
    let wide = record("Wide",json!((0..8).map(|n|json!({"name":format!("f{n}"),"type":"Leaf"})).collect::<Vec<_>>()));
    let document = json!({"schema":"hepta.hia.composite.v1","module":"bounded_expansion","types":[leaf,wide],
        "functions":[function("fanout",json!([{"name":"wide","type":"Wide"}]),
            json!(vec!["Wide";513]),json!([]),json!(vec!["wide";513]))]});
    let raw = serde_json::to_vec(&document).unwrap();
    assert!(raw.len()<20000);
    let error = normalize_composite_records(&raw).unwrap_err();
    assert_eq!(error.code,"E_HIA_LIMIT");
    assert!(error.detail.contains("scalar-reference expansion"));
}
