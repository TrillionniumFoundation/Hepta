use hia_core_shadow::verify;
use serde_json::{json, Value};

fn scalar(schema: &str) -> Value {
    json!({
      "schema": schema, "module": "sample",
      "functions": [{
        "name": "sum", "params": [
          {"name":"a", "type":"u32"}, {"name":"b", "type":"u32"}
        ],
        "returns":["u32"], "effects":["trap"], "entry":"entry",
        "blocks":[{
          "id":"entry","params":[
            {"name":"a","type":"u32"},{"name":"b","type":"u32"}
          ],
          "ops":[{
            "op":"int.add.checked", "args":["a","b"],
            "out":[{"name":"sum","type":"u32"}], "attrs":{}
          }], "term":{"op":"ret","values":["sum"]}
        }]
      }]
    })
}
fn check(v: &Value) -> bool {
    verify(&serde_json::to_vec(v).unwrap()).is_ok()
}

#[test]
fn accepts_scalar_ssa_in_all_known_envelopes() {
    for v in 1..=6 {
        let value = scalar(&format!("hepta.hia.program.v{v}"));
        let report = verify(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(report["claims"]["scalar_ssa_and_cfg_checked"], true);
        assert_eq!(report["claims"]["resource_provenance_verified"], false);
        assert_eq!(report["claims"]["backend_refinement_proved"], false);
    }
}
#[test]
fn rejects_unknown_versions_and_unknown_keys() {
    let mut v = scalar("hepta.hia.program.v7");
    assert!(!check(&v));
    v["schema"] = json!("hepta.hia.program.v1");
    v["extra"] = json!(false);
    assert!(!check(&v));
}
#[test]
fn rejects_duplicate_fields_floats_and_nonfinite_payload() {
    assert!(verify(br#"{"schema":"hepta.hia.program.v1","schema":"hepta.hia.program.v6","module":"m","functions":[]}"#).is_err());
    assert!(verify(br#"{"schema":"hepta.hia.program.v1","module":"m","functions":[1.0]}"#).is_err());
    assert!(verify(br#"{"schema":"hepta.hia.program.v1","module":"m","functions":[1e999]}"#).is_err());
}
#[test]
fn rejects_wrong_effect_type_and_nonlocal_ssa() {
    let mut v = scalar("hepta.hia.program.v1");
    v["functions"][0]["effects"] = json!([]);
    assert!(!check(&v));
    v["functions"][0]["effects"] = json!(["trap"]);
    v["functions"][0]["blocks"][0]["ops"][0]["args"][1] = json!("missing");
    assert!(!check(&v));
    v["functions"][0]["blocks"][0]["ops"][0]["args"][1] = json!("b");
    v["functions"][0]["blocks"][0]["ops"][0]["out"][0]["type"] = json!("i32");
    assert!(!check(&v));
}
#[test]
fn rejects_resource_isa_without_claiming_safety() {
    let mut v = scalar("hepta.hia.program.v6");
    v["functions"][0]["blocks"][0]["ops"][0]["op"] = json!("buffer.new");
    assert!(!check(&v));
}
#[test]
fn rejects_cfg_jump_to_entry_and_unreachable_blocks() {
    let mut v = scalar("hepta.hia.program.v1");
    v["functions"][0]["blocks"][0]["term"] = json!({
        "op":"jump","target":"entry","args":["a","b"]
    });
    assert!(!check(&v));
    v = scalar("hepta.hia.program.v1");
    v["functions"][0]["blocks"].as_array_mut().unwrap().push(json!({
       "id":"dead","params":[],"ops":[],"term":{"op":"trap","code":"user"}
    }));
    assert!(!check(&v));
}
#[test]
fn rejects_integer_bool_confusion_and_duplicate_ssa() {
    let mut v = scalar("hepta.hia.program.v1");
    v["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap().insert(0,json!({
        "op":"const", "args":[], "out":[{"name":"bad","type":"u32"}],
        "attrs":{"value":true}
    }));
    assert!(!check(&v));
    v["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = json!(5);
    assert!(check(&v));
    v["functions"][0]["blocks"][0]["ops"][0]["out"][0]["name"] = json!("a");
    assert!(!check(&v));
}
#[test]
fn accepts_explicit_phi_arguments_and_checks_edge_types() {
    let mut v = scalar("hepta.hia.program.v1");
    v["functions"][0]["blocks"][0]["term"] = json!({
       "op":"jump","target":"exit","args":["sum"]
    });
    v["functions"][0]["blocks"].as_array_mut().unwrap().push(json!({
       "id":"exit","params":[{"name":"result","type":"u32"}],
       "ops":[],"term":{"op":"ret","values":["result"]}
    }));
    assert!(check(&v));
    v["functions"][0]["blocks"][1]["params"][0]["type"] = json!("i32");
    assert!(!check(&v));
}
