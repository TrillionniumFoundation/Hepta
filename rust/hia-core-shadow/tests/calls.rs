//! Rust Owner/Loan interprocedural verifier regressions, no mock verifier.
use hia_core_shadow::verify_owned;
use serde_json::{json, Value};

fn program() -> Value {
    json!({
      "schema":"hepta.hia.program.v1", "module":"call_shadow",
      "functions":[
        {"name":"maker",
         "params":[{"name":"size","type":"usize"}],
         "returns":["buffer","bool"],"effects":["alloc"],"entry":"start",
         "blocks":[{
           "id":"start","params":[{"name":"size","type":"usize"}],
           "ops":[{"op":"buffer.try_new","args":["size"],
                   "out":[{"name":"newowner","type":"buffer"},
                          {"name":"succeeded","type":"bool"}],"attrs":{}}],
           "term":{"op":"ret","values":["newowner","succeeded"]}
         }]},
        {"name":"use",
         "params":[{"name":"n","type":"usize"}],
         "returns":["usize","bool"],"effects":["alloc"],"entry":"entry",
         "blocks":[{
           "id":"entry","params":[{"name":"n","type":"usize"}],
           "ops":[
             {"op":"call","args":["n"],
              "out":[{"name":"owned","type":"buffer"},
                     {"name":"ok","type":"bool"}],
              "attrs":{"function":"maker"}},
             {"op":"buffer.len","args":["owned"],
              "out":[{"name":"length","type":"usize"}],"attrs":{}},
             {"op":"owner.drop","args":["owned"],"out":[],"attrs":{}}
           ],
           "term":{"op":"ret","values":["length","ok"]}
         }]}
      ]
    })
}
fn checked(v: &Value) -> bool { verify_owned(&serde_json::to_vec(v).unwrap()).is_ok() }
#[test]
fn accepts_typed_owner_return_from_internal_call() {
    let d = program();
    let result = verify_owned(&serde_json::to_vec(&d).unwrap()).unwrap();
    assert_eq!(result["claims"]["interprocedural_resource_calls_checked"], true);
    assert_eq!(result["claims"]["recursion_or_stack_bounds_proved"], false);
    assert_eq!(result["claims"]["rust_is_production_admission_authority"], false);
}
#[test]
fn cannot_drop_moved_result_twice() {
    let mut d = program();
    d["functions"][1]["blocks"][0]["ops"].as_array_mut().unwrap().push(json!({
       "op":"owner.drop","args":["owned"],"out":[],"attrs":{}
    }));
    assert!(!checked(&d));
}
#[test]
fn owner_return_requires_new_result_capability() {
    let mut d = program();
    d["functions"][1]["blocks"][0]["ops"][0]["out"][0]["type"] = json!("usize");
    assert!(!checked(&d));
}
#[test]
fn caller_must_cover_callee_effects() {
    let mut d = program();
    d["functions"][1]["effects"] = json!([]);
    assert!(!checked(&d));
}
#[test]
fn call_rejects_unknown_callee_or_forged_effects() {
    let mut d = program();
    d["functions"][1]["blocks"][0]["ops"][0]["attrs"]["function"] = json!("not_a_callee");
    assert!(!checked(&d));
    d = program();
    d["functions"][1]["blocks"][0]["ops"][0]["attrs"]["unsafe_proof"] = json!(true);
    assert!(!checked(&d));
}
