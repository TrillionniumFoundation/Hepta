use hia_core_shadow::execute_scalar;
use serde_json::{json, Value};

fn machine(op: &str, ty: &str, effects: Vec<&str>) -> Value {
    json!({
        "schema": "hepta.hia.program.v1", "module": "rust_vm_tests",
        "functions": [{
            "name":"calculate",
            "params":[{"name":"a","type":ty},{"name":"b","type":ty}],
            "returns":[ty], "effects":effects,
            "entry":"entry",
            "blocks":[{
                "id":"entry",
                "params":[{"name":"a","type":ty},{"name":"b","type":ty}],
                "ops":[{"op":op, "args":["a","b"],
                        "out":[{"name":"value","type":ty}], "attrs":{}}],
                "term":{"op":"ret","values":["value"]}
            }]
        }]
    })
}
fn run(document: &Value, function: &str, args: Vec<Value>, steps: u64) -> Value {
    execute_scalar(&serde_json::to_vec(document).unwrap(), function, &args, steps).unwrap()
}
#[test]
fn checked_and_wrapping_u64_arithmetic_are_distinct() {
    let a = json!(u64::MAX);
    let doc = machine("int.add.wrap", "u64", vec![]);
    assert_eq!(run(&doc, "calculate", vec![a.clone(),json!(2)], 100)["values"], json!([1]));
    let doc = machine("int.add.checked", "u64", vec!["trap"]);
    let result = run(&doc, "calculate", vec![a,json!(2)], 100);
    assert_eq!(result["status"], "trapped");
    assert_eq!(result["error"]["code"], "overflow");
    let doc = machine("int.mul.wrap", "u64", vec![]);
    assert_eq!(run(&doc, "calculate", vec![json!(u64::MAX),json!(u64::MAX)], 100)["values"], json!([1]));
}
#[test]
fn old_scalar_v6_profile_rejects_an_unreviewed_exports_field() {
    let mut doc = machine("int.add.wrap", "u32", vec![]);
    doc["exports"] = json!(["calculate"]);
    let args = vec![json!(2), json!(3)];
    // The Python canonical v1-v6 program grammar does not admit exports.
    // That feature belongs to the separately integrated v7 lineage.
    assert!(execute_scalar(&serde_json::to_vec(&doc).unwrap(),
                           "calculate", &args, 100).is_err());
}

#[test]
fn signed_division_and_remainder_truncate_toward_zero() {
    let division = machine("int.div.checked","i64",vec!["trap"]);
    assert_eq!(run(&division,"calculate",vec![json!(-7),json!(3)],100)["values"],json!([-2]));
    let remainder = machine("int.rem.checked","i64",vec!["trap"]);
    assert_eq!(run(&remainder,"calculate",vec![json!(-7),json!(3)],100)["values"],json!([-1]));
    let result = run(&division,"calculate",vec![json!(i64::MIN),json!(-1)],100);
    assert_eq!(result["error"]["code"],"overflow");
    let zero = run(&division,"calculate",vec![json!(2),json!(0)],100);
    assert_eq!(zero["error"]["code"],"division_by_zero");
}
#[test]
fn signed_minimum_division_and_remainder_trap_for_each_width() {
    for (ty, low) in [
        ("i8", -128_i64), ("i16", -32_768_i64),
        ("i32", -2_147_483_648_i64), ("i64", i64::MIN),
    ] {
        for op in ["int.div.checked", "int.rem.checked"] {
            let doc = machine(op, ty, vec!["trap"]);
            let result = run(&doc, "calculate", vec![json!(low), json!(-1)], 100);
            assert_eq!(result["status"], "trapped", "{op} {ty}");
            assert_eq!(result["error"]["code"], "overflow", "{op} {ty}");
            // A nearby negative input is representable and may be divided
            // normally. The fix must not turn every /-1 into a false trap.
            let safe = run(&doc, "calculate", vec![json!(low + 1), json!(-1)], 100);
            assert_eq!(safe["status"], "returned", "{op} {ty}");
            let expected = if op == "int.rem.checked" { 0 } else { -(low + 1) };
            assert_eq!(safe["values"], json!([expected]), "{op} {ty}");
        }
    }
    // A signed-only guard must not change unsigned remainder semantics.
    let unsigned = machine("int.rem.checked", "u64", vec!["trap"]);
    assert_eq!(
        run(&unsigned, "calculate", vec![json!(u64::MAX), json!(1)], 100)["values"],
        json!([0])
    );
}
#[test]
fn signed_shift_arithmetic_and_count_traps() {
    let shr = machine("int.shr.checked","i64",vec!["trap"]);
    assert_eq!(run(&shr,"calculate",vec![json!(-9),json!(2)],100)["values"],json!([-3]));
    assert_eq!(run(&shr,"calculate",vec![json!(1),json!(64)],100)["error"]["code"],"overflow");
    let shl = machine("int.shl.checked","i64",vec!["trap"]);
    assert_eq!(run(&shl,"calculate",vec![json!(1_i64 << 62),json!(2)],100)["values"],json!([0]));
}
fn iterative() -> Value {
    json!({
        "schema":"hepta.hia.program.v1", "module":"loop", "functions":[{
          "name":"counter","params":[{"name":"n","type":"u32"}],
          "returns":["u32"], "effects":["trap"], "entry":"entry",
          "blocks":[
            {"id":"entry","params":[{"name":"n","type":"u32"}],
             "ops":[
               {"op":"const","args":[],"out":[{"name":"zero","type":"u32"}],"attrs":{"value":0}},
               {"op":"const","args":[],"out":[{"name":"one","type":"u32"}],"attrs":{"value":1}}
             ],
             "term":{"op":"jump","target":"loop","args":["n","zero","one"]}},
            {"id":"loop","params":[{"name":"remain","type":"u32"},{"name":"total","type":"u32"},{"name":"step","type":"u32"}],
             "ops":[
               {"op":"const","args":[],"out":[{"name":"zero_loop","type":"u32"}],"attrs":{"value":0}},
               {"op":"compare.gt","args":["remain","zero_loop"],"out":[{"name":"condition","type":"bool"}],"attrs":{}}
             ],
             "term":{"op":"branch","cond":"condition","then":{"target":"body","args":["remain","total","step"]},
                                          "else":{"target":"done","args":["total"]}}},
            {"id":"body","params":[{"name":"r","type":"u32"},{"name":"acc","type":"u32"},{"name":"s","type":"u32"}],
             "ops":[
               {"op":"int.sub.checked","args":["r","s"],"out":[{"name":"remaining","type":"u32"}],"attrs":{}},
               {"op":"int.add.checked","args":["acc","s"],"out":[{"name":"updated","type":"u32"}],"attrs":{}}
             ],
             "term":{"op":"jump","target":"loop","args":["remaining","updated","s"]}},
            {"id":"done","params":[{"name":"answer","type":"u32"}],"ops":[],"term":{"op":"ret","values":["answer"]}}
          ]
        }]
    })
}
#[test]
fn phi_block_arguments_and_loop_step_budget() {
    let doc = iterative();
    let done = run(&doc,"counter",vec![json!(5)],100);
    assert_eq!(done["status"],"returned");
    assert_eq!(done["values"],json!([5]));
    assert_eq!(done["steps"],json!(38));
    let timed = run(&doc,"counter",vec![json!(100)],5);
    assert_eq!(timed["status"],"budget_exceeded");
    assert_eq!(timed["error"]["code"],"steps");
}
#[test]
fn invalid_program_or_wrong_type_cannot_enter_oracle() {
    let doc=machine("int.add.checked","u32",vec!["trap"]);
    let raw=serde_json::to_vec(&doc).unwrap();
    assert!(execute_scalar(&raw,"calculate",&[json!(true),json!(4)],100).is_err());
    assert!(execute_scalar(&raw,"calculate",&[json!(2),json!(4)],0).is_err());
    let mut invalid=doc;
    invalid["functions"][0]["blocks"][0]["ops"][0]["op"] = json!("owner.drop");
    assert!(execute_scalar(&serde_json::to_vec(&invalid).unwrap(),
                           "calculate",&[json!(2),json!(4)],100).is_err());
}
#[test]
fn recursion_is_bounded_independently_of_step_budget() {
    let doc=json!({
        "schema":"hepta.hia.program.v1","module":"recursion",
        "functions":[{
            "name":"recur","params":[{"name":"value","type":"i32"}],
            "returns":["i32"],"effects":[],"entry":"entry",
            "blocks":[{"id":"entry","params":[{"name":"value","type":"i32"}],
                "ops":[{"op":"call","args":["value"],
                    "out":[{"name":"result","type":"i32"}],"attrs":{"function":"recur"}}],
                "term":{"op":"ret","values":["result"]}}
            ]
        }]
    });
    let status=run(&doc,"recur",vec![json!(8)],1000);
    assert_eq!(status["status"],"budget_exceeded");
    assert_eq!(status["error"]["code"],"calls");
    // Python _Machine.invoke admits root depth=0 through nested depth=32:
    // 33 entered frames * (entry tick + call-op tick) = 66 actual ticks.
    // The previous Rust >= comparison stopped at depth 32 with only 64.
    assert_eq!(status["steps"], json!(66));
}
