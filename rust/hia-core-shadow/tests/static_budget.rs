//! Independent finite bound calculations and explicit unsupported boundaries.
use hia_core_shadow::{analyze_static_budget, execute_owned, verify_owned};
use serde_json::{json, Value};

fn wire(value: &Value) -> Vec<u8> { serde_json::to_vec(value).unwrap() }
fn parameter(name: &str, ty: &str) -> Value { json!({"name":name,"type":ty}) }
fn instruction(op: &str, args: Vec<&str>, outputs: Vec<Value>, attrs: Value) -> Value {
    json!({"op":op,"args":args,"out":outputs,"attrs":attrs})
}
fn function(name: &str, params: Vec<Value>, operations: Vec<Value>) -> Value {
    json!({"name":name,"params":params,"returns":[],"effects":["alloc","read","write","trap"],
        "entry":"entry","blocks":[{"id":"entry","params":params,"ops":operations,
            "term":{"op":"ret","values":[]}}]})
}
fn module(functions: Vec<Value>) -> Value {
    json!({"schema":"hepta.hia.program.v8","module":"static_budget","functions":functions})
}
fn owned() -> Value {
    module(vec![function("allocate",vec![parameter("n","usize")],vec![
        instruction("buffer.try_new",vec!["n"],vec![parameter("owner","buffer"),parameter("ok","bool")],json!({})),
        instruction("owner.drop",vec!["owner"],vec![],json!({})),
    ])])
}
fn bound(source: &Value) -> Value { analyze_static_budget(&wire(source)).unwrap() }

#[test]
fn zero_and_failed_allocations_still_receive_conservative_interaction_counts() {
    for version in 1..=8 {
        let mut source=owned();
        source["schema"]=json!(format!("hepta.hia.program.v{version}"));
        let result=bound(&source);
        assert_eq!(result["functions"][0],json!({"function":"allocate",
            "max_allocator_interactions":2,"max_vm_ticks":4,"max_call_depth":1}));
        for (size, failure) in [(0,None),(1,None),(1,Some(1))] {
            let run=execute_owned(&wire(&source),"allocate",&[json!(size)],20,16,failure).unwrap();
            assert_eq!(run["status"],"returned");
            assert!(run["steps"].as_u64().unwrap()<=4);
            assert!(run["resources"]["allocations"].as_u64().unwrap()+
                    run["resources"]["frees"].as_u64().unwrap()<=2);
        }
        assert_eq!(result["claims"]["live_heap_or_process_rss_bounded"],false);
        assert_eq!(result["claims"]["rust_is_production_admission_authority"],false);
    }
}

fn diamond() -> Value {
    module(vec![json!({"name":"choose","params":[parameter("decision","bool"),parameter("n","usize")],
        "returns":[],"effects":["alloc"],"entry":"entry","blocks":[
            {"id":"entry","params":[parameter("decision","bool"),parameter("n","usize")],"ops":[],
                "term":{"op":"branch","cond":"decision","then":{"target":"allocates","args":["n"]},
                    "else":{"target":"longer","args":[]}}},
            {"id":"allocates","params":[parameter("size","usize")],"ops":[
                instruction("buffer.try_new",vec!["size"],vec![parameter("owner","buffer"),parameter("ok","bool")],json!({})),
                instruction("owner.drop",vec!["owner"],vec![],json!({}))],"term":{"op":"ret","values":[]}},
            {"id":"longer","params":[],"ops":(0..4).map(|n|instruction("const",vec![],
                vec![parameter(&format!("v{n}"),"u8")],json!({"value":n}))).collect::<Vec<_>>(),
                "term":{"op":"ret","values":[]}}]})])
}

#[test]
fn branch_metrics_are_independent_maxima_not_an_exact_feasible_path_claim() {
    let source=diamond();let result=bound(&source);
    assert_eq!(result["functions"][0],json!({"function":"choose",
        "max_allocator_interactions":2,"max_vm_ticks":7,"max_call_depth":1}));
    assert_eq!(result["claims"]["exact_feasible_path_maxima_proved"],false);
    let yes=execute_owned(&wire(&source),"choose",&[json!(true),json!(1)],20,16,None).unwrap();
    let no=execute_owned(&wire(&source),"choose",&[json!(false),json!(1)],20,16,None).unwrap();
    assert_eq!(yes["steps"],5);assert_eq!(no["steps"],7);
    assert_eq!(yes["resources"]["allocations"],1);assert_eq!(no["resources"]["allocations"],0);
}

#[test]
fn repeated_calls_add_each_entry_and_callee_body_but_depth_uses_maximum() {
    let mut source=owned();
    source["functions"].as_array_mut().unwrap().push(function("twice",vec![parameter("n","usize")],vec![
        instruction("call",vec!["n"],vec![],json!({"function":"allocate"})),
        instruction("call",vec!["n"],vec![],json!({"function":"allocate"})),
    ]));
    let result=bound(&source);
    assert_eq!(result["functions"][1],json!({"function":"twice",
        "max_allocator_interactions":4,"max_vm_ticks":12,"max_call_depth":2}));
    let run=execute_owned(&wire(&source),"twice",&[json!(1)],20,16,None).unwrap();
    assert_eq!(run["steps"],12);
}

#[test]
fn a_trap_never_promises_cleanup_and_unreachable_suffix_cost_is_still_conservative() {
    let mut source=owned();
    source["functions"][0]["blocks"][0]["ops"][0]["op"]=json!("buffer.new");
    source["functions"][0]["blocks"][0]["ops"][0]["out"]=json!([parameter("owner","buffer")]);
    let result=bound(&source);
    let run=execute_owned(&wire(&source),"allocate",&[json!(1)],20,16,Some(1)).unwrap();
    assert_eq!(run["status"],"trapped");assert_eq!(run["steps"],2);
    assert_eq!(result["functions"][0]["max_vm_ticks"],4);
    assert_eq!(result["functions"][0]["max_allocator_interactions"],2);
}

#[test]
fn direct_and_mutual_recursion_are_refused_before_any_bounded_claim() {
    for mutual in [false,true] {
        let first=function("first",vec![],vec![instruction("call",vec![],vec![],json!({"function":if mutual {"second"} else {"first"}}))]);
        let mut source=module(vec![first]);
        if mutual { source["functions"].as_array_mut().unwrap().push(function("second",vec![],
            vec![instruction("call",vec![],vec![],json!({"function":"first"}))])); }
        verify_owned(&wire(&source)).unwrap();
        assert_eq!(analyze_static_budget(&wire(&source)).unwrap_err().code,"E_HIA_BUDGET_UNBOUNDED");
    }
}

#[test]
fn hidden_cfg_cycle_and_hidden_chain_declaration_are_not_ignored() {
    let mut cycle=module(vec![function("public",vec![],vec![]),function("hidden",vec![],vec![])]);
    cycle["exports"]=json!(["public"]);
    let blocks=cycle["functions"][1]["blocks"].as_array_mut().unwrap();
    blocks[0]["term"]=json!({"op":"jump","target":"loop","args":[]});
    blocks.push(json!({"id":"loop","params":[],"ops":[],"term":{"op":"jump","target":"loop","args":[]}}));
    verify_owned(&wire(&cycle)).unwrap();
    assert_eq!(analyze_static_budget(&wire(&cycle)).unwrap_err().code,"E_HIA_BUDGET_UNBOUNDED");
    let mut chain=module(vec![function("public",vec![],vec![]),function("destroy",vec![parameter("input","chain")],
        vec![instruction("owner.drop",vec!["input"],vec![],json!({}))])]);
    chain["exports"]=json!(["public"]);
    verify_owned(&wire(&chain)).unwrap();
    assert_eq!(analyze_static_budget(&wire(&chain)).unwrap_err().code,"E_HIA_BUDGET_PROFILE");
}

#[test]
fn invalid_resource_graph_is_not_qualified_by_an_empty_public_entry() {
    let mut source=owned();source["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap().pop();
    source["functions"].as_array_mut().unwrap().push(function("public",vec![],vec![]));
    source["exports"]=json!(["public"]);
    assert_eq!(analyze_static_budget(&wire(&source)).unwrap_err().code,"E_HIA_RESOURCE");
}

fn expanding_calls(count: usize) -> Value {
    module((0..count).map(|n|function(&format!("f{n}"),vec![],if n+1==count {vec![]} else {vec![
        instruction("call",vec![],vec![],json!({"function":format!("f{}",n+1)})),
        instruction("call",vec![],vec![],json!({"function":format!("f{}",n+1)})),
    ]})).collect())
}

#[test]
fn finite_exponential_cost_is_not_wrapped_into_a_small_bound() {
    let admitted=bound(&expanding_calls(62));
    assert_eq!(admitted["functions"][0]["max_vm_ticks"],json!(13_835_058_055_282_163_708u64));
    let too_large=expanding_calls(63);
    verify_owned(&wire(&too_large)).unwrap();
    assert_eq!(analyze_static_budget(&wire(&too_large)).unwrap_err().code,"E_HIA_BUDGET_OVERFLOW");
}
