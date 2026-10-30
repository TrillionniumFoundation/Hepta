//! Real raw admission, complete-module policy and unchanged v4 execution.
use std::io::Write;
use std::process::{Command, Stdio};

use hia_core_shadow::{admit_and_run_byte_dag, execute_owned_bound_v4};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn wire(value: &Value) -> Vec<u8> { serde_json::to_vec(value).unwrap() }
fn param(name: &str, ty: &str) -> Value { json!({"name":name,"type":ty}) }
fn owned() -> Value {
    json!({"schema":"hepta.hia.program.v8","module":"byte_dag","functions":[{
        "name":"allocate","params":[param("n","usize")],"returns":["bool"],
        "effects":["alloc"],"entry":"entry","blocks":[{
            "id":"entry","params":[param("n","usize")],"ops":[
                {"op":"buffer.try_new","args":["n"],"out":[param("owner","buffer"),param("ok","bool")],"attrs":{}},
                {"op":"owner.drop","args":["owner"],"out":[],"attrs":{}}],
            "term":{"op":"ret","values":["ok"]}}]}]})
}
fn limits() -> Value { json!({"max_allocator_interactions":2,"max_vm_ticks":4,"max_call_depth":1}) }
fn policy() -> Value { json!({"max_steps":4,"max_heap_bytes":8,"max_call_depth":1,"allocation_fail_at":null}) }
fn run(raw: &[u8], entry: &str, args: &[Value], bounds: &Value, runtime: &Value) -> Result<Value, hia_core_shadow::VerifyError> {
    admit_and_run_byte_dag(raw,entry,args,&wire(bounds),&wire(runtime))
}
fn identity() -> Value {
    json!({"name":"identity","params":[],"returns":[],"effects":[],"entry":"entry",
        "blocks":[{"id":"entry","params":[],"ops":[],"term":{"op":"ret","values":[]}}]})
}

#[test]
fn every_primitive_version_admits_exact_limits_and_preserves_complete_v4_observation() {
    for version in 1..=8 {
        let mut source=owned();source["schema"]=json!(format!("hepta.hia.program.v{version}"));
        for size in [0,3,9] {
            for failure in [Value::Null,json!("0x1"),json!("0x10000000000000001")] {
                let mut selected=policy();selected["allocation_fail_at"]=failure;
                let raw=wire(&source);let args=[json!(size)];
                let report=run(&raw,"allocate",&args,&limits(),&selected).unwrap();
                assert_eq!(report["runtime"],execute_owned_bound_v4(&raw,"allocate",&args,&wire(&selected)).unwrap());
                assert_eq!(report["claims"]["rust_interpreter_admission_authority_for_this_profile"],true);
                assert_eq!(report["claims"]["python_verifier_required_for_this_mode"],false);
                assert_eq!(report["claims"]["default_production_admission_changed"],false);
                assert_eq!(report["runtime"]["execution"]["claims"]["production_admission_authorized"],false);
            }
        }
    }
}

#[test]
fn raw_snapshot_static_limits_and_exact_runtime_policy_are_all_request_bound() {
    let source=owned();let canonical=wire(&source);
    let padded=serde_json::to_vec_pretty(&source).unwrap();
    let base=run(&canonical,"allocate",&[json!(3)],&limits(),&policy()).unwrap();
    let formatted=run(&padded,"allocate",&[json!(3)],&limits(),&policy()).unwrap();
    assert_eq!(base["runtime"],formatted["runtime"]);
    assert_eq!(base["static_budget"],formatted["static_budget"]);
    assert_ne!(base["request_sha256"],formatted["request_sha256"]);
    assert_eq!(formatted["request"]["input_sha256"],format!("{:x}",Sha256::digest(&padded)));
    assert_eq!(formatted["request_sha256"],format!("{:x}",Sha256::digest(wire(&formatted["request"]))));
    let mut changed=limits();changed["max_vm_ticks"]=json!(5);
    let looser=run(&canonical,"allocate",&[json!(3)],&changed,&policy()).unwrap();
    assert_ne!(base["request_sha256"],looser["request_sha256"]);
    assert_eq!(base["runtime"],looser["runtime"]);
    let mut changed=policy();changed["max_heap_bytes"]=json!(7);
    let other=run(&canonical,"allocate",&[json!(3)],&limits(),&changed).unwrap();
    assert_ne!(base["request_sha256"],other["request_sha256"]);
    assert_ne!(base["runtime"]["request_sha256"],other["runtime"]["request_sha256"]);
}

#[test]
fn one_below_any_limit_and_over_budget_private_functions_refuse_admission() {
    for (metric,value) in [("max_allocator_interactions",1),("max_vm_ticks",3),("max_call_depth",0)] {
        let mut bound=limits();bound[metric]=json!(value);
        assert_eq!(run(&wire(&owned()),"allocate",&[json!(0)],&bound,&policy()).unwrap_err().code,
                   "E_HIA_BUDGET_EXCEEDED");
    }
    let mut source=owned();source["functions"].as_array_mut().unwrap().push(identity());
    source["exports"]=json!(["identity"]);
    let mut bound=limits();bound["max_vm_ticks"]=json!(2);
    assert_eq!(run(&wire(&source),"identity",&[],&bound,&policy()).unwrap_err().code,"E_HIA_BUDGET_EXCEEDED");
    assert_eq!(run(&wire(&source),"identity",&[],&limits(),&policy()).unwrap()["runtime"]["execution"]["status"],"returned");
}

#[test]
fn lower_runtime_budgets_preserve_stopped_prefix_and_never_invent_cleanup() {
    let source=owned();let mut runtime=policy();runtime["max_steps"]=json!(2);
    let observed=run(&wire(&source),"allocate",&[json!(3)],&limits(),&runtime).unwrap();
    let stopped=&observed["runtime"]["execution"];
    assert_eq!(stopped["status"],"budget_exceeded");assert_eq!(stopped["error"]["code"],"steps");
    assert_eq!(stopped["steps"],3);assert_eq!(stopped["resources"]["live_bytes"],3);
    assert_eq!(stopped["resources"]["live_owners"],1);assert_eq!(stopped["resources"]["frees"],0);
    runtime=policy();runtime["max_heap_bytes"]=json!(2);
    let observed=run(&wire(&source),"allocate",&[json!(3)],&limits(),&runtime).unwrap();
    assert_eq!(observed["runtime"]["execution"]["error"]["code"],"heap");
    let mut trapped=source;trapped["functions"][0]["effects"]=json!(["alloc","trap"]);
    let op=&mut trapped["functions"][0]["blocks"][0]["ops"][0];
    op["op"]=json!("buffer.new");op["out"]=json!([param("owner","buffer")]);
    trapped["functions"][0]["returns"]=json!([]);
    trapped["functions"][0]["blocks"][0]["term"]["values"]=json!([]);
    runtime=policy();runtime["allocation_fail_at"]=json!("0x1");
    assert_eq!(run(&wire(&trapped),"allocate",&[json!(3)],&limits(),&runtime).unwrap()["runtime"]["execution"]["status"],"trapped");
}

#[test]
fn hidden_cycles_chains_invalid_ownership_and_nominal_schemas_never_run() {
    let mut source=owned();source["functions"].as_array_mut().unwrap().push(identity());
    source["exports"]=json!(["identity"]);
    let mut cycle=source.clone();
    cycle["functions"][0]["blocks"][0]["term"]=json!({"op":"jump","target":"loop","args":[]});
    cycle["functions"][0]["blocks"].as_array_mut().unwrap().push(json!({
        "id":"loop","params":[],"ops":[],"term":{"op":"jump","target":"loop","args":[]}}));
    assert_eq!(run(&wire(&cycle),"identity",&[],&limits(),&policy()).unwrap_err().code,"E_HIA_BUDGET_UNBOUNDED");
    let mut chain=source.clone();
    chain["functions"][0]["params"]=json!([param("owner","chain")]);
    chain["functions"][0]["returns"]=json!([]);
    chain["functions"][0]["blocks"][0]["params"]=json!([param("owner","chain")]);
    chain["functions"][0]["blocks"][0]["ops"]=json!([{"op":"owner.drop","args":["owner"],"out":[],"attrs":{}}]);
    chain["functions"][0]["blocks"][0]["term"]["values"]=json!([]);
    assert_eq!(run(&wire(&chain),"identity",&[],&limits(),&policy()).unwrap_err().code,"E_HIA_BUDGET_PROFILE");
    source["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap().pop();
    assert_eq!(run(&wire(&source),"identity",&[],&limits(),&policy()).unwrap_err().code,"E_HIA_RESOURCE");
    let mut nominal=owned();nominal["schema"]=json!("hepta.hia.composite.v4");
    assert_eq!(run(&wire(&nominal),"allocate",&[json!(3)],&limits(),&policy()).unwrap_err().code,"E_HIA_SCHEMA");
}

#[test]
fn raw_static_policy_has_exact_types_fields_duplicates_and_wire_boundaries() {
    let raw=wire(&owned());let runtime=wire(&policy());
    for value in [json!(true),json!(-1),json!(1.0),json!(null),json!("4")] {
        let mut altered=limits();altered["max_vm_ticks"]=value;
        assert!(admit_and_run_byte_dag(&raw,"allocate",&[json!(0)],&wire(&altered),&runtime).is_err());
    }
    let mut extra=limits();extra["trusted_proof"]=json!(true);
    assert!(admit_and_run_byte_dag(&raw,"allocate",&[json!(0)],&wire(&extra),&runtime).is_err());
    let duplicated=b"{\"max_allocator_interactions\":2,\"max_vm_ticks\":4,\"max_call_depth\":1,\"max_vm_ticks\":4}";
    assert!(admit_and_run_byte_dag(&raw,"allocate",&[json!(0)],duplicated,&runtime).is_err());
    let mut padded=wire(&limits());padded.resize(1024,b' ');
    assert!(admit_and_run_byte_dag(&raw,"allocate",&[json!(0)],&padded,&runtime).is_ok());
    padded.push(b' ');
    assert_eq!(admit_and_run_byte_dag(&raw,"allocate",&[json!(0)],&padded,&runtime).unwrap_err().code,"E_HIA_BUDGET_POLICY");
    let mut bad_runtime=policy();bad_runtime["allocation_fail_at"]=json!("0x01");
    assert_eq!(run(&raw,"allocate",&[json!(0)],&limits(),&bad_runtime).unwrap_err().code,"E_HIA_BUDGET_POLICY");
}

#[test]
fn private_entries_and_resource_capabilities_cannot_cross_public_boundary() {
    let mut source=owned();source["exports"]=json!([]);
    assert_eq!(run(&wire(&source),"allocate",&[json!(3)],&limits(),&policy()).unwrap_err().code,"E_HIA_INPUT");
    assert_eq!(run(&wire(&owned()),"allocate",&[json!(true)],&limits(),&policy()).unwrap_err().code,"E_HIA_INPUT");
    assert_eq!(run(&wire(&owned()),"allocate",&[json!({"owner":3})],&limits(),&policy()).unwrap_err().code,"E_HIA_INPUT");
}

#[test]
fn actual_cli_admits_and_executes_without_any_python_in_path() {
    let mut child=Command::new(env!("CARGO_BIN_EXE_hia-core-shadow"))
        .args(["--byte-dag-admit-run","allocate","[3]",
               std::str::from_utf8(&wire(&limits())).unwrap(),std::str::from_utf8(&wire(&policy())).unwrap()])
        .env_clear().env("PATH","/no-python-or-tools")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(&wire(&owned())).unwrap();
    let output=child.wait_with_output().unwrap();
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    let report:Value=serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["runtime"]["execution"]["values"],json!([true]));
    assert_eq!(report["claims"]["python_verifier_required_for_this_mode"],false);
}
