//! Independent, bounded abstract interpretation of one checked Core invocation.
//!
//! This analysis never creates a Machine, calls an allocator, or executes a
//! path to observe a peak. Both CFG alternatives and all allocator outcomes
//! are overapproximated. The existing owned verifier remains the type/linear
//! admission authority; the complete structural budget audit excludes cycles,
//! chains and unknown operations before any invocation analysis begins.
use std::collections::{BTreeMap, BTreeSet};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use super::{analyze_static_budget, array, decode_hia, failure, object, scalar,
            string, term_edges, valid_constant, R};

mod scalars;
use scalars::{Fact, intrinsic};

const MAX_REQUEST: u64 = i64::MAX as u64;
const MAX_CONTEXTS: usize = 1024;
const MAX_TRANSFERS: u64 = 32768;
const MAX_DEPTH: usize = 64;
// Cumulative abstract-value creation/copy events, not a measured RSS limit.
// Charging before copies bounds large argument/state/cache inventories even
// when few instructions produce or forward many SSA values.
const MAX_VALUES: u64 = 262144;

fn unknown<T>(detail: &str) -> R<T> { failure("E_HIA_BUDGET_UNBOUNDED", detail) }
fn sum(a: u64, b: u64) -> R<u64> {
    a.checked_add(b).ok_or_else(|| super::VerifyError {
        code: "E_HIA_BUDGET_OVERFLOW", detail: "finite live payload bound exceeds u64".into(),
    })
}
fn name(value: &Value) -> R<&str> { string(value,"finite heap identifier") }
fn loan(ty: &str) -> bool { matches!(ty,"readbuf"|"mutbuf") }

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Argument { Scalar(Fact), Owned(u64), Borrowed(Option<u64>) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Root { Local(u64), External(Option<u64>) }
impl Root {
    fn upper(self) -> Option<u64> { match self { Self::Local(n)=>Some(n),Self::External(n)=>n } }
}
#[derive(Default)]
struct State {
    roots: BTreeMap<String,Root>,
    known: BTreeMap<String,Fact>,
    loans: BTreeMap<String,String>,
}
impl State {
    fn payload(&self) -> R<u64> {
        self.roots.values().try_fold(0,|total,root| match root {
            Root::Local(n)=>sum(total,*n), Root::External(_)=>Ok(total),
        })
    }
    fn fact(&self,n:&str)->Fact { self.known.get(n).copied().unwrap_or(Fact::Unknown) }
    fn root(&self,n:&str)->Option<&str> {
        if self.roots.contains_key(n) { self.roots.get_key_value(n).map(|(key,_)|key.as_str()) }
        else { self.loans.get(n).map(String::as_str) }
    }
    fn free_owner(&self,n:&str)->R<u64> {
        if self.loans.values().any(|root|root==n) { return unknown("bounded owner still has a live loan"); }
        match self.roots.get(n) { Some(Root::Local(n))=>Ok(*n),_=>unknown("free finite owner extent unavailable") }
    }
    fn merge(mut self,other:Self)->R<Self> {
        if !self.roots.keys().eq(other.roots.keys()) || self.loans!=other.loans {
            return unknown("incompatible owner inventory or borrowed roots at CFG join");
        }
        for (key,root) in &mut self.roots {
            *root=match (*root,other.roots[key]) {
                (Root::Local(a),Root::Local(b))=>Root::Local(a.max(b)),
                (Root::External(Some(a)),Root::External(Some(b)))=>Root::External(Some(a.max(b))),
                (Root::External(_),Root::External(_))=>Root::External(None),
                _=>return unknown("local owner and external root disagree at join"),
            };
        }
        self.known.retain(|key,value| {
            *value=value.join(other.fact(key)); *value!=Fact::Unknown
        });
        Ok(self)
    }
}

#[derive(Clone)]
struct ResultBound { peak:u64, returned:Option<Vec<Argument>> }
struct Function<'a> {
    source:&'a Value,
    blocks:BTreeMap<String,&'a Value>,
    order:Vec<String>,
}
struct Analysis<'a> {
    functions:BTreeMap<String,Function<'a>>,
    cache:BTreeMap<(String,Vec<Argument>),ResultBound>,
    contexts:usize, transfers:u64, depth:usize, peak_depth:usize, values:u64,
    borrowed_extents:bool,
}
impl<'a> Analysis<'a> {
    fn step(&mut self)->R<()> {
        self.transfers=sum(self.transfers,1)?;
        if self.transfers>MAX_TRANSFERS { return failure("E_HIA_BUDGET_LIMIT","finite heap transfer work limit"); }
        Ok(())
    }
    fn values(&mut self,n:usize)->R<()> {
        self.values=sum(self.values,n as u64)?;
        if self.values>MAX_VALUES { return failure("E_HIA_BUDGET_LIMIT","finite heap abstract-value work limit"); }
        Ok(())
    }
    fn invoke(&mut self,callee:&str,args:&[Argument])->R<ResultBound> {
        self.values(args.len()+1)?;
        let key=(callee.to_owned(),args.to_vec());
        if let Some(found)=self.cache.get(&key) {
            let size=found.returned.as_ref().map_or(0,Vec::len)+1;
            self.values(size)?;
            return Ok(self.cache[&key].clone());
        }
        if self.contexts>=MAX_CONTEXTS || self.depth>=MAX_DEPTH {
            return failure("E_HIA_BUDGET_LIMIT","finite heap context/depth work limit");
        }
        self.contexts+=1;self.depth+=1;self.peak_depth=self.peak_depth.max(self.depth);
        let calculated=self.function(callee,args);
        self.depth-=1;
        let result=calculated?;
        self.values(result.returned.as_ref().map_or(0,Vec::len)+1)?;
        self.cache.insert(key,result.clone());
        Ok(result)
    }

    fn function(&mut self,callee:&str,args:&[Argument])->R<ResultBound> {
        // Function ASTs are immutable borrows of the single decoded snapshot.
        // Only a bounded block-name schedule is copied per abstract context.
        let source=self.functions[callee].source;
        let params=array(&source["params"],"finite heap parameters")?;
        if params.len()!=args.len() { return unknown("finite invocation argument inventory differs"); }
        self.values(params.len()*3+self.functions[callee].order.len())?;
        let order=self.functions[callee].order.clone();
        let mut initial=State::default();
        for (p,arg) in params.iter().zip(args) {
            let id=name(&p["name"])?;let ty=name(&p["type"])?;
            match (ty,*arg) {
                ("buffer",Argument::Owned(n)) if n<=MAX_REQUEST=>{initial.roots.insert(id.into(),Root::Local(n));},
                (_,Argument::Borrowed(extent)) if loan(ty) &&
                    (extent.is_none() || self.borrowed_extents && extent.is_some_and(|n|n<=MAX_REQUEST))=>{
                    initial.roots.insert(id.into(),Root::External(extent));initial.loans.insert(id.into(),id.into());
                },
                (_,Argument::Scalar(fact)) if scalar(&p["type"]).is_ok()=>{
                    let fact=if fact==Fact::Unknown {intrinsic(ty)} else {fact};
                    if fact!=Fact::Unknown {initial.known.insert(id.into(),fact);}
                },
                _=>return unknown("unproved owned/borrowed argument extent"),
            }
        }
        let mut states=BTreeMap::from([(name(&source["entry"])?.to_owned(),initial)]);
        let mut peak=0;let mut returned:Option<Vec<Argument>>=None;
        for block_name in order {
            self.step()?;
            let Some(mut state)=states.remove(&block_name) else {continue;};
            let block=self.functions[callee].blocks[&block_name];
            peak=peak.max(state.payload()?);
            let mut stopped=false;
            for ins in array(&block["ops"],"finite heap instructions")? {
                self.step()?;
                let opcode=name(&ins["op"])?;let inputs=array(&ins["args"],"finite heap operands")?;
                let out=array(&ins["out"],"finite heap outputs")?;
                self.values(inputs.len()+out.len()*3+1)?;
                let operands=inputs.iter().map(name).collect::<R<Vec<_>>>()?;
                let output=out.first().map(|p|name(&p["name"])).transpose()?;
                let attrs=&ins["attrs"];
                match opcode {
                    "buffer.new"|"buffer.try_new"=>{
                        let Some((lo,hi))=state.fact(operands[0]).span() else {
                            return unknown("allocator extent lacks a finite verified bound");
                        };
                        if lo>MAX_REQUEST as i128 {
                            if opcode=="buffer.new" {stopped=true;break;}
                            state.roots.insert(output.unwrap().into(),Root::Local(0));
                            state.known.insert(name(&out[1]["name"])?.into(),Fact::Bool(false));
                            continue;
                        }
                        if lo<0 || hi>MAX_REQUEST as i128 {
                            return unknown("allocator extent crosses the supported object-size domain");
                        }
                        // A fallible request may produce a zero-byte logical
                        // owner. Its upper extent is charged, never assumed exact.
                        state.roots.insert(output.unwrap().into(),Root::Local(hi as u64));
                        peak=peak.max(state.payload()?);
                    },
                    "borrow.read"|"borrow.mut"=>{
                        let root=state.root(operands[0]).ok_or_else(||super::VerifyError {
                            code:"E_HIA_BUDGET_UNBOUNDED",detail:"borrow lacks a bounded root".into(),
                        })?.to_owned();
                        state.loans.insert(output.unwrap().into(),root);
                    },
                    "loan.end"=>{if state.loans.remove(operands[0]).is_none() {return unknown("loan end lacks a root");}},
                    "owner.move"|"owner.drop"=>{
                        let size=state.free_owner(operands[0])?;state.roots.remove(operands[0]);
                        if opcode=="owner.move" {state.roots.insert(output.unwrap().into(),Root::Local(size));}
                    },
                    "buffer.len"=>{
                        let Some(root)=state.root(operands[0]) else {return unknown("buffer length lacks root");};
                        if let Some(upper)=state.roots[root].upper() {
                            state.known.insert(output.unwrap().into(),Fact::Int(0,upper as i128));
                        }
                    },
                    "call"=>{
                        let child_name=name(&attrs["function"])?;
                        let child=self.functions[child_name].source;
                        let child_params=array(&child["params"],"callee parameters")?;
                        let mut actuals=Vec::new();let mut moved=BTreeSet::new();
                        for (p,actual) in child_params.iter().zip(&operands) {
                            let ty=name(&p["type"])?;
                            let bound=if ty=="buffer" {
                                if !moved.insert(*actual) {return unknown("duplicate owned actual");}
                                Argument::Owned(state.free_owner(actual)?)
                            } else if loan(ty) {
                                let Some(root)=state.loans.get(*actual) else {return unknown("borrowed actual lacks root");};
                                let Some(extent)=state.roots.get(root) else {return unknown("borrowed actual lost root");};
                                Argument::Borrowed(if self.borrowed_extents {extent.upper()} else {None})
                            } else {Argument::Scalar(state.fact(actual))};
                            actuals.push(bound);
                        }
                        for owned in moved {state.roots.remove(owned);}
                        let result=self.invoke(child_name,&actuals)?;
                        // Callee peak already includes the moved owners; only
                        // retained caller roots are added. Borrowed aliases add 0.
                        peak=peak.max(sum(state.payload()?,result.peak)?);
                        let Some(results)=result.returned else {stopped=true;break;};
                        if results.len()!=out.len() {return unknown("callee return inventory differs");}
                        for (p,bound) in out.iter().zip(results) {
                            let id=name(&p["name"])?;let ty=name(&p["type"])?;
                            match (ty,bound) {
                                ("buffer",Argument::Owned(n)) if n<=MAX_REQUEST=>{state.roots.insert(id.into(),Root::Local(n));},
                                (_,Argument::Borrowed(None)) if loan(ty) && self.borrowed_extents=>{},
                                (_,Argument::Scalar(fact)) if scalar(&p["type"]).is_ok()=>{
                                    if fact!=Fact::Unknown {state.known.insert(id.into(),fact);}
                                },
                                _=>return unknown("callee returned an unbounded resource"),
                            }
                        }
                        if let Some(origins)=child.get("return_loans") {
                            for (p,origin) in out.iter().zip(array(origins,"returned loan origins")?) {
                                if loan(name(&p["type"])?) {
                                    let formal=name(origin)?;
                                    let index=child_params.iter().position(|p|p["name"].as_str()==Some(formal))
                                        .ok_or_else(||super::VerifyError {code:"E_HIA_BUDGET_UNBOUNDED",detail:"returned loan origin missing".into()})?;
                                    let Some(root)=state.loans.get(operands[index]) else {return unknown("returned loan lost caller root");};
                                    state.loans.insert(name(&p["name"])?.into(),root.clone());
                                }
                            }
                        }
                        peak=peak.max(state.payload()?);
                    },
                    _=>{
                        // The full-module static audit already closed the
                        // opcode inventory. Pure arithmetic propagates facts;
                        // loads/stores/bulk operations allocate no payload here.
                        if let Some(p)=out.first() {
                            let args:Vec<_>=operands.iter().map(|n|state.fact(n)).collect();
                            let fact=scalars::transfer(opcode,&args,name(&p["type"])?,attrs)?;
                            if fact!=Fact::Unknown {state.known.insert(name(&p["name"])?.into(),fact);}
                        }
                    },
                }
            }
            if stopped {continue;}
            self.step()?;
            let term=&block["term"];
            if term["op"]=="ret" {
                let types=array(&source["returns"],"heap returns")?;
                self.values(types.len())?;
                let mut values=Vec::new();
                for (ty,value) in types.iter().zip(array(&term["values"],"return values")?) {
                    let ty=name(ty)?;let value=name(value)?;
                    values.push(if ty=="buffer" {Argument::Owned(state.free_owner(value)?)}
                    else if loan(ty) {
                        let Some(root)=state.loans.get(value) else {return unknown("returned loan lacks formal root");};
                        if !self.borrowed_extents || !matches!(state.roots.get(root),Some(Root::External(_))) {
                            return unknown("returned loan is not parameter bound");
                        }
                        Argument::Borrowed(None)
                    } else {Argument::Scalar(state.fact(value))});
                }
                if let Some(previous)=&mut returned {
                    for (old,new) in previous.iter_mut().zip(values) {
                        *old=match (*old,new) {
                            (Argument::Owned(a),Argument::Owned(b))=>Argument::Owned(a.max(b)),
                            (Argument::Scalar(a),Argument::Scalar(b))=>Argument::Scalar(a.join(b)),
                            (Argument::Borrowed(None),Argument::Borrowed(None))=>Argument::Borrowed(None),
                            _=>return unknown("incompatible return resource summary"),
                        };
                    }
                } else {returned=Some(values);}
            }
            // Do not prune either edge using a sample or exact branch flag.
            // Per-root joins may overestimate correlated owners, never erase one.
            for edge in term_edges(term)? {
                let params=array(&self.functions[callee].blocks[&edge.target]["params"],"edge parameters")?;
                self.values(params.len()*4+1)?;
                let mut remap=BTreeMap::new();
                for (source,p) in edge.args.iter().zip(params) {
                    let ty=name(&p["type"])?;
                    if ty=="buffer" || loan(ty) {remap.insert(source.as_str(),name(&p["name"])?);}
                }
                let mut proposed=State::default();
                for (source,p) in edge.args.iter().zip(params) {
                    let ty=name(&p["type"])?;let id=name(&p["name"])?;
                    if ty=="buffer" {
                        let Some(Root::Local(n))=state.roots.get(source) else {return unknown("edge missing bounded owner");};
                        proposed.roots.insert(id.into(),Root::Local(*n));
                    } else if loan(ty) {
                        let Some(root)=state.loans.get(source) else {return unknown("edge missing borrowed root");};
                        let Some(target_root)=remap.get(root.as_str()) else {return unknown("edge does not forward borrowed root");};
                        proposed.loans.insert(id.into(),(*target_root).into());
                        if let Some(Root::External(extent))=state.roots.get(root) {
                            proposed.roots.insert((*target_root).into(),Root::External(*extent));
                        }
                    } else {
                        let fact=state.fact(source);
                        if fact!=Fact::Unknown {proposed.known.insert(id.into(),fact);}
                    }
                }
                let merged=if let Some(previous)=states.remove(&edge.target) {previous.merge(proposed)?} else {proposed};
                states.insert(edge.target,merged);
            }
        }
        Ok(ResultBound {peak,returned})
    }
}

/// Derive a logical live-payload upper bound without running the Machine.
/// The exact scalar entry and all module types/graphs are independently checked.
pub fn analyze_finite_entry_heap(input:&[u8],function:&str,arguments:&[Value],heap_policy:&[u8])->R<Value> {
    if heap_policy.len()>1024 {return failure("E_HIA_BUDGET_POLICY","heap policy exceeds 1024 bytes");}
    let (policy,_)=decode_hia(heap_policy)?;
    let policy=object(&policy,&["max_live_heap_bytes"],"finite heap policy")?;
    let Some(limit)=policy["max_live_heap_bytes"].as_u64().filter(|n|*n<=MAX_REQUEST) else {
        return failure("E_HIA_BUDGET_POLICY","finite heap policy requires exact integer in 0..2^63-1");
    };
    let static_budget=analyze_static_budget(input)?;
    let (document,canonical)=decode_hia(input)?;
    let version=name(&document["schema"])?;
    if !matches!(version,"hepta.hia.program.v7"|"hepta.hia.program.v8") {
        return failure("E_HIA_BUDGET_PROFILE","finite invocation heap profile requires primitive v7/v8");
    }
    let mut functions=BTreeMap::new();
    for function in array(&document["functions"],"functions")? {
        let mut blocks=BTreeMap::new();let mut graph=BTreeMap::new();
        for block in array(&function["blocks"],"heap blocks")? {
            let id=name(&block["id"])?.to_owned();
            graph.insert(id.clone(),term_edges(&block["term"])?.into_iter().map(|e|e.target).collect());
            blocks.insert(id,block);
        }
        let order=super::static_budget::topological(&graph,"finite heap CFG")?;
        functions.insert(name(&function["name"])?.to_owned(),Function {source:function,blocks,order});
    }
    let Some(entry)=functions.get(function).map(|f|f.source) else {return failure("E_HIA_INPUT","unknown scalar entry");};
    if document.get("exports").is_some_and(|xs|!xs.as_array().unwrap().iter().any(|v|v.as_str()==Some(function))) {
        return failure("E_HIA_INPUT","entry is not explicitly exported");
    }
    let params=array(&entry["params"],"entry parameters")?;
    if params.iter().any(|p|scalar(&p["type"]).is_err()) || array(&entry["returns"],"entry returns")?.iter().any(|t|scalar(t).is_err()) {
        return failure("E_HIA_INPUT","heap boundary cannot import or return capabilities");
    }
    if params.len()!=arguments.len() || params.iter().zip(arguments).any(|(p,a)|!valid_constant(p["type"].as_str().unwrap(),a)) {
        return failure("E_HIA_INPUT","heap entry arguments are not exact typed scalars");
    }
    let mut analysis=Analysis {functions,cache:BTreeMap::new(),contexts:0,transfers:0,depth:0,
        peak_depth:0,values:0,borrowed_extents:version=="hepta.hia.program.v8"};
    analysis.values(arguments.len())?;
    let args:Vec<_>=arguments.iter().map(|v|Argument::Scalar(Fact::constant(v))).collect();
    let result=analysis.invoke(function,&args)?;
    if result.peak>limit {return failure("E_HIA_BUDGET_EXCEEDED","finite invocation live payload exceeds static policy");}
    let row=array(&static_budget["functions"],"static rows")?.iter().find(|r|r["function"].as_str()==Some(function)).unwrap();
    Ok(json!({
        "schema":"hepta.hia.rust-finite-entry-heap.v1",
        "profile":if analysis.borrowed_extents {"acyclic-byte-owner-transfer-caller-borrowed-extents-v8"} else {"acyclic-byte-owner-transfer-v7"},
        "status":"conservative_finite_invocation_payload_bound_not_authority",
        "program_sha256":format!("{:x}",Sha256::digest(&canonical)),"core_schema":version,
        "function":function,"arguments":arguments,"limit_bytes":limit,"peak_bound_bytes":result.peak,
        "max_vm_ticks":row["max_vm_ticks"],"max_allocator_interactions":row["max_allocator_interactions"],"max_call_depth":row["max_call_depth"],
        "static_budget_sha256":format!("{:x}",Sha256::digest(serde_json::to_vec(&static_budget).unwrap())),
        "analysis_work":{"contexts":analysis.contexts,"transfer_steps":analysis.transfers,
            "peak_analysis_call_depth":analysis.peak_depth,"abstract_value_events":analysis.values,
            "max_contexts":MAX_CONTEXTS,"max_transfer_steps":MAX_TRANSFERS,
            "max_analysis_call_depth":MAX_DEPTH,"max_abstract_value_events":MAX_VALUES},
        "claims":{"whole_module_independently_checked":true,"exact_scalar_invocation_only":true,
            "owned_call_transfer_accounted":true,"external_borrow_payload_counted_in_caller":true,
            "borrowed_extents_derived_from_caller_roots":analysis.borrowed_extents,
            "parameter_bound_returned_loans_checked":analysis.borrowed_extents,
            "allocation_failure_and_stop_prefixes_in_bound":true,"analysis_work_limits_enforced":true,
            "allocation_failure_index_specialized":false,"branch_reachability_proved":false,
            "all_function_input_extents_bounded":false,"caller_supplied_resource_extents_trusted":false,
            "borrowed_lengths_assumed_exact":false,"cleanup_after_trap_or_budget_stop_proved":false,
            "recursive_chain_storage_bounded":false,"process_rss_or_native_stack_bytes_bounded":false,
            "source_or_native_backend_refinement_proved":false,"whole_language_soundness_proved":false,
            "native_execution_authorized":false,"execution_used_to_establish_bound":false}
    }))
}
