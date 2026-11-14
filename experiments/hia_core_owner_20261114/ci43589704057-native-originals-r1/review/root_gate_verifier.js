return function(load,store){
const N="root_v8_CurrentNative_capture",R=(new Function(load("root_runtime_helper_recovered_v6")))()();
const read=(new Function("load","store",load(N+"_native_original_reader_source")))(load,store)(N,R),inv=load(N+"_native_inventory_by_name"),sel=load(N+"_selected_by_name"),map=load("root_v7_CoreBalanced_derive8_actual_source_map900").data,leaves=load("root_v7_CoreBalanced_final_source_leaves"),base="/home/runner/work/_temp/",repo="/home/runner/work/Hepta/Hepta/";
const sort=x=>Array.isArray(x)?x.map(sort):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,sort(x[k])])):x,eq=(a,b)=>JSON.stringify(sort(a))===JSON.stringify(sort(b));
const checks=[];function chk(name,x){checks.push({name,pass:!!x});if(!x)throw Error(name)}
const pins=[],unknown=[];
function walk(v,key){
 if(!v||typeof v!=="object")return;
 if(typeof v.path==="string"&&Number.isSafeInteger(v.bytes)&&typeof v.sha256==="string"&&/^[0-9a-f]{64}$/.test(v.sha256)){
  if(v.path.startsWith(base)){
   const p=v.path.slice(base.length),i=inv[p];chk(key+": inventory pin "+p,!!i&&i.body_fully_read===true&&i.bytes===v.bytes&&i.sha256===v.sha256);
   let rootRead=false;
   if(sel[p]){const r=read(p);chk(key+": raw selected pin "+p,r.bytes===v.bytes&&r.sha256===v.sha256);rootRead=true;}
   pins.push({path:p,bytes:v.bytes,sha256:v.sha256,root_body_read:rootRead,collector_body_read:true});
  } else if(v.path.startsWith(repo)){
   const p=v.path.slice(repo.length),leaf=leaves.find(x=>x.path===p);chk(key+": source pin "+p,!!leaf&&leaf.size===v.bytes&&map[p]===v.sha256);
   pins.push({path:p,bytes:v.bytes,sha256:v.sha256,source900:true});
  } else {unknown.push(v);throw Error("unmapped pin "+v.path)}
 }
 for(const [k,x]of Object.entries(v))walk(x,key+"/"+k);
}
const gates=[];
for(const p of ["hia-core-lowering-gate.json","hia-machine-elf-component-gate.json","hia-machine-elf-caller-gate.json","hia-machine-elf-component-owner/component-child-gate.json"]){
 const r=read(p,true),g=r.data;
 chk(p+": source exact",eq(g.source_before,map)&&eq(g.source_after,map)&&g.source_preserved===true);
 chk(p+": original pass",g.schema==="hepta.hia.compiler-owner-gate.v1"&&g.scope==="MATCHING_SOURCE_COLD_OWNER_GATES"&&g.status==="PASS"&&g.whole_native_delivery_qualified===false&&g.development_or_prior_result_reused===false&&g.cold_inputs_preserved===true);
 chk(p+": gates true",Object.values(g.gates).every(x=>x===true));
 walk(g.inspection,p+"/inspection");walk(g.cold_inputs,p+"/cold");
 if(g.inspection.process_owner){
  const o=g.inspection.process_owner;chk(p+": owner180+3 natural",o.qualification_seconds===180&&o.cleanup_seconds===3&&o.natural_exit_and_echild===true&&o.historical_descendant_inventory_complete===false);
 }
 gates.push({path:p,bytes:r.bytes,sha256:r.sha256,git:r.git,seconds:g.seconds,passed:Object.keys(g.gates),status:g.status});
}
const root="hia-machine-elf-component-evidence/fixture/MachineElfNativeTests",c55=read(root+"/complete-55.json",true),defs=load(N+"_source_tests/hia_machine_elf_cases.json").data;
chk("ELF reconstructed55 declared",c55.data.revision===defs.revision&&defs.revision==="RECONSTRUCTED_NEW_55_NOT_RECOVERED_OLD_CONTROL"&&c55.data.loaded===55&&c55.data.executed===55&&c55.data.cases.length===55&&new Set(c55.data.cases.map(x=>x.id)).size===55&&eq(c55.data.cases.map(x=>x.id),defs.cases.map(x=>x.id)));
let hex=0;
function checkHex(o,label){chk(label+": canonical hex",typeof o.hex==="string"&&/^(?:[0-9a-f]{2})+$/.test(o.hex));const b=Uint8Array.from(o.hex.match(/../g).map(x=>parseInt(x,16)));chk(label+": bytes SHA",b.length===o.bytes&&R.sha256(b)===o.sha256);hex++;}
for(let i=0;i<55;i++){
 const a=c55.data.cases[i];chk("ELF55 "+a.id,a.equal===true&&eq(a.original,a.native)&&a.original[0]===defs.cases[i].expected_kind);
 if(a.original[0]==="bytes")checkHex(a.original[1],"ELF55 "+a.id);
}
chk("ELF55 native counts positive",Object.values(c55.data.native_operation_counts).every(v=>Number.isSafeInteger(v)&&v>0));
const ret=read(root+"/complete-return-object.json",true).data;
chk("ELF full dataclass same identity",eq(ret.selected,ret.same_identity_oracle)&&eq(ret.selected,ret.frozen)&&eq(ret.original.object_bytes,ret.selected.object_bytes)&&ret.original.implementation_sha256!==ret.selected.implementation_sha256);
checkHex(ret.selected.object_bytes,"ELF return");
const src=load(N+"_source_tools/hia_compiler_owner_gates.py").text,block=src.slice(src.indexOf("ELF_BOUNDARIES = ("),src.indexOf("\n\n\ndef compare_gzip_pair"));
const expected=[...block.matchAll(/\('([^']+)', (\d+), (\d+), (\d+), (\d+), (None|'[^']*')\)/g)].map(m=>({case:m[1],code_bytes:+m[2],symbols:+m[3],relocations:+m[4],alignment:+m[5],error:m[6]==="None"?null:m[6].slice(1,-1)}));
chk("ELF11 original gate literals",expected.length===11);
const runtime=read("hia-machine-elf-component-gate.json",true).data.inspection.component_runtime,pairs=load(N+"_elf_gzip_pairs_closed"),bounds=[];
chk("ELF declared cases archives",runtime.boundary_cases.length===11&&runtime.complete_boundary_cases===11&&runtime.complete_decoded_archive_count===12&&pairs.length===6);
for(let i=0;i<11;i++){
 const e=expected[i],record=runtime.boundary_cases[i],p=record.observation.path.slice(base.length),raw=read(p,true),d=raw.data;
 chk("ELF boundary literals "+e.case,["case","code_bytes","symbols","relocations","alignment"].every(k=>d[k]===e[k])&&d.equal===true);
 chk("ELF boundary counts "+e.case,Object.values(d.native_operation_counts).every(v=>Number.isSafeInteger(v)&&v>0)&&Object.keys(d.native_operation_counts).length>0);
 if(e.error!==null)chk("ELF boundary exception "+e.case,eq(d.original,d.native)&&eq(d.original,{args:[e.error],kind:"exception",type:"MachineObjectError"})&&record.archive_replay===null);
 else{
  const pair=pairs.find(x=>x.case===e.case);chk("ELF root entire decode "+e.case,!!pair&&pair.gzip_bytes_identical===true&&pair.single_original_decoded_entirely===true&&pair.native_complete_gzip_bytes_identical_to_decoded_original===true);
  for(const k of ["original","native"])chk("ELF boundary full output "+e.case+" "+k,d[k].kind==="bytes"&&d[k].bytes===pair.decoded_bytes_each&&d[k].sha256===pair.decoded_sha256&&d[k].archive_sha256===pair.compressed_sha256&&d[k].archive===e.case+"-"+k+".elf.gz");
  chk("ELF original gate decoder agreement "+e.case,record.archive_replay.decoded_bytes_each===pair.decoded_bytes_each&&record.archive_replay.decoded_sha256===pair.decoded_sha256);
 }
 bounds.push({...e,observation:{path:p,bytes:raw.bytes,sha256:raw.sha256},positive_native_operation_keys:Object.keys(d.native_operation_counts).length,bytes:e.error===null?d.original.bytes:null});
}
const unique=Object.values(Object.fromEntries(pins.map(x=>[x.path,x])));
store(N+"_gate_actual_binding_checks",checks);store(N+"_gate_actual_closures",{gates,boundaries:bounds,case55:{loaded:55,executed:55,revision:defs.revision,bytes:c55.bytes,sha256:c55.sha256,hex_records_verified:hex},pin_occurrences:pins.length,unique_pins:unique,whole_native_delivery:false,root_boundary_decodes:6,root_complete_compressed_files:12,original_gate_decodes:12});
return {all_true:true,checks:checks.length,gates:gates.map(x=>({path:x.path,status:x.status,seconds:x.seconds,pass_keys:x.passed})),pin_occurrences:pins.length,unique_pins:unique.length,unique_root_bodies:unique.filter(x=>x.root_body_read).length,elf_boundaries:11,case55:55,hex_records:hex,root_decodes:6,root_full_equal_compressed_pairs:6};
};