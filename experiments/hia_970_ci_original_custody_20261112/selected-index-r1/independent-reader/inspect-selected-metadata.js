function inspect970SelectedMetadata(raw, expectedNames, compilerRecords) {
"use strict";
function require(v,m){if(!v)throw new Error(m);}
const value=JSON.parse(raw),rows=value.selected_members;
require(value.schema==="hia.ci-selected-original-members.v1"&&value.unselected_nested_phase_archives_replayed===false,"original SELECTED schema/scope differs");
require(Array.isArray(rows)&&rows.length===354&&expectedNames.length===354&&new Set(expectedNames).size===354,"original354 denominator differs");
const map=new Map();let total=0;
for(let n=0;n<rows.length;n++){
 const r=rows[n];require(r.original_name===expectedNames[n]&&r.retained_file===String(n).padStart(4,"0")+".raw","exact ordered selected member differs");
 require(Number.isSafeInteger(r.bytes)&&r.bytes>=0&&r.bytes<=134217728&&/^[0-9a-f]{64}$/.test(r.sha256),"original member extent/hash differs");
 require(r.actual_entire_member_read===true&&r.original_CRC_checked===true,"original complete-member record differs");
 const ir=r.independent_retained_file_readback;require(ir&&ir.bytes===r.bytes&&ir.sha256===r.sha256&&ir.actual_bytes_independently_read===r.bytes,"recorded full readback differs");
 require(Array.isArray(ir.identity)&&ir.identity.length===9,"recorded file identity shape differs");
 map.set(r.original_name,r);total+=r.bytes;
}
require(map.size===354&&total===112639137,"original raw-byte denominator differs");
require(value.directory.bytes===13678084&&value.directory.sha256==="9aeb1fb0ce400ef7e1d0e7a58bba55f7b5c3a80cdccbfb63ebbde3e814221e66","original DIRECTORY pin differs");
const sequence=["hia-cold.json","hia-cold.cold/qualification.json","hia-cold.cold/qualification.evidence/phase-index.json"];
for(const [owner,operation,gate,evidence,process] of compilerRecords){
 sequence.push(gate,evidence+"/report.json",process+"/process-owner.json",process+"/process-owner.json.request.json",process+"/run-result.json");
}
const entries=sequence.map((name,order)=>{const r=map.get(name);require(r,"observation member absent");return{order,name,bytes:r.bytes,sha256:r.sha256,retained_file:r.retained_file,size_exceeds_original4194304_observation_bound:r.bytes>4194304};});
const critical=[...new Set(["hia-cold.json","hia-cold.cold/qualification.json","hia-cold.cold/qualification.evidence/phase-index.json","hia-cold.cold/process-owner.json","hia-cold.cold/process-owner.json.request.json","hia-cold.cold/request.json",...compilerRecords.flatMap(([owner,operation,gate,evidence,process])=>[gate,evidence+"/report.json",process+"/run-result.json",process+"/process-owner.json",process+"/process-owner.json.request.json",process+"/stderr.log",process+"/stdout.log"])])].map(name=>{const r=map.get(name);require(r,"critical member absent");return{name,bytes:r.bytes,sha256:r.sha256,retained_file:r.retained_file};});
return{schema:"hia.970-selected-metadata-independent-inspection.v1",original_members:354,original_raw_bytes:total,observation_bound:4194304,observation_read_order:entries,first_size_ineligible_observation:entries.find(x=>x.size_exceeds_original4194304_observation_bound)||null,all_size_ineligible_observations:entries.filter(x=>x.size_exceeds_original4194304_observation_bound),largest_originals:[...rows].sort((a,b)=>b.bytes-a.bytes).slice(0,20).map(r=>({name:r.original_name,bytes:r.bytes,sha256:r.sha256})),critical_original_plan_inputs:critical,scope:"Exact sealedmetadata inspection only. No original CI body parsed/reexecuted; failed call fstat fields were not independently captured. OriginalHOLD remains.",identity_array_numeric_lexemes_not_reserialized:true};
}
