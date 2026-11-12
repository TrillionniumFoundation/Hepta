"use strict";
// Static ASCII byte arithmetic only. Does not import/execute Hepta, CPython,
// a compiler, HIA, or the CLI. No program-admission result is claimed.
function witness(n) {
  function name(i) { return "v" + String(i).padStart(7, "0") + "x".repeat(120); }
  const ops = Array.from({length:n}, (_,i)=>({
    args:[], attrs:{value:0}, op:"const", out:[{name:name(i),type:"u32"}]
  }));
  return {functions:[{blocks:[{id:"entry",ops,params:[],
    term:{op:"ret",values:[name(n-1)]}}],effects:[],entry:"entry",
    name:"main",params:[],returns:["u32"]}],module:"pretty_capacity",
    schema:"hepta.hia.program.v1"};
}
function count(value, depth=0) {
  let nodes=1, maximum=depth;
  if(value!==null && typeof value==="object") {
    for(const child of (Array.isArray(value)?value:Object.values(value))) {
      const c=count(child,depth+1);nodes+=c.nodes;maximum=Math.max(maximum,c.maximum_depth);
    }
  }
  return {nodes,maximum_depth:maximum};
}
function measure(n) {
  const value=witness(n), compact=JSON.stringify(value),pretty=JSON.stringify(value,null,2);
  if(Array.from(compact+pretty).some(c=>c.charCodeAt(0)>127))throw Error("non-ASCII witness");
  const c=count(value);
  return {operations:n,unique_scalar_definitions:n,identifier_ascii_bytes:128,
    compact_ascii_bytes:compact.length,pretty_ascii_bytes_without_newline:pretty.length,
    stdout_ascii_bytes_with_newline:pretty.length+1,functions:1,blocks:1,...c};
}
return {schema:"hia.cli-json.static-capacity-arithmetic.v1",
  status:"V8_ASCII_ARITHMETIC_ONLY_NOT_PROGRAM_OR_CLI_EXECUTION",
  operation:"const u32=0, no operands/effects/resources; final ret of final definition",
  size_gate:8388608,node_gate:262144,depth_gate:64,
  rows:[measure(1),measure(2),measure(25000)]};
