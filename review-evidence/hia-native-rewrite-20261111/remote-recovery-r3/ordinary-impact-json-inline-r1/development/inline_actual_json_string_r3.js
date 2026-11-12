"use strict";
// Mechanical HIA assembly source transformation, never an interpreter.
// Inline one ignored write_scalar call and each straight-line get/put call
// inside the exact decode_string function. All other function bytes remain.
function requireCondition(value,message){if(!value)throw new Error(message);}
function splitFunctions(source){
 const matches=[...source.matchAll(/^fn (f\d+)\(/gm)];
 requireCondition(matches.length>0 && source.endsWith("\n"),"function source shape");
 return {prefix:source.slice(0,matches[0].index),functions:matches.map((m,i)=>({name:m[1],text:source.slice(m.index,i+1<matches.length?matches[i+1].index:source.length)}))};
}
function parseFunction(source){
 const lines=source.split("\n");requireCondition(lines.pop()==="","final newline");
 const header=lines.shift();requireCondition(/^fn f\d+\(/.test(header),"header");
 requireCondition(lines.pop()==="end","function end");
 const blocks=[];
 for(const line of lines){
  const match=/^block (b\d+)\(([^)]*)\)$/.exec(line);
  if(match){const params=match[2]?match[2].split(",").map(x=>{const p=/^(v\d+):([A-Za-z0-9_]+)$/.exec(x);requireCondition(p,"block param");return{name:p[1],type:p[2]};}):[];blocks.push({name:match[1],params,body:[]});}
  else {requireCondition(blocks.length>0&&line.startsWith("  "),"body line");blocks[blocks.length-1].body.push(line);}
 }
 requireCondition(new Set(blocks.map(b=>b.name)).size===blocks.length,"duplicate block");
 return {header,blocks};
}
function renderFunction(fn){
 return fn.header+"\n"+fn.blocks.map(b=>"block "+b.name+"("+b.params.map(p=>p.name+":"+p.type).join(",")+")\n"+b.body.join("\n")+"\n").join("")+"end\n";
}
function callRow(line){
 const m=/^  (v\d+):u64 = call\(([^)]*)\) \{"function":"(f\d+)"\}$/.exec(line);
 return m?{out:m[1],args:m[2]?m[2].split(","):[],callee:m[3]}:null;
}
function terminalRow(line){
 let m=/^  jump (b\d+)\(([^)]*)\)$/.exec(line);
 if(m)return{kind:"jump",edges:[{block:m[1],args:m[2]?m[2].split(","):[]}]};
 m=/^  branch (v\d+) (b\d+)\(([^)]*)\) (b\d+)\(([^)]*)\)$/.exec(line);
 if(m)return{kind:"branch",condition:m[1],edges:[{block:m[2],args:m[3]?m[3].split(","):[]},{block:m[4],args:m[5]?m[5].split(","):[]}]};
 m=/^  ret\((v\d+)\)$/.exec(line);
 return m?{kind:"ret",value:m[1]}:null;
}
function renderTerminal(row){
 if(row.kind==="jump")return"  jump "+row.edges[0].block+"("+row.edges[0].args.join(",")+")";
 if(row.kind==="branch")return"  branch "+row.condition+" "+row.edges.map(e=>e.block+"("+e.args.join(",")+")").join(" ");
 return"  ret("+row.value+")";
}
function normalizeFunction(source){return source.replace(/^fn f\d+\(/,"fn FUNCTION(").replace(/"function":"f\d+"/g,'"function":"CALL"');}
function inspectProfile(source){
 const parsed=splitFunctions(source),fs=parsed.functions.map(f=>{
  const p=parseFunction(f.text),variables=[...f.text.matchAll(/\bv(\d+)\b/g)].map(m=>Number(m[1]));
  return{name:f.name,blocks:p.blocks.length,operations:p.blocks.reduce((s,b)=>s+b.body.filter(l=>/^  (?:v\d+:[A-Za-z0-9_]+|_) = /.test(l)).length,0),max_block_parameters:Math.max(...p.blocks.map(b=>b.params.length)),max_ssa_numeric_suffix:Math.max(...variables)};
 });
 return{functions:fs.length,blocks:fs.reduce((s,f)=>s+f.blocks,0),operations:fs.reduce((s,f)=>s+f.operations,0),max_function_blocks:Math.max(...fs.map(f=>f.blocks)),max_block_parameters:Math.max(...fs.map(f=>f.max_block_parameters)),max_ssa_numeric_suffix:Math.max(...fs.map(f=>f.max_ssa_numeric_suffix)),per_function:fs};
}
function transformInline(source,binding,reference){
 const module=splitFunctions(source),byName=new Map(module.functions.map(f=>[f.name,f.text])),map=binding.mapping;
 const before=byName.get(map.decode_string),writer=byName.get(map.write_scalar);
 requireCondition(normalizeFunction(before)===normalizeFunction(reference.decode_string),"exact decoder shape");
 requireCondition(normalizeFunction(writer)===normalizeFunction(reference.write_scalar),"exact writer shape");
 const caller=parseFunction(before),callee=parseFunction(writer),get=parseFunction(byName.get(map.get)),put=parseFunction(byName.get(map.put));
 requireCondition(caller.blocks.length===6 && callee.blocks.length===8,"exact expected CFG cardinalities");
 const allIds=[...before.matchAll(/\bv(\d+)\b/g)].map(m=>Number(m[1]));
 let nextValue=Math.max(...allIds)+1,nextBlock=Math.max(...caller.blocks.map(b=>Number(b.name.slice(1))))+1;
 const fresh=()=>"v"+nextValue++;
 const targets=caller.blocks.flatMap(b=>b.body.map((line,index)=>({block:b,index,line,call:callRow(line)}))).filter(x=>x.call&&x.call.callee===map.write_scalar);
 requireCondition(targets.length===1,"one exact ignored writer call");
 const target=targets[0],cont=terminalRow(target.block.body[target.index+1]);
 requireCondition(target.index===target.block.body.length-2&&cont&&cont.kind==="jump","writer continuation");
 requireCondition(cont.edges[0].args.length===6 && target.call.args.length===3,"continuation arity");
 const outputOccurrences=[...before.matchAll(new RegExp("\\b"+target.call.out+"\\b","g"))].length;
 requireCondition(outputOccurrences===1,"writer result must remain unused");
 const continuation=cont.edges[0],carryOriginal=[continuation.args[0],...continuation.args.slice(3)];
 const carryTypes=["readbuf","u64","u64","bool"];
 requireCondition(target.call.args[0]===continuation.args[1]&&target.call.args[1]===continuation.args[2],"buffer continuation identity");
 const types=new Map();
 for(const b of caller.blocks){for(const p of b.params)types.set(p.name,p.type);for(const line of b.body){const m=/^  (v\d+):([A-Za-z0-9_]+) = /.exec(line);if(m)types.set(m[1],m[2]);}}
 requireCondition(carryOriginal.every((v,i)=>types.get(v)===carryTypes[i]),"carry types");
 const valueMap=new Map([...new Set([...writer.matchAll(/\bv\d+\b/g)].map(m=>m[0]))].map(v=>[v,fresh()]));
 const blockMap=new Map(callee.blocks.map(b=>[b.name,"b"+nextBlock++]));
 const rename=line=>line.replace(/\bv\d+\b/g,v=>{requireCondition(valueMap.has(v),"unknown writer value");return valueMap.get(v);});
 const cloned=[];
 for(const b of callee.blocks){
  requireCondition(b.params.length>=2 && b.params[0].type==="mutbuf" && b.params[1].type==="mutbuf","writer ordered buffers");
  const extras=carryTypes.map(type=>({name:fresh(),type})),extraNames=extras.map(p=>p.name),last=terminalRow(b.body[b.body.length-1]);
  requireCondition(last,"writer terminal");
  const body=b.body.slice(0,-1).map(rename);
  if(last.kind==="ret"){
   body.push(renderTerminal({kind:"jump",edges:[{block:continuation.block,args:[extraNames[0],valueMap.get(b.params[0].name),valueMap.get(b.params[1].name),...extraNames.slice(1)]}]}));
  }else{
   for(const edge of last.edges){
    requireCondition(edge.args[0]===b.params[0].name&&edge.args[1]===b.params[1].name,"writer must forward ordered buffers unchanged");
    requireCondition(blockMap.has(edge.block),"writer successor");
   }
   body.push(renderTerminal({kind:last.kind,condition:last.condition?valueMap.get(last.condition):undefined,
    edges:last.edges.map(e=>({block:blockMap.get(e.block),args:e.args.map(v=>valueMap.get(v)).concat(extraNames)}))}));
  }
  cloned.push({name:blockMap.get(b.name),params:b.params.map(p=>({name:valueMap.get(p.name),type:p.type})).concat(extras),body});
 }
 const entry=callee.blocks[0];
 requireCondition(entry.params.map(p=>p.type).join(",")==="mutbuf,mutbuf,u64","writer entry");
 target.block.body.splice(target.index,2,renderTerminal({kind:"jump",edges:[{block:blockMap.get(entry.name),args:target.call.args.concat(carryOriginal)}]}));
 caller.blocks.push(...cloned);
 const expandedWriter=renderFunction(caller);
 let wordCalls=0,clonedWordOperations=0;
 const wordBindings=new Map([[map.get,get],[map.put,put]]);
 const allowed=new Set(["const","int.add.wrap","int.cast","bit.or","bit.and","int.shl.checked","int.shr.checked","buffer.load","buffer.store"]);
 for(const b of caller.blocks){
  const body=[];
  for(const line of b.body){
   const c=callRow(line),word=c&&wordBindings.get(c.callee);
   if(!word){body.push(line);continue;}
   requireCondition(word.blocks.length===1,"exact straight-line word helper");
   const one=word.blocks[0],ret=terminalRow(one.body[one.body.length-1]);
   requireCondition(ret&&ret.kind==="ret"&&c.args.length===one.params.length,"word helper signature");
   const defs=one.body.slice(0,-1).map(l=>/^  (v\d+):[A-Za-z0-9_]+ = /.exec(l)).filter(Boolean).map(m=>m[1]);
   const returnsParameter=one.params.some(p=>p.name===ret.value);
   requireCondition(defs.includes(ret.value)||returnsParameter,"word return must be a known scalar");
   if(returnsParameter)requireCondition([...renderFunction(caller).matchAll(new RegExp("\\b"+c.out+"\\b","g"))].length===1,"parameter-return call output must be unused");
   const remap=new Map(one.params.map((p,i)=>[p.name,c.args[i]]));
   for(const v of defs){requireCondition(!remap.has(v),"word SSA");remap.set(v,v===ret.value?c.out:fresh());}
   for(const op of one.body.slice(0,-1)){
    const mm=/^  (?:v\d+:[A-Za-z0-9_]+|_) = ([A-Za-z0-9_.]+)\(/.exec(op);
    requireCondition(mm&&allowed.has(mm[1]),"word helper operation allowlist");
    body.push(op.replace(/\bv\d+\b/g,v=>{requireCondition(remap.has(v),"word unknown SSA");return remap.get(v);}));
    clonedWordOperations++;
   }
   wordCalls++;
  }
  b.body=body;
 }
 requireCondition(wordCalls===8,"exact eight static word helper call sites");
 const after=renderFunction(caller);
 const remainingCalls=[...after.matchAll(/"function":"(f\d+)"/g)].map(m=>m[1]);
 requireCondition(remainingCalls.length===1&&remainingCalls[0]===map.decoded,"only original Unicode reader call remains");
 const outputs=caller.blocks.flatMap(b=>b.params.map(p=>p.name).concat(b.body.map(l=>/^  (v\d+):[A-Za-z0-9_]+ = /.exec(l)).filter(Boolean).map(m=>m[1])));
 requireCondition(outputs.length===new Set(outputs).size,"new SSA definitions unique");
 const fnByName=new Map(caller.blocks.map(b=>[b.name,b]));
 for(const b of caller.blocks){const term=terminalRow(b.body[b.body.length-1]);requireCondition(term,"new terminal");if(term.edges)for(const e of term.edges)requireCondition(fnByName.has(e.block)&&fnByName.get(e.block).params.length===e.args.length,"new edge arity");}
 const result=module.prefix+module.functions.map(f=>f.name===map.decode_string?after:f.text).join("");
 requireCondition(result.replace(after,before)===source && result.split(after).length===2,"full exact inverse");
 const profile=inspectProfile(result);
 requireCondition(profile.functions<=128&&profile.blocks<=1536&&profile.operations<=8192&&profile.max_function_blocks<=256&&profile.max_block_parameters<=16&&profile.max_ssa_numeric_suffix<2048,"unchanged textual profile bounds role="+binding.role+" "+JSON.stringify(Object.fromEntries(Object.entries(profile).filter(([k])=>k!=="per_function"))));
 return{source:result,before_function:before,after_function:after,expanded_writer_before_word_inlining:expandedWriter,proof:{role:binding.role,mapping:map,ignored_writer_call_sites:1,inlined_straight_line_word_calls:wordCalls,cloned_word_operations:clonedWordOperations,all_other_function_bytes_identical:true,complete_reverse_source_equality:true,removed_operations_only_call_return_and_scalar_parameter_transport:true,all_memory_operations_and_guarded_arithmetic_copied_in_order:true,output_cursor_read_and_written_on_every_original_scalar:true,no_cross_scalar_cursor_cache:true,original_readonly_input_and_mutable_buffer_operation_order_preserved:true,profile_is_textual_not_Core_or_B3_qualification:true,textual_profile:profile,HIA_AST_parse:0,B3:0,VM:0,native:0}};
}

function compactExactOversizedSSA(source,allowedNames){
 const module=splitFunctions(source),changed=[];
 const rewritten=module.functions.map(fn=>{
  const values=[...new Set([...fn.text.matchAll(/\bv\d+\b/g)].map(m=>m[0]))],max=Math.max(...values.map(x=>Number(x.slice(1))));
  if(max<2048){requireCondition(!allowedNames.includes(fn.name),"unexpected approved alpha target already bounded");return fn.text;}
  requireCondition(allowedNames.includes(fn.name)&&values.length<2048,"SSA alpha target not exactly approved");
  for(const q of fn.text.matchAll(/"(?:[^"\\]|\\.)*"/g))requireCondition(!/\bv\d+\b/.test(q[0]),"SSA-looking token inside literal");
  const mapping=new Map(values.map((v,i)=>[v,"v"+i])),reverse=new Map([...mapping].map(([a,b])=>[b,a]));
  const after=fn.text.replace(/\bv\d+\b/g,v=>mapping.get(v));
  requireCondition(after.replace(/\bv\d+\b/g,v=>reverse.get(v))===fn.text,"alpha exact full inverse");
  requireCondition(new Set(mapping.values()).size===mapping.size,"alpha bijection");
  changed.push({name:fn.name,before:fn.text,after,mapping:[...mapping].map(([before,after])=>({before,after})),original_max:max,new_max:values.length-1,unique_values:values.length});
  return after;
 }).join("");
 requireCondition(changed.length===allowedNames.length&&changed.every(c=>allowedNames.includes(c.name)),"exact alpha target count");
 return{source:module.prefix+rewritten,changed};
}
function makeInlineCandidate(source,binding,reference){
 const alpha=compactExactOversizedSSA(source,binding.role===27?["f2"]:[]);
 const inlined=transformInline(alpha.source,binding,reference);
 let inverse=inlined.source.replace(inlined.after_function,inlined.before_function);
 for(const c of alpha.changed)inverse=inverse.replace(c.after,c.before);
 requireCondition(inverse===source,"two stage complete original inverse");
 return{...inlined,alpha_source:alpha.source,alpha_changes:alpha.changed,
  proof:{...inlined.proof,all_other_function_bytes_identical_relative_to_alpha_input:true,
   alpha_function_names:alpha.changed.map(c=>c.name),alpha_values_total:alpha.changed.reduce((s,c)=>s+c.unique_values,0),
   full_two_stage_inverse_equals_complete_actual_original:true,
   actual_original_function_changes:[binding.mapping.decode_string,...alpha.changed.map(c=>c.name)],
   all_actual_original_other_function_bytes_identical:true}};
}
