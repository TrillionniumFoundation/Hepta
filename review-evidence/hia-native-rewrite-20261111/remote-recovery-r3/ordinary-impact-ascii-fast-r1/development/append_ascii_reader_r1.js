"use strict";
// Text-only HIA source transformation. This is not a HIA interpreter or compiler.
function asciiReaderSource(name,slow){
 if(!/^f[0-9]+$/.test(name)||!/^f[0-9]+$/.test(slow)||name===slow)throw Error("function binding");
 return [
 "fn "+name+"(v0:readbuf,v1:u64) -> (u64) effects(read,write,trap) entry(b0)",
 "block b0(v0:readbuf,v1:u64)",
 "  v2:usize = buffer.len(v0)",
 '  v3:u64 = int.cast(v2) {"mode":"wrap"}',
 "  v4:bool = compare.ge(v1,v3)",
 "  branch v4 b3(v0,v1) b1(v0,v1)",
 "block b1(v5:readbuf,v6:u64)",
 '  v7:usize = int.cast(v6) {"mode":"wrap"}',
 "  v8:u8 = buffer.load(v5,v7)",
 '  v9:u64 = int.cast(v8) {"mode":"wrap"}',
 '  v10:u64 = const() {"value":32}',
 "  v11:bool = compare.ge(v9,v10)",
 '  v12:u64 = const() {"value":128}',
 "  v13:bool = compare.lt(v9,v12)",
 '  v14:u64 = const() {"value":34}',
 "  v15:bool = compare.ne(v9,v14)",
 '  v16:u64 = const() {"value":92}',
 "  v17:bool = compare.ne(v9,v16)",
 "  v18:bool = bool.and(v11,v13)",
 "  v19:bool = bool.and(v15,v17)",
 "  v20:bool = bool.and(v18,v19)",
 "  branch v20 b2(v5,v6,v9) b3(v5,v6)",
 "block b2(v21:readbuf,v22:u64,v23:u64)",
 '  v24:u64 = const() {"value":1}',
 "  v25:u64 = int.add.wrap(v22,v24)",
 '  v26:u64 = const() {"value":32}',
 "  v27:u64 = int.shl.checked(v25,v26)",
 "  v28:u64 = bit.or(v27,v23)",
 "  ret(v28)",
 "block b3(v29:readbuf,v30:u64)",
 '  v31:u64 = call(v29,v30) {"function":"'+slow+'"}',
 "  ret(v31)",
 "end",
 ""
 ].join("\n");
}
function transformASCIIReader(source,binding,identify,inspectProfile){
 const matches=[...source.matchAll(/^fn (f\d+)\(/gm)];
 if(!matches.length||!source.endsWith("end\n"))throw Error("complete canonical input required");
 const header=source.slice(0,matches[0].index),functions=matches.map((m,i)=>({name:m[1],text:source.slice(m.index,i+1<matches.length?matches[i+1].index:source.length)}));
 const map=binding.proof.mapping,caller=functions.find(f=>f.name===map.decode_string),slow=functions.find(f=>f.name===map.decoded);
 if(!caller||!slow||functions.filter(f=>f.name===map.decode_string).length!==1)throw Error("exact current source bindings");
 const helperName="f"+(Math.max(...functions.map(f=>Number(f.name.slice(1))))+1);
 const oldTarget='{"function":"'+map.decoded+'"}',newTarget='{"function":"'+helperName+'"}';
 const callLines=caller.text.split("\n").filter(l=>l.includes(oldTarget));
 if(callLines.length!==1||!/^  v\d+:u64 = call\(v\d+,v\d+\) \{"function":"f\d+"\}$/.test(callLines[0]))throw Error("one exact decoder read call required");
 const oldCall=callLines[0],newCall=oldCall.replace(oldTarget,newTarget),after=caller.text.replace(oldCall,newCall);
 if(after.replace(newCall,oldCall)!==caller.text||after===caller.text)throw Error("call exact inverse");
 const helper=asciiReaderSource(helperName,map.decoded);
 const result=header+functions.map(f=>f.name===map.decode_string?after:f.text).join("")+helper;
 if(result.slice(0,-helper.length).replace(after,caller.text)!==source)throw Error("complete source exact inverse");
 const profile=inspectProfile(result);
 if(!(profile.functions<=128&&profile.blocks<=1536&&profile.operations<=8192&&profile.max_function_blocks<=256&&profile.max_block_parameters<=16&&profile.max_ssa_numeric_suffix<2048))throw Error("unchanged bootstrap profile bounds");
 return {source:result,row:{
  role:binding.role,original:binding.original,input_inline:identify(source),candidate:identify(result),
  caller:map.decode_string,original_unicode_reader:map.decoded,
  helper:{name:helperName,...identify(helper),source:helper},
  old_call:oldCall,new_call:newCall,caller_before:identify(caller.text),caller_after:identify(after),
  unicode_reader:identify(slow.text),
  proof:{textual_profile:profile,one_call_target_and_one_appended_function_only:true,
   every_other_function_byte_unchanged:true,complete_reverse_to_inline_source_equal:true,
   fast_byte_set:"32 <= byte < 128, excluding byte34 quote and byte92 backslash",
   out_of_bounds_position_delegates_without_buffer_load:true,
   fast_return:"((position + 1) mod 2^64) << 32 OR byte, using the same original wrapping addition and checked shift",
   every_other_byte_calls_exact_original_unicode_reader:true,
   fallback_extra_reads:"One additional immutable in-bounds byte load; no mutation precedes the exact original reader call",
   mutable_buffers_and_cursor_operations_unchanged:true,
   no_bulk_access_no_cross_scalar_cursor_cache:true,
   arbitrary_VM_fuel_step_equivalence_claimed:false,
   only_textual_source_generation_executed:true,
   HIA_AST:0,B3:0,VM:0,native:0,performance_improvement_measured:false}
 }};
}
