
function validate(document) {
 const fns=new Map(document.functions.map(f=>[f.name,f]));if(fns.size!==document.functions.length)throw Error("duplicate function");
 let operations=0,blocks=0,maximumNames=0,maximumArgs=0;
 for(const f of document.functions){
  const blockMap=new Map(f.blocks.map(b=>[b.id,b]));if(blockMap.size!==f.blocks.length)throw Error("duplicate block");
  const entry=blockMap.get(f.entry);if(JSON.stringify(entry.params)!==JSON.stringify(f.params))throw Error("entry parameters");
  const names=new Set();for(const b of f.blocks){blocks++;const local=new Map();
   for(const p of b.params){if(names.has(p.name))throw Error("duplicate SSA "+f.name+" "+p.name);names.add(p.name);local.set(p.name,p.type);}
   maximumArgs=Math.max(maximumArgs,b.params.length);
   for(const op of b.ops){operations++;const types=op.args.map(n=>{if(!local.has(n))throw Error("undefined "+f.name+"/"+b.id+" "+n);return local.get(n);});const outTypes=op.out.map(v=>v.type);
    const exact=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
    if(op.op==="call"){const target=fns.get(op.attrs.function);if(!target||!exact(types,target.params.map(x=>x.type))||!exact(outTypes,target.returns))throw Error("call interface");}
    else if(op.op==="const"){if(types.length!==0||outTypes.length!==1)throw Error("constant arity");}
    else if(op.op==="buffer.len"){if(types.length!==1||!["readbuf","mutbuf"].includes(types[0])||!exact(outTypes,["usize"]))throw Error("buffer length interface");}
    else if(op.op==="buffer.load"){if(types.length!==2||!["readbuf","mutbuf"].includes(types[0])||types[1]!=="usize"||!exact(outTypes,["u8"]))throw Error("buffer load interface");}
    else if(op.op==="buffer.store"){if(!exact(types,["mutbuf","usize","u8"])||outTypes.length)throw Error("buffer store interface");}
    else if(op.op==="int.cast"){if(types.length!==1||outTypes.length!==1||!/^u(?:8|32|64|size)$/.test(types[0])||!/^u(?:8|32|64|size)$/.test(outTypes[0])||op.attrs.mode!=="wrap")throw Error("cast interface");}
    else if(op.op.startsWith("compare.")){if(types.length!==2||types[0]!==types[1]||!exact(outTypes,["bool"]))throw Error("comparison interface");}
    else if(op.op.startsWith("bool.")){if(!exact(types,["bool","bool"])||!exact(outTypes,["bool"]))throw Error("boolean interface");}
    else {if(types.length!==2||types[0]!==types[1]||!exact(outTypes,[types[0]]))throw Error("binary interface");}
    for(const out of op.out){if(names.has(out.name))throw Error("duplicate SSA output");names.add(out.name);local.set(out.name,out.type);}maximumArgs=Math.max(maximumArgs,op.args.length);
   }
   const t=b.term;
   const edge=e=>{const target=blockMap.get(e.target);if(!target||e.args.length!==target.params.length||e.args.some((n,i)=>local.get(n)!==target.params[i].type))throw Error("edge interface "+f.name+"/"+b.id);maximumArgs=Math.max(maximumArgs,e.args.length);};
   if(t.op==="jump")edge(t);else if(t.op==="branch"){if(local.get(t.cond)!=="bool")throw Error("branch condition");edge(t.then);edge(t.else);}else if(t.op==="ret"){if(JSON.stringify(t.values.map(n=>local.get(n)))!==JSON.stringify(f.returns))throw Error("return interface");}else throw Error("terminator");
  }
  maximumNames=Math.max(maximumNames,names.size);
 }
 return{functions:document.functions.length,blocks_total:blocks,blocks_per_function:Math.max(...document.functions.map(f=>f.blocks.length)),instructions:operations,ssa_names_per_function:maximumNames,parameters_or_arguments:maximumArgs};
}
function makeVM(document,maximumSteps=20000000){
 const functions=new Map(document.functions.map(f=>[f.name,{...f,blockMap:new Map(f.blocks.map(b=>[b.id,b]))}]));
 let steps=0;const mask=t=>(1n<<BigInt(t==="u8"?8:t==="u32"?32:64))-1n;
 function execute(name,parameters){
  const f=functions.get(name);let block=f.blockMap.get(f.entry),incoming=parameters;
  for(;;){const local=new Map(block.params.map((v,i)=>[v.name,incoming[i]]));
   for(const op of block.ops){if(++steps>maximumSteps)throw Error("development VM instruction budget");const args=op.args.map(v=>local.get(v));let value;const type=op.out[0]?.type;
    const [a,b]=args;
    switch(op.op){
     case"const":value=type==="bool"?op.attrs.value:BigInt(op.attrs.value);break;
     case"buffer.len":value=BigInt(a.length);break;
     case"buffer.load":if(b<0n||b>=BigInt(a.length))throw Error("buffer load trap");value=BigInt(a[Number(b)]);break;
     case"buffer.store":if(b<0n||b>=BigInt(a.length))throw Error("buffer store trap");a[Number(b)]=Number(args[2]);break;
     case"int.cast":value=a&mask(type);break;
     case"int.add.wrap":value=(a+b)&mask(type);break;
     case"int.sub.wrap":value=(a-b)&mask(type);break;
     case"int.mul.wrap":value=(a*b)&mask(type);break;
     case"int.shl.checked":if(b<0n||b>=BigInt(type==="u8"?8:type==="u32"?32:64))throw Error("shift trap");value=(a<<b)&mask(type);break;
     case"int.shr.checked":if(b<0n||b>=BigInt(type==="u8"?8:type==="u32"?32:64))throw Error("shift trap");value=a>>b;break;
     case"bit.or":value=a|b;break;
     case"bit.and":value=a&b;break;
     case"bit.xor":value=a^b;break;
     case"bool.and":value=a&&b;break;
     case"bool.or":value=a||b;break;
     case"compare.eq":value=a===b;break;
     case"compare.ne":value=a!==b;break;
     case"compare.lt":value=a<b;break;
     case"compare.le":value=a<=b;break;
     case"compare.gt":value=a>b;break;
     case"compare.ge":value=a>=b;break;
     case"call":value=execute(op.attrs.function,args);break;
     default:throw Error("unsupported development VM operation "+op.op);
    }if(op.out.length)local.set(op.out[0].name,value);
   }
   const t=block.term;if(t.op==="ret")return local.get(t.values[0]);const edge=t.op==="jump"?t:local.get(t.cond)?t.then:t.else;incoming=edge.args.map(x=>local.get(x));block=f.blockMap.get(edge.target);
  }
 }
 return{run:(source,out,work)=>execute("f0",[source,out,work]),steps:()=>steps};
}
return{validate,makeVM};
