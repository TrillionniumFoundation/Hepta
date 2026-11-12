
class FunctionBuilder {
  constructor(name, parameters, returns="u64") { this.name=name; this.parameters=parameters; this.returns=returns; this.next=0; this.blocks=[]; this.entry=this.block(parameters); this.params=this.entry.params; }
  block(types) {const b={id:"b"+this.blocks.length,params:types.map(type=>({name:"v"+this.next++,type})),ops:[],term:null};this.blocks.push(b);return b;}
  op(b,op,args,type,attrs) {const out=type?[{name:"v"+this.next++,type}]:[];b.ops.push({op,args:args.map(v=>v.name),out,attrs:attrs||{}});return out[0];}
  constant(b,type,value) {return this.op(b,"const",[],type,{value});}
  cast(b,value,type) {return value.type===type?value:this.op(b,"int.cast",[value],type,{mode:"wrap"});}
  bin(b,op,a,c,type=a.type){return this.op(b,op,[a,c],type);}
  compare(b,op,a,c){return this.op(b,"compare."+op,[a,c],"bool");}
  call(b,name,args,type="u64"){return this.op(b,"call",args,type,{function:name});}
  jump(b,target,args){if(b.term)throw Error("duplicate terminator");b.term={op:"jump",target:target.id,args:args.map(v=>v.name)};}
  branch(b,value,yes,yesArgs,no,noArgs){if(b.term)throw Error("duplicate terminator");b.term={op:"branch",cond:value.name,then:{target:yes.id,args:yesArgs.map(v=>v.name)},else:{target:no.id,args:noArgs.map(v=>v.name)}};}
  ret(b,value){if(b.term)throw Error("duplicate terminator");b.term={op:"ret",values:[value.name]};}
  document(){return{name:this.name,params:this.params,returns:[this.returns],effects:["read","write","trap"],entry:"b0",blocks:this.blocks};}
}
function render(document) {
 const p=vs=>vs.map(v=>v.name+":"+v.type).join(",");
 const lines=["hia-asm.v1 "+document.schema+" "+document.module];
 for(const f of document.functions){lines.push("fn "+f.name+"("+p(f.params)+") -> ("+f.returns.join(",")+") effects("+f.effects.join(",")+") entry("+f.entry+")");
 for(const b of f.blocks){lines.push("block "+b.id+"("+p(b.params)+")");for(const op of b.ops)lines.push("  "+(op.out.length?p(op.out):"_")+" = "+op.op+"("+op.args.join(",")+")"+(Object.keys(op.attrs).length?" "+JSON.stringify(op.attrs):""));
 const t=b.term;if(!t)throw Error("unterminated "+f.name+"/"+b.id);
 if(t.op==="ret")lines.push("  ret("+t.values.join(",")+")");else if(t.op==="jump")lines.push("  jump "+t.target+"("+t.args.join(",")+")");else if(t.op==="branch")lines.push("  branch "+t.cond+" "+t.then.target+"("+t.then.args.join(",")+") "+t.else.target+"("+t.else.args.join(",")+")");else throw Error("terminator");
 }lines.push("end");}return lines.join("\n")+"\n";
}
return {FunctionBuilder,render};
