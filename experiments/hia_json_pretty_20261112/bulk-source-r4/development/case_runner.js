
return function run(document,cases,H,vmSource) {
 const vmFactory=new Function(vmSource)();const output=[];
 const u64=(a,at)=>{let v=0n;for(let i=7;i>=0;i--)v=(v<<8n)|BigInt(a[at+i]);return v;};
 const equal=(a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
 for(const c of cases) {
  const input=c.repeat_input?new Uint8Array(c.repeat_input.count).fill(c.repeat_input.byte):H.utf8encode(c.wire);
  const before=new Uint8Array(input),vm=vmFactory.makeVM(document,60000000);
  function call(mode,capacity,workspace=161){
    const backing=new Uint8Array(capacity+32).fill(0xa5),out=backing.subarray(16,16+capacity),workBacking=new Uint8Array(workspace+32).fill(0xa5),work=workBacking.subarray(16,16+workspace);work.fill(0);if(work.length>=8)work[0]=mode;
    const code=Number(vm.run(input,out,work));
    if(!equal(before,input)||backing.subarray(0,16).some(x=>x!==0xa5)||backing.subarray(16+capacity).some(x=>x!==0xa5)||workBacking.subarray(0,16).some(x=>x!==0xa5)||workBacking.subarray(16+workspace).some(x=>x!==0xa5))throw Error("guard or source changed "+c.name);
    return {code,out,work};
  }
  if(c.kind==="exact_layout"){
    const expected=H.utf8encode(c.expected),measure=call(0,0),size=Number(u64(measure.work,8));if(measure.code!==0||size!==expected.length||u64(measure.work,16)!==0n||u64(measure.work,24)!==0n)throw Error("measure "+c.name);
    const emitted=call(1,size);if(emitted.code!==0||!equal(emitted.out,expected)||Number(u64(emitted.work,8))!==size||u64(emitted.work,16)!==0n||u64(emitted.work,24)!==0n)throw Error("emit "+c.name);
    output.push({id:c.name,status:"PASS",input_bytes:input.length,output_bytes:size,output_sha256:H.sha256(emitted.out),steps:vm.steps()});
  }else{
    const r=call(c.mode,c.output_bytes,c.workspace_bytes);if(r.code!==c.expected_status)throw Error("refusal "+c.name+" "+r.code);
    if(c.workspace_bytes>=32&&Number(u64(r.work,24))!==r.code)throw Error("diagnostic "+c.name);
    output.push({id:c.name,status:"PASS",expected_status:c.expected_status,observed_status:r.code,steps:vm.steps()});
  }
 }
 return output;
}