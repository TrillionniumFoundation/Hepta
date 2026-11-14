return function(load,store){
const N="root_v8_CurrentNative_capture",R=(new Function(load("root_runtime_helper_recovered_v6")))()();
const read=(new Function("load","store",load(N+"_native_original_reader_source")))(load,store)(N,R),map=load("root_v7_CoreBalanced_derive8_actual_source_map900").data,inv=load(N+"_native_inventory_by_name"),base="/home/runner/work/_temp/";
const sort=x=>Array.isArray(x)?x.map(sort):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,sort(x[k])])):x,eq=(a,b)=>JSON.stringify(sort(a))===JSON.stringify(sort(b));
const checks=[];function chk(name,x){checks.push({name,pass:!!x});if(!x)throw Error(name)}
const cs=load(N+"_source_tests/test_hia_core_lowering_native.py").text.match(/INSTALLED_CHILD = r'''([\s\S]*?)'''/);
const es=load(N+"_source_tests/test_hia_machine_elf_native.py").text.match(/INSTALLED_CONTROL = r"""([\s\S]*?)"""/);
chk("Core literal extracted",!!cs);chk("ELF literal extracted",!!es);
const coreSpecs=[
["hia-core-lowering-callers-evidence/component-fixture/installed-control","hia-core-lowering-callers-evidence/component-fixture/qualified",false],
["hia-core-unpack-evidence/callers/numeric/callers/core-callers/component-fixture/installed-control","hia-core-unpack-evidence/callers/numeric/callers/core-callers/component-fixture/qualified",true]
],rows=[];
let expectedDoc=null;
for(const [root,q,companions]of coreSpecs){
 const child=read(root+"/installed-child.py"),ep=read(root+"/expected.json",true),rp=read(root+"/report.json",true),procs=read(root+"/processes.json",true),built=read(q+"/build.json",true).data;
 chk(root+": actual original child literal exact",child.text===cs[1]);
 const expected=ep.data,report=rp.data;
 const pyNames=Object.keys(map).filter(p=>p.startsWith("hepta/")&&p.endsWith(".py")&&!p.split("/").includes("_data")).sort();
 chk(root+": all176 current Python",pyNames.length===176&&eq(Object.keys(expected.python).sort(),pyNames)&&report.python_files===176);
 chk(root+": resource111",Object.keys(expected.resources).length===111&&report.resource_files===111);
 for(const [group,entries]of Object.entries({python:expected.python,resources:expected.resources})){
  for(const [p,sha]of Object.entries(entries)){
   chk(root+": current "+group+" "+p,map[p]===sha);
   const installed=root+"/installed/"+(group==="resources"?"hepta/_data/":"")+p;
   const source=root+"/source/"+p;
   chk(root+": collector installed "+p,inv[installed]?.body_fully_read===true&&inv[installed].sha256===sha);
   chk(root+": collector staged "+p,inv[source]?.body_fully_read===true&&inv[source].sha256===sha);
  }
 }
 if(expectedDoc!==null)chk(root+": common smoke document",eq(expectedDoc,expected.document));else expectedDoc=expected.document;
 const pp=procs.data,python=pp[0]?.argv[0],a=base+root;
 chk(root+": original 3 processes",pp.length===3);
 chk(root+": wheel argv",eq(pp[0].argv,[python,"-B","-m","pip","wheel","--no-cache-dir","--no-deps","--no-index","--no-build-isolation","--wheel-dir",a+"/wheels",a+"/source"]));
 chk(root+": install argv",eq(pp[1].argv,[python,"-B","-m","pip","install","--no-cache-dir","--no-deps","--no-index","--target",a+"/installed",a+"/wheels/hia_core-0.3.0-py3-none-any.whl"]));
 const args=[python,"-I","-S","-B",a+"/installed-child.py",a+"/installed",base+q+"/manifest.json",a+"/expected.json"];
 if(companions)args.push("--companions-json",JSON.stringify(sort(report.companion_arguments)));
 chk(root+": isolated execution argv",eq(pp[2].argv,args));
 for(let i=0;i<3;i++){
  const label=["wheel-build","wheel-install","installed-execution"][i];
  const out=read(root+"/"+label+".stdout"),err=read(root+"/"+label+".stderr");
  chk(root+": process"+i+" zero+logs",pp[i].returncode===0&&pp[i].stdout_sha256===out.sha256&&pp[i].stderr_sha256===err.sha256&&err.bytes===0);
 }
 chk(root+": actual stdout report",eq(read(root+"/installed-execution.stdout",true).data,report));
 chk(root+": original installed status",report.status==="INSTALLED_CORE_LOWERING_PASS"&&report.units===39&&report.actual_native_steps>0);
 for(const k of ["authoring_forbidden","empty_PATH","isolated_without_site","retained_lowering_forbidden"])chk(root+": "+k,report[k]===true);
 chk(root+": same actual 39 images and sources",eq(report.image_sha256,built.units.map(u=>u.manifest.image_sha256))&&eq(report.source_sha256,Object.fromEntries(built.units.map(u=>[u.name,u.manifest.source_sha256])))&&report.abi_sha256===built.abi_sha256);
 if(!companions)chk(root+": no companion claim",report.integer_observations===null&&report.numeric_compare_observations===null&&report.unpack_observations===null&&eq(report.companion_arguments,{numeric_compare_manifest:null,schema:"hepta.hia.core-lowering-installed-companions.v1",unpack_manifest:null}));
 else{
  for(const [field,arg,kind]of [["integer_observations","integer_manifest","integer"],["numeric_compare_observations","numeric_compare_manifest","numeric"],["unpack_observations","unpack_manifest","unpack"]]){
   const obs=report[field],mp=report.companion_arguments[arg];chk(root+": companion absolute "+kind,mp.startsWith(base));
   const mr=read(mp.slice(base.length),true);
   for(const k of ["abi_sha256","bridge_sha256","compiler_sha256","image_sha256","selection_sha256","source_sha256"])chk(root+": companion "+kind+" "+k,obs[k]===mr.data[k]);
   if(obs.manifest_sha256!==undefined)chk(root+": companion "+kind+" manifest",obs.manifest_sha256===mr.sha256);
   chk(root+": hosted primitives "+kind,obs.CPython_object_primitives_still_hosted===true);
   chk(root+": refusals present "+kind,Array.isArray(obs.refusals)&&obs.refusals.length>0);
  }
  chk(root+": numeric admitted calls",report.numeric_compare_observations.actual_step_returns===26&&report.numeric_compare_observations.ordinary_step_returns===21&&report.numeric_compare_observations.window_probe_step_returns===5&&eq(report.numeric_compare_observations.actual_statuses,[0,1]));
  chk(root+": unpack admitted calls",report.unpack_observations.actual_step_returns===164&&eq(report.unpack_observations.actual_statuses,[0,1]));
  chk(root+": integer populations distinct",report.integer_observations.step_returns.length===21&&report.integer_observations.finish_returns.length===7&&report.integer_observations.ordinary_eligible_effects.length===27&&report.integer_observations.window_probes.length===4);
 }
 const wheels=Object.values(inv).filter(x=>x.name.startsWith(root+"/wheels/")&&!x.directory);
 chk(root+": one full collector wheel",wheels.length===1&&wheels[0].body_fully_read===true&&wheels[0].name.endsWith("/hia_core-0.3.0-py3-none-any.whl"));
 rows.push({root,actual_child:{bytes:child.bytes,sha256:child.sha256},expected:{bytes:ep.bytes,sha256:ep.sha256},report:{bytes:rp.bytes,sha256:rp.sha256},processes:{bytes:procs.bytes,sha256:procs.sha256},status:report.status,python_files:176,resource_files:111,all287_staged_and_installed_inventory_sha256_match_current900:true,actual_core_units:39,actual_core_steps:report.actual_native_steps,companions:report.companion_arguments,wheel:wheels[0],wheel_bytes_read_by_root:false,installed_287_bodies_read_by_root:false,whole_native_delivery:false});
}
const eroot="hia-machine-elf-component-evidence/fixture/MachineElfNativeTests/installed-wheel",eqroot="hia-machine-elf-component-evidence/fixture/MachineElfNativeTests/qualified";
const ec=read(eroot+"/installed.py"),ep=read(eroot+"/inputs.json",true),exe=read(eroot+"/execution.stdout",true),pp=read(eroot+"/processes.json",true),em=read(eqroot+"/manifest.json",true);
chk("ELF actual child literal",ec.text===es[1]);chk("ELF same smoke document",eq(ep.data.document,expectedDoc));
chk("ELF full return object equal",eq(exe.data.actual,ep.data.expected)&&exe.data.full_return_object_equal===true);
chk("ELF installed status",exe.data.status==="INSTALLED_NATIVE_ELF_PASS"&&exe.data.source_sha256===em.data.source_sha256&&exe.data.image_sha256===em.data.image_sha256&&exe.data.empty_PATH===true&&exe.data.isolated_without_site===true);
const a=base+eroot,python=pp.data[0].argv[0];
const eargs=[
[python,"-B","-m","pip","wheel","--no-cache-dir","--no-deps","--no-index","--no-build-isolation","--wheel-dir",a+"/wheels",a+"/source"],
[python,"-B","-m","pip","install","--no-cache-dir","--no-deps","--no-index","--target",a+"/installed",a+"/wheels/hia_core-0.3.0-py3-none-any.whl"],
[python,"-I","-S","-B",a+"/installed.py",a+"/installed",base+eqroot+"/manifest.json",a+"/inputs.json"]];
chk("ELF three original processes",pp.data.length===3);
for(let i=0;i<3;i++){
 const label=["build","install","execution"][i],pr=read(eroot+"/"+label+".process.json",true),out=read(eroot+"/"+label+".stdout"),err=read(eroot+"/"+label+".stderr");
 chk("ELF "+label+" exact argv/logs/return",eq(pp.data[i],pr.data)&&eq(pr.data.argv,eargs[i])&&pr.data.returncode===0&&pr.data.stdout_sha256===out.sha256&&pr.data.stderr_sha256===err.sha256&&err.bytes===0);
}
for(const k of ["object_bytes","text_bytes"]){
 const obj=exe.data.actual[k];chk("ELF "+k+" exact hex",/^(?:[0-9a-f]{2})+$/.test(obj.hex));
 const bytes=Uint8Array.from(obj.hex.match(/../g).map(v=>parseInt(v,16)));
 chk("ELF "+k+" body hash",bytes.length===obj.bytes&&R.sha256(bytes)===obj.sha256);
}
chk("ELF installed positive counts",Object.keys(exe.data.native_operation_counts).length===11&&Object.values(exe.data.native_operation_counts).every(v=>Number.isSafeInteger(v)&&v>0));
rows.push({root:eroot,script:{bytes:ec.bytes,sha256:ec.sha256},inputs:{bytes:ep.bytes,sha256:ep.sha256},execution:{bytes:exe.bytes,sha256:exe.sha256},status:exe.data.status,process_count:3,full_return_object_equal:true,native_operation_keys:11,object_sha256:exe.data.actual.object_bytes.sha256,wheel_bytes_read_by_root:false,whole_native_delivery:false});
store(N+"_installed_actual_checks",checks);store(N+"_installed_actual_closures",rows);
return {all_true:true,checks:checks.length,controls:rows.map(x=>({root:x.root,status:x.status,report:x.report,python_files:x.python_files,resource_files:x.resource_files,core_steps:x.actual_core_steps,object_sha256:x.object_sha256,wheel_bytes_read_by_root:x.wheel_bytes_read_by_root}))};
};