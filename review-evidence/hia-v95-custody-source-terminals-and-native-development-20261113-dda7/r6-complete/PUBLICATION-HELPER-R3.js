
const ROOT=load("v88r6formal:root"), REPO="TrillionniumFoundation/Hepta";
const H=(new Function(load("phase_hash_utility_code")))();
function enc(bytes){
 const a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 const out=[];
 for(let i=0;i<bytes.length;i+=3){
  const x=bytes[i], y=bytes[i+1]||0, z=bytes[i+2]||0;
  out.push(a[x>>2],a[((x&3)<<4)|(y>>4)],i+1<bytes.length?a[((y&15)<<2)|(z>>6)]:"=",i+2<bytes.length?a[z&63]:"=");
 }
 return out.join("");
}
function meta(source){const b=H.utf8(source);return{bytes:b.length,sha256:H.sha256Bytes(b),git_blob:H.sha1Bytes(H.utf8("blob "+b.length+"\0"+source))};}
async function cmd(source,max=4000){
 let r=await tools.exec_command({cmd:source,shell:"/bin/bash",login:false,workdir:"/",max_output_tokens:max,yield_time_ms:1000});
 let output=r.output;
 while(r.session_id!==undefined){r=await tools.write_stdin({session_id:r.session_id,chars:"",yield_time_ms:1000,max_output_tokens:max});output+=r.output;}
 if(r.exit_code!==0)throw Error("local command did not finish successfully: "+JSON.stringify(r));
 return output;
}
async function readText(file,size){
 if(!/^[A-Za-z0-9_./-]+$/.test(file))throw Error("unsafe local filename");
 const offsets=[];for(let i=0;i<size;i+=64000)offsets.push(i);
 const all=await Promise.allSettled(offsets.map(i=>cmd("python - <<'PY'\nfrom pathlib import Path\nimport sys\nb=Path('"+ROOT+"/"+file+"').read_text(encoding='utf-8')\nsys.stdout.write(b["+i+":"+Math.min(i+64000,size)+"])\nPY",65000)));
 for(const r of all)if(r.status!=="fulfilled")throw r.reason;
 const s=all.map(r=>r.value).join("");
 if(H.utf8(s).length!==size)throw Error("incomplete local text read "+file);
 return s;
}
async function writeText(file,source){
 if(!/^[A-Za-z0-9_./-]+$/.test(file))throw Error("unsafe output filename");
 const b=H.utf8(source);
 for(let pos=0;pos<b.length||pos===0;pos+=60000){
  const part=enc(b.slice(pos,pos+60000));
  await cmd("python - <<'PY'\nfrom pathlib import Path\nimport base64\np=Path('"+ROOT+"/"+file+"')\np.parent.mkdir(parents=True,exist_ok=True)\nwith p.open('"+(pos===0?"xb":"ab")+"') as o:o.write(base64.b64decode('"+part+"',validate=True))\nPY",1000);
 }
}
async function writeJson(file,value){await writeText(file,JSON.stringify(value,null,2)+"\n");}
async function publish(file,expected,source){
 if(source===undefined)source=await readText(file,expected.bytes);
 const actual=meta(source);
 if(actual.bytes!==expected.bytes||actual.sha256!==expected.sha256||actual.git_blob!==expected.git_blob)
  throw Error("local identity mismatch "+file);
 const intent={file,...actual,operation:"immutable UTF-8 blob create then full GET",timestamp:new Date().toISOString()};
 const intentName="GIT-CUSTODY/"+file+".intent.json";
 await writeJson(intentName,intent);
 store("v88r6formal:"+file+":intent",intent);

 let pre,post=null,mode;
 if(file.startsWith("parts/") && file.endsWith(".b64")){
  // Exclusive xb intent above means this is the first local attempt for
  // this item. Existing intents refuse every automatic second POST.
  post=await tools.mcp__codex_apps__github_create_blob({repository_full_name:REPO,content:source,encoding:"utf-8"});
  store("v88r6formal:"+file+":post",post);
  await writeJson("GIT-CUSTODY/"+file+".post.json",post);
  if(post.isError||post.structuredContent?.sha!==actual.git_blob)throw Error("POST ACK mismatch "+file+": "+JSON.stringify(post));
  mode="FRESH_IMMUTABLE_POST_ACK_FULL_GET";
  pre=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:REPO,blob_sha:actual.git_blob});
 } else {
 pre=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:REPO,blob_sha:actual.git_blob});
 store("v88r6formal:"+file+":preflight",{isError:pre.isError===true,error_code:pre.structuredContent?.error_code||null,content_bytes:typeof pre.structuredContent?.content==="string"?H.utf8(pre.structuredContent.content).length:null});
 mode="EXISTING_FULL_GET";
 if(pre.isError){
  if(pre.structuredContent?.error_code!=="NOT_FOUND"){await writeJson("GIT-CUSTODY/"+file+".preflight-error.json",pre);throw Error("preflight failed: "+JSON.stringify(pre));}
  post=await tools.mcp__codex_apps__github_create_blob({repository_full_name:REPO,content:source,encoding:"utf-8"});
  store("v88r6formal:"+file+":post",post);
  await writeJson("GIT-CUSTODY/"+file+".post.json",post);
  if(post.isError||post.structuredContent?.sha!==actual.git_blob)throw Error("POST ACK mismatch "+file+": "+JSON.stringify(post));
  mode="POST_ACK_FULL_GET";
  pre=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:REPO,blob_sha:actual.git_blob});
 }

 }
 store("v88r6formal:"+file+":fullget",{isError:pre.isError===true,content_bytes:typeof pre.structuredContent?.content==="string"?H.utf8(pre.structuredContent.content).length:null});
 if(pre.isError||typeof pre.structuredContent?.content!=="string"){await writeJson("GIT-CUSTODY/"+file+".get-error.json",pre);throw Error("GET failed "+file);}
 const back=pre.structuredContent.content, bm=meta(back);
 if(back!==source||bm.git_blob!==actual.git_blob||bm.sha256!==actual.sha256||bm.bytes!==actual.bytes)
  throw Error("full GET mismatch "+file);
 let decoded=null;
 if(file.endsWith(".b64")){
  if(!/^[A-Za-z0-9+/]*={0,2}$/.test(back)||back.includes("\n")||back.includes("\r"))throw Error("noncanonical wrapper");
  const raw=H.b64decode(back);
  if(enc(raw)!==back)throw Error("base64 roundtrip mismatch");
  const row=load("v88r6formal:metadata").chunks.find(x=>x.file===file);
  if(!row||raw.length!==row.decoded_bytes||H.sha256Bytes(raw)!==row.decoded_sha256)throw Error("raw chunk mismatch");
  const header=H.utf8("blob "+raw.length+"\0"), object=new Uint8Array(header.length+raw.length);
  object.set(header);object.set(raw,header.length);
  const decodedGit=H.sha1Bytes(object);
  if(decodedGit!==row.decoded_computed_git_blob)throw Error("raw Git chunk mismatch");
  decoded={bytes:raw.length,sha256:H.sha256Bytes(raw),computed_git_blob:decodedGit};
  store("v88r6formal:"+file+":decoded-metadata",decoded);
 }

 if(file.startsWith("parts/") && file.endsWith(".b64")) {
  const destination=ROOT+"/GIT-CUSTODY/readback/"+file;
  const temporary=ROOT+"/GIT-CUSTODY/staging/"+file.replaceAll("/","_")+"."+Date.now()+"."+Math.floor(Math.random()*1000000000);
  await tools.apply_patch("*** Begin Patch\n*** Add File: "+temporary+"\n+"+back+"\n*** End Patch\n");
  await cmd("python - <<'PY'\nfrom pathlib import Path\nimport hashlib,os\np=Path('"+temporary+"'); d=Path('"+destination+"')\nb=p.read_bytes()\nassert len(b)=="+(bm.bytes+1)+" and b[-1:]==b'\\n'\nassert hashlib.sha256(b[:-1]).hexdigest()=='"+bm.sha256+"'\nwith p.open('r+b') as out:out.truncate("+bm.bytes+")\nos.chmod(p,0o644)\nd.parent.mkdir(parents=True,exist_ok=True)\nos.link(p,d)\np.unlink()\nassert d.stat().st_size=="+bm.bytes+" and hashlib.sha256(d.read_bytes()).hexdigest()=='"+bm.sha256+"'\nPY",1000);
 } else {
  await writeText("GIT-CUSTODY/readback/"+file,back);
 }
 const receipt={file,...actual,custody_mode:mode,post_ack:post?.structuredContent||null,
  full_get_verified:true,full_get_bytes:bm.bytes,full_get_sha256:bm.sha256,full_get_blob:bm.git_blob,
  decoded,verified_at:new Date().toISOString()};
 await writeJson("GIT-CUSTODY/"+file+".receipt.json",receipt);
 store("v88r6formal:"+file+":receipt",receipt);
 const all=load("v88r6formal:receipts")||[];all.push(receipt);store("v88r6formal:receipts",all);
 return receipt;
}
return {publish,readText,writeText,writeJson,meta};
