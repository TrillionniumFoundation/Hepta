
const ROOT=load("v85localr3:root"), REPO="TrillionniumFoundation/Hepta";
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
 const r=await tools.exec_command({cmd:source,shell:"/bin/bash",login:false,workdir:"/",max_output_tokens:max});
 if(r.exit_code!==0||r.session_id!==undefined)throw Error("local command did not finish successfully: "+JSON.stringify(r));
 return r.output;
}
async function readText(file,size){
 if(!/^[A-Za-z0-9_./-]+$/.test(file))throw Error("unsafe local filename");
 const offsets=[];for(let i=0;i<size;i+=64000)offsets.push(i);
 const all=await Promise.allSettled(offsets.map(i=>cmd("python - <<'PY'\nfrom pathlib import Path\nimport sys\nb=Path('"+ROOT+"/"+file+"').read_bytes()\nsys.stdout.buffer.write(b["+i+":"+Math.min(i+64000,size)+"])\nPY",65000)));
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
 store("v85localr3:"+file+":intent",intent);
 let pre=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:REPO,blob_sha:actual.git_blob});
 store("v85localr3:"+file+":preflight",pre);
 let post=null, mode="EXISTING_FULL_GET";
 if(pre.isError){
  if(pre.structuredContent?.error_code!=="NOT_FOUND")throw Error("preflight failed: "+JSON.stringify(pre));
  post=await tools.mcp__codex_apps__github_create_blob({repository_full_name:REPO,content:source,encoding:"utf-8"});
  store("v85localr3:"+file+":post",post);
  await writeJson("GIT-CUSTODY/"+file+".post.json",post);
  if(post.isError||post.structuredContent?.sha!==actual.git_blob)throw Error("POST ACK mismatch "+file+": "+JSON.stringify(post));
  mode="POST_ACK_FULL_GET";
  pre=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:REPO,blob_sha:actual.git_blob});
 }
 store("v85localr3:"+file+":fullget",pre);
 if(pre.isError||typeof pre.structuredContent?.content!=="string")throw Error("GET failed "+file);
 const back=pre.structuredContent.content, bm=meta(back);
 if(back!==source||bm.git_blob!==actual.git_blob||bm.sha256!==actual.sha256||bm.bytes!==actual.bytes)
  throw Error("full GET mismatch "+file);
 let decoded=null;
 if(file.endsWith(".b64")){
  if(!/^[A-Za-z0-9+/]*={0,2}$/.test(back)||back.includes("\n")||back.includes("\r"))throw Error("noncanonical wrapper");
  const raw=H.b64decode(back);
  if(enc(raw)!==back)throw Error("base64 roundtrip mismatch");
  const row=load("v85localr3:metadata").chunks.find(x=>x.file===file);
  if(!row||raw.length!==row.decoded_bytes||H.sha256Bytes(raw)!==row.decoded_sha256)throw Error("raw chunk mismatch");
  decoded={bytes:raw.length,sha256:H.sha256Bytes(raw)};
  store("v85localr3:"+file+":decoded",Array.from(raw));
 }
 await writeText("GIT-CUSTODY/readback/"+file,back);
 const receipt={file,...actual,custody_mode:mode,post_ack:post?.structuredContent||null,
  full_get_verified:true,full_get_bytes:bm.bytes,full_get_sha256:bm.sha256,full_get_blob:bm.git_blob,
  decoded,verified_at:new Date().toISOString()};
 await writeJson("GIT-CUSTODY/"+file+".receipt.json",receipt);
 store("v85localr3:"+file+":receipt",receipt);
 const all=load("v85localr3:receipts")||[];all.push(receipt);store("v85localr3:receipts",all);
 return receipt;
}
return {publish,readText,writeText,writeJson,meta};
