function decodeSourceFrames(log, expected, h) {
  function need(v,m){if(!v)throw Error(m);}
  function json(raw) {
    let i=0;
    const space=()=>{while(i<raw.length&&/[\x20\t\r\n]/.test(raw[i]))i++;};
    function value(){
      space(); const c=raw[i];
      if(c==='"'){const start=i++;while(i<raw.length){const x=raw[i++];if(x==='\\'){i++;continue;}if(x==='"')return JSON.parse(raw.slice(start,i));}throw Error('unterminated JSON string');}
      if(c==='{'){i++;const out=Object.create(null),keys=new Set();space();if(raw[i]==='}'){i++;return out;}while(true){space();need(raw[i]==='"','JSON object key');const key=value();need(!keys.has(key),'duplicate JSON key');keys.add(key);space();need(raw[i++]===':','JSON colon');out[key]=value();space();const end=raw[i++];if(end==='}')return out;need(end===',','JSON object separator');}}
      if(c==='['){i++;const out=[];space();if(raw[i]===']'){i++;return out;}while(true){out.push(value());space();const end=raw[i++];if(end===']')return out;need(end===',','JSON array separator');}}
      for(const [word,v] of [['true',true],['false',false],['null',null]])if(raw.startsWith(word,i)){i+=word.length;return v;}
      const m=raw.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);need(m,'JSON token');
      i+=m[0].length;const n=Number(m[0]);need(Number.isFinite(n),'nonfinite JSON number');
      if(/^-?[0-9]+$/.test(m[0])&&!Number.isSafeInteger(n))return {lossless_integer:m[0]};
      return n;
    }
    const out=value();space();need(i===raw.length,'JSON trailing data');return out;
  }
  function bytes64(value){need(typeof value==='string','base64 text required');const bytes=h.unb64(value);need(h.b64(bytes)===value,'noncanonical base64');return bytes;}
  function isInt(n,max){return Number.isSafeInteger(n)&&n>=0&&n<=max;}
  function object(v){return v!==null&&typeof v==='object'&&!Array.isArray(v);}
  const names=['HIA_CLI_JSON_SOURCE_INDEX ','HIA_CLI_JSON_SOURCE_CHUNK ','HIA_CLI_JSON_SOURCE_END '];
  const stream=[];
  for(let line of log.split('\n')){
    if(line.endsWith('\r'))line=line.slice(0,-1);
    line=line.replace(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z /,'');
    if(names.some(name=>line.startsWith(name)))stream.push(line+'\n');
  }
  need(stream.length>=2,'source frame stream missing');
  need(stream[0].startsWith(names[0])&&stream.at(-1).startsWith(names[2]),'source stream endpoints differ');
  need(stream.filter(x=>x.startsWith(names[0])).length===1&&stream.filter(x=>x.startsWith(names[2])).length===1,'duplicate source stream endpoints');
  const indexRaw=bytes64(stream[0].slice(names[0].length).trimEnd());need(indexRaw.length<=65536,'source index cap');
  const index=json(h.text8(indexRaw));
  need(object(index)&&index.schema==='hia.cli-json.remote-source-r3c.v1.frames-index','source index schema');
  need(index.source_commit===expected.source_commit&&index.policy_sha256===expected.policy_sha256,'source index identity');
  need(index.raw_limit===524288&&index.stdout_limit===1048576&&index.whole_files_only===true&&index.all_available_raw_originals_in_stdout===false,'source transport scope');
  need(['HOLD','REMOTE_FOUR_SOURCE_COMPONENTS_PASS_NOT_NATIVE'].includes(index.source_status),'source result status');
  need(Array.isArray(index.selected)&&isInt(index.selected_raw_bytes,524288),'selected source population');
  const fileNames=new Set();
  const files=index.selected.map((row,i)=>{
    need(object(row)&&row.index===i&&typeof row.name==='string'&&!fileNames.has(row.name),'selected source filename/index');
    need(!row.name.startsWith('/')&&!row.name.split('/').some(x=>x==='..'||x===''||x==='.'),'selected source name');
    fileNames.add(row.name);
    need(isInt(row.bytes,524288)&&/^[0-9a-f]{64}$/.test(row.sha256)&&/^[0-9a-f]{40}$/.test(row.git_blob),'selected source byte pins');
    return {expected:row,chunks:[],size:0};
  });
  need(files.reduce((n,x)=>n+x.expected.bytes,0)===index.selected_raw_bytes,'selected raw size sum');
  let lastFile=-1;
  for(const line of stream.slice(1,-1)){
    need(line.startsWith(names[1]),'unexpected source protocol line');
    const frame=json(line.slice(names[1].length));
    need(object(frame)&&JSON.stringify(Object.keys(frame).sort())===JSON.stringify(['base64','bytes','file','offset','sha256']),'source frame fields');
    need(isInt(frame.file,files.length-1)&&frame.file>=lastFile,'source frame order');
    lastFile=frame.file;
    const file=files[frame.file],bytes=bytes64(frame.base64);
    need(isInt(frame.offset,524288)&&frame.offset===file.size&&isInt(frame.bytes,8192)&&frame.bytes>0&&frame.bytes===bytes.length,'source frame offset/length');
    need(/^[0-9a-f]{64}$/.test(frame.sha256)&&h.sha256(bytes)===frame.sha256,'source frame SHA');
    need(file.size+bytes.length<=file.expected.bytes,'source frame past original EOF');
    file.chunks.push(bytes);file.size+=bytes.length;
  }
  const originals=files.map(file=>{
    need(file.size===file.expected.bytes,'incomplete selected original');
    const bytes=new Uint8Array(file.size);let at=0;for(const part of file.chunks){bytes.set(part,at);at+=part.length;}
    need(h.sha256(bytes)===file.expected.sha256&&h.gitblob(bytes)===file.expected.git_blob,'complete selected original byte/Git seal');
    return {...file.expected,base64:h.b64(bytes)};
  });
  const prefix=h.utf8(stream.slice(0,-1).join('')),end=json(stream.at(-1).slice(names[2].length));
  need(object(end)&&end.schema==='hia.cli-json.remote-source-r3c.v1.frames-end'&&end.status==='BOUNDED_CHANNEL_COMPLETE','source END schema');
  need(end.index_sha256===h.sha256(indexRaw)&&end.prefix_sha256===h.sha256(prefix)&&end.prefix_bytes===prefix.length,'source END prefix/index seal');
  need(end.selected_files===originals.length&&end.selected_raw_bytes===index.selected_raw_bytes&&end.source_status===index.source_status,'source END population/status');
  need(/^[0-9a-f]{64}$/.test(end.framing_sha256),'source END framing pin');
  const full=h.utf8(stream.join(''));need(full.length<=1048576,'source stdout cap');
  return {schema:'hia.cli-json.source-small-readback.v1',status:'BOUNDED_SELECTED_ORIGINALS_DECODED_NOT_PRODUCT_QUALIFICATION',
    log:{bytes:h.utf8(log).length,sha256:h.sha256(h.utf8(log))},
    protocol:{bytes:full.length,sha256:h.sha256(full),base64:h.b64(full)},
    index:{bytes:indexRaw.length,sha256:h.sha256(indexRaw),base64:h.b64(indexRaw),value:index},
    end,originals,complete_artifact_read:false,unsafe_large_json_integers_preserved_as_lossless_integer_tokens:true};
}
