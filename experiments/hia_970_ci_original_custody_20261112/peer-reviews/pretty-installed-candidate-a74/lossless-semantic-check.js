function losslessSemanticCanonical(raw, omitted=['source_identity']) {
  let i=0; const ws=()=>{while(i<raw.length && /[\x20\t\n\r]/.test(raw[i]))i++;};
  const string=()=>{const b=i++;while(i<raw.length){const c=raw[i++];if(c==='"')return JSON.parse(raw.slice(b,i));if(c==='\\'){if(i>=raw.length)throw Error("escape EOF");i++;}else if(c.charCodeAt(0)<32)throw Error("control string");}throw Error("string EOF");};
  const value=(depth)=>{if(depth>1000)throw Error("depth");ws();let c=raw[i];
    if(c==='"')return {k:'s',v:string()};
    if(c==='['){i++;const a=[];ws();if(raw[i]===']'){i++;return{k:'a',v:a};}for(;;){a.push(value(depth+1));ws();if(raw[i]===']'){i++;break;}if(raw[i++]!==',')throw Error("array comma");}return{k:'a',v:a};}
    if(c==='{'){i++;const a=[],seen=new Set();ws();if(raw[i]==='}'){i++;return{k:'o',v:a};}for(;;){ws();if(raw[i]!=='"')throw Error("object key");const key=string();if(seen.has(key))throw Error("duplicate");seen.add(key);ws();if(raw[i++]!==':')throw Error("colon");a.push([key,value(depth+1)]);ws();if(raw[i]==='}'){i++;break;}if(raw[i++]!==',')throw Error("object comma");}return{k:'o',v:a};}
    for(const s of ['true','false','null'])if(raw.startsWith(s,i)){i+=s.length;return{k:'l',v:s};}
    const m=/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(raw.slice(i));if(m&&m.index===0){i+=m[0].length;return{k:'n',v:m[0]};}throw Error("value at "+i);
  };
  const root=value(0);ws();if(i!==raw.length||root.k!=='o')throw Error("complete root");
  let numbers=0,large_integer_tokens=0,nonascii_keys=0;
  const quote=s=>JSON.stringify(s).replace(/[\x7f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
  const emit=n=>{if(n.k==='n'){numbers++;if(/^-?[0-9]+$/.test(n.v)&&((BigInt(n.v)>9007199254740991n)||(BigInt(n.v)<-9007199254740991n)))large_integer_tokens++;return n.v;}if(n.k==='l')return n.v;if(n.k==='s')return quote(n.v);if(n.k==='a')return '['+n.v.map(emit).join(',')+']';if(n.k==='o'){for(const [k] of n.v)if(/[^\x00-\x7f]/.test(k))nonascii_keys++;const rows=n.v.slice().sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);return '{'+rows.map(([k,v])=>quote(k)+':'+emit(v)).join(',')+'}';}throw Error("node");};
  root.v=root.v.filter(([k])=>!omitted.includes(k));
  const canonical=emit(root);if(nonascii_keys)throw Error("unsupported nonascii key sort domain");
  return {canonical,numbers,large_integer_tokens,nonascii_keys,omitted_top_level:omitted};
}
