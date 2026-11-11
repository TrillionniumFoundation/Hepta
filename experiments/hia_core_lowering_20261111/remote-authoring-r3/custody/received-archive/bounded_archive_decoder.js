
// Read-only custody decoder. Single gzip stream, RFC 1951 blocks, bounded output.
// Does not execute archive members; verifies gzip CRC/size and USTAR metadata.
function base64Bytes(text) {
 if(typeof text!=="string"||text.length%4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))throw Error("base64 framing");
 const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 const n=text.length/4*3-(text.endsWith("==")?2:text.endsWith("=")?1:0),out=new Uint8Array(n);
 let p=0;for(let i=0;i<text.length;i+=4){const a=alphabet.indexOf(text[i]),b=alphabet.indexOf(text[i+1]),c=text[i+2]==="="?0:alphabet.indexOf(text[i+2]),d=text[i+3]==="="?0:alphabet.indexOf(text[i+3]);const v=(a<<18)|(b<<12)|(c<<6)|d;if(p<n)out[p++]=v>>>16;if(p<n)out[p++]=v>>>8;if(p<n)out[p++]=v;}
 if(text.endsWith("==")&&(alphabet.indexOf(text[text.length-3])&15))throw Error("noncanonical base64 bits");
 if(text.endsWith("=")&&!text.endsWith("==")&&(alphabet.indexOf(text[text.length-2])&3))throw Error("noncanonical base64 bits");
 return out;
}
function bytesBase64(raw) {
 const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", parts=[];
 for(let at=0;at<raw.length;at+=3){const left=raw.length-at,a=raw[at],b=left>1?raw[at+1]:0,c=left>2?raw[at+2]:0,v=(a<<16)|(b<<8)|c;parts.push(alphabet[(v>>>18)&63]+alphabet[(v>>>12)&63]+(left>1?alphabet[(v>>>6)&63]:"=")+(left>2?alphabet[v&63]:"="));}
 return parts.join("");
}
function crc32(raw) {
 const table=new Uint32Array(256);for(let i=0;i<256;i++){let c=i;for(let j=0;j<8;j++)c=(c&1)?0xedb88320^(c>>>1):c>>>1;table[i]=c>>>0;}
 let c=0xffffffff;for(const b of raw)c=table[(c^b)&255]^(c>>>8);return(c^0xffffffff)>>>0;
}
function gunzip(raw,limit=16*1024*1024) {
 const u32=(p)=>(raw[p]|raw[p+1]<<8|raw[p+2]<<16|raw[p+3]<<24)>>>0;
 if(raw.length<18||raw[0]!==31||raw[1]!==139||raw[2]!==8||(raw[3]&224))throw Error("gzip header");
 let pos=10;const flag=raw[3];
 function need(n){if(pos+n>raw.length-8)throw Error("truncated gzip header");}
 if(flag&4){need(2);const n=raw[pos]|raw[pos+1]<<8;pos+=2;need(n);pos+=n;}
 for(const bit of [8,16])if(flag&bit){while(true){need(1);if(raw[pos++]===0)break;}}
 if(flag&2){need(2);if((crc32(raw.subarray(0,pos))&65535)!==(raw[pos]|raw[pos+1]<<8))throw Error("gzip header crc");pos+=2;}
 const expected=u32(raw.length-4);if(expected>limit)throw Error("gzip size limit");
 const out=new Uint8Array(expected);let used=0,bits=0,acc=0,blocks=0;
 function read(n){while(bits<n){if(pos>=raw.length)throw Error("deflate truncation");acc|=raw[pos++]<<bits;bits+=8;}const value=acc&((1<<n)-1);acc>>>=n;bits-=n;return value;}
 function tree(lengths){
  const count=new Int32Array(16);let max=0;for(const n of lengths){if(!Number.isInteger(n)||n<0||n>15)throw Error("invalid code length");if(n){count[n]++;max=Math.max(max,n);}}
  if(!max)return {max:0,table:new Uint32Array(1)};
  let left=1;for(let n=1;n<=15;n++){left=left*2-count[n];if(left<0)throw Error("oversubscribed Huffman tree");}
  const next=new Int32Array(16);let code=0;for(let n=1;n<=15;n++){code=(code+count[n-1])*2;next[n]=code;}
  const table=new Uint32Array(1<<max);
  for(let symbol=0;symbol<lengths.length;symbol++){const n=lengths[symbol];if(!n)continue;let value=next[n]++,reverse=0;for(let i=0;i<n;i++){reverse=(reverse<<1)|(value&1);value>>>=1;}for(let i=reverse;i<table.length;i+=1<<n)table[i]=(symbol<<5)|n;}
  return {max,table};
 }
 function decode(h){if(!h.max)throw Error("empty Huffman tree used");while(bits<h.max){if(pos>=raw.length)throw Error("deflate truncation");acc|=raw[pos++]<<bits;bits+=8;}const entry=h.table[acc&((1<<h.max)-1)],n=entry&31;if(!n)throw Error("invalid Huffman symbol");acc>>>=n;bits-=n;return entry>>>5;}
 const lenBase=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258],lenExtra=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0],distBase=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577],distExtra=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
 let last=0;
 while(!last){last=read(1);const type=read(2);blocks++;
  if(type===0){const drop=bits&7;acc>>>=drop;bits-=drop;const n=read(16),not=read(16);if((n^not)!==65535||used+n>out.length)throw Error("stored block extent");for(let i=0;i<n;i++)out[used++]=read(8);continue;}
  if(type===3)throw Error("reserved deflate block");
  let lit,dist;
  if(type===1){lit=tree(Array.from({length:288},(_,i)=>i<144?8:i<256?9:i<280?7:8));dist=tree(Array(32).fill(5));}
  else {
   const nlit=read(5)+257,ndist=read(5)+1,ncode=read(4)+4;if(nlit>286)throw Error("dynamic literal extent");
   const orderExact=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];
   const lengths=Array(19).fill(0);for(let i=0;i<ncode;i++)lengths[orderExact[i]]=read(3);
   const codeTree=tree(lengths),all=[];
   while(all.length<nlit+ndist){const code=decode(codeTree);if(code<16){all.push(code);continue;}let n,value;if(code===16){if(!all.length)throw Error("missing repeat predecessor");n=read(2)+3;value=all[all.length-1];}else if(code===17){n=read(3)+3;value=0;}else if(code===18){n=read(7)+11;value=0;}else throw Error("invalid repeat");if(all.length+n>nlit+ndist)throw Error("repeat overflow");while(n--)all.push(value);}
   if(!all[256])throw Error("missing end of block");lit=tree(all.slice(0,nlit));dist=tree(all.slice(nlit));
  }
  while(true){const symbol=decode(lit);if(symbol<256){if(used>=out.length)throw Error("literal overflow");out[used++]=symbol;continue;}if(symbol===256)break;if(symbol>285)throw Error("reserved length");
   const i=symbol-257,n=lenBase[i]+read(lenExtra[i]),d=decode(dist);if(d>29)throw Error("reserved distance");const distance=distBase[d]+read(distExtra[d]);if(distance>used||used+n>out.length)throw Error("backreference extent");for(let j=0;j<n;j++){out[used]=out[used-distance];used++;}
  }
 }
 const compressedEnd=pos-Math.floor(bits/8);if(compressedEnd!==raw.length-8)throw Error("gzip trailing or missing stream bytes");
 if(used!==expected||crc32(out)!==u32(raw.length-8))throw Error("gzip output CRC/size");
 return {bytes:out,blocks,crc32:crc32(out)};
}
function utf8Text(raw) {
 const parts=[];for(let i=0;i<raw.length;){const first=raw[i++];let p,n,min;if(first<128){parts.push(String.fromCharCode(first));continue;}if(first>=194&&first<=223){p=first&31;n=1;min=128;}else if(first>=224&&first<=239){p=first&15;n=2;min=2048;}else if(first>=240&&first<=244){p=first&7;n=3;min=65536;}else throw Error("invalid UTF8");if(i+n>raw.length)throw Error("truncated UTF8");while(n--){const b=raw[i++];if((b&192)!==128)throw Error("invalid UTF8 continuation");p=(p<<6)|(b&63);}if(p<min||p>0x10ffff||(p>=0xd800&&p<=0xdfff))throw Error("invalid UTF8 scalar");parts.push(String.fromCodePoint(p));}return parts.join("");
}
function parseUSTAR(raw) {
 const files=[];let at=0,ended=false;const dec=(view)=>{let end=view.indexOf(0);return utf8Text(end<0?view:view.subarray(0,end));};
 const oct=(view)=>{const value=dec(view).trim();if(!/^[0-7]+$/.test(value))throw Error("invalid tar octal");return parseInt(value,8);};
 while(at+512<=raw.length){const header=raw.subarray(at,at+512);if(header.every(x=>x===0)){ended=true;break;}
  let sum=0;for(let i=0;i<512;i++)sum+=i>=148&&i<156?32:header[i];if(oct(header.subarray(148,156))!==sum)throw Error("tar checksum");
  if(dec(header.subarray(257,263))!=="ustar")throw Error("tar format");
  const leaf=dec(header.subarray(0,100)),prefix=dec(header.subarray(345,500)),path=prefix?prefix+"/"+leaf:leaf;
  if(!path||path.startsWith("/")||path.split("/").some(x=>x===".."||x==="."||x===""))throw Error("tar path");
  if(header[156]!==48&&header[156]!==0)throw Error("nonregular tar member");
  const size=oct(header.subarray(124,136)),mode=oct(header.subarray(100,108)),uid=oct(header.subarray(108,116)),gid=oct(header.subarray(116,124)),mtime=oct(header.subarray(136,148));
  const start=at+512,end=start+size,next=start+Math.ceil(size/512)*512;if(next>raw.length)throw Error("truncated tar member");
  if(raw.subarray(end,next).some(x=>x!==0))throw Error("tar member padding");
  files.push({path,size,mode,uid,gid,mtime,bytes:raw.subarray(start,end)});at=next;
 }
 if(!ended||raw.length-at<1024||raw.subarray(at).some(x=>x!==0))throw Error("tar end blocks");
 if(new Set(files.map(x=>x.path)).size!==files.length)throw Error("duplicate tar member");
 return files;
}
return {base64Bytes,bytesBase64,crc32,gunzip,utf8Text,parseUSTAR};
