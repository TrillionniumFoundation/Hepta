(()=>{
function require(ok,text){if(!ok)throw Error(text)}
function base64(s){
 const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 require(typeof s==="string"&&s.length%4===0&&/^[A-Za-z0-9+/]*={0,2}$/.test(s),"strict base64 grammar");
 const n=s.length/4*3-(s.endsWith("==")?2:s.endsWith("=")?1:0),out=new Uint8Array(n);let at=0;
 for(let i=0;i<s.length;i+=4){const x=[0,1,2,3].map(j=>s[i+j]==="="?0:chars.indexOf(s[i+j]));require(x.every(v=>v>=0),"base64 alphabet");
  const v=x[0]*262144+x[1]*4096+x[2]*64+x[3];if(at<n)out[at++]=v>>>16;if(at<n)out[at++]=(v>>>8)&255;if(at<n)out[at++]=v&255;
  if(i+4===s.length&&s.endsWith("=="))require((x[1]&15)===0,"base64 pad bits");
  if(i+4===s.length&&s.endsWith("=")&&!s.endsWith("=="))require((x[2]&3)===0,"base64 pad bits");
 }return out;
}
function utf8(raw){
 let text="";for(let i=0;i<raw.length;){
  let a=raw[i++],cp,n,min;if(a<128){cp=a;n=0;min=0}else if(a>=194&&a<=223){cp=a&31;n=1;min=128}
  else if(a>=224&&a<=239){cp=a&15;n=2;min=2048}else if(a>=240&&a<=244){cp=a&7;n=3;min=65536}else throw Error("invalid UTF8 lead");
  require(i+n<=raw.length,"short UTF8");for(let k=0;k<n;k++){const b=raw[i++];require((b&192)===128,"invalid UTF8 continuation");cp=cp*64+(b&63)}
  require(cp>=min&&cp<=0x10ffff&&!(cp>=0xd800&&cp<=0xdfff),"noncanonical UTF8");
  text+=String.fromCodePoint(cp)
 }return text;
}
function inflateZlib(input,expected){
 require(input instanceof Uint8Array&&input.length>=6,"short zlib");
 require((input[0]&15)===8&&(input[0]>>>4)<=7&&((input[0]*256+input[1])%31)===0&&(input[1]&32)===0,"zlib header/dictionary");
 let bit=16,end=(input.length-4)*8,at=0;const out=new Uint8Array(expected);
 function bits(n){require(bit+n<=end,"deflate exceeds payload");let v=0;for(let i=0;i<n;i++,bit++)v|=((input[bit>>>3]>>>(bit&7))&1)<<i;return v}
 function table(lens){
  const count=new Array(16).fill(0),next=new Array(16).fill(0),maps=Array.from({length:16},()=>new Map());let max=0;
  for(const n of lens){require(Number.isInteger(n)&&n>=0&&n<=15,"invalid code length");if(n){count[n]++;max=Math.max(max,n)}}
  let left=1;for(let n=1;n<=15;n++){left=left*2-count[n];require(left>=0,"oversubscribed Huffman")}
  let code=0;for(let n=1;n<=15;n++){code=(code+count[n-1])*2;next[n]=code}
  lens.forEach((n,sym)=>{if(n){let c=next[n]++,rev=0;for(let k=0;k<n;k++){rev=rev*2+(c&1);c>>>=1}require(!maps[n].has(rev),"duplicate Huffman code");maps[n].set(rev,sym)}})
  return {max,maps};
 }
 function symbol(t){let c=0;for(let n=1;n<=t.max;n++){c|=bits(1)<<(n-1);if(t.maps[n].has(c))return t.maps[n].get(c)}throw Error("invalid Huffman symbol")}
 function put(v){require(at<expected,"inflated extent exceeded");out[at++]=v}
 const lengths=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
 const lextra=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
 const distances=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
 const dextra=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
 let final=0,blocks=0;
 while(!final){final=bits(1);const kind=bits(2);blocks++;
  if(kind===0){bit=(bit+7)&~7;const n=bits(16),inv=bits(16);require((n^inv)===65535,"stored block length");for(let i=0;i<n;i++)put(bits(8));continue}
  require(kind===1||kind===2,"reserved block");let lit,dist;
  if(kind===1){lit=table(Array.from({length:288},(_,i)=>i<=143?8:i<=255?9:i<=279?7:8));dist=table(new Array(32).fill(5))}
  else{const nl=bits(5)+257,nd=bits(5)+1,nc=bits(4)+4;require(nl<=286&&nd<=32,"dynamic counts");
   const order=[16,17,18,0,8,7,9,6,10,5,11,4,10+2,3,13,2,14,1,15],cl=new Array(19).fill(0);
   for(let i=0;i<nc;i++)cl[order[i]]=bits(3);
   const ct=table(cl),all=[];while(all.length<nl+nd){const s=symbol(ct);
    if(s<=15)all.push(s);else{let n,v=0;if(s===16){require(all.length>0,"repeat without predecessor");n=bits(2)+3;v=all[all.length-1]}
     else if(s===17)n=bits(3)+3;else if(s===18)n=bits(7)+11;else throw Error("invalid code-length symbol");
     require(all.length+n<=nl+nd,"repeat crosses total");for(let j=0;j<n;j++)all.push(v)}
   }
   require(all[256]>0,"missing EOB");lit=table(all.slice(0,nl));dist=table(all.slice(nl))
  }
  for(;;){const s=symbol(lit);if(s<256){put(s);continue}if(s===256)break;
   require(s>=257&&s<=285,"reserved length");const k=s-257,n=lengths[k]+bits(lextra[k]),d=symbol(dist);require(d<30,"reserved distance");
   const offset=distances[d]+bits(dextra[d]);require(offset>0&&offset<=at,"invalid back reference");for(let i=0;i<n;i++)put(out[at-offset])
  }
 }
 require(at===expected&&Math.ceil(bit/8)===input.length-4,"trailing/short zlib payload");
 let a=1,b=0;for(const v of out){a=(a+v)%65521;b=(b+a)%65521}const sum=(b*65536+a)>>>0;
 const n=input.length,actual=(input[n-4]*16777216+input[n-3]*65536+input[n-2]*256+input[n-1])>>>0;
 require(sum===actual,"Adler32 mismatch");return {raw:out,blocks,adler32:sum};
}
return {base64,utf8,inflateZlib};
})()
