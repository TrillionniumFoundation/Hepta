const decodeBase64 = (function decodeBase64(text){
 const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 if(text.length%4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))throw Error("invalid strict base64");
 const padding=text.endsWith("==")?2:text.endsWith("=")?1:0,out=new Uint8Array(text.length/4*3-padding);let p=0;
 for(let i=0;i<text.length;i+=4){const a=alphabet.indexOf(text[i]),b=alphabet.indexOf(text[i+1]),c=text[i+2]==="="?0:alphabet.indexOf(text[i+2]),d=text[i+3]==="="?0:alphabet.indexOf(text[i+3]);if(i===text.length-4&&((padding===2&&(b&15))||(padding===1&&(c&3))))throw Error("noncanonical base64 pad bits");const v=(a<<18)|(b<<12)|(c<<6)|d;for(let j=16;j>=0;j-=8)if(p<out.length)out[p++]=(v>>>j)&255;}
 return out;
});
const decodePinnedZlib = (function decodePinnedZlib(data, expectedLength) {
  if (!(data instanceof Uint8Array) || data.length < 6 || (data[0]&15)!==8 ||
      (data[0]>>>4)>7 || ((data[0]<<8)|data[1])%31!==0 || (data[1]&32))
    throw Error("unsupported or invalid zlib header");
  const end=data.length-4, out=new Uint8Array(expectedLength);
  let bit=16,pos=0,final=0,blocks=0;
  function bits(n){if(bit+n>end*8)throw Error("truncated deflate");let v=0;for(let i=0;i<n;i++,bit++)v|=((data[bit>>>3]>>>(bit&7))&1)<<i;return v;}
  function table(lengths){
    const counts=new Uint32Array(16), next=new Uint32Array(16);
    for(const n of lengths){if(n<0||n>15)throw Error("invalid code length");counts[n]++;}
    let code=0,left=1;
    for(let n=1;n<=15;n++){left=(left<<1)-counts[n];if(left<0)throw Error("oversubscribed Huffman tree");code=(code+(n===1?0:counts[n-1]))<<1;next[n]=code;}
    const map=new Map();let max=0;
    for(let symbol=0;symbol<lengths.length;symbol++){const n=lengths[symbol];if(!n)continue;max=Math.max(max,n);const c=next[n]++;let reverse=0;for(let i=0;i<n;i++)reverse=(reverse<<1)|((c>>>i)&1);const key=(1<<n)|reverse;if(map.has(key))throw Error("duplicate Huffman symbol");map.set(key,symbol);}
    return {map,max};
  }
  function symbol(tree){let code=0;for(let n=1;n<=tree.max;n++){code|=bits(1)<<(n-1);const key=(1<<n)|code;if(tree.map.has(key))return tree.map.get(key);}throw Error("invalid Huffman code");}
  function put(v){if(pos>=out.length)throw Error("inflated output exceeds pinned length");out[pos++]=v;}
  const lengths=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
  const lextra=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
  const distances=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
  const dextra=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
  while(!final){
    final=bits(1);const kind=bits(2);blocks++;
    if(kind===0){
      bit=(bit+7)&~7;const n=bits(16),opposite=bits(16);
      if(((n^65535)&65535)!==opposite)throw Error("stored block length mismatch");
      for(let i=0;i<n;i++)put(bits(8));
      continue;
    }
    if(kind===3)throw Error("reserved deflate block");
    let literal,distance;
    if(kind===1){
      literal=table(Array.from({length:288},(_,i)=>i<144?8:i<256?9:i<280?7:8));
      distance=table(Array(32).fill(5));
    }else{
      const nlit=bits(5)+257,ndist=bits(5)+1,ncode=bits(4)+4;
      if(nlit>286||ndist>32)throw Error("invalid dynamic extent");
      const order=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],cl=Array(19).fill(0);
      for(let i=0;i<ncode;i++)cl[order[i]]=bits(3);
      const codeTree=table(cl),all=[];
      while(all.length<nlit+ndist){
        const v=symbol(codeTree);
        if(v<=15)all.push(v);
        else{
          if(v===16&&all.length===0)throw Error("repeat before a code length");
          const repeat=v===16?bits(2)+3:v===17?bits(3)+3:v===18?bits(7)+11:0;
          if(!repeat||all.length+repeat>nlit+ndist)throw Error("invalid code repeat");
          const x=v===16?all[all.length-1]:0;for(let i=0;i<repeat;i++)all.push(x);
        }
      }
      if(all[256]===0)throw Error("missing end-of-block");
      literal=table(all.slice(0,nlit));distance=table(all.slice(nlit));
    }
    while(true){
      const v=symbol(literal);
      if(v<256){put(v);continue;}
      if(v===256)break;
      if(v<257||v>285)throw Error("reserved length symbol");
      const n=lengths[v-257]+bits(lextra[v-257]),d=symbol(distance);
      if(d>=30)throw Error("reserved distance symbol");
      const offset=distances[d]+bits(dextra[d]);
      if(offset>pos||offset>32768)throw Error("invalid back reference");
      for(let i=0;i<n;i++)put(out[pos-offset]);
    }
  }
  if(pos!==out.length || Math.ceil(bit/8)!==end)throw Error("trailing or truncated zlib payload");
  if(bit&7){const paddingMask=(255<<(bit&7))&255;if(data[bit>>>3]&paddingMask)throw Error("nonzero final padding");}
  let a=1,b=0;for(let start=0;start<out.length;start+=5552){for(let i=start;i<Math.min(start+5552,out.length);i++){a+=out[i];b+=a;}a%=65521;b%=65521;}
  const adler=((b<<16)|a)>>>0, expected=((data[end]<<24)|(data[end+1]<<16)|(data[end+2]<<8)|data[end+3])>>>0;
  if(adler!==expected)throw Error("zlib Adler32 mismatch");
  return {out,blocks,adler32:adler.toString(16).padStart(8,"0"),compressed_consumed:data.length};
});
