
function gunzipExact(bytes,wantedSize){
 function fail(s){throw Error("gzip/deflate: "+s);}
 if(bytes.length<18||bytes[0]!==31||bytes[1]!==139||bytes[2]!==8||bytes[3]!==0)fail("unsupported header");
 const src=bytes.slice(10,-8);let bit=0;
 function read(n){if(bit+n>src.length*8)fail("truncated bits");let v=0;for(let i=0;i<n;i++,bit++)v|=((src[bit>>3]>>(bit&7))&1)<<i;return v;}
 function huffman(lengths){
  const max=Math.max(...lengths),count=Array(max+1).fill(0),next=Array(max+1).fill(0),maps=Array.from({length:max+1},()=>new Map());
  for(const n of lengths){if(n<0||n>15)fail("code length");if(n)count[n]++;}
  let left=1,c=0;for(let n=1;n<=max;n++){left=left*2-count[n];if(left<0)fail("oversubscribed tree");c=(c+(count[n-1]||0))*2;next[n]=c;}
  for(let sym=0;sym<lengths.length;sym++){const n=lengths[sym];if(!n)continue;let x=next[n]++,rev=0;for(let j=0;j<n;j++){rev=(rev<<1)|(x&1);x>>>=1;}if(maps[n].has(rev))fail("duplicate code");maps[n].set(rev,sym);}
  return {max,maps};
 }
 function decode(h){let c=0;for(let n=1;n<=h.max;n++){c|=read(1)<<(n-1);if(h.maps[n].has(c))return h.maps[n].get(c);}fail("invalid symbol");}
 const lb=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
 const le=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
 const db=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
 const de=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
 const out=new Uint8Array(wantedSize);let at=0,final=0;
 function put(b){if(at>=out.length)fail("output size overrun");out[at++]=b;}
 while(!final){
  final=read(1);const type=read(2);
  if(type===0){bit=(bit+7)&~7;const n=read(16),nn=read(16);if(((n^nn)&65535)!==65535)fail("stored inverse length");for(let i=0;i<n;i++)put(read(8));continue;}
  let lit,dist;
  if(type===1){
   lit=huffman(Array.from({length:288},(_,i)=>i<144?8:i<256?9:i<280?7:8));dist=huffman(Array(32).fill(5));
  }else if(type===2){
   const nl=257+read(5),nd=1+read(5),nc=4+read(4),order=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],cl=Array(19).fill(0);
   for(let i=0;i<nc;i++)cl[order[i]]=read(3);
   const ch=huffman(cl),lengths=[];
   while(lengths.length<nl+nd){
    const v=decode(ch);
    if(v<16)lengths.push(v);
    else{
     let repeat,value;
     if(v===16){if(!lengths.length)fail("repeat without prior");value=lengths[lengths.length-1];repeat=3+read(2);}
     else if(v===17){value=0;repeat=3+read(3);}
     else if(v===18){value=0;repeat=11+read(7);}
     else fail("length symbol");
     if(lengths.length+repeat>nl+nd)fail("code lengths overflow");
     for(let k=0;k<repeat;k++)lengths.push(value);
    }
   }
   if(!lengths[256])fail("missing end code");
   lit=huffman(lengths.slice(0,nl));dist=huffman(lengths.slice(nl));
  }else fail("reserved block");
  while(true){
   const v=decode(lit);
   if(v<256){put(v);continue;}
   if(v===256)break;
   if(v<257||v>285)fail("length code");
   const i=v-257,n=lb[i]+read(le[i]),d=decode(dist);
   if(d>=30)fail("distance code");
   const back=db[d]+read(de[d]);if(back>at||back<1)fail("distance beyond output");
   for(let k=0;k<n;k++)put(out[at-back]);
  }
 }
 if(at!==wantedSize||Math.ceil(bit/8)!==src.length)fail("complete stream size");
 function u32(pos){return (bytes[pos]|bytes[pos+1]<<8|bytes[pos+2]<<16|bytes[pos+3]<<24)>>>0;}
 if(u32(bytes.length-4)!==(at>>>0))fail("footer size");
 let crc=0xffffffff;
 for(const b of out){crc^=b;for(let k=0;k<8;k++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}
 crc=(crc^0xffffffff)>>>0;if(crc!==u32(bytes.length-8))fail("CRC32");
 return Array.from(out);
}
