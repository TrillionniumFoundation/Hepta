// Authored audit utility; does not execute recovered source.
export default function transferCodecFactory(){
 const b64=(s,expected)=>{
  if(s.length%4!==0||s.length!==4*Math.ceil(expected/3))throw new Error("base64 length mismatch");
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const vals=new Int16Array(128).fill(-1);for(let i=0;i<64;i++)vals[alphabet.charCodeAt(i)]=i;
  const out=new Uint8Array(expected);let pos=0;
  for(let i=0;i<s.length;i+=4){
   const q=[s.charCodeAt(i),s.charCodeAt(i+1),s.charCodeAt(i+2),s.charCodeAt(i+3)];
   if(q[0]>=128||q[1]>=128||vals[q[0]]<0||vals[q[1]]<0)throw new Error("bad base64 head");
   const a=vals[q[0]],b=vals[q[1]],last=i+4===s.length;
   if(q[2]===61){if(!last||q[3]!==61||(b&15)!==0||pos+1!==expected)throw new Error("bad base64 double padding");out[pos++]=(a<<2)|(b>>4);}
   else {if(q[2]>=128||vals[q[2]]<0)throw new Error("bad base64 third");const c=vals[q[2]];
    out[pos++]=(a<<2)|(b>>4);
    if(q[3]===61){if(!last||(c&3)!==0||pos+1!==expected)throw new Error("bad base64 padding");out[pos++]=((b&15)<<4)|(c>>2);}
    else{if(q[3]>=128||vals[q[3]]<0||pos+2>expected)throw new Error("bad base64 fourth");const d=vals[q[3]];out[pos++]=((b&15)<<4)|(c>>2);out[pos++]=((c&3)<<6)|d;}
   }
  }
  if(pos!==expected)throw new Error("decoded size mismatch");return out;
 };
 const utf8=b=>{
  const parts=[];for(let i=0;i<b.length;){
   const a=b[i++];let c,n,min;if(a<128){c=a;n=0;min=0;}else if(a>=0xc2&&a<=0xdf){c=a&31;n=1;min=128;}else if(a>=0xe0&&a<=0xef){c=a&15;n=2;min=2048;}else if(a>=0xf0&&a<=0xf4){c=a&7;n=3;min=65536;}else throw new Error("invalid UTF-8 lead");
   if(i+n>b.length)throw new Error("incomplete UTF-8");
   for(let j=0;j<n;j++){const d=b[i++];if((d&0xc0)!==0x80)throw new Error("invalid UTF-8 continuation");c=(c<<6)|(d&63);}
   if(c<min||c>0x10ffff||(c>=0xd800&&c<=0xdfff))throw new Error("non-scalar UTF-8");
   parts.push(String.fromCodePoint(c));
  }
  return parts.join("");
 };
 return {b64,utf8};
}
