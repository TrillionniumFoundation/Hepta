return function decodeOriginalUTF8(bytes) {
  const pieces=[],points=[];
  function flush(){if(points.length){pieces.push(String.fromCodePoint(...points));points.length=0;}}
  for(let i=0;i<bytes.length;){
    const first=bytes[i++];let cp,count,min;
    if(first<128){cp=first;count=0;min=0;}
    else if(first>=194&&first<=223){cp=first&31;count=1;min=128;}
    else if(first>=224&&first<=239){cp=first&15;count=2;min=2048;}
    else if(first>=240&&first<=244){cp=first&7;count=3;min=65536;}
    else throw Error("ORIGINAL_UTF8_REFUSAL: invalid lead");
    if(i+count>bytes.length)throw Error("ORIGINAL_UTF8_REFUSAL: truncated scalar");
    for(let k=0;k<count;k++){const next=bytes[i++];if((next&192)!==128)throw Error("ORIGINAL_UTF8_REFUSAL: invalid continuation");cp=(cp<<6)|(next&63);}
    if(cp<min||cp>1114111||(cp>=55296&&cp<=57343))throw Error("ORIGINAL_UTF8_REFUSAL: noncanonical scalar");
    points.push(cp);if(points.length>=8192)flush();
  }
  flush();return pieces.join("");
};
