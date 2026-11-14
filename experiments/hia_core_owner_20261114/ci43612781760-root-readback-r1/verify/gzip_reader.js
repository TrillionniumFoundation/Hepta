return function(gz,expectedSize,expectedSHA,R){
function need(x,m){if(!x)throw Error(m);}
need(gz.length>=18&&gz[0]===31&&gz[1]===139&&gz[2]===8&&gz[3]===0,"gzip fixed header");
need(gz[4]===0&&gz[5]===0&&gz[6]===0&&gz[7]===0,"gzip mtime");
let bit=80,limit=(gz.length-8)*8,op=0;
const out=new Uint8Array(expectedSize),u32=p=>(gz[p]|gz[p+1]<<8|gz[p+2]<<16|gz[p+3]<<24)>>>0;
function read(n){need(bit+n<=limit,"deflate EOF");let v=0;for(let k=0;k<n;k++,bit++)v|=((gz[bit>>>3]>>>(bit&7))&1)<<k;return v>>>0;}
function tree(lens,emptyOK=false){const count=new Int32Array(16),next=new Int32Array(16),map=new Map();let max=0;for(const n of lens){need(Number.isInteger(n)&&n>=0&&n<=15,"code length");if(n){count[n]++;max=Math.max(max,n);}}need(max>0||emptyOK,"empty Huffman tree");let left=1,code=0;for(let n=1;n<=15;n++){left=(left<<1)-count[n];need(left>=0,"oversubscribed Huffman tree");code=(code+count[n-1])<<1;next[n]=code;}for(let sym=0;sym<lens.length;sym++){const n=lens[sym];if(!n)continue;let c=next[n]++,rev=0;for(let k=0;k<n;k++){rev=(rev<<1)|(c&1);c>>>=1;}map.set((1<<n)|rev,sym);}return{map,max};}
function sym(t){let c=0;for(let n=1;n<=t.max;n++){c|=read(1)<<(n-1);const x=t.map.get((1<<n)|c);if(x!==undefined)return x;}throw Error("invalid Huffman symbol");}
const lb=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258],le=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
const db=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577],de=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
let final=0,blocks=0;while(!final){need(++blocks<=65536,"block bound");final=read(1);const kind=read(2);
if(kind===0){bit=(bit+7)&~7;const n=read(16),nn=read(16);need((n^nn)===65535&&op+n<=out.length&&bit+n*8<=limit,"stored block");out.set(gz.slice(bit>>>3,(bit>>>3)+n),op);op+=n;bit+=n*8;continue;}
need(kind===1||kind===2,"reserved block");let lt,dt;
if(kind===1){const a=Array.from({length:288},(_,i)=>i<=143?8:i<=255?9:i<=279?7:8);lt=tree(a);dt=tree(Array(32).fill(5));}
else{const nl=257+read(5),nd=1+read(5),nc=4+read(4);need(nl<=286&&nd<=32,"dynamic counts");const order=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],cl=Array(19).fill(0);for(let k=0;k<nc;k++)cl[order[k]]=read(3);const ct=tree(cl),lens=[];while(lens.length<nl+nd){const v=sym(ct);if(v<=15)lens.push(v);else{let n,value;if(v===16){need(lens.length>0,"repeat missing predecessor");n=3+read(2);value=lens[lens.length-1];}else if(v===17){n=3+read(3);value=0;}else if(v===18){n=11+read(7);value=0;}else throw Error("code repeat");need(lens.length+n<=nl+nd,"code repeat overflow");for(let k=0;k<n;k++)lens.push(value);}}need(lens[256]>0,"end code absent");lt=tree(lens.slice(0,nl));dt=tree(lens.slice(nl),true);}
while(true){const v=sym(lt);if(v<256){need(op<out.length,"literal output bound");out[op++]=v;continue;}if(v===256)break;need(v>=257&&v<=285,"reserved length");const n=lb[v-257]+read(le[v-257]),d=sym(dt);need(d<30,"reserved distance");const distance=db[d]+read(de[d]);need(distance<=op&&distance<=32768&&op+n<=out.length,"match output bound");for(let k=0;k<n;k++){out[op]=out[op-distance];op++;}}}
need(op===expectedSize&&Math.ceil(bit/8)===(gz.length-8),"exact single deflate stream");while(bit<limit)need(read(1)===0,"nonzero final padding");
const table=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0);table[n]=c>>>0;}let crc=0xffffffff;for(const b of out)crc=(crc>>>8)^table[(crc^b)&255];crc=(crc^0xffffffff)>>>0;
need(crc===u32(gz.length-8)&&u32(gz.length-4)===(expectedSize>>>0),"gzip CRC32/ISIZE");need(R.sha256(out)===expectedSHA,"full uncompressed original SHA256");return{bytes:out,blocks,crc32:crc};
};