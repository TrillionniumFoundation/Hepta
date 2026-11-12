
const {FunctionBuilder:F,render}=new Function(builderSource)();
const funcs=[];
function helperRead() {
 const f=new F("f3",["mutbuf","u64"]),e=f.entry,[w,at]=e.params;
 const loop=f.block(["mutbuf","u64","u64","u64"]),body=f.block(["mutbuf","u64","u64","u64"]),done=f.block(["u64"]);
 const z=f.constant(e,"u64",0);f.jump(e,loop,[w,at,z,z]);
 {const [w,at,i,acc]=loop.params,limit=f.constant(loop,"u64",8);f.branch(loop,f.compare(loop,"lt",i,limit),body,[w,at,i,acc],done,[acc]);}
 {const [w,at,i,acc]=body.params,offset=f.bin(body,"int.add.wrap",at,i),ch=f.op(body,"buffer.load",[w,f.cast(body,offset,"usize")],"u8"),bits=f.bin(body,"int.mul.wrap",i,f.constant(body,"u64",8)),part=f.bin(body,"int.shl.checked",f.cast(body,ch,"u64"),bits),next=f.bin(body,"int.add.wrap",i,f.constant(body,"u64",1));f.jump(body,loop,[w,at,next,f.bin(body,"bit.or",acc,part)]);}
 f.ret(done,done.params[0]);return f.document();
}
function helperWrite() {
 const f=new F("f4",["mutbuf","u64","u64"]),e=f.entry;
 const loop=f.block(["mutbuf","u64","u64","u64"]),body=f.block(["mutbuf","u64","u64","u64"]),done=f.block([]);
 f.jump(e,loop,[...e.params,f.constant(e,"u64",0)]);
 {const [w,at,v,i]=loop.params;f.branch(loop,f.compare(loop,"lt",i,f.constant(loop,"u64",8)),body,[w,at,v,i],done,[]);}
 {const [w,at,v,i]=body.params,offset=f.bin(body,"int.add.wrap",at,i),bits=f.bin(body,"int.mul.wrap",i,f.constant(body,"u64",8)),part=f.bin(body,"int.shr.checked",v,bits);f.op(body,"buffer.store",[w,f.cast(body,offset,"usize"),f.cast(body,part,"u8")]);f.jump(body,loop,[w,at,v,f.bin(body,"int.add.wrap",i,f.constant(body,"u64",1))]);}
 f.ret(done,f.constant(done,"u64",0));return f.document();
}
function helperAppend(){
 const f=new F("f1",["mutbuf","mutbuf","u8"]),e=f.entry,[o,w,ch]=e.params;
 const select=f.block(["mutbuf","mutbuf","u8","u64","u64"]),write=f.block(["mutbuf","mutbuf","u8","u64","u64"]),store=f.block(["mutbuf","mutbuf","u8","u64","u64"]),advance=f.block(["mutbuf","u64"]),overflow=f.block([]),small=f.block([]);
 const cursor=f.call(e,"f3",[w,f.constant(e,"u64",8)]),next=f.bin(e,"int.add.wrap",cursor,f.constant(e,"u64",1));
 f.branch(e,f.compare(e,"gt",next,cursor),select,[o,w,ch,cursor,next],overflow,[]);
 {const [o,w,ch,cursor,next]=select.params,mode=f.call(select,"f3",[w,f.constant(select,"u64",0)]);f.branch(select,f.compare(select,"eq",mode,f.constant(select,"u64",0)),advance,[w,next],write,[o,w,ch,cursor,next]);}
 {const [o,w,ch,cursor,next]=write.params,len=f.cast(write,f.op(write,"buffer.len",[o],"usize"),"u64");f.branch(write,f.compare(write,"lt",cursor,len),store,[o,w,ch,cursor,next],small,[]);}
 {const [o,w,ch,cursor,next]=store.params;f.op(store,"buffer.store",[o,f.cast(store,cursor,"usize"),ch]);f.jump(store,advance,[w,next]);}
 {const [w,next]=advance.params;f.call(advance,"f4",[w,f.constant(advance,"u64",8),next]);f.ret(advance,f.constant(advance,"u64",0));}
 f.ret(overflow,f.constant(overflow,"u64",5));f.ret(small,f.constant(small,"u64",3));return f.document();
}
function helperIndent(){
 const f=new F("f2",["mutbuf","mutbuf","usize"]),e=f.entry,[o,w,depth]=e.params;
 const start=f.block(["mutbuf","mutbuf","usize"]),loop=f.block(["mutbuf","mutbuf","usize","usize"]),body=f.block(["mutbuf","mutbuf","usize","usize"]),next=f.block(["mutbuf","mutbuf","usize","usize"]),done=f.block([]),fail=f.block(["u64"]);
 const status=f.call(e,"f1",[o,w,f.constant(e,"u8",10)]);f.branch(e,f.compare(e,"eq",status,f.constant(e,"u64",0)),start,[o,w,depth],fail,[status]);
 {const [o,w,depth]=start.params,total=f.bin(start,"int.mul.wrap",depth,f.constant(start,"usize",2));f.jump(start,loop,[o,w,total,f.constant(start,"usize",0)]);}
 {const [o,w,total,i]=loop.params;f.branch(loop,f.compare(loop,"lt",i,total),body,[o,w,total,i],done,[]);}
 {const [o,w,total,i]=body.params,status=f.call(body,"f1",[o,w,f.constant(body,"u8",32)]);f.branch(body,f.compare(body,"eq",status,f.constant(body,"u64",0)),next,[o,w,total,i],fail,[status]);}
 {const [o,w,total,i]=next.params;f.jump(next,loop,[o,w,total,f.bin(next,"int.add.wrap",i,f.constant(next,"usize",1))]);}
 f.ret(done,f.constant(done,"u64",0));f.ret(fail,fail.params[0]);return f.document();
}
function helperError(){
 const f=new F("f5",["mutbuf","usize","u64"]),e=f.entry,[w,i,code]=e.params;
 f.call(e,"f4",[w,f.constant(e,"u64",16),f.cast(e,i,"u64")]);f.call(e,"f4",[w,f.constant(e,"u64",24),code]);f.ret(e,code);return f.document();
}
function main(){
 const f=new F("f0",["readbuf","mutbuf","mutbuf"],"u32"),e=f.entry;
 const abi=f.block([]),config=f.block(["readbuf","mutbuf","mutbuf"]),init=f.block(["readbuf","mutbuf","mutbuf"]);
 const loop=f.block(["readbuf","mutbuf","mutbuf","usize","usize","bool","bool"]);
 const take=f.block(loop.params.map(v=>v.type)),finish=f.block(["mutbuf","usize","usize","bool","bool"]),success=f.block([]);
 const error=f.block(["mutbuf","usize","u64"]);
 f.ret(abi,f.constant(abi,"u32",1));f.ret(success,f.constant(success,"u32",0));f.ret(error,f.cast(error,f.call(error,"f5",error.params),"u32"));
 const [s,o,w]=e.params;f.branch(e,f.compare(e,"ge",f.op(e,"buffer.len",[w],"usize"),f.constant(e,"usize",32)),config,[s,o,w],abi,[]);
 {const [s,o,w]=config.params,size=f.op(config,"buffer.len",[s],"usize"),mode=f.call(config,"f3",[w,f.constant(config,"u64",0)]),sizeOK=f.compare(config,"le",size,f.constant(config,"usize",8388608)),modeOK=f.compare(config,"le",mode,f.constant(config,"u64",1)),valid=f.bin(config,"bool.and",sizeOK,modeOK,"bool");f.branch(config,valid,init,[s,o,w],error,[w,f.constant(config,"usize",0),f.constant(config,"u64",1)]);}
 {const [s,o,w]=init.params,z=f.constant(init,"u64",0);for(const off of [8,16,24])f.call(init,"f4",[w,f.constant(init,"u64",off),z]);const size=f.op(init,"buffer.len",[s],"usize");const uz=f.constant(init,"usize",0),bfalse=f.constant(init,"bool",false);f.branch(init,f.compare(init,"gt",size,uz),loop,[s,o,w,uz,uz,bfalse,bfalse],error,[w,uz,f.constant(init,"u64",2)]);}
 {const [s,o,w,i,depth,quoted,escaped]=loop.params;f.branch(loop,f.compare(loop,"lt",i,f.op(loop,"buffer.len",[s],"usize")),take,[s,o,w,i,depth,quoted,escaped],finish,[w,i,depth,quoted,escaped]);}
 {const [w,i,depth,quoted,escaped]=finish.params,badString=f.bin(finish,"bool.or",quoted,escaped,"bool"),badDepth=f.compare(finish,"ne",depth,f.constant(finish,"usize",0)),bad=f.bin(finish,"bool.or",badString,badDepth,"bool");f.branch(finish,bad,error,[w,i,f.constant(finish,"u64",2)],success,[]);}
 const text=f.block(["readbuf","mutbuf","mutbuf","usize","usize","bool","u8"]);
 const outside=f.block(["readbuf","mutbuf","mutbuf","usize","usize","u8"]);
 {const [s,o,w,i,depth,quoted,escaped]=take.params,ch=f.op(take,"buffer.load",[s,i],"u8");f.branch(take,quoted,text,[s,o,w,i,depth,escaped,ch],outside,[s,o,w,i,depth,ch]);}
 function env(block,names){return Object.fromEntries(names.map((n,i)=>[n,block.params[i]]));}
 function guard(block,v,name,args){const status=f.call(block,name,args),yes=f.block(Object.values(v).map(x=>x.type));f.branch(block,f.compare(block,"eq",status,f.constant(block,"u64",0)),yes,Object.values(v),error,[v.w,v.i,status]);return[yes,env(yes,Object.keys(v))];}
 function back(block,v,quoted=false,escaped=false,step=1,depth=v.depth){const qi=typeof quoted==="boolean"?f.constant(block,"bool",quoted):quoted,ei=typeof escaped==="boolean"?f.constant(block,"bool",escaped):escaped;f.jump(block,loop,[v.s,v.o,v.w,f.bin(block,"int.add.wrap",v.i,f.constant(block,"usize",step)),depth,qi,ei]);}
 {let b=text,v=env(text,["s","o","w","i","depth","escaped","ch"]);[b,v]=guard(b,v,"f1",[v.o,v.w,v.ch]);const notEscaped=f.compare(b,"eq",v.escaped,f.constant(b,"bool",false)),slash=f.compare(b,"eq",v.ch,f.constant(b,"u8",92)),quote=f.compare(b,"eq",v.ch,f.constant(b,"u8",34)),isEnd=f.bin(b,"bool.and",notEscaped,quote,"bool"),q=f.compare(b,"eq",isEnd,f.constant(b,"bool",false)),esc=f.bin(b,"bool.and",notEscaped,slash,"bool");back(b,v,q,esc);}
 const quote=f.block(outside.params.map(v=>v.type)),openCheck=f.block(outside.params.map(v=>v.type));
 {const v=env(outside,["s","o","w","i","depth","ch"]);f.branch(outside,f.compare(outside,"eq",v.ch,f.constant(outside,"u8",34)),quote,Object.values(v),openCheck,Object.values(v));}
 {let b=quote,v=env(b,["s","o","w","i","depth","ch"]);[b,v]=guard(b,v,"f1",[v.o,v.w,v.ch]);back(b,v,true,false);}
 const open=f.block(outside.params.map(v=>v.type)),closeCheck=f.block(outside.params.map(v=>v.type));
 {const v=env(openCheck,["s","o","w","i","depth","ch"]),a=f.compare(openCheck,"eq",v.ch,f.constant(openCheck,"u8",91)),o=f.compare(openCheck,"eq",v.ch,f.constant(openCheck,"u8",123));f.branch(openCheck,f.bin(openCheck,"bool.or",a,o,"bool"),open,Object.values(v),closeCheck,Object.values(v));}
 const peek=f.block(outside.params.map(v=>v.type)),nonempty=f.block(outside.params.map(v=>v.type)),empty=f.block(outside.params.map(v=>v.type));
 {const v=env(open,["s","o","w","i","depth","ch"]),next=f.bin(open,"int.add.wrap",v.i,f.constant(open,"usize",1));f.branch(open,f.compare(open,"lt",next,f.op(open,"buffer.len",[v.s],"usize")),peek,Object.values(v),nonempty,Object.values(v));}
 {const v=env(peek,["s","o","w","i","depth","ch"]),next=f.bin(peek,"int.add.wrap",v.i,f.constant(peek,"usize",1)),actual=f.op(peek,"buffer.load",[v.s,next],"u8"),expected=f.bin(peek,"int.add.wrap",v.ch,f.constant(peek,"u8",2));f.branch(peek,f.compare(peek,"eq",actual,expected),empty,Object.values(v),nonempty,Object.values(v));}
 {let b=empty,v=env(b,["s","o","w","i","depth","ch"]);[b,v]=guard(b,v,"f1",[v.o,v.w,v.ch]);const closer=f.bin(b,"int.add.wrap",v.ch,f.constant(b,"u8",2));[b,v]=guard(b,v,"f1",[v.o,v.w,closer]);back(b,v,false,false,2);}
 const push=f.block(outside.params.map(v=>v.type));
 {const v=env(nonempty,["s","o","w","i","depth","ch"]),capacity=f.bin(nonempty,"int.sub.wrap",f.op(nonempty,"buffer.len",[v.w],"usize"),f.constant(nonempty,"usize",32));f.branch(nonempty,f.compare(nonempty,"lt",v.depth,capacity),push,Object.values(v),error,[v.w,v.i,f.constant(nonempty,"u64",4)]);}
 {let b=push,v=env(b,["s","o","w","i","depth","ch"]);f.op(b,"buffer.store",[v.w,f.bin(b,"int.add.wrap",v.depth,f.constant(b,"usize",32)),v.ch]);[b,v]=guard(b,v,"f1",[v.o,v.w,v.ch]);v={...v,depth:f.bin(b,"int.add.wrap",v.depth,f.constant(b,"usize",1))};[b,v]=guard(b,v,"f2",[v.o,v.w,v.depth]);back(b,v);}
 const close=f.block(outside.params.map(v=>v.type)),commaCheck=f.block(outside.params.map(v=>v.type));
 {const v=env(closeCheck,["s","o","w","i","depth","ch"]),a=f.compare(closeCheck,"eq",v.ch,f.constant(closeCheck,"u8",93)),o=f.compare(closeCheck,"eq",v.ch,f.constant(closeCheck,"u8",125));f.branch(closeCheck,f.bin(closeCheck,"bool.or",a,o,"bool"),close,Object.values(v),commaCheck,Object.values(v));}
 const pop=f.block(outside.params.map(v=>v.type)),matched=f.block(outside.params.map(v=>v.type));
 {const v=env(close,["s","o","w","i","depth","ch"]);f.branch(close,f.compare(close,"gt",v.depth,f.constant(close,"usize",0)),pop,Object.values(v),error,[v.w,v.i,f.constant(close,"u64",2)]);}
 {const v=env(pop,["s","o","w","i","depth","ch"]),depth=f.bin(pop,"int.sub.wrap",v.depth,f.constant(pop,"usize",1)),opener=f.op(pop,"buffer.load",[v.w,f.bin(pop,"int.add.wrap",depth,f.constant(pop,"usize",32))],"u8"),expected=f.bin(pop,"int.add.wrap",opener,f.constant(pop,"u8",2));f.branch(pop,f.compare(pop,"eq",v.ch,expected),matched,[v.s,v.o,v.w,v.i,depth,v.ch],error,[v.w,v.i,f.constant(pop,"u64",2)]);}
 {let b=matched,v=env(b,["s","o","w","i","depth","ch"]);[b,v]=guard(b,v,"f2",[v.o,v.w,v.depth]);[b,v]=guard(b,v,"f1",[v.o,v.w,v.ch]);back(b,v);}
 const comma=f.block(outside.params.map(v=>v.type)),colonCheck=f.block(outside.params.map(v=>v.type));
 {const v=env(commaCheck,["s","o","w","i","depth","ch"]);f.branch(commaCheck,f.compare(commaCheck,"eq",v.ch,f.constant(commaCheck,"u8",44)),comma,Object.values(v),colonCheck,Object.values(v));}
 const commaEmit=f.block(outside.params.map(v=>v.type));
 {const v=env(comma,["s","o","w","i","depth","ch"]);f.branch(comma,f.compare(comma,"gt",v.depth,f.constant(comma,"usize",0)),commaEmit,Object.values(v),error,[v.w,v.i,f.constant(comma,"u64",2)]);}
 {let b=commaEmit,v=env(b,["s","o","w","i","depth","ch"]);[b,v]=guard(b,v,"f1",[v.o,v.w,v.ch]);[b,v]=guard(b,v,"f2",[v.o,v.w,v.depth]);back(b,v);}
 const colon=f.block(outside.params.map(v=>v.type)),ordinary=f.block(outside.params.map(v=>v.type));
 {const v=env(colonCheck,["s","o","w","i","depth","ch"]);f.branch(colonCheck,f.compare(colonCheck,"eq",v.ch,f.constant(colonCheck,"u8",58)),colon,Object.values(v),ordinary,Object.values(v));}
 const colonParent=f.block(outside.params.map(v=>v.type)),colonEmit=f.block(outside.params.map(v=>v.type));
 {const v=env(colon,["s","o","w","i","depth","ch"]);f.branch(colon,f.compare(colon,"gt",v.depth,f.constant(colon,"usize",0)),colonParent,Object.values(v),error,[v.w,v.i,f.constant(colon,"u64",2)]);}
 {const v=env(colonParent,["s","o","w","i","depth","ch"]),depth=f.bin(colonParent,"int.sub.wrap",v.depth,f.constant(colonParent,"usize",1)),opener=f.op(colonParent,"buffer.load",[v.w,f.bin(colonParent,"int.add.wrap",depth,f.constant(colonParent,"usize",32))],"u8");f.branch(colonParent,f.compare(colonParent,"eq",opener,f.constant(colonParent,"u8",123)),colonEmit,Object.values(v),error,[v.w,v.i,f.constant(colonParent,"u64",2)]);}
 {let b=colonEmit,v=env(b,["s","o","w","i","depth","ch"]);[b,v]=guard(b,v,"f1",[v.o,v.w,v.ch]);[b,v]=guard(b,v,"f1",[v.o,v.w,f.constant(b,"u8",32)]);back(b,v);}
 const ordinaryEmit=f.block(outside.params.map(v=>v.type));
 {const v=env(ordinary,["s","o","w","i","depth","ch"]),normal=f.compare(ordinary,"gt",v.ch,f.constant(ordinary,"u8",32));f.branch(ordinary,normal,ordinaryEmit,Object.values(v),error,[v.w,v.i,f.constant(ordinary,"u64",2)]);}
 {let b=ordinaryEmit,v=env(b,["s","o","w","i","depth","ch"]);[b,v]=guard(b,v,"f1",[v.o,v.w,v.ch]);back(b,v);}
 return f.document();
}
funcs.push(main(),helperAppend(),helperIndent(),helperRead(),helperWrite(),helperError());
const document={schema:"hepta.hia.program.v8",module:"json_pretty",functions:funcs};
return {document,assembly:render(document)};
