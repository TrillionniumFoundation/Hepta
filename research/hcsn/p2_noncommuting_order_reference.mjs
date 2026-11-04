/** HCSN P2 research only. Independent two-state noncommuting generator reference.
 * Inputs 0/1 enable only transition 0->1 / 1->0. This is a CONTROL model,
 * NOT a verified He-Xiong first-hit, dynamic boundary, learned HCSN or MQAR.
 * Node usage: node research/hcsn/p2_noncommuting_order_reference.mjs > /tmp/iter37.json
 * Gate usage: node research/hcsn/p2_noncommuting_order_reference.mjs --strict
 * --strict ALWAYS exits 2 without independent external scientific evidence.
 */
function bad(x){throw new Error(x)}

function validated(s){if(!Array.isArray(s)||!s.length)bad("empty schedule");for(const a of s){if(!Array.isArray(a)||a.length!==2||!Number.isFinite(a[0])||a[0]<=0||!(a[1]===0||a[1]===1))bad("bad schedule")}}

function exact(s,r=2){validated(s);if(!Number.isFinite(r)||r<=0)bad("bad rate");let p=0;for(const [dt,x] of s){const q=Math.exp(-r*dt);p=x===0?1-(1-p)*q:p*q}return p}

function independentRk4(s,r=2,step=1/2000){validated(s);let p=0;for(const [dt,x] of s){const n=Math.ceil(dt/step),h=dt/n,f=v=>x===0?r*(1-v):-r*v;for(let k=0;k<n;k++){const a=f(p),b=f(p+h*a/2),c=f(p+h*b/2),d=f(p+h*c);p+=h*(a+2*b+2*c+d)/6}}return p}

function rng32(seed){let x=seed>>>0;if(!x)x=0x6d2b79f5;return function(){x^=x<<13;x^=x>>>17;x^=x<<5;return ((x>>>0)+.5)/4294967296}}

function sample(s,r,random){validated(s);let state=0;for(const [dt,x] of s){if(state===x){const hit=-Math.log(random())/r;if(hit<dt)state=1-x}}return state}

function split(s,n){return s.flatMap(([dt,x])=>Array.from({length:n},()=>[dt/n,x]))}

function scalarEndpoint(s,beta=1.5,a=2,b=1){validated(s);const h=s.reduce((v,[dt,x])=>v+dt*Math.exp(beta*x),0);return a/(a+b)*(-Math.expm1(-(a+b)*h))}

function assert(condition,what){if(!condition)bad("FAIL "+what);return 1}

function runVerification(){
 const A=[[1,0],[1,1]],B=[[1,1],[1,0]],r=2,q=Math.exp(-r);
 const pA=exact(A,r),pB=exact(B,r);
 let tests=0;
 tests+=assert(Math.abs(pA-(1-q)*q)<1e-14,"analytic A");
 tests+=assert(Math.abs(pB-(1-q))<1e-14,"analytic B");
 tests+=assert(Math.abs((pB-pA)-(1-q)*(1-q))<1e-14,"commutator signature");
 tests+=assert(Math.abs(scalarEndpoint(A)-scalarEndpoint(B))<1e-14,"scalar control");
 let maxOdeError=0,maxRefinementError=0;
 for(const s of [A,B]){const e=Math.abs(exact(s)-independentRk4(s));maxOdeError=Math.max(maxOdeError,e);tests+=assert(e<1e-9,"independent RK4");for(const n of [4,16,64]){const ee=Math.abs(exact(s)-exact(split(s,n)));maxRefinementError=Math.max(maxRefinementError,ee);tests+=assert(ee<1e-12,"physical time partition")}}
 const randomized=[];
 let maxZ=0;
 for(const seed of [11,23,37]){
   const u=rng32(seed^0xada772),v=rng32(seed^0xbbda830),n=20000;let ca=0,cb=0;
   for(let j=0;j<n;j++){ca+=sample(A,r,u);cb+=sample(B,r,v)}
   const za=Math.abs(ca/n-pA)/Math.sqrt(pA*(1-pA)/n),zb=Math.abs(cb/n-pB)/Math.sqrt(pB*(1-pB)/n);
   maxZ=Math.max(maxZ,za,zb);tests+=assert(za<4&&zb<4,"MC 4sigma "+seed);
   randomized.push({seed,n,success_A:ca,success_B:cb,freq_A:ca/n,freq_B:cb/n,z_A:za,z_B:zb})
 }
 const ood=[];
 for(const rate of [0.7,2,4])for(const duration of [.25,1,3]){
    const a=[[duration,0],[duration,1]],b=[[duration,1],[duration,0]];
    const diff=exact(b,rate)-exact(a,rate),pred=(1-Math.exp(-rate*duration))**2;
    tests+=assert(Math.abs(diff-pred)<1e-12,"rate/duration heldout "+rate+","+duration);
    ood.push({rate,duration,p_A:exact(a,rate),p_B:exact(b,rate),difference:diff,analytic_difference:pred})
 }
 for(const s of [[],[[0,0]],[[-1,1]],[[1,3]]]){let threw=false;try{exact(s)}catch(e){threw=true}tests+=assert(threw,"bad input rejected")}
 return {research_only:true,gate_states:Object.fromEntries(Array.from({length:7},(_,i)=>["P"+i,"OPEN"])),production_activation:false, strict_expected_exit_code:2, reference:"two-state noncommuting Q0,Q1 exact piecewise CTMC; labels last symbol; NOT a trained model", samples_per_seed_per_order:20000, segments_A:A,segments_B:B,labels_A_B:[0,1],rate:r,p_A:pA,p_B:pB,scalar_shared_Q_gap:scalarEndpoint(A)-scalarEndpoint(B),bayes_balanced_endpoint_accuracy:0.5+Math.abs(pB-pA)/2,max_independent_rk4_error:maxOdeError,max_physical_refinement_error:maxRefinementError,max_MC_standardized_error:maxZ,seed_results:randomized,heldout_analytic_scenarios:ood,assertions_passed:tests,limitations:["not He-Xiong free boundary","not a learned HCSN","not Selective Copy/MQAR","not FLOP-matched or preregistered","not pretrained encoders or device measurement","separate independent external scientific gate not available"]}
}

const result=runVerification();
console.log(JSON.stringify(result,null,2));
if(process.argv.includes("--strict"))process.exitCode=2;
