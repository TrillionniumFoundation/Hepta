/** Deterministic negative reference, pinned to #745 exact-source Git blob.
 * Run: node research/hcsn/p2_scale_equivariance_evidence.mjs --strict
 * STRICT exit 2 unless independently signed P0–P6 scientific evidence is present;
 * this bounded counterexample never supplies that evidence.
 */
import {ExactOccupancyLedger} from './p2_exact_occupancy_reference.mjs';
import {writeFileSync} from 'node:fs';

const sourceCommit = 'b05d49607c4b90c424623e9aee1f6e3d0d70d864';
const sourceBlob = 'ac5a4a6c757c5c9c01983639d17178b29c08d406';
const a=[1,1], b=[7,7];
const norm=v=>v.map(x=>x/Math.hypot(...v));
const exactIntegerRay=(u,v)=>u[0]*v[1]===u[1]*v[0]&&u[0]*v[0]+u[1]*v[1]>0;
const ledger = new ExactOccupancyLedger({dimension:2,capacity:2,collisionRadius:1e-6});
ledger.write(a,17);
const witness={write:a,read:b,exact_same_positive_integer_ray:exactIntegerRay(a,b),normalized_write:norm(a),normalized_read:norm(b),normalized_distance:Math.hypot(...norm(a).map((v,i)=>v-norm(b)[i])),read_result:ledger.read(b),same_array_result:ledger.read(a),scaled_write: (()=> {try{return ledger.write(b,19)}catch(e){return e.constructor.name}})(),occupancy:ledger.occupancy};

const samples=[];
for(let x=1;x<=12;x++) for(let y=1;y<=12;y++) for(let s=2;s<=19;s++) {
  const w=[x,y],q=[s*x,s*y];
  const t=new ExactOccupancyLedger({dimension:2,capacity:1,collisionRadius:1e-6});
  t.write(w,23);
  samples.push({x,y,s,status:t.read(q).status});
}
const frequencies=Object.fromEntries(['known','ambiguous','unknown'].map(status=>[status,samples.filter(x=>x.status===status).length]));
const out={kind:'HCSN_P2_EXACT_NORMALIZED_RAY_SCALE_NEGATIVE',sourceCommit,sourceBlob,nodeVersion:process.version,rounding:'IEEE754 binary64 via Node Math.hypot and division',witness,grid:{x:[1,12],y:[1,12],scale:[2,19],total:samples.length,frequencies},gates:Object.fromEntries(Array.from({length:7},(_,i)=>['P'+i,'OPEN'])),external_acceptance:false,production_activation:false,scope:'finite numerical ledger only; not original HX/QVI or trained model'};
if (!witness.exact_same_positive_integer_ray || witness.read_result.status!=='ambiguous' || witness.scaled_write!=='AddressCollision' || witness.same_array_result.status!=='known' || frequencies.ambiguous===0 || frequencies.unknown!==0) throw new Error('unexpected regression: inspect source and runtime');
const arg=process.argv.indexOf('--json');
if(arg>=0&&process.argv[arg+1])writeFileSync(process.argv[arg+1],JSON.stringify(out,null,2)+'\n');
console.log(JSON.stringify(out,null,2));
if(process.argv.includes('--strict'))process.exitCode=2;
