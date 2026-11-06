/** Deterministic evidence generator for exact binary64 chord-radius comparison. */
import assert from 'node:assert/strict';
import {writeFileSync, existsSync} from 'node:fs';
import {ExactOccupancyLedger, AddressCollision} from './p2_binary64_exact_ray_candidate.mjs';
import {exactChordWithinRadius} from './p2_exact_radius_reference.mjs';

function nextDown(x) { const v = new DataView(new ArrayBuffer(8)); v.setFloat64(0,x); v.setBigUint64(0,v.getBigUint64(0)-1n); return v.getFloat64(0); }
function nextUp(x) { const v = new DataView(new ArrayBuffer(8)); v.setFloat64(0,x); v.setBigUint64(0,v.getBigUint64(0)+1n); return v.getFloat64(0); }
function floatChord(a,b) { const na=Math.hypot(...a),nb=Math.hypot(...b); return Math.hypot(...a.map((x,i)=>x/na-b[i]/nb)); }
const e=0.01672897773676785, radius=0.016727222397810555;
const a=[1,0], b=[1,e];
const roundedDistance=floatChord(a,b);
assert.ok(roundedDistance>radius);
assert.equal(exactChordWithinRadius(a,b,radius),true);
const m=new ExactOccupancyLedger({dimension:2,capacity:2,collisionRadius:radius});
m.write(a,17);
const read=m.read(b);
assert.equal(read.status,'ambiguous');
let writeError=''; try {m.write(b,19);} catch (error) {writeError=error.constructor.name;}
assert.equal(writeError,'AddressCollision');
assert.equal(m.occupancy,1);

let state=0x5e20d473;
const rand=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state/0x100000000;};
let comparisons=0, mismatches=0;
for(let k=0;k<512;k++){
  const dim=2+(k%7);
  const x=Array.from({length:dim},()=>rand()*2-1);
  const y=x.map(v=>v+(rand()-0.5)*0.05);
  const nx=Math.hypot(...x),ny=Math.hypot(...y);
  const d=Math.hypot(...x.map((v,i)=>v/nx-y[i]/ny));
  for(const r of [d,nextDown(d),nextUp(d)]){
    if(!(r>0&&r<1))continue;
    const expected=exactChordWithinRadius(x,y,r);
    const q=new ExactOccupancyLedger({dimension:dim,capacity:2,collisionRadius:r});
    q.write(x,1);
    const got=q.read(y).status==='ambiguous';
    if(got!==expected)mismatches++;
    comparisons++;
  }
}
assert.ok(comparisons>=1500);
assert.equal(mismatches,0);

const highDimA=Array(4096).fill(1),highDimB=Array(4096).fill(1);highDimB[2048]+=1e-7;
const highDim=new ExactOccupancyLedger({dimension:4096,capacity:2,collisionRadius:1e-6});
highDim.write(highDimA,1);
assert.equal(highDim.read(highDimB).status,'ambiguous');
assert.throws(()=>highDim.write(highDimB,2),AddressCollision);

const evidence={
  schema:'hcsn.p2-exact-binary64-chord-radius.v1',
  sourceParent:'75d0a499bd987f84e85f7461066c38879fa6b06b',
  nodeVersion:process.version,
  witness:{a,b,radius,roundedBinary64Distance:roundedDistance,exactOracleWithinRadius:true,
    fixedRead:read,fixedSecondWrite:writeError,occupancy:m.occupancy},
  deterministicOracleSweep:{seed:'0x5e20d473',vectors:512,comparisons,mismatches},
  maximumDimension:{dimension:4096,nearCollisionRead:'ambiguous',secondWrite:'AddressCollision'},
  exactPredicate:'D^2*(2q^2)^2 >= (2q^2-p^2)^2*A*B for r=p/q',
  gates:{P0:'OPEN',P1:'OPEN',P2:'OPEN',P3:'OPEN',P4:'OPEN',P5:'OPEN',P6:'OPEN'},
  external_acceptance:false,
  production_activation:false,
  scope:'bounded binary64 direction ledger only; no learned semantic identity or trained HCSN evidence'
};
const json=JSON.stringify(evidence,null,2)+'\n';
const out=process.argv[2];
if(out==='--strict') { console.log(json); process.exitCode=2; }
else if(out==='--json') { const path=process.argv[3]; assert.ok(path,'--json requires output path'); assert.equal(existsSync(path),false,'refuse to replace evidence'); writeFileSync(path,json,{flag:'wx'}); console.log(JSON.stringify({path,comparisons,mismatches,external_acceptance:false},null,2)); }
else { console.log(json); }
