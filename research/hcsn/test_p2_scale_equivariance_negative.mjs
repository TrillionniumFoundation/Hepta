import test from 'node:test';
import assert from 'node:assert/strict';
import {ExactOccupancyLedger,AddressCollision} from './p2_exact_occupancy_reference.mjs';

const samePositiveRationalRay=(a,b)=> a[0]*b[1]===a[1]*b[0]&&a[0]*b[0]+a[1]*b[1]>0;

test('exact-source: rescaling an identical rational ray can return ambiguous',()=>{
  const a=[1,1], b=[7,7];
  assert.ok(samePositiveRationalRay(a,b));
  const m=new ExactOccupancyLedger({dimension:2,capacity:2,collisionRadius:1e-6});
  assert.equal(m.write(a,17),'inserted');
  assert.equal(m.read(a).status,'known');
  assert.deepEqual(m.read(b),{status:'ambiguous',value:null,epoch:0});
  assert.throws(()=>m.write(b,19),AddressCollision);
  assert.equal(m.occupancy,1);
  assert.equal(m.read(a).value,17);
});

test('distinct nearby direction continues fail-closed, no false known',()=>{
  const m=new ExactOccupancyLedger({dimension:2,capacity:2,collisionRadius:1e-6});
  m.write([1,1],17);
  assert.equal(m.read([1,1+1e-7]).status,'ambiguous');
  assert.throws(()=>m.write([1,1+1e-7],18),AddressCollision);
});

test('same source vector is readable and reset always revokes',()=>{
  const m=new ExactOccupancyLedger({dimension:2,capacity:1});
  m.write([1,1],17);
  assert.equal(m.read([1,1]).value,17);
  m.reset();
  assert.deepEqual(m.read([1,1]),{status:'unknown',value:null,epoch:1});
});

test('rational equivalence does not imply binary64 normalized identity on a fixed grid',()=>{
  let total=0,ambiguous=0,known=0;
  for(let x=1;x<=12;x++)for(let y=1;y<=12;y++)for(let scale=2;scale<=19;scale++){
    const a=[x,y],b=[x*scale,y*scale];
    assert.ok(samePositiveRationalRay(a,b));
    const m=new ExactOccupancyLedger({dimension:2,capacity:1});
    m.write(a,17);const status=m.read(b).status;
    assert.notEqual(status,'unknown');
    total++;if(status==='known')known++;else if(status==='ambiguous')ambiguous++;else assert.fail('unexpected status: '+status);
  }
  assert.equal(total,2592);
  assert.ok(known>0);assert.ok(ambiguous>0);
});
