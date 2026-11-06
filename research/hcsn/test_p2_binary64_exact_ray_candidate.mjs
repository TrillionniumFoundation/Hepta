// New candidate-only assertions. Frozen #746 negative controls remain unchanged.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ExactOccupancyLedger, AddressCollision, AddressContractError, CapacityExceeded,
} from './p2_binary64_exact_ray_candidate.mjs';

test('2592 exact positive integer rays are all readable and overwritable', () => {
  let checked = 0;
  for (let x=1; x<=12; x++) for (let y=1; y<=12; y++)
    for (let s=2; s<=19; s++) {
      const m = new ExactOccupancyLedger({dimension:2, capacity:1});
      assert.equal(m.write([x,y],17),'inserted');
      assert.deepEqual(m.read([s*x,s*y]),{status:'known',value:17,epoch:0});
      assert.equal(m.write([s*x,s*y],19),'overwritten');
      assert.equal(m.occupancy,1);
      assert.equal(m.read([x,y]).value,19);
      checked++;
    }
  assert.equal(checked,2592);
});

test('nearby distinct binary64 rays remain ambiguous and cannot overwrite', () => {
  const m=new ExactOccupancyLedger({dimension:2,capacity:2,collisionRadius:1e-6});
  assert.equal(m.write([1,1],17),'inserted');
  assert.deepEqual(m.read([1,1+1e-7]),{status:'ambiguous',value:null,epoch:0});
  assert.throws(()=>m.write([1,1+1e-7],20),AddressCollision);
  assert.equal(m.occupancy,1);
  assert.equal(m.read([1,1]).value,17);
});

test('underflow no longer upgrades a distinct nonzero ray into known', () => {
  const m=new ExactOccupancyLedger({dimension:2,capacity:2});
  m.write([1e308,-Number.MIN_VALUE],7);
  assert.deepEqual(m.read([1,0]),{status:'ambiguous',value:null,epoch:0});
  assert.throws(()=>m.write([1e308,0],8),AddressCollision);
  assert.equal(m.occupancy,1);
  assert.equal(m.read([1e308,-Number.MIN_VALUE]).value,7);
});

test('signed zero and exact positive rescaling remain one direction', () => {
  const m=new ExactOccupancyLedger({dimension:3,capacity:2});
  m.write([1,-0,2],7);
  assert.deepEqual(m.read([3,+0,6]),{status:'known',value:7,epoch:0});
  assert.equal(m.write([3,+0,6],8),'overwritten');
  assert.equal(m.occupancy,1);
});

test('negative rescaling cannot impersonate an antipodal direction', () => {
  const m=new ExactOccupancyLedger({dimension:2,capacity:2});
  m.write([1,1],7);
  assert.deepEqual(m.read([-7,-7]),{status:'unknown',value:null,epoch:0});
  assert.equal(m.write([-7,-7],9),'inserted');
  assert.equal(m.occupancy,2);
  assert.equal(m.read([1,1]).value,7);
});

test('subnormal positive scaling is exact without a tolerant alias', () => {
  const m=new ExactOccupancyLedger({dimension:2,capacity:1});
  m.write([Number.MIN_VALUE,Number.MIN_VALUE],7);
  assert.equal(m.read([1,1]).status,'known');
  assert.equal(m.write([7,7],9),'overwritten');
  assert.equal(m.occupancy,1);
});

test('mutable coordinate getter is observed exactly once', () => {
  const m=new ExactOccupancyLedger({dimension:2,capacity:2});
  let reads=0;const key=[1,0];
  Object.defineProperty(key,0,{get(){reads++;return reads===1?1:0;}});
  assert.equal(m.write(key,11),'inserted');
  assert.equal(reads,1);
  assert.equal(m.read([1,0]).value,11);
  assert.throws(()=>m.read([0,0]),AddressContractError);
});

test('finite capacity, unknown rejection and reset retain fail-closed semantics', () => {
  const m=new ExactOccupancyLedger({dimension:2,capacity:1});
  m.write([1,0],7);
  assert.equal(m.read([0,1]).status,'unknown');
  assert.throws(()=>m.write([0,1],9),CapacityExceeded);
  assert.throws(()=>{m.capacity=2;},TypeError);
  m.reset();
  assert.deepEqual(m.read([1,0]),{status:'unknown',value:null,epoch:1});
  assert.equal(m.write([0,1],13),'inserted');
});
