import test from 'node:test';
import assert from 'node:assert/strict';
import {ExactOccupancyLedger,CapacityExceeded,AddressCollision,AddressContractError} from './p2_exact_occupancy_reference.mjs';

test('original capacity cannot be enlarged after writes', () => {
  const m = new ExactOccupancyLedger({dimension:2,capacity:1});
  m.write([1,0],7);
  assert.equal(Object.isFrozen(m),true);
  assert.throws(() => { m.capacity=2; },TypeError);
  assert.throws(() => { Object.defineProperty(m,'capacity',{value:2}); },TypeError);
  assert.throws(() => m.write([0,1],9),CapacityExceeded);
  assert.equal(m.occupancy,1);
  assert.equal(m.read([1,0]).value,7);
});

test('collision radius cannot be reduced to silently admit near-collisions', () => {
  const m = new ExactOccupancyLedger({dimension:2,capacity:3,collisionRadius:1e-6});
  m.write([1,0],7);
  assert.equal(m.read([1,1e-7]).status,'ambiguous');
  assert.throws(() => { m.collisionRadius=1e-12; },TypeError);
  assert.throws(() => m.write([1,1e-7],11),AddressCollision);
  assert.equal(m.occupancy,1);
});

test('dimension cannot be changed to weaken key contract', () => {
  const m = new ExactOccupancyLedger({dimension:2,capacity:2});
  assert.throws(() => {m.dimension=1;},TypeError);
  assert.throws(() => m.write([1],7),AddressContractError);
});

test('freezing public contract does not freeze private write/overwrite/reset state', () => {
  const m = new ExactOccupancyLedger({dimension:2,capacity:1});
  assert.equal(m.write([1,0],7),'inserted');
  assert.equal(m.write([1,0],8),'overwritten');
  assert.equal(m.read([1,0]).value,8);
  m.reset();
  assert.equal(m.epoch,1);
  assert.equal(m.read([1,0]).status,'unknown');
  assert.equal(m.write([0,1],9),'inserted');
  assert.equal(m.read([0,1]).value,9);
});
