import test from 'node:test';
import assert from 'node:assert/strict';
import {ExactOccupancyLedger,AddressCollision} from './p2_exact_occupancy_reference.mjs';

test('negative and positive zero are the same numeric address', () => {
  const m = new ExactOccupancyLedger({dimension:2, capacity:2});
  assert.equal(m.write([1,-0],7),'inserted');
  assert.deepEqual(m.read([1,+0]),{status:'known',value:7,epoch:0});
  assert.equal(m.write([1,+0],8),'overwritten');
  assert.equal(m.occupancy,1);
  assert.equal(m.read([1,-0]).value,8);
});

test('signed zero canonicalizes in any dimension and index', () => {
  const m = new ExactOccupancyLedger({dimension:4, capacity:2});
  assert.equal(m.write([0,1,-0,-0],3),'inserted');
  assert.equal(m.read([-0,1,0,0]).status,'known');
  assert.equal(m.write([-0,1,0,0],4),'overwritten');
  assert.equal(m.occupancy,1);
});

test('underflow to negative zero also matches exact address', () => {
  const m = new ExactOccupancyLedger({dimension:2, capacity:2});
  m.write([1e308,-Number.MIN_VALUE],11);
  assert.equal(m.read([1,0]).status,'known');
  assert.equal(m.write([1e308,0],13),'overwritten');
  assert.equal(m.occupancy,1);
});

test('distinct directions remain ambiguous within collision radius', () => {
  const m = new ExactOccupancyLedger({dimension:2, capacity:2,collisionRadius:1e-6});
  m.write([1,-0],7);
  assert.equal(m.read([1,1e-7]).status,'ambiguous');
  assert.throws(() => m.write([1,1e-7],9),AddressCollision);
  assert.equal(m.read([0,1]).status,'unknown');
});

test('reset still revokes signed-zero addresses and epoch advances', () => {
  const m = new ExactOccupancyLedger({dimension:2,capacity:2});
  m.write([1,-0],7);
  m.reset();
  assert.deepEqual(m.read([1,+0]),{status:'unknown',value:null,epoch:1});
});
