import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AddressContractError, AddressCollision, CapacityExceeded, ExactOccupancyLedger,
} from './p2_exact_occupancy_reference.mjs';

function make(capacity = 3) {
  return new ExactOccupancyLedger({dimension: 2, capacity});
}

const k1 = [1, 0], anti = [-3 / 5, 4 / 5], orth = [0, 1];
const unseen = [3 / 5, 4 / 5];

test('initially unknown, retained first key after anti-correlated second write', () => {
  const m = make();
  assert.equal(m.read(k1).status, 'unknown');
  assert.equal(m.write(k1, 7), 'inserted');
  assert.equal(m.write(anti, 9), 'inserted');
  assert.deepEqual(m.read(k1), {status: 'known', value: 7, epoch: 0});
  assert.deepEqual(m.read(anti), {status: 'known', value: 9, epoch: 0});
});

test('an unwritten direction remains unknown after two writes', () => {
  const m = make();
  m.write(k1, 7);
  m.write(orth, 11);
  assert.equal(m.read(unseen).status, 'unknown');
  assert.equal(m.read(k1).value, 7);
  assert.equal(m.read(orth).value, 11);
});

test('exact overwrite updates value without allocating a new occupancy slot', () => {
  const m = make();
  m.write(k1, 7);
  assert.equal(m.write(k1, 10), 'overwritten');
  assert.equal(m.occupancy, 1);
  assert.equal(m.read(k1).value, 10);
});

test('reset revokes every old address regardless of values', () => {
  const m = make();
  m.write(k1, 7); m.write(anti, 9);
  m.reset();
  assert.equal(m.epoch, 1);
  assert.equal(m.occupancy, 0);
  assert.deepEqual(m.read(k1), {status: 'unknown', value: null, epoch: 1});
  m.write(orth, 13);
  assert.equal(m.read(orth).value, 13);
  assert.equal(m.read(anti).status, 'unknown');
});

test('capacity overflow is an explicit rejection, not silent loss', () => {
  const m = make(1);
  m.write(k1, 7);
  assert.throws(() => m.write(orth, 9), CapacityExceeded);
  assert.equal(m.read(k1).value, 7);
  assert.equal(m.occupancy, 1);
});

test('nearby distinct addresses refuse writes and do not alias queries', () => {
  const m = make();
  m.write(k1, 7);
  const near = [1, 1e-7];
  assert.equal(m.read(near).status, 'ambiguous');
  assert.throws(() => m.write(near, 8), AddressCollision);
  assert.equal(m.read(k1).value, 7);
});

test('invalid key/value inputs are rejected before any mutation', () => {
  const m = make();
  for (const bad of [[], [1], [0, 0], [NaN, 1], [1, Infinity], ['1', 0]]) {
    assert.throws(() => m.write(bad, 1), AddressContractError);
  }
  assert.throws(() => m.write(k1, NaN), AddressContractError);
  assert.throws(() => m.read([0, 0]), AddressContractError);
  assert.equal(m.occupancy, 0);
});

test('learned-address aliasing is an unavoidable external identification limit', () => {
  const m = make();
  m.write(k1, 7);
  // Two distinct semantic keys encoded to exactly the same vector cannot
  // be told apart without additional provenance; this is intentionally NOT
  // presented as an exact semantic-identity solution.
  assert.equal(m.read(k1).value, 7);
  assert.equal(m.occupancy, 1);
});

test('invalid constructor budgets reject early', () => {
  assert.throws(() => new ExactOccupancyLedger({dimension: 0, capacity: 1}), AddressContractError);
  assert.throws(() => new ExactOccupancyLedger({dimension: 2, capacity: 0}), AddressContractError);
  assert.throws(() => new ExactOccupancyLedger({dimension: 2, capacity: 1, collisionRadius: Infinity}), AddressContractError);
});
