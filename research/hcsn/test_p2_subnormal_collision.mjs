// Candidate-only regression. The frozen original source and its tests stay unchanged.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ExactOccupancyLedger, AddressCollision, AddressContractError,
} from './p2_binary64_exact_ray_candidate.mjs';

const MIN_NORMAL = 2 ** -1022;
const tiny = [Number.MIN_VALUE, Number.MIN_VALUE];
const nearby = [1, 1 + 1e-7];

function refusesNearby(first, second) {
  const m = new ExactOccupancyLedger({dimension: first.length, capacity: 2});
  assert.equal(m.write(first, 7), 'inserted');
  assert.deepEqual(m.read(second), {status: 'ambiguous', value: null, epoch: 0});
  assert.throws(() => m.write(second, 9), AddressCollision);
  assert.equal(m.occupancy, 1);
  assert.deepEqual(m.read(first), {status: 'known', value: 7, epoch: 0});
}

test('subnormal write refuses a nearby distinct normal ray', () => {
  refusesNearby(tiny, nearby);
});

test('normal write refuses a nearby distinct subnormal ray', () => {
  refusesNearby(nearby, tiny);
});

test('exact overwrite retains near-collision refusal across scales', () => {
  for (const [first, repeat] of [[tiny, [7, 7]], [[7, 7], tiny]]) {
    const m = new ExactOccupancyLedger({dimension: 2, capacity: 2});
    m.write(first, 7);
    assert.equal(m.write(repeat, 11), 'overwritten');
    assert.equal(m.read(first).value, 11);
    assert.equal(m.read(repeat).value, 11);
    assert.equal(m.read(nearby).status, 'ambiguous');
    assert.throws(() => m.write(nearby, 13), AddressCollision);
    assert.equal(m.occupancy, 1);
  }
});

test('16384 directed subnormal integer-ray near-collisions fail closed', () => {
  let checked = 0;
  for (let x = 1; x <= 32; x++) for (let y = 1; y <= 32; y++) {
    for (const scale of [1, 2, 3, 7, 16, 31, 64, 127]) {
      const a = [x * scale * Number.MIN_VALUE, y * scale * Number.MIN_VALUE];
      const b = [x, y * (1 + 1e-7)];
      // Geometric control uses ordinary small integers, not the tiny norm.
      const norm = Math.hypot(x, y), otherNorm = Math.hypot(...b);
      assert.ok(Math.hypot(x / norm - b[0] / otherNorm,
        y / norm - b[1] / otherNorm) < 1e-6);
      refusesNearby(a, b);
      refusesNearby(b, a);
      checked += 2;
    }
  }
  assert.equal(checked, 16384);
});

test('signed subnormal near-collisions refuse in either insertion order', () => {
  for (const sx of [-1, 1]) for (const sy of [-1, 1]) {
    for (const zeros of [[], [-0]]) {
      const a = [sx * Number.MIN_VALUE, sy * Number.MIN_VALUE, ...zeros];
      const b = [sx, sy * (1 + 1e-7), ...zeros.map(() => +0)];
      refusesNearby(a, b);
      refusesNearby(b, a);
    }
  }
});

test('4096-dimensional subnormal norm does not separate nearby rays', () => {
  const a = Array(4096).fill(Number.MIN_VALUE);
  const b = Array(4096).fill(1);
  b[2048] += 1e-7;
  refusesNearby(a, b);
  refusesNearby(b, a);
});

test('subnormal-to-normal boundary retains exact and near directions', () => {
  for (const scale of [MIN_NORMAL / 2, MIN_NORMAL - Number.MIN_VALUE,
    MIN_NORMAL, MIN_NORMAL * 2]) {
    const a = [scale, scale];
    refusesNearby(a, nearby);
    refusesNearby(nearby, a);
    const m = new ExactOccupancyLedger({dimension: 2, capacity: 1});
    m.write(a, 7);
    assert.equal(m.read([1, 1]).status, 'known');
  }
});

test('subnormal normalization captures getters only once on write and read', () => {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 2});
  for (const operation of ['write', 'read']) {
    let reads = 0;
    const raw = [Number.MIN_VALUE, Number.MIN_VALUE];
    Object.defineProperty(raw, 0, {get() {
      reads++;
      return reads === 1 ? Number.MIN_VALUE : NaN;
    }});
    if (operation === 'write') assert.equal(m.write(raw, 7), 'inserted');
    else assert.equal(m.read(raw).status, 'known');
    assert.equal(reads, 1);
  }
  assert.equal(m.read(nearby).status, 'ambiguous');
});

test('distant and antipodal subnormal rays remain distinct', () => {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 3});
  m.write(tiny, 7);
  for (const key of [[-Number.MIN_VALUE, -Number.MIN_VALUE],
    [Number.MIN_VALUE, -Number.MIN_VALUE]]) {
    assert.equal(m.read(key).status, 'unknown');
    assert.equal(m.write(key, 9), 'inserted');
  }
  assert.equal(m.occupancy, 3);
  m.reset();
  assert.deepEqual(m.read(tiny), {status: 'unknown', value: null, epoch: 1});
});

test('zero, invalid coordinates and overflowing norm still reject', () => {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 2});
  for (const key of [[0, -0], [NaN, 1], [Infinity, 1],
    [Number.MAX_VALUE, Number.MAX_VALUE]]) {
    assert.throws(() => m.write(key, 1), AddressContractError);
    assert.throws(() => m.read(key), AddressContractError);
  }
  assert.equal(m.occupancy, 0);
});
