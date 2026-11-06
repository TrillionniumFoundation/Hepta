import test from 'node:test';
import assert from 'node:assert/strict';
import {ExactOccupancyLedger, AddressCollision} from './p2_binary64_exact_ray_candidate.mjs';
import {exactChordWithinRadius} from './p2_exact_radius_reference.mjs';

const e = 0.01672897773676785;
const radius = 0.016727222397810555;
const a = [1, 0];
const b = [1, e];

function nextDown(x) {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, x, false);
  const bits = view.getBigUint64(0, false);
  view.setBigUint64(0, bits - 1n, false);
  return view.getFloat64(0, false);
}
function nextUp(x) {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, x, false);
  const bits = view.getBigUint64(0, false);
  view.setBigUint64(0, bits + 1n, false);
  return view.getFloat64(0, false);
}
function floatChord(x, y) {
  const nx = Math.hypot(...x), ny = Math.hypot(...y);
  return Math.hypot(...x.map((v, i) => v / nx - y[i] / ny));
}

test('independent exact oracle proves the one-ULP boundary witness is within radius', () => {
  const rounded = floatChord(a, b);
  assert.ok(rounded > radius, {rounded, radius});
  assert.equal(exactChordWithinRadius(a, b, radius), true);
  assert.equal(exactChordWithinRadius(a, b, nextDown(radius)), false);
  assert.equal(exactChordWithinRadius(a, b, nextUp(radius)), true);
});

test('candidate refuses read and second write at exact binary64 radius boundary', () => {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 2, collisionRadius: radius});
  assert.equal(m.write(a, 17), 'inserted');
  assert.deepEqual(m.read(b), {status: 'ambiguous', value: null, epoch: 0});
  assert.throws(() => m.write(b, 19), AddressCollision);
  assert.equal(m.occupancy, 1);
  assert.equal(m.read(a).value, 17);
});

test('exact radius predicate is insertion-order symmetric', () => {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 2, collisionRadius: radius});
  assert.equal(m.write(b, 19), 'inserted');
  assert.deepEqual(m.read(a), {status: 'ambiguous', value: null, epoch: 0});
  assert.throws(() => m.write(a, 17), AddressCollision);
  assert.equal(m.occupancy, 1);
});

test('one ULP below exact radius permits a genuinely farther direction', () => {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 2, collisionRadius: nextDown(radius)});
  assert.equal(m.write(a, 17), 'inserted');
  assert.equal(m.read(b).status, 'unknown');
  assert.equal(m.write(b, 19), 'inserted');
  assert.equal(m.occupancy, 2);
});

test('one ULP above exact radius remains conservatively ambiguous', () => {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 2, collisionRadius: nextUp(radius)});
  assert.equal(m.write(a, 17), 'inserted');
  assert.equal(m.read(b).status, 'ambiguous');
  assert.throws(() => m.write(b, 19), AddressCollision);
});

test('positive rescaling overwrites while antipodal and orthogonal directions stay distinct', () => {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 3, collisionRadius: radius});
  assert.equal(m.write([1, 1], 3), 'inserted');
  assert.equal(m.write([7, 7], 5), 'overwritten');
  assert.equal(m.read([1, 1]).value, 5);
  assert.equal(m.read([-1, -1]).status, 'unknown');
  assert.equal(m.write([-1, -1], 7), 'inserted');
  assert.equal(m.read([1, -1]).status, 'unknown');
  assert.equal(m.write([1, -1], 11), 'inserted');
  assert.equal(m.occupancy, 3);
});

test('independent oracle agrees on 512 deterministic radius-neighbor cases', () => {
  let state = 0x5e20d473;
  const rand = () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state / 0x100000000; };
  let checked = 0;
  for (let k = 0; k < 512; k++) {
    const dim = 2 + (k % 7);
    const x = Array.from({length: dim}, () => rand() * 2 - 1);
    const y = x.map(v => v + (rand() - 0.5) * 0.05);
    const nx = Math.hypot(...x), ny = Math.hypot(...y);
    const d = Math.hypot(...x.map((v, i) => v / nx - y[i] / ny));
    if (!(d > 0 && d < 0.9)) continue;
    const candidates = [d, nextDown(d), nextUp(d)];
    for (const r of candidates) {
      if (!(r > 0 && r < 1)) continue;
      const expected = exactChordWithinRadius(x, y, r);
      const m = new ExactOccupancyLedger({dimension: dim, capacity: 2, collisionRadius: r});
      m.write(x, 1);
      const got = m.read(y).status === 'ambiguous';
      assert.equal(got, expected, 'case=' + k + ' radius=' + r);
      checked++;
    }
  }
  assert.ok(checked >= 1500, 'checked=' + checked);
});

test('4096-dimensional exact predicate remains bounded and fail-closed', () => {
  const x = Array(4096).fill(1);
  const y = Array(4096).fill(1);
  y[2048] += 1e-7;
  const m = new ExactOccupancyLedger({dimension: 4096, capacity: 2, collisionRadius: 1e-6});
  m.write(x, 1);
  assert.equal(m.read(y).status, 'ambiguous');
  assert.throws(() => m.write(y, 2), AddressCollision);
});
