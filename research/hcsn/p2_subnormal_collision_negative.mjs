/** Retained #747 negative, not a passing learned-model or production gate.
 * Supply the unchanged #747 candidate source file as the only argument.
 * Its Git blob is checked before its exports are used.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

assert.equal(process.argv.length, 3, 'supply the frozen #747 candidate source path');
const sourcePath = resolve(process.argv[2]);
const source = readFileSync(sourcePath);
const sourceBlob = createHash('sha1').update(`blob ${source.length}\0`)
  .update(source).digest('hex');
assert.equal(sourceBlob, '9783215b5567846c876f72fa2af95165e986c1e4');
const {ExactOccupancyLedger} = await import(pathToFileURL(sourcePath).href);

const a = [Number.MIN_VALUE, Number.MIN_VALUE], b = [1, 1 + 1e-7];
const normalize = v => v.map(x => x / Math.hypot(...v));
const distance = (u, v) => Math.hypot(...u.map((x, i) => x - v[i]));
const roundedDistance = distance(normalize(a), normalize(b));
// [1,1] is the exact same positive ray as a and avoids the tiny norm.
const ordinaryScaleDistance = distance(normalize([1, 1]), normalize(b));
assert.ok(ordinaryScaleDistance > 0 && ordinaryScaleDistance < 1e-6);
assert.ok(roundedDistance > 0.4);
const observations = [];
for (const [first, query] of [[a, b], [b, a]]) {
  const m = new ExactOccupancyLedger({dimension: 2, capacity: 2});
  const firstWrite = m.write(first, 7);
  const readBeforeWrite = m.read(query);
  const nearbyWrite = m.write(query, 9);
  assert.equal(firstWrite, 'inserted');
  assert.equal(readBeforeWrite.status, 'unknown');
  assert.equal(nearbyWrite, 'inserted');
  assert.equal(m.occupancy, 2);
  observations.push({first, query, firstWrite, readBeforeWrite, nearbyWrite,
    occupancy: m.occupancy});
}
console.log(JSON.stringify({
  kind: 'HCSN_P2_SUBNORMAL_COLLISION_NEGATIVE',
  sourceCommit: '3877297cdcd896a02e42fd0fd7b2ade45070d4d0',
  sourceBlob, nodeVersion: process.version, roundedDistance,
  ordinaryScaleDistance, observations,
  hold: true, external_acceptance: false, production_activation: false,
  scope: 'bounded binary64 geometry only; no learned semantic identity or P0-P6 closure',
}, null, 2));
