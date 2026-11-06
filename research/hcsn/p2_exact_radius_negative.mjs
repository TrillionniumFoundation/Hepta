/** Source-bound reproduction of the #760 binary64 radius-boundary false negative.
 * Pass the exact frozen #760 candidate source as the sole argument.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {exactChordWithinRadius} from './p2_exact_radius_reference.mjs';

assert.equal(process.argv.length, 3, 'supply frozen #760 candidate source path');
const path = resolve(process.argv[2]);
const bytes = readFileSync(path);
const blob = createHash('sha1').update(Buffer.concat([Buffer.from('blob ' + bytes.length), Buffer.from([0]), bytes])).digest('hex');
assert.equal(blob, 'ad18bd8ed8821b9b60eb1948f08605a73ae6e841');
const {ExactOccupancyLedger} = await import(pathToFileURL(path).href);
const a = [1, 0];
const b = [1, 0.01672897773676785];
const radius = 0.016727222397810555;
const unit = v => v.map(x => x / Math.hypot(...v));
const roundedDistance = Math.hypot(...unit(a).map((x, i) => x - unit(b)[i]));
assert.ok(roundedDistance > radius);
assert.equal(exactChordWithinRadius(a, b, radius), true);
const m = new ExactOccupancyLedger({dimension: 2, capacity: 2, collisionRadius: radius});
assert.equal(m.write(a, 17), 'inserted');
const readBeforeWrite = m.read(b);
assert.equal(readBeforeWrite.status, 'unknown');
const secondWrite = m.write(b, 19);
assert.equal(secondWrite, 'inserted');
assert.equal(m.occupancy, 2);
console.log(JSON.stringify({
  kind: 'HCSN_P2_EXACT_RADIUS_BOUNDARY_NEGATIVE',
  frozenSourceBlob: blob,
  nodeVersion: process.version,
  a, b, radius,
  roundedDistance,
  independentExactOracleWithinRadius: true,
  readBeforeWrite, secondWrite,
  occupancy: m.occupancy,
  external_acceptance: false,
  production_activation: false,
  scope: 'bounded binary64 geometry only; no learned semantic identity or P0-P6 closure'
}, null, 2));
