/** Independent exact rational oracle for binary64 chord-distance boundaries.
 *
 * This module accepts raw finite binary64 vectors. It does not import the
 * occupancy candidate, normalize with Math.hypot, or compare rounded floats.
 * Every input coordinate and radius is decoded into an exact dyadic rational.
 */
const FRACTION = (1n << 52n) - 1n;
const SIGN = 1n << 63n;

function decode(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new TypeError('finite binary64 value required');
  }
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, value, false);
  const bits = view.getBigUint64(0, false);
  const eb = Number((bits >> 52n) & 0x7ffn);
  const sig = (bits & FRACTION) + (eb === 0 ? 0n : (1n << 52n));
  const signed = (bits & SIGN) === 0n ? sig : -sig;
  return {signed, exponent: eb === 0 ? -1074 : eb - 1075};
}

function integerVector(vector) {
  if (!Array.isArray(vector) || vector.length < 1 || vector.length > 4096) {
    throw new TypeError('vector dimension outside [1,4096]');
  }
  const terms = vector.map(decode);
  const active = terms.filter(t => t.signed !== 0n);
  if (active.length === 0) throw new TypeError('zero vector');
  const minExponent = Math.min(...active.map(t => t.exponent));
  return terms.map(t => t.signed === 0n ? 0n :
    t.signed << BigInt(t.exponent - minExponent));
}

function positiveFraction(value) {
  if (!(value > 0 && value < 1)) throw new RangeError('radius must be in (0,1)');
  const {signed, exponent} = decode(value);
  if (signed <= 0n) throw new RangeError('positive radius required');
  return exponent >= 0
    ? {p: signed << BigInt(exponent), q: 1n}
    : {p: signed, q: 1n << BigInt(-exponent)};
}

/** Exact predicate for Euclidean chord distance between normalized directions. */
export function exactChordWithinRadius(rawA, rawB, radius) {
  if (!Array.isArray(rawA) || !Array.isArray(rawB) || rawA.length !== rawB.length) {
    throw new TypeError('equal vector dimensions required');
  }
  const a = integerVector(rawA);
  const b = integerVector(rawB);
  let dot = 0n, aa = 0n, bb = 0n;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    aa += a[i] * a[i];
    bb += b[i] * b[i];
  }
  if (dot <= 0n) return false;
  const {p, q} = positiveFraction(radius);
  const den = 2n * q * q;
  const num = den - p * p;
  return dot * dot * den * den >= num * num * aa * bb;
}
