/** Research-only P2 reference for an explicit bounded learned-address ledger.
 *
 * CANDIDATE ONLY: no proof of learned semantic identity or native production.
 * This is NOT a drop-in replacement for the learned, differentiable state in
 * p2_reset_validity.py. It receives already inferred write/reset events and
 * learned address vectors, not token IDs, targets or oracle key identities.
 * No finite-dimensional embedding can distinguish two semantic keys whose
 * learned addresses are identical. Near-collisions must fail closed.
 */

export class AddressContractError extends Error {}
export class CapacityExceeded extends Error {}
export class AddressCollision extends Error {}

/** Candidate-only exact binary64 projective direction. This is not semantic
 * identity: distinct tokens can still share a learned vector. Rounding is
 * never treated as proof of address identity. All coordinates were captured
 * once by normalize(), so getters cannot change between the two calculations.
 * Positive rescaling preserves direction; negative rescaling does not.
 */
const FRACTION_MASK = (1n << 52n) - 1n;
const SIGN_MASK = 1n << 63n;
function gcdBigInt(a, b) {
  while (b !== 0n) {
    const remainder = a % b;
    a = b;
    b = remainder;
  }
  return a;
}
function exactBinary64Ray(coordinates) {
  const view = new DataView(new ArrayBuffer(8));
  const terms = coordinates.map(x => {
    if (x === 0) return {coefficient: 0n, exponent: 0};
    view.setFloat64(0, x, false);
    const bits = view.getBigUint64(0, false);
    const exponentBits = Number((bits >> 52n) & 0x7ffn);
    const significand = (bits & FRACTION_MASK) +
      (exponentBits === 0 ? 0n : (1n << 52n));
    return {
      coefficient: (bits & SIGN_MASK) === 0n ? significand : -significand,
      exponent: exponentBits === 0 ? -1074 : exponentBits - 1075,
    };
  });
  const nonzero = terms.filter(t => t.coefficient !== 0n);
  // normalize() has already rejected a zero vector and non-finite values.
  const minimumExponent = Math.min(...nonzero.map(t => t.exponent));
  const integers = terms.map(t => t.coefficient === 0n ? 0n :
    t.coefficient << BigInt(t.exponent - minimumExponent));
  let common = 0n;
  for (const value of integers) {
    common = gcdBigInt(common, value < 0n ? -value : value);
  }
  return integers.map(value => value / common);
}

function normalize(raw, dimension) {
  if (!Array.isArray(raw) || raw.length !== dimension) {
    throw new AddressContractError('expected finite numeric address of fixed dimension');
  }
  // Capture each coordinate once. A caller-supplied Array may contain getters,
  // so validating, measuring and normalizing `raw` in separate passes can
  // observe different addresses and insert a slot that cannot be read back.
  const coordinates = [];
  for (let i = 0; i < dimension; i++) {
    const x = raw[i];
    if (typeof x !== 'number' || !Number.isFinite(x)) {
      throw new AddressContractError('expected finite numeric address of fixed dimension');
    }
    coordinates.push(x);
  }
  const magnitude = Math.hypot(...coordinates);
  if (!(magnitude > 0) || !Number.isFinite(magnitude)) {
    throw new AddressContractError('invalid zero or nonfinite address norm');
  }
  // A subnormal norm can have order-one relative rounding error: hypot(m, m)
  // rounds to m for m = Number.MIN_VALUE. Dividing by it produces [1, 1],
  // not a unit vector, and can hide a nearby distinct ray from the guard.
  // Scale this numeric copy exactly into the normal range before measuring.
  // Keep the captured coordinates for exact identity and preserve the original
  // zero/overflow contract and ordinary-magnitude normalization above.
  const normalizationCoordinates = magnitude < 2 ** -1022
    ? coordinates.map(x => x * 2 ** 1022) : coordinates;
  const normalizationMagnitude = normalizationCoordinates === coordinates
    ? magnitude : Math.hypot(...normalizationCoordinates);
  // Object.is distinguishes -0 from +0, but numeric vector addresses do not.
  // Canonicalize the sign of zero to preserve exact writes and readback.
  const key = normalizationCoordinates.map(x => {
    const unit = x / normalizationMagnitude;
    return unit === 0 ? 0 : unit;
  });
  if (key.some(x => !Number.isFinite(x))) {
    throw new AddressContractError('nonfinite normalized address');
  }
  return {key, ray: exactBinary64Ray(coordinates)};
}

function distance(a, b) {
  return Math.hypot(...a.map((x, i) => x - b[i]));
}

/** Bounded, exact-address occupancy with explicit conservative ambiguity.
 * Complexity: O(capacity * dimension) lookup and O(capacity * dimension)
 * numeric-key storage. A write requires a separate trusted/learned event.
 */
export class ExactOccupancyLedger {
  #slots = [];
  #epoch = 0;

  constructor({dimension, capacity, collisionRadius = 1e-6} = {}) {
    if (!Number.isSafeInteger(dimension) || dimension < 1 || dimension > 4096 ||
        !Number.isSafeInteger(capacity) || capacity < 1 || capacity > 4096 ||
        typeof collisionRadius !== 'number' || !Number.isFinite(collisionRadius) ||
        !(collisionRadius > 0) || collisionRadius >= 1) {
      throw new AddressContractError('invalid finite dimension, capacity or collision radius');
    }
    this.dimension = dimension;
    this.capacity = capacity;
    this.collisionRadius = collisionRadius;
    // Config is part of the safety contract; private slots/epoch stay mutable.
    Object.freeze(this);
  }

  get occupancy() { return this.#slots.length; }
  get epoch() { return this.#epoch; }

  reset() {
    this.#slots = [];
    this.#epoch += 1;
  }

  write(rawKey, value) {
    const {key, ray} = normalize(rawKey, this.dimension);
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new AddressContractError('value must be finite');
    }
    for (const slot of this.#slots) {
      if (slot.ray.every((x, i) => x === ray[i])) {
        slot.value = value;  // Explicit latest-write-wins for exact repeats.
        return 'overwritten';
      }
      if (distance(slot.key, key) <= this.collisionRadius) {
        throw new AddressCollision('distinct nearby learned keys cannot be disambiguated');
      }
    }
    if (this.#slots.length === this.capacity) {
      throw new CapacityExceeded('capacity exhausted; no implicit eviction or false validity');
    }
    this.#slots.push({key, ray, value});
    return 'inserted';
  }

  read(rawKey) {
    const {key, ray} = normalize(rawKey, this.dimension);
    for (const slot of this.#slots) {
      if (slot.ray.every((x, i) => x === ray[i])) {
        return {status: 'known', value: slot.value, epoch: this.#epoch};
      }
    }
    if (this.#slots.some(slot => distance(slot.key, key) <= this.collisionRadius)) {
      return {status: 'ambiguous', value: null, epoch: this.#epoch};
    }
    return {status: 'unknown', value: null, epoch: this.#epoch};
  }
}
