/** Research-only P2 reference for an explicit bounded learned-address ledger.
 *
 * This is NOT a drop-in replacement for the learned, differentiable state in
 * p2_reset_validity.py. It receives already inferred write/reset events and
 * learned address vectors, not token IDs, targets or oracle key identities.
 * No finite-dimensional embedding can distinguish two semantic keys whose
 * learned addresses are identical. Near-collisions must fail closed.
 */

export class AddressContractError extends Error {}
export class CapacityExceeded extends Error {}
export class AddressCollision extends Error {}

function normalize(raw, dimension) {
  if (!Array.isArray(raw) || raw.length !== dimension ||
      raw.some(x => typeof x !== 'number' || !Number.isFinite(x))) {
    throw new AddressContractError('expected finite numeric address of fixed dimension');
  }
  const magnitude = Math.hypot(...raw);
  if (!(magnitude > 0) || !Number.isFinite(magnitude)) {
    throw new AddressContractError('invalid zero or nonfinite address norm');
  }
  const key = raw.map(x => x / magnitude);
  if (key.some(x => !Number.isFinite(x))) {
    throw new AddressContractError('nonfinite normalized address');
  }
  return key;
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
  }

  get occupancy() { return this.#slots.length; }
  get epoch() { return this.#epoch; }

  reset() {
    this.#slots = [];
    this.#epoch += 1;
  }

  write(rawKey, value) {
    const key = normalize(rawKey, this.dimension);
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new AddressContractError('value must be finite');
    }
    for (const slot of this.#slots) {
      if (slot.key.every((x, i) => Object.is(x, key[i]))) {
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
    this.#slots.push({key, value});
    return 'inserted';
  }

  read(rawKey) {
    const key = normalize(rawKey, this.dimension);
    for (const slot of this.#slots) {
      if (slot.key.every((x, i) => Object.is(x, key[i]))) {
        return {status: 'known', value: slot.value, epoch: this.#epoch};
      }
    }
    if (this.#slots.some(slot => distance(slot.key, key) <= this.collisionRadius)) {
      return {status: 'ambiguous', value: null, epoch: this.#epoch};
    }
    return {status: 'unknown', value: null, epoch: this.#epoch};
  }
}
