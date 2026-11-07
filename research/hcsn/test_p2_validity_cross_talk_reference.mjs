import test from 'node:test';
import assert from 'node:assert/strict';
import { evidence } from './p2_validity_cross_talk_reference.mjs';

const result = evidence();

test('source-bound recurrence reproduces the exact rational lost-key witness', () => {
  const x = result.first_stored_key_lost;
  assert.deepEqual(x.exact_postwrite_validity, ['1/25', '32/25']);
  assert.ok(Math.abs(x.prior_key_projection - 1/25) < 1e-12);
  assert.ok(x.known_probability < 0.005);
});

test('a never-written direction receives near-certain known mass', () => {
  const x = result.unwritten_key_accepted;
  assert.equal(x.exact_unwritten_projection, '7/5');
  assert.ok(Math.abs(x.unwritten_projection - 1.4) < 1e-12);
  assert.ok(x.known_probability > 0.99997);
});

test('exact erasure remains a positive control', () => {
  assert.deepEqual(result.exact_erasure_control.post_reset_validity, [0, 0]);
  assert.ok(Math.abs(
    result.exact_erasure_control.known_probability - 0.0024726231566347743
  ) < 1e-15);
});

test('binary32 rounding does not remove either bounded counterexample', () => {
  assert.ok(result.binary32_controls.known_written_key_probability < 0.005);
  assert.ok(result.binary32_controls.unwritten_key_known_probability > 0.99997);
});

test('the witness is not mislabeled as trained-model or scientific acceptance', () => {
  assert.equal(result.trained_checkpoint_tested, false);
  assert.equal(result.external_attestation, false);
  assert.equal(result.production_activation, false);
  assert.equal(result.pass_scope, 'LIMITED_COUNTEREXAMPLE_ONLY');
  assert.deepEqual(Object.values(result.p0_to_p6), Array(7).fill('OPEN'));
});
