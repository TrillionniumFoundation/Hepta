# P2 subnormal near-collision repair: HOLD

## Frozen source and retained counterexample

This research-only child is based on [Draft #747](https://github.com/TrillionniumFoundation/Hepta/pull/747),
exact head `3877297cdcd896a02e42fd0fd7b2ade45070d4d0`. Its candidate Git blob is
`9783215b5567846c876f72fa2af95165e986c1e4`. That PR and its historical results
remain unchanged. Repository PR searches for subnormal, exact ray, and #747
found no existing successor repair at this work's start.

Let `m = Number.MIN_VALUE`. The old candidate accepts `[m,m]`, but computes
`Math.hypot(m,m) = m`, then stores numeric key `[1,1]` rather than a unit vector.
The exact BigInt ray remains correct. The separate numeric collision guard does not.

With radius `1e-6`, `[1,1+1e-7]` is a distinct nearby ray. Its ordinary-scale
direction distance from `[1,1]` is approximately `4.999999754652822e-8`, but the
old candidate computes `0.4142135623730994`. In either insertion order it
returns UNKNOWN, accepts the second write, and reaches occupancy 2. This is a
near-collision refusal failure, not a false KNOWN result.

`p2_subnormal_collision_negative.mjs` binds the imported old source to its Git
blob before replaying and asserting both original failures. The original
`p2_exact_occupancy_reference.mjs` and all 27 controls, the 8 earlier candidate
tests, and the scale-equivariance negative remain byte-identical.

## Small repair and justification

Only the candidate's numeric normalization changes. After the unchanged
original norm validation, if the norm is below `2**-1022`, make a numeric copy
of the captured coordinates multiplied by `2**1022`, recompute its norm, and
normalize that copy. Ordinary magnitudes retain their prior path. Zero and
overflowing raw norms still reject. Getter values are still captured once and
the exact-ray calculation still uses that original snapshot.

In the selected branch every nonzero coordinate is subnormal. Multiplication
by this power of two is exact and yields normal coordinates in `[2**-52,1)`
in magnitude. With dimension at most 4096 the scaled norm is finite, at most
64, and nonzero. Thus the final normalization no longer divides by a severely
quantized subnormal norm. This does not relax the collision threshold or use
tolerance to establish ray identity.

Independent review recommended this narrow branch over general max-component
scaling, which would change ordinary rounding and could broaden the accepted
overflow domain. Relevant numeric background is the ECMAScript
[Math.hypot contract](https://tc39.es/ecma262/#sec-math.hypot); implementation-
approximated norms are not exact geometric certificates.

## Actual local checks

Environment: Node `v24.22.1`, Linux x86-64. All fetched baseline source/test
files were checked against their remote Git blob identities before execution.

- Existing suites on unchanged #747: 35 tests passed, 0 failed, 0 skipped.
- Added 10 regression tests on unchanged #747: 4 passed, 6 failed, 0 skipped;
  exit 1. These failures were observed before applying the repair.
- Fixed source: original 27 + prior candidate 8 + new 10 = 45 passed,
  0 failed, 0 skipped. Fixed source Git blob:
  `ad18bd8ed8821b9b60eb1948f08605a73ae6e841`.
- The new fixed-source corpus checks 16,384 directed near-collision pairs
  (32 x 32 small-integer directions x 8 exact subnormal scales x both orders).
  It covers nonuniform directions, signs and signed zeros, overwrite across
  scales, subnormal/normal boundary, 4096 dimensions, one-shot getters,
  distant and antipodal controls, reset, and unchanged invalid/overflow rejection.
- Original scale-equivariance `--strict` returned the required exit code 2.
- The source-bound old subnormal witness reproduced both UNKNOWN/inserted
  results. Its raw JSON and local TAP logs accompany this report.

Reproduce fixed tests:

    node --test --test-reporter=tap research/hcsn/test_p2_*.mjs
    node research/hcsn/p2_scale_equivariance_evidence.mjs --strict

Reproduce the frozen negative without changing the current source:

    mkdir -p /tmp/hcsn-subnormal-original
    git show 3877297cdcd896a02e42fd0fd7b2ade45070d4d0:research/hcsn/p2_binary64_exact_ray_candidate.mjs > /tmp/hcsn-subnormal-original/p2_binary64_exact_ray_candidate.mjs
    node research/hcsn/p2_subnormal_collision_negative.mjs /tmp/hcsn-subnormal-original/p2_binary64_exact_ray_candidate.mjs

The dedicated exact-head workflow runs both Node 22 and 24 on Ubuntu 24.04,
requires the old 6-failure/4-pass result, all 45 fixed tests with zero skips,
frozen-source checks, and strict negative exit 2. Hosted results are pending at
publication and are separate from local evidence or #747's earlier CI.

## Limits

This addresses subnormal norm quantization only. The distance calculation is
still binary64, not an interval or exact geometric predicate. It does not
prove conservative decisions for arbitrary radius boundaries at rounding
resolution, semantic identity of learned vectors, trained event inference,
MQAR/OOD, end-to-end training, hardware costs, or any P0-P6 scientific gate.
No broader repository/backend suite or performance benchmark was run for this
research-only change. Keep Draft/HOLD/DENY_ALL, production activation false,
all P0-P6 OPEN, no merge or deployment.
