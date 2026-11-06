# HCSN P2 exact binary64 chord-radius boundary: HOLD

## Frozen lineage and new negative

This is a research-only child of Draft PR #760, frozen HEAD
75d0a499bd987f84e85f7461066c38879fa6b06b (tree
7e216f753b37710a07f35c08982040f23ed57760), whose parent is the exact #747
HEAD 3877297cdcd896a02e42fd0fd7b2ade45070d4d0. The #760 candidate source is
Git blob ad18bd8ed8821b9b60eb1948f08605a73ae6e841; it remains unchanged in
this new branch's frozen-baseline negative replay. No existing exact-radius
successor branch or PR was found before this work.

A new one-ULP collision-boundary false negative was reproduced against that
exact #760 source using Node v22.16.0:

- a = [1, 0]
- b = [1, 0.01672897773676785]
- collisionRadius = 0.016727222397810555
- rounded normalized Math.hypot distance: 0.01672722239781056 (greater
  than the radius)
- independent exact real chord distance:
  0.0167272223978105548254110431713217955521319497873436534982194809440949552769306729010669237938125653219100
  (less than the radius)

The exact old-source result was read=unknown, second write inserted,
occupancy 2. This is a fail-open near-collision refusal error at a rounded
radius boundary, not a false known alias. The source-bound reproducer checks
Git blob ad18bd8ed8821b9b60eb1948f08605a73ae6e841 before importing it.

An independent Python standard-library reference (Fraction exact binary64
rationals plus Decimal square root) proves the exact inequality. Its exact
positive squared-inequality gap is recorded as a numerator and denominator in
2026-11-06-iteration44-exact-radius-python-reference.json. The one-ULP
lower radius is outside the true distance; the recorded radius and its one-ULP
upper neighbor are inside.

## Narrow candidate repair

The candidate no longer uses rounded normalized-vector distance to decide the
collision boundary. It uses the exact primitive integer ray already decoded
from the binary64 inputs. For integer rays u,v, define

    A = u dot u, B = v dot v, D = u dot v.

For positive chord radius r=p/q (the exact rational represented by its
binary64 bits), and D>0,

    ||u/||u|| - v/||v||||_2 <= r
    iff D^2 (2q^2)^2 >= (2q^2-p^2)^2 A B.

All terms are BigInt; no rounded square root or tolerance decides the
boundary. Since this reference restricts 0<r<1, D<=0 cannot be a collision.
Exact positive-ray identity still takes the overwrite path first. The original
#760 source, its prior subnormal repair, all 45 prior controls and both prior
negative witnesses are preserved byte-for-byte.

## Actual local execution

Environment: Node v22.16.0, Python 3.13.5, Linux x86-64.

- Frozen #760 exact source blob was verified and the new radius witness
  reproduced: unknown / second inserted / occupancy 2.
- New candidate suite: 8/8 Node tests passed, 0 failed, 0 skipped; raw TAP is
  2026-11-06-iteration44-exact-radius-node22.tap.
- Independent Python exact-rational reference: 4/4 tests passed; raw test
  output is 2026-11-06-iteration44-exact-radius-python-unittest.txt.
- Frozen #760 source negative is retained in
  2026-11-06-iteration44-exact-radius-old-negative-node22.json; fixed-source
  deterministic evidence is 2026-11-06-iteration44-exact-radius-node22.json.
- The exact Python rational/Decimal witness is
  2026-11-06-iteration44-exact-radius-python-reference.json.
- Deterministic candidate-vs-independent-oracle sweep: 512 vector pairs,
  1,536 radius-neighbor comparisons, 0 mismatches.
- Maximum supported dimension 4,096: the near-collision is ambiguous and
  the second write throws AddressCollision.
- New exact-radius strict gate: exit 2 by design; raw strict JSON and exit
  code are preserved in 2026-11-06-iteration44-exact-radius-strict.json and
  2026-11-06-iteration44-exact-radius-strict-exit.txt; external attestation
  is absent and P0–P6 remain OPEN.

## Reproduction

From repository root:

    mkdir -p /tmp/hcsn-exact-radius-baseline
    git show 75d0a499bd987f84e85f7461066c38879fa6b06b:research/hcsn/p2_binary64_exact_ray_candidate.mjs > /tmp/hcsn-exact-radius-baseline/p2_binary64_exact_ray_candidate.mjs
    node research/hcsn/p2_exact_radius_negative.mjs /tmp/hcsn-exact-radius-baseline/p2_binary64_exact_ray_candidate.mjs
    node --test --test-reporter=tap research/hcsn/test_p2_exact_radius_predicate.mjs
    python3 research/hcsn/test_p2_exact_radius_reference.py
    python3 research/hcsn/p2_exact_radius_reference.py
    node research/hcsn/p2_exact_radius_evidence.mjs --strict  # expected exit 2

The exact-head hosted workflow additionally reruns all 45 frozen #760
controls plus the 8 new Node tests on Node 22 and 24, the Python reference,
source/blob checks, and the original strict negative. Hosted CI is pending at
publication and is not inferred from local execution. All source/evidence
files and the exact-head workflow are covered by
2026-11-06-iteration44-exact-radius-SHA256SUMS.txt.

## Limits and gate decision

This repairs a bounded binary64 geometric predicate only. BigInt comparison
cost has not been benchmarked; no claim is made about CPU/GPU performance,
RSS, p95/p99, learned semantic identity, token-level write/reset inference,
trainable input-driven event boundaries, autonomous multi-event MQAR, long
memory, multi-seed OOD, multimodal pretrained encoders, or any P0–P6 scientific
closure. The exact predicate may materially increase per-lookup cost and must
be evaluated under P5 before adoption. No external signed scientific
attestation is present.

Keep Draft/HOLD/DENY_ALL, production activation false, all P0–P6 OPEN, no main
merge, no deployment, and no relaxation of signature or production gates.
