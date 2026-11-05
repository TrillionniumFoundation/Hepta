# HCSN Iteration 36: common-scalar marked hazard loses order

Parent #512 head: ef771f2c3780b0b006af83d7f019f39f2e18c236.
All P0–P6 OPEN. This is a narrow synthetic endpoint counterexample only.

lambda_ij(t)=R_ij exp(beta*x(t)) implies Q(t)=exp(beta*x(t))*Q0.
The final four-state (event parity, mode) distribution is
p(0)exp(Q0*sum(dt*exp(beta*x))). Write segment permutations commute.

Balanced last-write task:
A=[(0.4,-1.2),(0.4,0.9),(0.2,0.0)], label 1.
B=[(0.4,0.9),(0.4,-1.2),(0.2,0.0)], label 0.
Final endpoint distributions are identical for ANY scalar beta, and
the optimal balanced endpoint classifier's accuracy ceiling is 50%.
Event timestamps can differ: this is NOT a theorem for richer event-history
readouts, neural dynamic boundaries, Brownian first hits, or full HCSN.

Seven beta settings: exact four-state gap zero, independent solve_ivp
DOP853 max absolute error 3.0964120156795616e-13. Same-seed
pathwise (event-count, terminal mode) endpoints matched on 21,000 pairs.
60 local combined tests passed (53 previous + 7 new); no remote CI claimed.

Reproduce on this #512 HEAD:
    export PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
    python -m unittest -v research.hcsn.test_p2_joint_input_hazard research.hcsn.test_p2_joint_sojourn_markov research.hcsn.test_p2_markov_defective_firsthit research.hcsn.test_p2_defective_first_hit_clock research.hcsn.test_p2_first_hit_renewal_falsification research.hcsn.test_p2_physical_hazard_clock research.hcsn.test_p2_order_oblivious_hazard
    python -m research.hcsn.p2_order_oblivious_evidence --output /tmp/hcsn-iter36.json
    python -c "import base64,gzip,pathlib; p=pathlib.Path('research/hcsn/gates/2026-11-04-iteration36-order-blind-raw.json.gz.b64');pathlib.Path('/tmp/hcsn-iter36-reference.json').write_bytes(gzip.decompress(base64.b64decode(p.read_text())))"
    sha256sum /tmp/hcsn-iter36.json /tmp/hcsn-iter36-reference.json
    cmp /tmp/hcsn-iter36.json /tmp/hcsn-iter36-reference.json
    python -m research.hcsn.independent_gate --bundle /tmp/hcsn-empty-untrusted --strict --output /tmp/hcsn-iter36-strict.json
Last strict gate must exit 2 without independent external trust root.

SHA256 source e836fd37fa83f3d500da644ebcc3246a353dcee7eaac31f9a896a84096934868
SHA256 test 737e0b7448eb216f0fce1ad81dd010515808a67215197817d6a4600ef533c592
SHA256 generator 709c2266cbd4528ad542e6791d387619ef85c1341f8014b2226c8c8d282c8920
SHA256 original JSON 5b59247b36024522abbc416fc470efa5e0ff98dd2c0fb34c93907f954cbf99af
SHA256 compressed base64 c950d0ce0f283cc98b82e8c2ae70c8fbcecc74c601d6c8600fb194168799cc2d

Keep earlier P0/P1/P2 negative results. #468 CodeQL #124550087193 failed.
No main merge, trust-root change, signature weakening, or activation.
