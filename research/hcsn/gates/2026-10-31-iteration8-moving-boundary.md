# HCSN P2 Iteration 8 — Moving free-boundary events and gradients

**2026-10-31, research-only. All scientific gates P0–P6 remain OPEN, production disabled.**

## Distinct new mechanism

The state log V and boundary log V_B have independent piecewise-affine velocities on irregular input intervals, including negative/zero relative depletion. At m = log V - log V_B = 0, the state resets to m_reset while the boundary continues moving. Time to contact is solved exactly within each interval; there is no forced reset token. Exact event-time and output gradients propagate through PyTorch autograd only on OPEN fixed-event-count/order regions. Event count, grazing hits and event-interval ownership are discontinuous and NOT differentiable.

Source files and verified local/remote matching Git blob SHA:
- research/hcsn/moving_boundary_events.py — b54889a59d16241da869450b05363b5fae9b4ce2
- research/hcsn/test_moving_boundary_events.py — 2a5ebe933b04cfeaacd7f5daf01bcee2afdf18b5
- research/hcsn/p2_moving_boundary_evidence.py — 3a2509eba6075f30a534896992770c6f84f63071
- Introducing commit 4e41d767a79c59737bf7ce1c4d64c67a9e3dcdad.

## Reproduction

From repository root, in CPU PyTorch + NumPy:

    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_moving_boundary_evidence --output /tmp/hcsn-p2-moving-boundary.json
    python -m research.hcsn.independent_gate --bundle research/hcsn --strict

Locally against the exact SHA-matching sources under /mnt/data/hcsn_round5_20261031: **96/96 CPU tests passed** including 7 additional moving-boundary methods. Evidence generator: 128 deterministic random attempts, 115 fixed-event-count trajectories checked, 13 near interval-event transitions explicitly excluded, 1,380 signed gradient components independently compared with centered differences, maximum absolute discrepancy **2.4505295570520502e-09**. Reproducible JSON SHA256: c20580a8f52598ec620a39bd322e38007302ed5384ca0856826f99ef1f026751.

The tests separately cover moving boundary through stationary state, retreating boundary without events, exact multi-reset times, irregular interval partition invariance, gradient wrt initial state, boundary position, reset size, state and boundary slopes, and durations, a strict equality contact, and invalid/overfull event rejection.

**Scientific caveats:** This validates a deterministic first-contact module only. It does NOT establish continuous-time stochastic He–Xiong equity semantics, learned QVI solutions, event-count gradient correctness, trained long-context recall, many-seed heldout gains, or superior accuracy versus GRU/Mamba/Transformer. This is exploratory, not independent preregistration. P2 remains OPEN.

Strict independent attestation still exits 2 with all P0–P6 OPEN. No activation or main merge.