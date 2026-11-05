# Iteration 38 supplemental independent-gate and local cross-module regression receipt

This is supplemental evidence for research-only HCSN Draft #512; it does not change the previously submitted Iteration 38 training or numerical results.

Local execution:
- Constructed a standalone test worktree by extracting the **Iteration 35 and 36 original reproduction ZIPs** and overlaying exactly the three new Iteration 38 Python files. This is an archived-evidence cross-module regression, **not** an exhaustive checkout of HEAD #512 or a CI run.
- `OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=research/hcsn python -m unittest discover -s research/hcsn -p 'test_p2_*.py' -v` returned **0**, with **67 tests passed**. The unedited full verbose log is preserved as `2026-11-05-iteration38-combined-p2-tests.log.gz`, decompression via `gzip -dc`. Compressed SHA256 `0fb20cb4528e231b99eaf0878e859bf55709d51933bb86ce6c9f5970964f77fd`; expanded log SHA256 `0711a2c705cadb00c3d10e55a8a97b5a5ee052cf4c3dfaaba53763163ae8bd17`.
- Executed the prior independent evidence-gate implementation from the archived Iteration 36 reproduction bundle with: `python research/hcsn/independent_gate.py --bundle research/hcsn --strict > /tmp/hcsn38-independent-gate.json`. **Actual exit: 2**, with all P0–P6 OPEN, `full_closure=false`, `production_activation=false`, `independent_attestation_verified=false`. Its raw JSON is checked in as `2026-11-05-iteration38-independent-gate.json`, SHA256 `7b895f6758982fc19030c9c39d72707b6e179e7d9c695c2fa93f86fc04c53203`.
- The independent gate's reason is `External trust root not configured`, meaning **no external attestation** was supplied. No trust root was invented, no signatures bypassed, and none of the seven science phases closed.
- The original #468 high CodeQL alert remained unresolved at pre-submit inspection. PR #512 was still a Draft; no current-head CI success claim is made.

No main merge, trust-root or signature change, or production activation is authorized by these local checks.
