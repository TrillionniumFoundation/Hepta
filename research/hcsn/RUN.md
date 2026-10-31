# HCSN independent research branch: reproduce experiments and gated evidence

Repo: `TrillionniumFoundation/Hepta`
Branch: `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`
Draft PR: https://github.com/TrillionniumFoundation/Hepta/pull/468

All code runs independently under `research/hcsn`; it is *not* a production neural engine. Research code depends on Python 3.13, numpy, scipy, torch CPU, mpmath, psutil and cryptography.

From the **repository root**:

```bash
python -m pip install -r research/hcsn/requirements.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p0_extreme_precision --output /tmp/hcsn_hx_new.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p1_hermite_control --output /tmp/hcsn_p1_new.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_regen_recall --steps 420 --seeds 11 --batch-size 48 --train-length 30 --output /tmp/hcsn_p2_new.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p5_recurrent_cpu_probe --repeats 35 --output /tmp/hcsn_p5_new.json
python -m research.hcsn.gate_evidence --folder research/hcsn --strict
```

**The final strict command MUST exit code 2 until independent scientific evidence for P0–P6 is verified; 66 passing unit tests do not certify production readiness.**

## Independent evidence gate v2

`independent_gate.py` is an *evidence-authentication* protocol, not an automatic correctness theorem. It can verify external two-party Ed25519 signatures (Evaluator, Observer), an independently provisioned trust-root JSON **outside** the repository/evidence folder, immutable source SHA, pre-registration hash, and per-topic artifact SHA256. There is no built-in key material, no automatic signed evidence, and no production-activation action. 

To run with externally reviewed evidence:

```bash
python -m research.hcsn.gate_evidence --folder /path/to/evidence_bundle --trust-root /external/release-authority/root.json --strict
```

The evaluator and observer keys must be distinct and externally governed; tests generate throwaway keys only as synthetic protocol fixtures. Signed review alone cannot establish fair scientific comparison or formally prove a QVI; reviewers must validate those properties separately. Replacing an OPEN status without actual scientific evidence is not valid.

The original He–Xiong A7 (`hx_a7.py`) and independent coupled equity Green evaluator (`hx_original.py`) are scalar FP64 references, not per-neuron GPU-ready activations. State-dependent QVI is a separately invented HCSN operator. Report `research/hcsn/gates/2026-10-31-iteration4.md` enumerates remaining blockers.