# HCSN P0–P6 round 4 — reproducibility (2026-10-31)

CPU-only evidence. No production activation. Existing baseline reports are preserved.

## Run from the extracted zip parent

```bash
python -m pip install -r hcsn_next_20261031/requirements.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s hcsn_next_20261031 -p 'test_*.py' -v
# Strict scientific gate: exit code 2 is EXPECTED; a zero exit is not a goal until evidence exists.
python -m hcsn_next_20261031.gate_evidence --folder hcsn_next_20261031 --strict
```

## Experimental replay (do not overwrite frozen output records)

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m hcsn_next_20261031.p0_extreme_precision --output /tmp/hcsn-p0-new.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m hcsn_next_20261031.p1_tangent_control --rows 150 --steps 90 --output /tmp/hcsn-p1-new.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m hcsn_next_20261031.p2_regen_recall --seeds 11 23 37 --steps 125 --batch-size 32 --train-length 24 --output /tmp/hcsn-p2-new.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m hcsn_next_20261031.p5_end_to_end_cpu --iterations 40 --output /tmp/hcsn-p5-new.json
```

Note: CPU timing varies with machine/load, unlike deterministic data seeds and test assertions.
`p2_regen_recall` intentionally injects two explicit reset markers. Its unsupervised endogenous reset-time quality is **not** established.
The direct HX A7 has a removable singularity at zero liquidity hazard; use `hx_a7_mp_regularized.py` only for high-precision research reference, not vectorized production.
The independent stationary QVI finite-grid solver is `qvi_fd_reference.py`; the nonlocal state-dependent solver is `contextual_qvi.py`.

The three-seed P1 and P2 panels are exploratory and did not establish HCSN superiority. Some JSON reports originated in an earlier run and are retained as historical evidence. No released real model checkpoint, external data, GPU, energy readings or full training frontier is included.
