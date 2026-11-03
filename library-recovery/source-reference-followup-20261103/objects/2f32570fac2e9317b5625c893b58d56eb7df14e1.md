# HCSN P0–P6 research bundle: reproducible local runs

Run in a CPU Python environment with the requirements installed. Tested on Python 3.13.5, numpy 2.3.5, scipy 1.17.0, torch 2.10.0 (CPU), mpmath 1.3.0, 2026-10-31.

From `/mnt/data` or any parent folder containing `hcsn_next_20261031`:

```sh
python -m pip install -r hcsn_next_20261031/requirements.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s hcsn_next_20261031 -p 'test_*.py' -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m hcsn_next_20261031.p1_audit --output /tmp/p1_new.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m hcsn_next_20261031.temporal_bench --steps 140 --output /tmp/temporal_new.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m hcsn_next_20261031.perf_probe --output /tmp/perf_new.json
python -m hcsn_next_20261031.gate_evidence --folder hcsn_next_20261031 --strict
```

The last command *intentionally returns 2* until every P0–P6 gate has independent closure evidence. Preserve baseline files and never overwrite signed/heldout results.

`temporal_replicates.json` is the three-seed replication with v2 HCSN, v2 ordinary learned gate, and GRU. It used direct `train_temporal` calls with seeds 11/23/37, tasks `selective_copy,mqar`, 140 updates. `temporal_results.json` is the original first-run three-model study. `temporal_v2_results.json` is the one-seed preliminary v2 study.

The original HX direct A7 (`hx_a7.py`) and independent original coupled equity Green (`hx_original.py`) are scalar FP64 validation references; they are **not** per-neuron GPU-efficient activation implementations. `hx_stable.py` is a near-boundary log-margin expansion on [0, 1e-3] only. `regenerative_qvi.py` is the **new** independent stationary impulse-reset control model, not original HX.

Paper: He & Xiong, Journal of Finance, 2012, https://www.princeton.edu/~wxiong/papers/rollover.pdf (equations 8,11,12,A5,A7).
