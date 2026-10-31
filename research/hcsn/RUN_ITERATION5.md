# HCSN P0-P6 iteration 5 — deterministic reproduction

Extract `hcsn_p0_p6_iteration5_20261031.zip` into a working directory; the package folder is `hcsn_round5_20261031`.

```bash
python -m pip install -r hcsn_round5_20261031/requirements.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s hcsn_round5_20261031 -p 'test_*.py' -q
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m hcsn_round5_20261031.iteration5_evidence --output /tmp/hcsn_iteration5_fresh.json
python -m hcsn_round5_20261031.gate_evidence --folder hcsn_round5_20261031 --strict
```

Last command must return exit status **2** while scientific evidence remains missing. A zero return before independent scientific validation is a bug. The evidence recorder will never overwrite an existing output. The `timestamp_utc` varies, but computed deterministic numerical results should reproduce within float tolerances. Source hashes refer to script bytes in this package. CPU performance figures from previous rounds are not re-measured here. The remote PR contains the five new source files plus this checkpoint report, not all local raw experiment JSON outputs.
