# Reproduce the Agent readout without running a model

`build_results.py` reads retained original and supplemental records only. It does
not call a model, compiler, candidate binary, solver, or network service. Restore
the per-model archives and supplemental archives under their recorded suite
layout, then run:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 \
  experiments/hia_optimizer_eval/agent_readout_20261028/build_results.py \
  --suite /tmp/hepta-next-20261028-agent-final-02 \
  --output /tmp/hepta-agent-readout-reproduction
```

The destination reports must not already exist. Model weights and pruned native
ELF copies are not needed for readout. The request/response JSON, original result
JSON, execution plans and Bash `OUTER_EXECUTION.txt` records are needed. Exact
byte-for-byte report identities also depend on retaining the recorded paths;
relocating restored evidence changes path fields but not the result arithmetic.

The aggregator requires exactly 16 primary and four upgrade attempted cells per
family, in their original prefix/suffix order, and cross-checks every actual
transport count against the recorded runtime counters. It reuses the frozen
completion-counter validator for retained responses. Actual prompt token IDs
give known input counts even for a timeout; absent output usage remains null.
There is no inference of zero cost from missing old summary fields.

It separately records original qualification status, supplemental coverage,
task-level outcomes and errors, all attempts/repairs, native-validation counts,
phase timers, whole-process outer timers, runtime amendments, dependency costs,
and verified archive manifests. Parent and child timing intervals must not be
added together. Reference controls and format probes never become scored task
successes. The four real probes remain part of total request/token accounting.

The initial derived readout is retained in `review/`. The final display clarifies
that a response-field rejection happened before native public validation, and
that an unused supplemental phase is not applicable rather than an unknown
incurred duration. Neither clarification changes any raw experimental record,
count, original verdict, or token observation.
