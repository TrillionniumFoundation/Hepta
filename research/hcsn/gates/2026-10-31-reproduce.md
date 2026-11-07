# Remote delivery — isolated HCSN research branch (2026-10-31)

- GitHub: https://github.com/TrillionniumFoundation/Hepta
- Research branch: `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`
- Draft PR: https://github.com/TrillionniumFoundation/Hepta/pull/468
- Remote audit report: `research/hcsn/gates/2026-10-31-iteration3.md`
- All scientific/production closure gates P0–P6 **OPEN**, `production_enabled=false`.
- Local reproducible test: `OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s hcsn_round3_20261031 -p 'test_*.py' -q`: 62 tests OK.
- Draft PR is not merged into `main`. Local CPU results do not establish full-scale encoder quality, energy efficiency or real-time inference.

## Artifact consistency

Local source and corresponding unit tests have been copied into the research branch under `research/hcsn/`; the report provides the evaluated boundaries. Local raw JSON experiment outputs and SHA fingerprints are in this archive, not presumed to be present in the remote branch.