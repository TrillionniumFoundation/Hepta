# Report rendering revision

`build_v7_soak_report_v3.py` only reads the existing frozen receipts and renders the four delivery reports. It executes no Hepta code, tests, native calls or compiler. Its source change preserves historical blocker wording separately from the current finite closure descriptions. The v2 script remains in the unchanged raw archive; the initial v2 render remains in `../report-generation-v2/`.

The renderer requires the original evidence-directory layout (the archive prefixes are mapped by `RAW_ROOTS` in the script), the historical PR335 evidence package, and packager-generated indexes in the output directory. Supply `--base` explicitly. It refuses to overwrite its four output filenames. The recorded invocation was:

```sh
/usr/bin/python3 hepta/evidence/hia_v7_soak_20261028/reproduction/build_v7_soak_report_v3.py --base /workspace/scratch/7e691a7ff65f --output /workspace/scratch/7e691a7ff65f/hepta/evidence/hia_v7_soak_20261028
```

The raw producer/supervisor commands and source/tool identities remain separate reproduction evidence; rendering this report cannot establish a qualification pass.
