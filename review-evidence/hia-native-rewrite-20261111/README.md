# Complete retained qualification harness

This directory retains the current source-bound qualification entry
`run_hia_qualification_v4.py` and its adjacent `workflow_process.py` supervisor.
Their exact paths, original source checks, declared test groups, full
`tests/` discovery, deadlines and cleanup behavior remain unchanged.

Run only from a prepared, frozen source checkout with the required toolchains,
NDU dependencies and native inputs available, and choose a fresh output path
outside that source tree:

```sh
python -B review-evidence/hia-native-rewrite-20261111/run_hia_qualification_v4.py \
  --source /absolute/path/to/Hepta --output /absolute/path/to/new-evidence --full
```

The resulting evidence belongs to the exact executed source. Component passes
do not replace complete retained regression, installation, service migration or
whole-product native acceptance. See the [current state](../../docs/CURRENT.md).

Historical development reports and independent development replayers are
recoverable from the [original published Git tree](https://github.com/TrillionniumFoundation/Hepta/tree/a7710b5727cca43875357f92c6b83308046deb6e/review-evidence/hia-native-rewrite-20261111).
The [member recovery ledger](../hia-native-cleanup-20261111/retired-rewrite-observations.json)
records their exact Git objects, modes, lengths and hashes. Their failures,
interruptions and source-specific results retain their original meanings.
