# Portable P2 local-gradient diagnostic

The original six review artifacts are preserved byte for byte. This bundle adds a portable executable and a separately executed receipt for the **same 36 synthetic cases**, with **0 fits, 0 optimizer steps, no checkpoint or dataset reads, and no heldout access**.

## What changed

`portable_review_autograd.py` accepts mandatory `--root REPO` and `--output-dir FRESH_DIR` arguments. The repository must contain the frozen source. The output directory must not already exist, including as a symlink. The script creates it exclusively before importing PyTorch or running any cases, and creates its JSON file with exclusive mode. The diagnostic formulas, hand-set coefficients, model calls, assertions, case ordering, and reported gradients are unchanged. `portable_source.diff` records the complete patch; reversing exactly the four declared path/output edits reproduces the original script byte for byte.

No `/workspace/` path remains in the portable executable. The historical execution receipt contains the actual paths used for this run, as provenance.

## Reproduce after checkout

Run from any directory, using a Python environment with the repository's numerical dependencies:

```sh
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
python /path/to/portable_review_autograd.py \
  --root /path/to/Hepta \
  --output-dir /path/to/a-new-gradient-evidence-directory
```

Choose an output path that does not already exist. Reusing a path fails before diagnostic execution and does not overwrite evidence. The executable checks the frozen model SHA-256 before and after running:

```
7ebeaf9069bdd547a2e41d607345a3ce3b29c300d93acf187bdfb51ebc99a02d
```

## Executed verification

The normal run exited **0** in **2.568117 seconds**, with all **36 / 36** cases passing. Every case value is exactly equal to the original evidence. The full payload is also exactly equal after excluding only `source_path` and `script_sha256`, which are provenance fields. Counts remain 12 immediate-reset, 6 all-query-reset, 6 no-reset control, and 12 future-gradient cases across ordinary, HCSN, and Put+linear parameterizations in FP32 and FP64.

A second invocation deliberately reused the output path. It exited **2** in **0.038328 seconds**, with the expected create-only rejection; it ran **0** diagnostic cases and left the existing JSON hash unchanged. All six original artifact hashes and the frozen model source hash were verified unchanged afterward.

The new raw evidence SHA-256 is:

```
66eac636ac8b649c030fd97e545820e20c464577f7d6f248c4d8c9cbe9f6d501
```

The canonical semantic payload digest shared by the original and portable runs is:

```
88a79de4cbb555cd03d8dbe5348f50d91dd95482d41a419581aa97c390595008
```

## Scientific conclusion is unchanged

At a query with hard reset 1, both the address and stored matrix/validity values are zero. Their product readouts have zero first-order gradient to the current write/reset events and the non-readout core, even with the STE. Readout parameters can still fit the class prior. The binding logit is -6, so UNKNOWN has probability approximately 0.9975273768.

The claim remains conditional: later non-reset queries can transmit a nonzero STE gradient to an earlier reset through persistent-state sensitivities. This is neither global unlearnability nor a task-quality acceptance result. It does not alter the frozen P2 completion configuration or the empirical decision gates. The original `REVIEW.md` contains the full mathematical proof and gradient-path analysis.

## Bundle inventory

- `portable_review_autograd.py`: portable executable with create-only output.
- `portable_source.diff`: exact patch from the original executable.
- `run/autograd_evidence.json`: new complete 36-case evidence.
- `portable_receipt.json`: actual command, source hashes, exact semantic comparison, preservation checks, and create-only rejection receipt.
- `execution.log`: actual successful run output.
- `create_only_rejection.log`: expected existing-directory rejection.
- `PORTABLE_REVIEW.md`: this review and reproduction instructions.
- `SHA256SUMS.txt`: local bundle checksums, ready for inclusion in the final experiment manifest.
