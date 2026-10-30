# P3/P6 953fa62 finite C++ checkpoint evidence

This directory is a portable evidence delivery for implementation commit `953fa62dee5aa563551d57b1374ab95b6d548b45`, tree `aa0683509a02ca97e4e0c1dd723e4047f50d81b3`. It retains a separate, unchanged `prior-3533/` package, including that package's failed reader attempt 001 and successful fixed attempt 002. Development observations, 3533 qualification, and 953 qualification keep separate identities and denominators.

## Actual result and scope

The new formal collector ran 146 workers: 73 for each of nlohmann/json 3.11.3 and 3.12.0. Per version this is 2 calibration calls, 17 actual allocation sites with 4 calls per fault chain, and 3 ordinary cases. Across the 34 injected fault calls, 28 returned declared caught-exception failures and 6 terminated with foreign SIGABRT (sites 15, 16 and 17 in each version).

The same 34-site cohort supplies 34 preserved parent checkpoints, 34 reconstructions by distinct fresh requests, and 34 continuations. These observations are contained in the 146 calls; they are not extra holdouts or an in-process recovery of the six foreign terminations. No automatic retry occurs. Parent state is bounded ordinary integer data, not arbitrary foreign objects or pointers.

Scope is Linux x86-64, the two fixed library versions, and the fixed adapter/configuration. Parent state has 1-64 integers in [-1000000,1000000], with at most 128 issued requests per owner. Only a normal exit and the complete bound result/resource protocol permit a commit. Uncertain cleanup or protocol failure poisons the owner. There is no general C++ safety theorem, C++ rewrite, external-effect rollback, arbitrary pointer/handle transfer, universal migration qualification, full environment closure, or proof that every escaped descendant has ended. Prior signed-UB, overflow and general C++ failures are not removed by this result.

## Package contents

`p3-p6-json-checkpoint-953fa62.tar.xz` contains 1,580 regular members totaling 17,087,528 uncompressed bytes. The package preserves current raw qualification and launch records, all three development attempt directories, measured cost metadata, original-object audit records, and 1,130 original Git objects. Those objects bind the original commit and complete tree graph to the 354 profile source blobs. The 6,907-file repository inventory is retained; this is not a copy of every repository blob payload.

`MANIFEST.json` binds every archive member. `verify_evidence.py` is an external, reviewable, standard-library-only reader. It checks original Git objects, source closure, raw worker requests/results, finite state transitions, mathematical sums, failure classifications, counts and nested costs. It does not extract or execute archive contents, import repository code, run workers, grant execution authority, or qualify a later implementation HEAD.

`prior-3533/` contains all 19 files named by its original delivery manifest plus that manifest itself: 20 files / 2,842,113 bytes. The current reader hashes this copied historical delivery and preserves its failed/successful reader records. The old package remains independently readable with its own reader. The original archives and raw records have not been rewritten.

`verification-attempt-001/`, `peer-independent-archive-review/`, and `portability-attempt-001/` retain the current reader execution, independent compiler-research execution, and detached portability probe. All returned zero, with empty stderr. The portability probe ran both standalone readers from temporary copies under `/tmp` using system Python with a guard refusing every `/workspace` file open. It then removed only those temporary copies. No original repository or working directory is required for the commands below; an appropriate Python standard library is still required.

## Offline current-package verification

Run from this delivery directory using a trusted Python 3 interpreter:

```sh
python3 -B verify_evidence.py \
  --archive p3-p6-json-checkpoint-953fa62.tar.xz \
  --manifest MANIFEST.json \
  --archive-sha256 3702dadead10feafb7de0ad7788aca5f8c4e1ed79d8e434a2bfb6cbdb0b33ad8 \
  --manifest-sha256 4d21b4ff124005d40818248e617018441a8a49a473f443979aa5fde92a8658e0 \
  --prior-directory prior-3533
```

The reviewed reader SHA-256 is `d6b1caa475c3059b1823926539c85ac3531cb89067d8964beea09a686206f005`. External archive/manifest pins are checked against the same bounded bytes subsequently parsed. The reader uses no-follow/nonblocking regular-file reads, a 32 MiB compressed-file limit, 8 MiB manifest limit, 64 MiB XZ memory limit, 128 MiB total tar-stream limit, 16 MiB member limit and 10,000-member limit. It rejects unsafe paths, duplicate entries, links and special members. Hash consistency is not hostile-producer authentication or proof of a historical execution beyond the retained observations.

## Independent historical-package verification

Run from `prior-3533/`:

```sh
python3 -B verify_evidence.py \
  --archive p3-p6-json-checkpoint-3533.tar.xz \
  --manifest MANIFEST.json \
  --archive-sha256 5e69e0790bead8d54a9c9126b34d8bc7bb8ca7f133a75bfdf905d8d2724e9ace \
  --manifest-sha256 2479de679af9ec53928d4a74dcf565c64f68f48cd020651a88a683457cb6b1d8
```

Historical reader SHA-256: `4c72f7ff8f101e1c35f8fd10388650ee9e0bec431a6405245982f8b2b3a4d5a5`. Its first recorded reader attempt failed because an archive-prefix local was shadowed by a calibration-prefix dictionary. The fixed reader changes that name and checks tree-object kind; the raw qualification and archive stayed unchanged. Both attempts, their exact scripts, streams and elapsed costs remain in the copied historical package.

## Costs and denominator discipline

The 953 formal timings are nested: collector 23.800755358 s; stage 23.922731220 s; launcher 27.613573332 s; outer call 27.663971308 s. They must not be added. The run overlapped resource correctness work and supplies no performance comparison.

Original-object audit took 0.358318097 s; archive creation took 2.712901854 s. Current reader outer/inner times were 0.485457253 / 0.426014012 s; independent reader outer/inner times were 0.408472112 / 0.364506986 s. Each inner time is contained in its outer time. Detached portability work took 0.887538770 s including child executions, copying and temporary cleanup; its 953 and 3533 children took 0.433843970 and 0.441015181 s. These children are contained in that total.

Development attempt 002 ran 23 method executions and attempt 003 ran 3, with one repeated method; those counts are not 26 distinct tests and do not enlarge the formal worker denominator. Historical timing records and reader failure costs are preserved separately. Complete human development, review/integration, agent token/financial and total development costs remain unknown; the recorded wall times are not a complete bill.

## Copy and delivery

Copy this entire directory to `evidence/hia_next2_cpp_checkpoint_20261030`. `COPY_LIST.txt` names every file, including `DELIVERY.json`. `DELIVERY.json` lists byte counts and SHA-256 for every other file; its own SHA must be bound externally. All sidecars remain outside the already verified archives. Copying docs/evidence does not create new execution qualification for a descendant Git commit.
