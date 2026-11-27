# Frozen u32 R2 full qualification: hosted preparation

This harness is authored, not executed or published. It reproduces the fixed 3,180-file R2 source tree `4c62be4ed66ff107fa6f88c6131313a354868bd9`, not the latest union. The local complete-gate attempt ended in the original 180-second `QUALIFICATION_TIMEOUT`; that result and every partial observation remain unchanged.

The original ten execution Python files are transported without byte changes. Four copied JSON inputs have exactly 155 enumerated binding sites. Every hosted value must come from an actual source/runtime/tool/archive capture, and inversing the replacements must restore all four original JSON byte strings. Historical generation/C0 entry points are never called.

## Stages

`tools/materialize_hosted.py prepare` verifies the published base commit and its complete actual 3,177-file content/modes, materializes the exact target using the 20 after-images and two explicit absences, and verifies all 3,180 actual target files and their tree. A fresh connector GET independently proved that base commit `26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d` has tree `84df4b42f1e20fd7d0c7229e658cf3b458984ffb`, exactly matching the artifact manifest. The artifact manifest is not assumed to be the Git tree without that proof.

`tools/download_originals.py` receives the two exact R20 Actions artifacts. API authorization is restricted to fixed GitHub endpoints, is never forwarded to the storage provider, and is not written into evidence. The provider response cannot redirect. The downloader hashes the received bytes, then independently reads the stored complete ZIP bytes, then verifies every member CRC and records full member metadata. Failed or partial downloads are retained. The old REPORT and TRANSFER records are unchanged; new download evidence has separate paths.

`materialize_hosted.py bind` captures the actual Linux x86_64 CPython 3.14.4 executable, its one loaded libpython, and the five actual tools selected by the original clean PATH. It verifies a clean-environment version/context child before using the runtime. It binds generation, storage and projection JSON first, reads their final identities, and binds the full plan last. All unlisted changes fail the inverse. It does not run references, a compiler, a test, or a product helper.

`materialize_hosted.py launch` invokes the unchanged full R2 runner once with the exact generated `env -i` argv. All 17 fresh independent references and two observer references, real B0, B1/B2/B3 and M1/M2/M3, 38 phases and 5,052 checks stay in the original one 180+3 owner. All original native 20-second wall/10-second CPU/1 MiB limits, reference fuel, archive bounds, worker counts, and the 3 GiB instantaneous free-space floor remain unchanged. The 33 retained-body checks remain inside the owner. No previous compiler or reference result is supplied as input.

The launch step returns the actual original gate failure code. Artifact upload cannot convert a failure into success. A process return of zero also requires the original outer result to report its exact PASS status. The workflow has no `continue-on-error` or success wrapper around the gate.

## Complete actual originals and modes

`materialize_hosted.py collect` runs after termination under `if: always()`. It records actual source, harness and execution files, directories, symlink targets, and nonregular-node metadata. It does not follow symlinks. On the same filesystem it hardlinks each captured regular file into a safe ordinary-file export; on a different filesystem it streams a copy. It records full byte/SHA/Git identities and POSIX modes, including the explicit post-gate ctime/nlink effect of hardlinking. Original product receipts are never rewritten. Logical reconstruction uses `NODE-MANIFEST.json`, not permission normalization performed by the Actions artifact wrapper. An append-only node stream survives a collection failure.

The two already complete original R20 ZIP wrappers are not duplicated in the new artifact: their exact original Actions IDs, full byte identities, independent stored-byte readback, every-member CRC results, and actual stat records are retained. Their original Actions artifacts remain the wrapper source. Incomplete downloads are exported as actual partial files. Checkout metadata is excluded; the entire fixed harness input set is included. Collection cannot manufacture absent terminal frames or finish skipped qualification work.

If collection itself fails, a separate always-upload step preserves the raw available scope, partial collection and original download files. Such an artifact is explicitly incomplete and the job stays failed. If the runner is stopped before a terminal receipt is observed, missing cleanup stays unobserved.

## Boundaries

Surface is the only authorized publisher. This directory does not authorize a push or execution. It selects a dedicated branch and rejects workflow attempts other than attempt 1. A future attempt requires Root's explicit review and authorization. Workflow setup and artifact collection are outside the product owner; neither moves any existing qualification work outside its original deadline. The 40-minute job limit is only containment.

The full gate can still time out on hosted CI. Its result will not grant latest-source cold authority, ordinary-encoding or entry-layout qualification, R8 or aggregate qualification, or whole-system/default-worker authority. Integration into the newest joint source and all matching gates remain future work.
