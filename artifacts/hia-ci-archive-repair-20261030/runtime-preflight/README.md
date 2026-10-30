# Isolated step21 preflight on 46d88

All six requested existing CI qualification commands passed once on an independent sparse checkout of `46d88bd18b1b3dadb246e92eb22c49fe44ec2d72`. The 356 selected source files were matched to their exact Git blobs, and checkout HEAD, clean status and every bound file were checked before and after each command. The main repository was not edited.

| Qualification | Exit | Command outer wall | Actual result |
| --- | ---: | ---: | --- |
| NDU loop | 0 | 12.835164116 s | 30 episodes complete; all actual outputs and budgets pass |
| Adaptive | 0 | 1.960142945 s | Native switching, sealing/tamper/active-call/expired-evidence controls pass |
| Owned state | 0 | 0.832185654 s | Live-owner switch, alias/queue replay/cancellation/refusal controls pass |
| Narrowing | 0 | 1.861900357 s | 288 finite native observations; source/tools unchanged; no performance qualification |
| Owned continuation | 0 | 0.828372805 s | Actual cancelled prefix, verified switch, exact single-use suffix and resource release pass |
| Agent assembly | 0 | 2.306951096 s | Exact roundtrip/LLVM, 81 VM and 24 native observations; 0 model requests |

Commands match workflow step21 flags/defaults; only absolute output storage paths and local compiler/build locations differ. The original recursive NDU profile is used: source `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b`, Rust 1.90.0, binary SHA-256 `04b6c861af5dd119a566f9cf1d43f5524f0fa148beeccd2e9fee5bb9bcc518b7`. It was extracted from the retained `hia-verified-000ac.zip`; the manifest is unmodified and the actual executable `--identity` response matches it. No finite/stream substitute or relaxed identity check was used.

This is an existing CI qualification replay, not a repeat of the separately frozen e223 NDU/Agent/Ring research. Reported timing here is command execution bookkeeping, not a new performance advantage claim. Agent assembly consists of controls and native checks; its `agent_advantage_qualified` remains false and `model_completion_requests` is zero.

## Preparation failures and isolation

The first whole-history clone failed because the partial source repository lacks unrelated promisor history object `c1dbf715fcda2bdf53984ebad3e0f526887faecb`; its original failure and diagnostic stderr are preserved. The isolated checkout was then initialized independently with read-only access to available Git objects, and all required current-tree blobs were materialized into its own object store from hash-matched source bytes. Sparse-index setup emitted existing-path warnings; no source was overwritten, and clean status plus all 356 blob/file hashes were verified before qualification. No qualification itself was retried.

Host `/dev/shm` holds the isolated checkout and original native artifacts; the default sandbox mounts a separate empty `/dev/shm`. Original outputs are therefore exported here for review. `evidence.tar.gz` contains every qualification output file, including native binaries, selected exact source files, the original recursive manifest/binary, commands, logs and setup records. Every archive member is inventoried and rehashed. No failure or native output is omitted.

`SUMMARY.json` provides scoped results; `RUN.json` holds exact commands and return codes; `reports/` preserves the six primary reports byte-for-byte. The remaining step20 historical-validator restoration belongs to a separate task.
