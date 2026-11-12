# Agent representation reproduction on the new source snapshot

This directory repeats the disclosed v4 comparison on an independently frozen
implementation snapshot. **These are not new blind tasks.** No old model answer
is repaired, rerun, or rescored. The original v4 protocol, tasks, prompts,
schemas, ordering, two-attempt limit, hidden tests, and comparison gates remain
byte-identical to commit `a32ad51250b905bb4729168f4d8f9328880b44db`.

The arms are JSON HIA, compact HIA assembly, and Rust. Each of the two pinned
model families receives all four tasks and all three arms. A new completion is
scored against the existing finite controls; it is not evidence about an unseen
project population or a larger model family. `reproduction-01/READOUT.json`, when
present, is the final observed outcome. Preparation alone is not a completed
model comparison.

## Source identity and original evidence

`PROTOCOL_SOURCE_BLOBS.json` records the exact Git blobs for the original study
and its study-specific imports. `prepare_replication.py freeze` verifies those
blobs, copies current implementation/tool/test source into a new directory, and
checks that none of the copied source changed during the freeze. It does not
copy the old study's registration, controls, responses, or results.

The snapshot's content hash is over its complete file-identity map. The baseline
commit identifies the retrieved parent source; it is not claimed to identify
the new, uncommitted implementation snapshot. The source archive and manifest
retain the actual measured source even while unrelated development continues in
the working tree. Source files in the measured snapshot are read-only.

The registration and model plans independently bind the loaded implementation,
prompts, fixtures, native compilers, runtime, model bytes, and fresh controls.
Native execution uses the unchanged scalar resource envelope and sealed
artifacts. HIA provider observations are Core-VM traces plus native entrypoint
execution, as in the original study; they are not native HIA call counters.

## Reproduction sequence

Use a fresh output directory for every preparation attempt. A completed model
cell is never rerun to improve its result. The original pipeline records a
timeout as terminal for that cell and starts a new owned process only for the
next distinct cell. Identity or native-infrastructure failure halts the study.

1. Run `prepare_replication.py freeze --source CURRENT_REPOSITORY
   --protocol-source PINNED_ORIGINAL_REPOSITORY --output FRESH_RUN_DIRECTORY`.
   Alternatively, extract the retained `source.tar.xz` to reproduce that exact
   implementation snapshot instead of current development source.
2. In the snapshot root, run the original `tokenizer_check.py` with both pinned
   model paths and the pinned `llama-server`, with `LLAMA_ARG_REPACK=0`. This
   generates no answers. It verifies both context and output capacity, the
   runtime executable, the owned process's actual no-repack environment, the
   model/runtime hashes, and shutdown. Preserve any failed preflight separately.
3. Run `prepare_replication.py controls --snapshot SNAPSHOT --output FRESH_CONTROLS
   --clang CLANG --rustc RUSTC`. This executes all 20 original orchestration tests,
   36 reference/partial-migration controls, and nine hostile-provider controls.
   The orchestration tests use fake engines and may print synthetic cell records;
   those records are unit-test controls and are never model observations.
4. Copy the passing capacity `RESULT.json`, without editing it, to
   `SNAPSHOT/experiments/hia_agent_assembly_v4_20261030/TOKENIZER_CAPACITY.json`.
   The control helper already copies its three passing control JSON files there.
5. Run the original `run_study.py register`, then `run_study.py validate`. Keep
   the resulting registration hash before making any completion request.
6. Run the original `run_study.py run --output FRESH_SUITE --model-id qwen_coder1_5b
   --model-path PINNED_QWEN --binary PINNED_SERVER --clang CLANG --rustc RUSTC`.
   Set `LLAMA_ARG_REPACK=0`. After the first family has a terminal result, invoke
   the same command with `--model-id granite2b --model-path PINNED_GRANITE` and
   the same suite directory.
7. Run the original `run_study.py summarize --output FRESH_SUITE`. Retain every
   request, response, failed submission, executable, identity check, server log,
   and model/cohort result; do not infer complete totals from partial token usage.
8. Run `collect_results.py --run-directory FRESH_RUN_DIRECTORY --output EVIDENCE`
   to archive the raw records and derive a descriptive readout from that original
   cohort result. Run `rebind_sources.py --registration REGISTRATION
   --snapshot-manifest SOURCE_SNAPSHOT --current-root CURRENT_REPOSITORY
   --output NEW_REBIND_REPORT` after development settles. The latter checks the
   measured source closure without changing the registration or rerunning models.

All three original scripts are in
`SNAPSHOT/experiments/hia_agent_assembly_v4_20261030/`. Their source and protocol
are included in the source archive. A restricted executor that prohibits local
Unix-socket binding or owned-process `/proc` reads cannot run this exact
protocol; run it in an appropriately authorized local execution environment.
Do not remove those ownership checks or silently replace the transport.

## Retained scope and costs

The source preparation, successful controls, failed and successful capacity
checks, registration, identity validation, all model calls, shutdown/restart,
native validation, and archiving costs are recorded with their scopes. The
already cached model/runtime bytes are reused with exact identity verification;
their historical download cost is not misrepresented as a new download.
Human engineering time and total economic costs remain unknown. Nested process
and request durations must not be summed as independent wall time.

The finite original gate requires compact HIA to finish both tasks correctly in
each stratum, have at least as many successes as its comparator, and use no more
complete tokens, submissions, or compilation/public/hidden/identity validation
time. Both registered model families must pass for a cross-family gate. Missing
cells or token usage cannot pass. The JSON-HIA comparison is reported separately
from the Rust comparison. These requirements have not been relaxed.

## Archive transport

The collector packages every raw file with an XZ/LZMA2 dictionary of 64 MiB,
CRC64, and one compression thread. This retains duplicate native binaries and
debug sections while compressing their repeated bytes across file boundaries.
It does not strip symbols, remove files, or alter tar metadata.

For `reproduction-01`, the original 4 MiB-dictionary container was later
recompressed for publication. `ARCHIVE_TRANSPORT.json` records both container
identities, the original and additional packaging costs, exact equality of the
entire decompressed tar stream, and all 996 member hashes/names/metadata. The
study's registration, raw run records, gates, and scores are unchanged. The new
container requires about 65 MiB of decompressor memory.
