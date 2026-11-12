# Exact FOLLOW48 cold artifact readback

Status: new reader source only. It has not been parsed, imported, or executed in
a Python process in this delivery. The GitHub run/artifact metadata and original
40,434-byte job log have been read and their identities checked. No new native,
compiler, or cold qualification result is claimed.

## Original input

| Field | Exact value |
| --- | --- |
| Repository | TrillionniumFoundation/Hepta |
| Commit | e035dfd0e2603adcf2bfcb28958afaddffe9fb62 |
| Tree | a80210cfcba140ebe413914767a86815b6f152f5 |
| Run | 43210143623 |
| Native job | 131155352486 |
| Artifact | 13940703193 |
| ZIP bytes | 54245802 |
| ZIP SHA256 | 4eec8d75658d48abe01c9518efa4362ba97b9b534576cc1d5b9deacde4a514cc |
| Original uploaded files | 3928 |

The producer log reports cold 6/11 and an empty generation list. Neither proves
a 180-second timeout or absence of native generation. Python 3.14.10 and clang20
are observations in the original job, without a causal conclusion.

## Independent workflow

Use a checkout containing the exact original commit's Git objects, Python
3.12.14, and ordinary git. No common.prepare(), archive restoration, Z3, pytest,
project import, compiler image, or executing a file from the input is needed.

Download the exact artifact through the normal authenticated Actions endpoint:

    gh api repos/TrillionniumFoundation/Hepta/actions/artifacts/13940703193/zip > "$RUNNER_TEMP/core48-original.zip"

Run the single reader as a fresh process:

    python -B review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ci/read_core48_original_cold_r1.py --repo "$GITHUB_WORKSPACE" --zip "$RUNNER_TEMP/core48-original.zip" --out "$RUNNER_TEMP/core48-original-readback-r1"

Suggested independent selection tag: core48-original-readback.
Upload the complete output directory even on failure. The reader sets the same
90 CPU / 180 wall / 1 GiB / core0 observation bounds, includes read-only Git
child CPU in its final aggregate check, and does not change any original
20/180-second native/cold gate. Download time is outside the bounded reader.

## What is checked and preserved

The entire original ZIP is copied and verified. Every regular outer member is
streamed through CRC, SHA256 and Git-blob SHA1 computation, with original mode
and archive metadata recorded. Directory records are also inventoried. All
source exports, JSON/log/text evidence, and embedded ZIP containers are retained
as exact original bytes. The output always includes the original ZIP, so binary
input/output payloads that were not separately extracted are still recoverable.

Every embedded ZIP is streamed. HIA lossless archives additionally require the
exact full manifest inventory, original member bytes/SHA/mode, total extent,
canonical manifest SHA, and any present publication receipt. Missing
publication receipts remain explicit observations; an incomplete publication is
not promoted to completed evidence. Original phase-process raw_artifacts are
also compared with their actual archived-stage receipt.

The source manifest is taken from the original cold report and independently
matched to the original request, the exact support contract, every source
member SHA256, and Git-blob SHA1/mode metadata from the exact original Git tree.
No old 580-file count or earlier-head source inventory is substituted.

The disk owner receipt and the returned owner object remain separate original
records. The reader verifies the actual run_owned augmentation, including
supervisor_returncode, receipt_sha256 and its one status rewrite. An original
OWNER_UNCONFIRMED_HOLD is not upgraded by a subsequently present disk receipt.
The exact owner request binds the original implementation hash and 180/3
budgets.

The phase family set is read with ast.parse and ast.literal_eval from the
already verified original qualifier source. No project module is imported.
Failed and pending phases are selected from the actual original phase index;
there is no hardcoded chain, names, exports, timeout, or environment diagnosis.
Complete original requests/process receipts/stdout/stderr are retained.
Nonreturned child receipts are observations and are not automatically labeled
unexpected failures, since some qualification cases intentionally trap.

Before interpretation, the primary cold/owner/request/stdout/stderr/index
originals are eligible for exact base64 log export. Console original-data
output is bounded to 512 KiB, with full omitted records retained in the output
artifact and listed by path/bytes/SHA/mode. The complete custody ledgers and
source inventory are not dumped into stdout.

All materialized originals, the reader itself and input ZIP undergo
unconditional byte/mode after-checks on success or failure. Primary exceptions
and after-errors remain distinct. The final CPU and wall checks happen after
these checks and full ledger persistence.

A reader PASS means original custody and readback only. It cannot supersede
the original Core failure, qualify another commit, activate a route, or close
the ordinary Worker/namespace/public diagnostics work.
