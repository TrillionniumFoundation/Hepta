# Store persistence: actual remaining boundary

This is a bounded static reading of the current source, not a result from a
new product execution. The CLI file-action entry and one-request Worker are
separate entrypoints; there is no single in-process call chain from every CLI
command to the Worker.

| Current caller | Existing HIA owner | Remaining original provider |
|---|---|---|
| `hia_agent_worker._run` | `NativeWorkerReport`, selected by a pinned worker bundle | Unselected `_reference_run`; separately selected request admission; Service construction; Python IO and object effects |
| `HIAAgentService.__init__` and per-family proxies | Requests/context/emission/verification/evaluation/artifacts owners | Reference families when absent; Core/compiler providers; Store/SQL foreign effects |
| `AgentStore.__init__`, `close` | `NativeStoreLifecycleOwner` owns both original lifecycle bodies | `sqlite3.connect`, WAL/FULL pragmas, schema creation and actual SQLite connection |
| `AgentStore.put/get/profile/...` | `NativeArtifactNamespaceStore` owns namespace protocol | Fixed `main.artifacts`/`main.profiles` SQL and transaction effects |
| `HIAAgentService.call` | `NativeRequestJournalStore` owns claim/replay/dispatch/completion | Original SQLite file and WAL, guarded SQL connection; atomic tool mutations and response commit share that connection |
| Artifact payload bytes | `artifact_publication_native` sealed `hia-artifact` executable | Source/code admission and process launch remain hosted; relational metadata is explicitly outside the file application |

## Reusable filesystem entrypoints

`hepta/artifact_publication_native.py` has `admit_artifact_store` and
`invoke_artifact_store` for `store-hash`, `store-put` and `store-get`, plus
`publish`, `verify` and `withdraw`. One public put binds one immutable code
admission for hash and durable put; the next public operation revalidates.
The source inputs are the HIA publication policy/packer, SHA-256 stream
component and the fixed assembly syscall ports. The fixed file writer already
implements immutable content, exact deduplication, private temporary files,
file fsync before linking, directory fsync before a success receipt, and
failure/possible-effect reporting. The assembly explicitly excludes namespace
and SQLite journal ownership.

`hepta/hia_linux_file.py` and its `generate_hia_native_file_read.py`/
`generate_hia_selfhost_linux_file.py` components provide a distinct explicit
profile: one private readonly open/stat/read/close FD, startup argv/env, and
stdout/stderr. They do not supply general write, transaction, rename, fsync or
database capabilities. The roundtrip profile reuses this readonly file model.

## A real SQLite replacement still needs these capabilities

1. **Durable metadata and indexes:** artifact ID/URI/content-key uniqueness,
   `(profile id, digest)` lookup, plus contexts, requests, costs, cursors,
   slots, versions, leases and execution-budget records. Content files alone
   cannot answer these queries or reproduce the original issued-reference
   authority.
2. **One atomic transaction owner:** request intent/completion and affected
   slot/version/budget rows must commit or roll back together. The current
   journal lends a guarded connection to the real tool helpers. Replacing just
   the request log with a separate file would split an existing commit boundary.
3. **Crash/reopen and uncertain effects:** durable intent, exact replay of an
   issued terminal response, conflicting-key refusal, lost COMMIT/ROLLBACK ACK,
   restart and competing-process behavior. Unknown completion must not become
   a retryable rejection or a new dispatch.
4. **Owned durable namespace:** bounded transaction encoding, file/parent/WAL
   identity checks, exclusive-writer/read visibility, safe partial-write and
   sync behavior, schema/version migration and a defined compatibility policy
   for existing `state.sqlite3` installations.

The next persistence implementation should expose an explicit HIA transaction
owner/receipt interface for the existing fixed record operations, then replace
one closed transaction family through it. It should not grow a generic SQL
parser or claim that today's continuation wrappers already implement durable
storage. The existing immutable-payload application is the first reusable
mechanical file substrate; the cross-table transaction/journal is the missing
production component.

## Existing tests that constrain that interface

Keep the full original suites. In particular:

- `tests.test_hia_store_lifecycle_native.StoreLifecycleSourceTests.test_two_exact_original_bodies_preserve_sql_and_reference_definitions`
- `tests.test_hia_store_lifecycle_native.StoreLifecycleNativeTests.test_all_ninety_original_provider_observations`
- `tests.test_hia_store_lifecycle_native.StoreLifecycleNativeTests.test_held_error_twenty_original_lifetimes`
- `tests.test_hia_store_lifecycle_native.StoreLifecycleNativeTests.test_unknown_actual_ack_forbids_all_twelve_replays`
- `tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_real_file_and_directory_fsync_and_post_fsync_receipt_boundary`
- `tests.test_hia_agent_artifact_store_native.AgentArtifactStoreKernelTests.test_actual_directory_fsync_failure_leaves_no_success_and_preserves_possible_content`
- `tests.test_hia_agent_artifact_store_native.AgentArtifactStoreRouteTests.test_real_store_bytes_metadata_dedup_restart_and_namespace_authority`
- `tests.test_hia_request_journal_native.RequestJournalNativeTests.test_actual_atomic_slot_and_response_have_one_commit_boundary`
- `tests.test_hia_request_journal_native.RequestJournalNativeTests.test_actual_atomic_transaction_does_not_capture_an_ordinary_writer`
- `tests.test_hia_request_journal_native.RequestJournalNativeTests.test_actual_process_exit_commit_boundaries_preserve_same_journal_on_restart`
- `tests.test_hia_request_journal_native.RequestJournalNativeTests.test_actual_concurrent_claim_has_one_owner_and_exact_response_cannot_change`
- `tests.test_hia_request_journal_native.RequestJournalNativeTests.test_main_and_wal_identity_changes_refuse_before_request_sql`

Some of these deliberately inspect SQLite rows/files and pin complete original
policy bodies. A future new backend therefore needs an explicit new storage
contract and additional independent controls while retaining the old oracle
and original behavior tests. They cannot be silently relabelled as a non-SQLite
backend pass. Current original Namespace timing failures and full fresh-source
admission requirements remain unresolved by this op8 candidate.
