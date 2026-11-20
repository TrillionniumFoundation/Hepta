# Installed Worker journal query and evidence

The installed v1 and v2 workloads preserve their original requests, worker code, command order, 60-second child budgets, and every original public and durable-state assertion. The original complete helper bytes are fixed under `tests/fixtures/worker_installed_journal_original_r18/`.

## Correct request identity

`HIAAgentService._reference_call` stores requests under `digest({"tool": tool, "key": request_key})`. Both original installed observers queried the raw `request_key`. That query cannot identify the service's namespaced row. R18's two installed methods failed the original `('running',)` assertion; their temporary original databases were subsequently removed by fixture teardown. The old observed value and the old database's real namespaced state are not reconstructed or claimed.

The explicit successor changes only the evidence lookup to the same namespaced identity. Product storage semantics and request arguments are unchanged. The v2 workload and independent reader bind the exact corrected full v1 helper identity; the original helper remains a fixed regression authority, not a passed test result.

## Actual snapshots before teardown

At each existing state-observation boundary, `JournalSnapshots` binds the immediately preceding actual worker receipt and captures the original arguments. SQLite's backup API copies the complete committed source database, including WAL content, into a new retained snapshot while opening the original database read-only. The observer reopens that snapshot, records both the raw-key and namespaced queries, and returns the original three-field state shape without changing values.

Every completed boundary publishes its own immutable progress file. Failed original assertions therefore retain the database bytes that were actually read. A complete index is emitted only after all four v1 or six v2 boundaries and all original assertions complete. The snapshot index is evidence capture, not native qualification.

The independent Worker reader reopens every snapshot read-only, recomputes the request namespace and digest from captured arguments, reads the actual stored row, checks its tool, key, state and response, counts artifacts and costs, and compares those results to the producer observations. It also verifies the original eight or ten command receipts, real stdout/stderr, installed wheel, identity flags, request replay and cost assertions. A missing row, raw-key alias, substituted snapshot, partial inventory or changed byte string cannot become a passing full installed result.

## Scope

The nine additional SQLite data controls cover namespacing, cross-tool separation, missing rows, actual completed state, postcapture drift, incomplete inventory, independent snapshot reopening, incorrectly re-signed metadata, a genuine row for another request and unchanged WAL snapshot consumption. Their synthetic command data is explicitly marked and does not qualify an installed worker. The original full v1 and v2 installed methods and their complete independent readers remain required. No whole-native, cold-selfhost or old-stack-removal claim follows from this correction.

## Independent reader custody successor

The first static reader draft is retained outside the product tree with its failed peer review. Its successor binds v2 journal arguments to the exact already captured worker stdin. Both profiles bind normal/replay and loss/unknown journal digests to the actual public response request IDs, and require paired complete argument equality. A different genuine running row with consistently re-signed metadata cannot supply evidence for the worker request.

SQLite consumes a byte-for-byte private copy of the snapshot raw bytes that the reader has already captured and hashed. The new temporary directory is private, the copied file becomes read-only, and the connection uses read-only immutable mode. The copy is checked before and after queries, and the original captured snapshot is checked again at the final boundary. This preserves unmodified WAL-format headers and avoids hashing one pathname instance while SQLite opens another.
