# Hepta study profile

The bootstrap compiler lowers to pinned rustc 1.90.0; native checks are required.
Modules use `import storage;` and `storage::make(...)`. Imported declarations must
be `pub`. Every function has an explicit return type and `effects {...}`.
`read`, `mut`, and `take` declare borrowed/exclusive/owned parameters. Owner
bindings must be transferred with `move`; `drop(move value)` recursively releases
owned ADTs. Owning Results use `match move named_result` or `match fresh_call()`;
each arm must consume its owned payload. Pattern bindings are immutable; move
into a new `let mut` binding to mutate one. `try_buffer(n)` returns
`Result<Buffer<u8>,u8>` with zero-initialized bytes, Err(1) for reserve failure,
and alloc/block effects. `buffer(n)` is infallible; failure aborts.

`spawn(worker, move bytes)` requires a named worker with
`(take Buffer<u8>, read Cancellation) -> u64`. `join(move task)` and
`cancel_and_join(move task)` consume it. `cancelled(read token)` observes
cooperative cancellation. Tasks cannot escape their creating scope. Array/slice
indexes are checked. FFI calls require `unsafe { ... }` and ffi/unsafe effects;
repr(C) structs and scalar signatures are checked against the supported ABI.

The semantic arm exposes the same function/body/declaration operations as
Rust, using actual production workspace-v4 node IDs. Every edit binds the
current workspace version and interface. Preparation validates the whole graph;
the task contract is independently compiled before the same request commits.
The production store persists across child processes; recover and a final pin
supply the submitted source. Expression/statement edits are outside this study's
public operation set. Initialization and all validation/recovery consume the
common wall budget. `interface_policy` in the task says whether declaration
interfaces may change; API/owned-Result tasks permit migration, other tasks
preserve their interfaces. The plain arm uses checked in-memory file updates.
