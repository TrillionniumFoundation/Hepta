# HIA Core program contract

HIA is the sole language product. A standalone program is strict JSON with an
explicit versioned `schema`, ASCII `module` and `functions` array. Primitive Core
v8 uses `hepta.hia.program.v8`; other existing Core schemas have their own exact
adapters and checks. An optional explicit `exports` inventory chooses public
entries, not an executable output profile. `hia catalog --schema
hepta.hia.program.v8` describes the actual instruction contract.

Each function declares its `name`, typed `params`, `returns`, `effects`, `entry`
and `blocks`. Parameters are objects such as `{"name":"x","type":"u32"}`.
Every block has an `id`, typed `params`, `ops` and one `term`. An instruction
declares `op`, `args`, typed `out` and `attrs`; values reference explicit SSA
names. For example, a `const` of type `u32` has no arguments and
`{"value":1}` attributes, and `int.add.wrap` combines two matching integers.
Arithmetic modes and casts are explicit, not inferred. Results and calls must
match exact types and signatures.

The Core verifier checks the entire program: structure, names, SSA and CFG
transfers, instruction attributes/types/effects, call interfaces and resource
state. Owned buffers/chains are linear; loans have explicit origins and must
respect exclusive/shared aliasing and parent suspension. A successful path
cannot leak or duplicate resources. Traps and budget stops are reported as
stopped executions, not successful cleanup or semantic equivalence.

`hia verify file.core.json` admits Core without execution. `hia inspect` exposes
the normalized structure; `hia normalize` publishes a new checked JSON file.
`hia build` emits a native ELF object using the admitted native backend and does
not silently call a foreign source-language compiler. Verification does not grant
filesystem, deployment, persistence or execution authority.

Agent editing uses snapshot-bound queries and explicit responses. Apply/batch
operations reverify the whole resulting module and publish only to a new path;
stale snapshots and invalid edits refuse without replacing the original. Static
patch impact is a call-graph advisory, not behavioral equivalence or proof that
external callers were revalidated.

The hosted CLI/Agent service and reference Core machine still use Python.
The native stdio entry currently implements capabilities, verify and compile;
native editing, durable persistence, full runtime/build and clean-machine
installation remain separate acceptance obligations. Consult the pinned native
support profile instead of treating hosted or historical tests as native closure.
