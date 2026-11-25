# Native size-derived NDU JSON transport

The separate transport role admits complete rank containers without turning a per-Core source limit into an aggregate rank limit. Original Core, proof, evaluator, process-output and background-submit bounds remain unchanged.

The actual flat is 148164 bytes, SHA-256 2e6537acb01c8c2e93c7f7bbcac4f9d0a9fe2e10836d6f56d479c9506f434144. Its 680 cases cover 642 exact existing-native comparisons, 34 malformed inputs and four larger graphs: 1048578 nodes, depth 600 and 32 candidates with 96 MiB of string contents. The same production Unicode/key helpers passed 26 sparse-memory probes across 2^32 offset and scope boundaries. The probe does not claim to scan a whole 4 GiB document.

Use the six-word buffer ABI. For sizing, set work byte 104 to zero with at least 128 work and 64 output bytes. Return zero yields HIANJS01 and u64 nodes/keys/depth/arena-capacity/work-capacity/source-length/zero. Sizing is not JSON admission.

Allocate fresh disjoint buffers using those capacities. Set work words at 48/56/96 to nodes/depth/keys and word 104 to one. Only a zero return admits the arena. Read full used bytes from arena word 24 as u64; the return value is a status. Other metadata retains the existing 64-byte header and 72-byte nodes. Unicode positions and key scopes are separate u64 fields. The native parent owns source and arena together; no public claimed arena is accepted.

The JSON qualifier takes --flat, --decoder and --output. The offset qualifier can emit identical probe source with --emit-probe-source PATH; compile it with the qualified native compiler, then supply --probe and a fresh --output directory. Exact source, flat, probe and evidence hashes appear in the accompanying JSON.

This role provides syntax and spans. Canonical serialization, finite float freezing, typed business admission and the complete rank owner are separate. This component qualification is not whole-rank or production closure.
