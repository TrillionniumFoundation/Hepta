# Native service records: development interface r1

This component is a development implementation of the complete successful service record and the data-level behavior of HIAAgentService._error. It is not an ordinary Worker route, a namespace publisher, or a whole-service qualification. The caller supplies an issued immutable Graph of native exception observations; the component does not perform Python exception-object introspection.

## Confirmed state before environment unavailability

The authoring generator completed and the historical f50 B3 compiled the actual HIA source under unchanged 10 CPU seconds, 20 wall seconds, and 256 MiB address-space limits. Source readback was unchanged. No native semantic or protocol case had started when the environment became unavailable; the first harness/test patch was still awaiting a tool receipt.

HIA source: 103588 bytes; SHA256 ca8c522d9986ef77ebab7047ae01c142820f55c4200147e402e0e219a1c64a9e.
Image: 154906 bytes; SHA256 9c3fd57c3914a1d2775a16a5369c21b96802656c28c966bde727575afe53cacb.
Authoring structure: 25 functions, 370 blocks, 1690 instructions, maximum 124 blocks per function and 16 parameters per block.
Compiler: 668608 bytes; SHA256 0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8.

These are observations read from the local completed compile log before disconnection. This document is not a substitute for its original source/image/receipt files or a new qualification.

## Semantics

Mode 0 creates the complete ordered record:
contract_version, request_id, status=completed, result.

Mode 1 creates the complete ordered record:
contract_version, request_id, status=rejected, error.
The error object has code, phase, message, retry_action, details_artifact in that order.

An absent or non-string code becomes E_HIA_REJECTED; otherwise its first 128 Unicode code points are retained. An absent phase becomes admission; an explicitly present null or other value is preserved. The first 4096 code points of the supplied actual exception message are retained; the actual exception type-name observation is used if this prefix is empty. An absent retry_action becomes correct_input. An absent details_artifact becomes null.

The component requests publication if pending_slot_snapshot exists and is non-null. False, zero, empty string, empty list and empty map all require publication, matching the original identity comparison with None. The complete original snapshot root is forwarded for store.json(snapshot, "slot-snapshot"). Only a successful actual publisher result replaces details_artifact. A publisher failure is returned as that failure's complete Graph, not converted into a successful error record. The enclosing service controller must propagate this failure and preserve the original transaction/finally behavior. No production namespace callback has been implemented by this component.

Source nodes, references and insertion order are retained. Output storage grows to measured size; there is no added total-node, record-byte or JSON-wire language quota. The later original JSON-wire gate is separate.

## Entry and lifetime

The retained RWW wrapper borrows its second buffer read-only. Both source Graph and command/ACK are read-only; only the third workspace is mutable. A workspace starts with 1024 zero bytes and grows by copying its complete previous contents.

The first command is 96 bytes / 12 little-endian u64 words:
[HIASRC01, lease, request, mode, requestIDRoot, payloadRoot, 0, 0, 0, 0, 0, 0].
Lease and request are nonzero. Mode is zero or one. Both roots name nodes in the same supplied Graph.

A pending-publication reply is a 64-byte prefix followed by its complete issued Graph:
[HIASRR01, lease, request, lastEventSequence, resultKind, GraphBytes, 0, 0].
resultKind zero means actual publisher success; one means actual publisher failure. The source Graph is still the exact same immutable source lease.

If the component requests GROW before accepting a reply, replay the initial command. If it requests GROW after accepting a reply, replay the same immutable reply; never repeat the namespace publication. The first 128 reply bytes and exact extent are retained for continuation correlation. This is not authentication of an arbitrary caller-substituted payload. The fixed issuer/executor must keep the original immutable lease alive.

Normal return value is 384. A 16-word event starts at workspace offset 256:
0 HIASRE01;
1 action (0 done, 1 grow, 2 store.json request, 3 publisher failure, 4 private refusal);
2 lease;
3 request;
4 monotonically increasing event sequence;
5 exact needed workspace bytes for grow, otherwise zero;
6 complete output Graph offset for done/failure, otherwise zero;
7 output Graph byte extent;
8 private refusal reason;
9 input mode;
10 output root;
11 pending source snapshot root for store request;
12 original source Graph lease;
13 consumed publisher Graph lease, otherwise zero;
14 and 15 reserved zero.

The full output Graph begins at offset 1024. Output views expire on any subsequent workspace invocation or relocation. A done or refused instance cannot be reused. The caller must immediately discard a lease after BAD=0xfffffffd, even if an illegally shortened workspace prevented writing a poison marker, or sequence exhaustion left an older event header. No retry on BAD is authorized.

## Boundaries still open

The component needs actual-image semantic, alias, Unicode, growth, failure-order and malformed-frame controls before handoff. Native exception observation production and the enclosing call/Worker controller are separate owners. High-level namespace publication is still pending the namespace owner's native service ABI. Neither a Graph node ID nor a nonce is a namespace handle or an external authenticator. No existing Python owner or ordinary selector has been removed or switched.
