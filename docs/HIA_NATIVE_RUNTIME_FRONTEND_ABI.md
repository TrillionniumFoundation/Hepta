# Native Runtime constructor frontend ABI

This component closes ordered primitive options and fresh verification over the sole native Value arena. It does not yet create a public ScalarMultiversionRuntime object. Scalar-profile admission, totality, directory creation, automatic terminal Runtime-resource borrowing, subclass publication and the complete public constructor remain separate required work.

## Native entry binding and custody

The new fixed native product exports the original owner, Future, sidecar and global entries, plus:

- `hia_generation_runtime_frontend_bind`
- `hia_generation_runtime_constructor_options`
- `hia_generation_runtime_verify`

All entries use the established six machine-word pointer/extent ABI. No public constructor request contains an entry pointer or context pointer. The fixed bridge captures its actual root and Value entry, checks root PID/self/identity, and captures the VFY dependencies from the same linked product.

Bind request is exactly 128 bytes, `HIARTBQ1`, operation at8: 0 initialize, 1 retire; bytes16..127 are zero. Work is the original root2048. Output is exactly1048576 bytes and becomes the stable owned frontend context; it must remain at the same address while pending custody exists. The response is at output1024, `HIARTBR1`: status8, state16, pending80, known88, consumed96, retired104, detail112. States:1 ready,2 closing,3 retired,4 unknown. Initialization owns an actual Value context token, actual global op2 resource borrow and an actual root active guard. It neither consumes a caller capability nor claims that Runtime construction is complete.

The context header captures PID8/self16/root24/Value entry32/Value context40/extent48/global entry56; actual global cap64..87 and Value token88..111; pending112/known120/state128/primary error136/detail144/cleanup stage152/Value nonce160. Tool FDs168/176/184, sourceFD192, threshold pointer200/extent208/FD216, global nonce224 and integer digit limit232 come from the real global borrow. root entry240 and guard-owned248 record custody. Options workspace is frontend4096/8192, verification workspace frontend16384/8192. Both workspaces are initialized by the native binder.

Retirement refuses outstanding nested work, consumes the actual token through92/93, drops/retries the actual global borrow, and decrements the root guard only after terminal facts. Unknown ownership retains the context and guard. The independent sidecar must remain available until the frontend retires; automatic public Runtime guard transfer is not yet qualified by this component.

## Ordered options

Request `HIARTOQ1`, exactly256 bytes, operation0 at8; seven Value triples start at24 with stride24: baseline, directory, clang, validation timeout, maximum live generations, prove-total and actual class. Baseline and directory are real required Values; optional zero triples mean omitted. Operation1 is explicit retained cleanup with all argument fields zero. Output is at least32768; workspace is the native8192-byte `HIARTOC1` context.

Order is actual platform inspection, exact timeout integer1..30000, exact live-limit integer2..64, exact prove-total bool. Defaults are2000,8,False and a newly created real str Value `clang`. Supplied clang is retained with its identity. The bool scalar encoding is one byte, as required by the actual Value ABI.

Reply `HIARTOR1` contains status8, disposition16 (1 success,2 actual exception), actual exception triple24..40, pending80, known88, delivered96, quarantine-kind104 and detail112. Success additionally returns timeout128, max-live136, prove144, independently owned baseline160, directory184, clang208, and supplied class232. Every delivered cap is a real strong capability. Primitive refusal returns actual canonical MultiversionRejected with the original argument tuple. Cleanup is based on actual78 consumed facts, not status alone.

## Fresh verification

Request `HIARTVQ1`, exactly128 bytes: operation0, actual baseline triple24..40. Operation1 retries retained cleanup and carries no baseline. Output is at least524288; workspace is8192 bytes, `HIARTVC1`. The binder captures the sole Value arena and sole provider payload registry, complete VFY3/4 capsule, sealed normalizer FD and all fixed nested dependencies.

The real class36 catalog/MRO check detects VerifiedProgram. Both actual fields (canonical_bytes and structured_bytes) are read through the immutable record API and supplied to VFY4. All other Values go through VFY3. An annotation or a class label does not grant verification authority.

Reply `HIARTVR1` fields:

| Offset | Meaning |
| --- | --- |
|8|status|
|16|format:0 normalization frame,1 native normalizer diagnostic,2 local verifier diagnostic|
|24..40|independently owned actual payload triple|
|48|payload byte length|
|56|actual normalization profile|
|64/72|canonical Core/original input byte lengths|
|80/88/96|quarantine kind/known/pending|
|104/112|borrowed canonical/original pointers, only valid while the delivered payload cap is retained|
|120|detail|

The payload borrow operation is actual `HIABPY01` op6 with request128 and **response512**; response `HIABPYR1` length40 and pointer64 identify its immutable bytes. Successful bytes are `HIAVCF01`:64-byte header, original length32, canonical length40, then original bytes followed by canonical bytes. Payload op3 releases the independently delivered capability.

A real payload remains explicitly delivered after later cleanup failure. The consumer must not discard a nonzero returned cap merely because status is nonzero. Nested retained/unknown facts retain the output identity and complete continuation for operation1.

Format1 contains the actual normalizer diagnostic envelope, whose driver code is not the HIA exception code. Format2 contains the actual local verifier descriptor. Their conversion into full typed HIAProgramRejected including original causal data is not claimed by this checkpoint.

## Construction and qualification

The qualified construction has46 logical root roles, one Value implementation/arena,15278638 bytes of .text and the unchanged16MiB text/4MiB leaf limits. The eleven-role frontend capsule shares all Value and global entries through fixed relocations. The original native compiler independently compiles both copies of every new HIA module, the native packers match independent expected bytes, and the original native linker links the product. The fixed malloc/free call stubs remain in the existing E8 relocation domain.

Seven actual behavior groups cover native token/global borrow/guard custody, defaults, nine original primitive refusals and ordering, explicit boundary values, raw bytes/text VFY3, actual VerifiedProgram VFY4 and revalidation of its structured field. Every test ends with actual cap/payload/FD/parent-guard retirement. Failed earlier runs are retained as evidence. This checkpoint does not qualify the complete public constructor, automatic per-Runtime borrow transfer, totality/directory sequence, or whole runtime.
