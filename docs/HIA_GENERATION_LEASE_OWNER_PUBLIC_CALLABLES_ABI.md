# Sole-owner public native callables

This profile keeps one actual Value arena and one fixed native code provider.
The independent mask-6 owner profile remains available with its original domain.
The callable profile admits public Value operations 68, 69, 70, 75 and 87 through
the enclosing owner operation 4 only after the real native sidecar has initialized
the code provider and captured both directions of the binding.

## Public operations

| Value operation | Behavior |
| --- | --- |
| Q05/68 | Compile admitted HIA source into an actual code capability and create a function with strong environment and name edges. |
| Q05/69 | Create a real bound method with strong function and self edges. |
| Q05/70 | Invoke real native code with actual tuple arguments and dictionary keyword arguments. The returned or raised Value capability has independent delivery and cleanup facts. |
| Q05/75 | Construct an actual exception instance from a BaseException class, tuple arguments and an optional namespace dictionary. |
| Q05/87 | Obtain an actual canonical exception class from the fixed catalog. |

The child reply begins at byte 16384 of the enclosing owner output. Q05/70
uses the Value invocation ABI: the actual capability is at 24/32/40, disposition
64 distinguishes return (1) from raise (2), known/delivered are 88/96, and pending
80 and cleanup 104 remain independent. The wrapper neither replaces a raised
exception with a class-name string nor hides a delivered capability when later
cleanup fails.

The enclosing core checks the native sidecar identity, actual allocation extent,
own nonce, lifecycle state and fixed code entry before accepting support mask 62.
The sidecar opens kinds 3, 4 and 5 only after native code-owner initialization and
both trusted Value bindings have succeeded. Closure follows the previously
qualified sidecar fence, actual code cleanup and rollback contracts.

## Private boundaries and retry

The entire Q06 profile remains private. Q05/48, /49, /52, /53, /54, /55,
/56, /58, /59, /60, /61, /64, /65, /66 and the managed-edge and call-custody
operations remain unavailable to public owner requests. In particular, Q05/56 is not added to the public whitelist.

The original kernel-fault fixtures retain their explicitly identified trusted
Q05/56 cleanup path. Three additional gates instead enter the ordinary public
Q04/47 query through owner.op4. The single query reaches the actual native
post-call cleanup loop and retires the retained code mapping or call record.
Its reply is the actual query reply; no fixture manufactures cleanup success.

## Actual qualification

The native build uses the unchanged original source compiler, fixed mechanical
bridges, the HIA packer and native linker. The new enclosing core is compiled
twice; the native object is compared byte-for-byte with the independent packet
layout. Frozen carrier bodies and the already qualified sidecar capsule are
identified individually by byte count and SHA-256. This is not a claim that all
historical source modules were recompiled during this incremental build.

The component qualification comprises 28 groups:

- 15 original invocation groups through the actual owner.op4 entry, including
  source compilation, strong environment/self retention, nested methods,
  reentrancy, real exception propagation, cycles and eight-thread execution.
- 8 original custody groups through the same public route, including actual
  getrandom, allocation, mapping retirement and mutex-contention failures.
- 3 ordinary-public-query recovery groups after real code, call-record and
  adoption-contention failures.
- 1 complete private-domain no-write refusal group.
- 1 true MultiversionRejected class/MRO, arguments and nested hia_cleanup
  namespace group.

The public Value15 flat is 3,517,686 bytes with SHA-256
8b9522da1a2c8451c592d27fde1beff7209224f893e22399c3fcf01ce0dbfdd7.
The enclosing product is 14,324,496 bytes with SHA-256
2f0a6124faf4534cddce6d3ba02b63dc37c6529b5622ee90bbb57c5f5947c7a6.

The evidence includes the initial fixture failure, caused by attempting to feed
a nested host dictionary into a scalar-only development convenience helper.
The corrected gate creates both dictionaries with real native Value operations;
no production code or original assertion was weakened.

Custom protocol dispatch, the complete ScalarMultiversionRuntime public
constructor, immediate generation-cache pruning and the complete fused
Runtime/Future/Background product remain separate unfinished qualifications.
A passing public callable boundary does not assert whole-runtime completion.
