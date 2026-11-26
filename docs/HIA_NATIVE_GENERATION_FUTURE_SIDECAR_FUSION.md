# Native generation / Future / callable sidecar fusion

This component keeps one physical Value implementation and one actual native Value arena across the Runtime owner, Future owner and source-bound code provider. The fixed native sidecar initializer performs code registration and captures the mutual Value/code binding. Public requests do not supply native entry pointers.

## Construction

The HIAGFUP3 frame has 64 logical roles, a 528-byte header and a 2048-byte packer workspace. The HIA packer resolves every fixed bridge hole and produces the Runtime owner, Future public owner and sidecar exports in one ELF object. Byte-identical immutable bodies are stored once. The role limit remains 4 MiB and the text limit remains 16 MiB.

The qualification records the original compiler, every captured input role, the changed HIA sources compiled twice, the native packer and linker, the independent reference-object equality, all invalid frame controls, and actual product hashes. The current image has a 15,519,460-byte text section and exactly one 3,517,686-byte Value body.

## Actual qualification

The same native function is captured in a Future, its original external reference is dropped, the result is retrieved, and operation 70 executes the actual compiled source through the code provider. Native retirement then closes all callable custody and the owner.

The fourteen existing Runtime/Lease/Future coupled cases run against this image with unchanged assertions: resource lifetime in both orders, binding rejection, concurrent last references, real pending retirement for both resource kinds, Future-held Runtime and Lease resources, both lifecycle orders, active-owner destruction refusal, typed calls, actual OS failure retention, and tool-bank custody.

HIA_NATIVE_GENERATION_FUTURE_SIDECAR_FUSION_QUALIFICATION.json contains the exact construction and behavioral evidence. This is a qualified fusion component. It does not qualify the remaining canonical Future resource initializer, custom truth dispatch, full public constructors, or the whole native system.
