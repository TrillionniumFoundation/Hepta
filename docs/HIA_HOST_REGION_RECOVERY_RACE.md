# Native reader and recovery race qualification

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

`retired harness qualify-hia-host-region-race` extends the existing Linux x86_64 host
region evidence with a controlled concurrent schedule. The same verified HIA
scalar exports, actual C ABI, memfd mapping, kernel page protections, host
ownership gates and native worker joins remain in the executed path.

Two actual native readers rendezvous through C11 atomics. One reader times out,
quarantining the region while both workers are still alive. Recovery, unmapping
and library unloading must refuse at that point. A separate control region
releases the native gate; it never obtains the data region's pointer or lease.

Two host threads then compete to recover the now-joined data region. Exactly one
may publish a zeroed ready generation; the other must be denied. The first
reader's original host caller is deliberately delayed **after its real native
worker join**, until recovery and a fresh HIA-backed fill have both completed.
That old caller must return uncertainty, and must neither commit its stale
result nor revoke or zero the new generation. The final data, generation,
mapping/lease state, code pins and empty ownership registries are checked.

The scheduling hook changes only the outer caller's timing. It does not replace
the native functions, manufacture a worker-completion receipt, skip the lock,
or create a recovery result. Native rendezvous has a fixed five-second upper
bound and cleanup releases the gate before joining owned threads.

This is one finite schedule with actual execution and fault recovery. It does
not exhaust all interleavings, prove a language memory model, add support for
devices or DMA, or establish recovery from process/OS crashes. The existing
trusted synchronous no-pointer-escape FFI contract remains part of the boundary.
