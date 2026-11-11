# Public workspace execution custody

The original 662734a3 source built a real HIA workspace pipeline using its
matching 698-input cold qualification. Direct execution returned the expected
920-byte ELF object, while the public host compilation bridge raised
`AttributeError` because this Python build omitted `fcntl.F_ADD_SEALS`.
The original failure and source-preservation observation are retained here.

The follow-up uses Linux UAPI constants when symbolic names are unavailable and
requires an actual complete kernel seal readback before execution. Source
controls exercise real memfd sealing and rejected incomplete or untyped
readback. Native integration controls require their own matching-source cold
and the original builder, execute the actual HIA pipeline through the public
bridge, and verify refusal before exec plus descriptor closure after a failed
seal observation. No original timeout, payload bound or semantic policy changes.
