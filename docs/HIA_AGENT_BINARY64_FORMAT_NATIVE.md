# Explicit native Agent binary64 printing

`HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST` selects a source-bound HIA image for
Agent `wire`/digest finite floating-number printing, including numeric object
keys. Selection is administrator-owned. Invalid or stale selections fail closed;
the default path is unchanged. This is not a complete native JSON serializer.

The image accepts exactly eight little-endian IEEE-754 bytes, a 32-byte output
capacity and 8192 bytes of private workspace. Integer interval digit generation
uses exact lower/upper half-ULPs, parity-dependent ties and asymmetric margins at
normal powers of two. It returns the shortest round-tripping decimal spelling;
fixed/scientific notation, explicit exponent signs and negative zero match the
existing Agent wire. All finite binary64 bit patterns are in domain. NaN and
infinities are rejected. Invalid inputs, insufficient scratch or output capacity
leave output untouched. Scratch is private per call; there is no shared numeric
state, host decimal printer, float arithmetic or precision-restricted fallback.

`tools/build_hia_agent_binary64_format.py` requires a successful matching-source
cold qualification with original 180-second execution and 3-second cleanup
limits before compiling the source and sealing its source/image identity.
Development seed builds are not cold qualification.

The selected Agent adapter transports Python float bits with `struct.pack` and
passes a native callback to the bounded structural JSON iterator. Python still
owns object traversal, duplicate-key conversion checks, string escaping,
arbitrary integers, allocation, manifest custody, hashing and SQLite persistence.
Core's distinct integer-only JSON protocol is unchanged. General native-only
bootstrap, build/install, editing/runtime and persistence remain open.

Tests execute the independent Core VM before a native seed. Actual native tests
cover every finite binary exponent at powers of two and both adjacent values,
both signs, random finite bit patterns, notation thresholds, subnormals,
nonfinite refusal, output canaries and private concurrent buffers. Selected
Agent wire/digest tests disable the default JSON iterator, exercise float keys
and collision rejection, and require bad images to refuse without fallback.
