# Independent Core-only runtime controls

The host-memory regression fixture now authors its two scalar functions directly
in typed HIA assembly. No source-language parser, checker, migration adapter or
source-to-Core path is retained to build it. The existing independently written
C bridge remains a test caller, not a production implementation.

`tests/hia_host_region_fixture.py` runs independent scalar observations in the
Core VM, emits a real direct-native ELF object, and links the unchanged C bridge.
The memory permission, borrow/lease, ownership, quarantine, recovery, code-pin
retirement and competing-recovery controls retain their actual operations. This
is hosted runtime regression evidence, not a native-only runtime completion.

Tests split from old mixed modules retain standalone Core controls. Empty obsolete
source-route test scaffolds are removed only after loading them confirms zero
test cases; no such module is counted as a successful regression. The 255-file
qualified compiler/application closure is byte-identical to the Core-only native
qualification at `f1bea765d6dee078faeaa2d7ea3f3f992785b617`.
