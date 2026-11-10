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
test cases; no such module is counted as a successful regression. The existing compiler, frontend, stdio and ELF linker assembly remains unchanged
from the Core-only native qualification at
`f1bea765d6dee078faeaa2d7ea3f3f992785b617`. The integrated installed-Agent
closure additionally binds the restored controls and their fixtures; it requires
its own fresh exact-source qualification. Prior execution receipts are not
promoted to the enlarged source identity.


The pure Core guarded-opportunity qualifier now imports an isolated raw Git
source-custody checker, not the removed mixed-language qualification dispatcher.
The same raw tree/blob/mode and hidden index-hint controls remain executable.
The old mixed workflow test IDs are explicitly retired without pass credit;
new Core workflow tests execute this product's actual source shell and reject
failed, skipped and expected-failing native fixture outcomes. They are wiring
controls, not substitutes for real native qualification.
