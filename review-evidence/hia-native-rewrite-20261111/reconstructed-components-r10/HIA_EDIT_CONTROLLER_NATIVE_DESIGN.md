# HIA edit controller and fixed executor integration design

Status: design for new development, not an executed or qualified controller.
The completed predecessor is the exact 24-case native composition in
native-agent-edit-development/complete_edit_pipeline.py. This work moves its
remaining mechanical control and constant diagnostic projection into HIA.
No public foreign-object capture or ordinary filesystem publication closure is
inferred from this private controller design.

## Ownership and fixed role table

Keep the frozen 35-image complete program-admission bundle's roles 1–28 and
40–46 unchanged. The new fixed executable has a bounded 64-slot image table,
with slot zero unused and these additional roles:

| Role | Immutable HIA image |
| ---: | --- |
| 29 | Graph wire scan |
| 30 | Graph wire emit |
| 31 | Public Agent integer JSON decode controller |
| 32 | Agent raw JSON arena decoder |
| 33 | Integer arena-to-Graph |
| 34 | Caller-specific bounded input r3 |
| 35 | Single/batch input prefix |
| 36 | Exact selector r3 |
| 37 | Core facts |
| 38 | Complete Agent SSA/CFG slice |
| 39 | Complete query packet |
| 47 | Typed packet-to-Graph |
| 48 | Graph merge |
| 49 | Ordered batch query/overlap |
| 50 | Response policy and pending patch/metadata Graph |
| 51 | Exact canonical query-byte match |
| 52 | Separate-component native patch envelope |
| 53 | Final complete receipt Graph |
| 54 | Native operation JSON canonicalizer |
| 55 | Exact raw-byte Graph issuer for native raw entry routing |
| 56–59 | New HIA edit main/query/service/apply controllers |
| 60 | Existing complete native Core patch, including result mode 2 |
| 61 | Complete single-query presentation renderer |
| 62–63 | Complete batch renderer control/emit |

Reuse native SHA stream role 22 for all payload hashes; do not add a 64th
nonzero image or change a SHA owner's 8 MiB chunk bound. The current queries,
responses and admitted Core each fit their original limits. Stream framing
and chunking remain HIA decisions, as in the complete program controller.

Image-role selection, validation stages, byte budgets, graph roots, pending
continuations, all semantic decisions and complete constant error text belong
to HIA. The executor performs only fixed allocation, complete copy, readonly
protection, actual image invocation, bounded observation, fixed child context
entry and release. It never parses a program/query field or chooses a schema.

## Program-admission child

Add RUN_CHILD mode 2 to a separate executor fork. Retain the existing 224-byte
ACK: 64 correlation bytes, the complete actual 128-byte child terminal, and
capacity/target/actualRole/reserved as four u64 values. Success makes one parent
readonly target contain exactly:

    [actual 256-byte HIAPRV01 receipt][actual canonical Core N bytes]

N is the actual child's terminal word 11 and must fit its real slot-45 extent.
The executor uses checked addition for 256 + N and does not introduce an 8 MiB
limit on that transport frame. The child receipt is its actual readonly slot 56,
not a reconstructed header. Copy both actual views before releasing the child;
protect the entire parent target before ACK. Refusal copies the original actual
terminal, creates no target and returns capacity zero.

The parent HIA checks lease/sequence, terminal receipt slot 56/length 256,
all receipt fields and complete Core extent, retaining separate input/Core SHA
values from the actual receipt. It must join a successful complete child and
the actual immutable views, not infer authority from a header alone.

Mode 2 still starts raw controller 44 and then routes to program controller 46.
The allowed context graph is finite:

    edit role 56..59, mode 2
      -> program role 46, mode 0
        -> ordinary roles 43 / 40..42 / 45

Do not simply remove the old no-grandparent check or enable arbitrary recursion.
The program child uses publication role 46; its ordinary grandchild uses 45.
Every impossible role, depth, mode, returned view or ACK permanently discards
the affected private contexts. The frozen standalone admission executable and
its complete evidence remain unchanged.

## Component service continuations

The main controller owns the original input snapshots and operation mode. Peer
controllers receive actual readonly views and fresh private workspaces. HIA
handles each inner GROW/NEXT and constructs the complete actual peer-reply frame
by copying the returned workspace. A projected event alone is not substituted
for its full backing bytes. Temporary workspaces cannot be reused until all
required views are copied into their owning scope.

The service controller must handle Graph wire scan/emit, Agent decode plus its
raw-decoder/arena peers, caller-bounded input, and single/batch renderers without
host callbacks. It pins issued commands and pending actual frames before either
success or error terminal branches. Source views stay readonly across nesting.
Its state and slot allocation are bounded; capabilities and nonces identify
actual held mappings and do not authenticate arbitrary external headers.

Query reconstruction uses the actual SourceLease bitmap issuer, facts, complete
slice, canonical operation hash, complete query packet, Graph bridge and wire.
Batch input shape and overlap order must remain identical to the completed
24-case composition. No later query/response stage may run after an earlier
refusal. A final receipt remains private until the exact complete candidate has
passed Core admission. Core dynamic diagnostic context/renderer is parallel work
and must be joined before claiming full public refusal-text compatibility.

## Validation and publication boundary

Retain the same original per-image compiler profile and resource gates. First
compare actual controller event sequences and complete buffers against the
completed composition, then execute the fixed native binary with empty PATH/HOME
and hosted policy disabled. Exercise actual child view/ACK mismatches, terminal
replay, incomplete copies, service GROW substitutions and late failures before
publication. Record original failures separately. A matching-source full cold,
complete retained zero-skip regression and ordinary installation/recovery remain
required before replacing defaults or removing any active legacy owner.
