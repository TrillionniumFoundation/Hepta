# Operator-selected complete source syntax in HIA

`HEPTA_HIA_SOURCE_DECLARATIONS_MANIFEST` selects the native application generated
from `examples/hia_bootstrap/source_declarations.hiaasm`. The default reference
parser and production/release selection remain unchanged. This is bounded
syntax recognition, not whole-toolchain completion or a hostile-code sandbox.

The application implements the existing complete source grammar: optional
module and imports/aliases; structs, repr(C), enums and function declarations;
generic parameters and lifetimes; parameter/return borrowing, contextual from;
extern/export ABI literals; effects and resources; and all existing blocks,
statements, expressions and types. It composes the actual HIA implementations,
not a bridge to foreign syntax helpers. Duplicate effects/resources and the
existing last-bound-wins struct constraint behavior are preserved.

## Data and execution boundary

Input is at most 8 MiB; the arena has at most 1,048,576 nodes. The 96-level
existing parser budget and standalone maximum 128 are unchanged. The inherited
statement frames remain 512 × 128 bytes at offset 25152. Declaration scratch and
scanner snapshots extend the fixed application workspace from 90688 to 92416
bytes; the generic-split trace adds ceil(input_bytes/8). These are separate
application-specific buffers, not raised compiler or qualification limits.

A count/validation pass completes before any ordinary output is published.
Failure leaves the output untouched. Separately marked diagnostic-only replay
retains qualified-name observations preceding a syntax error. The bridge
validates the entire ownership graph and payload before materializing AST
objects, including externally declared zero-width body spans. The new explicit
empty-program arena profile does not relax expression/statement profiles.

## Remaining foreign authority

The authoring generator, cold seed, filesystem/build/image custody and selection
remain host code. Token/AST/Span/Diagnostic object materialization, literal-value
bridging, graph/cursor validation, qualified namespace and AST-depth guards,
type/effect/ownership checking, modules/packages, runtime/agent/I/O, optimization,
proof tooling and full clean-machine release are not replaced by this change.
Native parsing of imports is not native module resolution.

`tools/build_hia_source_declarations.py` requires the completed matching cold
compiler's original eleven checks and all three generation hashes. Development
or differential results alone are not cold qualification or all-input proof.
