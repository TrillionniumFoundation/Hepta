# Experimental owner-bound single lexing

Status: isolated profile stacked on #625 at
`5158ab3e2f613b44efd196c1709fd8dccc2cc3da`. No production caller/default selects
this profile. This is finite token provenance and admission evidence, not a
complete bounded loader, sandbox, native qualification, merge or deployment.

## Shared normal algorithms, legacy behavior retained

The production Lexer token loop occurs once in its new private `_tokenize(result)`
collection seam. Public `Lexer.tokenize()` passes a normal list and keeps its
signature/result. Production Parser initialization after tokenization occurs once
in `_initialize_tokens(tokens)`. Public Parser still sets source and path before
resolving/calling its original namespace `tokenize(source, path)`, and initializes
position/depth/qualified expressions afterward. The parsing algorithm is unchanged.

The normal loader retains the original `for token in ops.tokenize(...)` expression
without holding its iterable in a new local. After scanning it obtains an optional
owner-local receipt through `scan_receipt()` and passes it to `ops.parse_admitted`.
The legacy receipt method is a no-op returning None, with no callback or retained
iterable, preserving custom iterable/iterator finalizer hook timing. The new owner
already owns its registered batch; taking the receipt clears its last-scan slot.
Legacy operations ignore the receipt and delegate to the
existing `parse` seam with its original arguments, preserving the second lex and
namespace hooks. Prior read/graph profiles also retain two separately admitted
passes. No new public token parameter, global pending-token cache, source rewriting,
production experiment import, or copied lexer/parser algorithm is introduced.
As with prior private extractions, internal stack frames/lifetimes are not an
arbitrary reflection compatibility promise.

The new experimental owner uses a subclass over the shared lexer loop, with
quota-admitted appends and existing checkpoint cadence. Its parser subclass calls
the shared initializer with a private token collection and uses the production
parse algorithm. It retains checkpoint/nesting admission but does not invoke a
second lexer. A source module consumes one lexical token budget and one parse
attempt. Parser splitting of `>>` / `>=` into type-close tokens is preserved and
operates on the private list; these synthesized tokens are not another lexing
pass or newly counted lexical input tokens. No complete AST/allocation bound is
claimed.

## Provenance and one-use authority

Each issued exact-type batch is registered by object identity in its issuing
operations instance with exact source text, exact path string, original token
tuple identity, and a strict immutable-field fingerprint. Only exact strings,
Token/Span classes and expected primitive fields are admitted. Values carry an
exact type tag; floats use `float.hex()` so signed zero cannot compare equal after
mutation. User-defined equality/iteration on forged objects is never authority.
Source identity means exact text content and path, not Python string object
identity, filesystem atomicity or a fresh disk hash.

Before parsing, the pre-parse admission/checkpoint callbacks run, then source/path, batch
identity, tuple identity and fingerprint are checked. The registry entry is
consumed before parser callbacks. Replay, forged lookalikes and cross-owner batches
are refused. The parser receives newly reconstructed Token/Span objects in its
own list. Later mutation of exposed batch objects is inert with respect to parser
input, rather than being detected continuously. Mutations observed before
consumption are refused, including reflective changes to frozen token/span fields.

The public experimental operation remains owner.load; issuing/consuming batches
through private ops is a test surface, not an untrusted serialization API.
Arbitrary mutation of private registries, function bytecode or the Python runtime
is excluded. Pending batches are cleared on issuance/consumption failure and outer
load/revalidation failure, including reserved-name scan failure between lex and
parse. Counters and terminal context state are never reset by this cleanup.

## Hooks, cancellation and retained boundaries

In addition to the existing finite owner hook allowlist, the profile checks
Lexer/Parser class identities, token/span constructor aliases in both namespaces,
parser.tokenize, the new shared entry seams, and selected advance/parse entry
methods after each checkpoint. Replacements fail before invocation. This does
not cover arbitrary inherited grammar/AST methods, private tables, concurrent
runtime mutation between checkpoints, or corrupt canonical functions before
trusted bootstrap. Legacy hooks still run with their old arguments.

Independent review found a shared owner lifecycle hole: a checkpoint could catch
a nested reentrancy rejection and let the outer final check return despite a
closed context. The shared read-owner Context now checks terminal state again
after the callback. Tests cover final-checkpoint swallowed failures in all three
prior/new owner profiles and during single-lex parse. Cancellation/reentrancy
cannot consume a batch and later return a successful result from a closed owner.

Graph/path/read quotas, private disk-revalidation authority and role provenance
remain as documented by the earlier profiles. All non-None source overrides are
still refused. Public graph.unchanged remains legacy, not owner authority. Owner
revalidation retains the original lock semantics: it does not reread Hepta.lock.
Single lexing does not turn a disk lock into overlay or native qualification.

## Validation and remaining limits

44 new controls cover single-vs-double lexical counts, shared source parity,
source/path binding, replay/forgery/cross-owner refusal, token/span/type/signed-zero
mutation, cancellation/reentrancy, private snapshot behavior, parser token
splitting, finite hook swaps, quotas, lock/override semantics, terminal cleanup
and all 80 example outcomes (68 matching graphs, 12 matching diagnostics; not 80
compilation successes). The prior 191 focused controls remain in the aggregate:
235 unique no-skip controls. Hosted exact-head Python 3.11/3.12 on Ubuntu 24.04
adds prior consumer regressions for 367 unique no-skip tests with Rust 1.90/GCC.

Run `python -m experiments.owned_tokens.gate --include-consumers`.

A separate reproducible direct normal-Lexer/Parser differential compares all
80 examples plus 19 synthetic lexical/parser cases, including full tokens, AST
data and diagnostics. It launches independent isolated Python subprocesses,
each importing only its selected checkout; no historical algorithm is bundled.
Run `python experiments/owned_tokens/compare_checkouts.py --baseline /path/to/625 --candidate .`.
The hosted workflow checks out exact #625 into `.token-baseline`, verifies both
baseline and candidate commit identities, runs this 99-case differential, then
runs the 367-control aggregate. Corpus discovery is confined to each checkout's
explicit examples directory, not the nested baseline or the whole repository.
Local Rust is absent; local focused results do not claim the hosted aggregate.
Source pins/inventory were refreshed after independent review of the shared
production seams and compatibility controls.
Compiler identity changes; old qualified artifacts cannot be relabelled.

Per-token snapshots and retained graph authority still allocate memory. Metadata,
AST assembly, digest/serialization, resolver internals, large configured recursion
limits and native processing remain outside a complete bound. No hard heap,
CPU/wall-clock or all-platform guarantee follows from this finite gate.
