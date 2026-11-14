# Native Store artifact and profile owner

`store_artifact_profile.hepta` owns all eight original `AgentStore` methods:
`put`, `json`, `_ref`, `get`, `get_json`, `resolve_uri`, `profile`, and
`check_profile`. The 87 original lines are retained verbatim as independent
fixtures from product `73f16346e7f84fa13305777a4595e2d1b422dee9`. Their source
also matches the implementation base `727edb47cd98a41c0fcc4c494cf85422aa879937`.
The separate 11-line `transaction` context manager is unchanged.

## Ownership and interoperation

HIA controls the original short circuits, ordered three-key reference loop,
native-file/fallback choice, profile and artifact authority checks, publication
order, and cleanup obligations. Python carries opaque objects and performs the
existing filesystem, SQLite, JSON, hash, UUID, and native-artifact provider calls.
Those providers are explicit interoperation boundaries, not newly native code.

Ordinary instance, subclass and descriptor replacements retain their real call
expressions. Canonical nested calls enter selected public Store bridges and
create actual native child frames. Literal method calls bind the callable before
HIA argument subcontinuations evaluate wire/decode/row operations. Argument
values remain ordinary opaque Python values, with no fixed-width object domain.
No retained complete method is used as a selected foreign effect.

The native cleanup state records obligations after successful temporary open,
stream entry and directory open. Claiming exit, close or unlink consumes the
obligation before executing it. The driver remains inside the original active
exception while HIA requests cleanup, so replacement errors retain their
context. A suppressed stream error or handled link collision leaves that handler
before the next normal effect. A lost native acknowledgement fences the frame
and active same-owner ancestors without retrying effects. This owner alone does
not establish cross-owner causal-loss closure.

## Original domain

The exact `bytes` check and inclusive 67,108,864-byte limit are unchanged. The
initial guard retains its original global reads, including
`MAX_ARTIFACT_BYTES`, and its opaque Python comparison without narrowing values
to a machine integer. HIA selects the original rejection or continuation.
The existing JSON provider's separate 8 MiB limit is not a new artifact limit. Native
`put` uses one admitted artifact executable for its hash and durable write;
native `get` falls back only for an exact `None` result. The original production
artifact process has no new wall timeout. Existing tests' 60-second subprocess
deadlines remain test limits.

`INSERT OR IGNORE` still returns the separately queried winning row. No new
transaction, directory rollback, content repair, file retry, broad serialization
lock, metadata quota, or frame-count limit is introduced.

## Selection and custody

`HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST` selects the image. An absent selector
retains the portable original route; an empty, invalid, changed, or out-of-bundle
selection refuses. Source, image, compiler receipt and all owner inputs are
bound by `tools/build_hia_store_artifact_profile.py`. A strict build requires
the current matching cold report; `--development` is labelled separately.
The image and source are packaged through the existing installed-resource list.

## Evidence scope

The independent fixture has 463 fixed cases covering original branch/effect
order, dynamic calls, exact unpack behavior, first faults, cleanup replacement,
and outer exception restoration. The original observer was frozen on Python
3.12, 3.13 and 3.14 before a candidate existed. Interpreter-specific with lookup
and unpack diagnostics are preserved, not normalized. Separately, 160 original
literal-call inputs were compared in cold and warm interpreter profiles before
choosing synchronous argument callbacks. Those finite observations do not prove
all Python inputs or all interpreter execution histories.

A separate 41-case original fixture binds the initial guard's actual global
lookup order, zero and negative limits, large integers, opaque comparison and
truth failures, and outer exception state. It leaves the earlier 463 and 160
inputs unchanged. These controls stop at the next original admission effect;
they do not replace the complete publication and cleanup observations.

The caller inventory distinguishes complete ordinary modules, original explicit
administrator bundles, and static marker candidates. It does not claim every
listed test enters this owner. Separate bundles are not silently supplemented
with a new selector. Qualification must retain original test bodies and budgets,
record real selected image entries, compare independent VM buffers, poison old
policies in the actual installed child, and preserve raw execution logs.

This support declaration is not an execution receipt. It does not establish
matching-cold qualification, whole-project dynamic caller closure, removal of
the portable reference, or complete native delivery.
