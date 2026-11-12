# HIA wire 04: facts for already admitted immutable keys

Status: static source candidate. No HIA generation, Core-VM test, native
compilation, timing, installed run or wire89 qualification has run on this
candidate. The prior CI failures at 6.503077664999637 s and
5.675053439999829 s remain failures of the unchanged 5 s assertion. The
local 3.12.14 diagnostic at 4.124192650 s is development evidence only.

## Protocol and entry selection

| Wire magic | Initial bytes | Capability | Behavior in this revision |
| --- | ---: | --- | --- |
| HIAWIR01 | Any | None | Rejected with 199 before a foreign observation, as in the baseline. |
| HIAWIR02 | 104 | Original protocol | Every original SUMMARY/CHILD/POINTS/LIMBS/digit-limit/renderer observation remains. |
| HIAWIR03 | 112 | Last word exactly 1; existing fresh stable builtin observer capability; no renderer | Existing short-key UTF-8 cache. Every original SUMMARY remains. Direct `_builtin_keys=True` still chooses this protocol. |
| HIAWIR04 | 112 | All 03 prerequisites plus the explicit private `_builtin_key_summaries is True` request | Same text cache and memory extent; HIA may reuse four facts of an already admitted exact-string **key** within this one session. |

The public low-level `encode` and `encode_observed` remain 02. The ordinary
selected entry creates a fresh `ForeignGraphObserver`, registers the original
root, and requests 04. The existing capability predicate can refuse that
request: custom/subclass observers, method/code/field replacement, an altered
digit-limit binding, and explicit renderers all remain on 02. The selected
binary64-renderer profile also remains on 02 because it has a renderer.
Source/manifest/image admission is completely unchanged.

The shared selector remains `HEPTA_HIA_JSON_WIRE_MANIFEST`; the manifest schema
is unchanged. This is a **wire protocol** revision, not a new selector or a
claim that an old 5eba image implements 04. That historical image must never
be substituted for a newly compiled candidate image in a 04 execution.

## Permission to omit one SUMMARY

All conditions must hold at the original key-summary request point:

1. The current workspace magic is 04. Legacy versions call the original `ask`
   with the same arguments and do not modify even the newly assigned header
   slots.
2. The current session's existing `CACHE_BASE` is nonzero and the handle is
   nonzero. The fixed `(handle & 1023)` slot contains that exact handle.
3. The entry's size is at most 32 codepoints, its stored UTF-8 length is at most
   128 bytes, and its preflight escaped width is between 2 and this session's
   original maximum. A missing, colliding, long or malformed entry falls back
   to the original request. There is no new input-size refusal on a miss.
4. The only writer of such an entry is the unchanged `key_cache_save`. It is
   reached from normalization phase 30 only after `remaining == 0`, with
   `T_MODE == 1`, size at most 32 and a nonzero cache base. `T_MODE == 1` comes
   from normalization of kind 4, role 0. The baseline exact observer returns
   kind 4 only for `type(value) is str`; that string's original key preflight
   has already validated every codepoint and the existing byte bound before
   this cache entry is committed. The handle is published after its bytes and
   metadata; occupied slots are never replaced.
5. The removed request is at one of these five exact sites: preflight key
   (next phase 12), a collision comparison with a previous key (15), sorted
   record preparation (114), or sorted/unsorted key emission (143). No value,
   container, iterator, child or numeric observation is cached.

A hit provides exactly `(STRING, codepoint_length, 0, 0)`. It changes only
the new cached-fact header fields and the next phase; it does not fabricate a
foreign acknowledgement, increment the external sequence, or consume the
previous packet as a SUMMARY. The original key normalization, equality,
collision, sorting, escaping and emission still run in HIA.

New header words are `ready=680`, `size=688`, `hits=696`, `misses=704`. They
occupy unused fixed-header bytes below `ACTIVE_BASE=1024`. Both 03 and 04 use
the original 1024 × 160-byte cache. No output or workspace budget increases.

## Observation lifetime and exclusions

The cache is in the existing fresh anonymous zeroed workspace. Each ordinary
call constructs a different observer and workspace. There is no global cache,
no reuse across operations, no read of a later value at an earlier time and
no registration pass. Every first uncached key summary still occurs at the
original request point. An exact key reused as a **value** still receives its
original value SUMMARY at phase 2 or 101.

This retains the existing capability's scope: no asynchronous mutation of
interpreter transport definitions during a synchronous session. It does not
extend that claim to arbitrary external mutation of private observer tables,
manual workspace fabrication or foreign user hooks. No such domain is used
to justify skipping a foreign observation.

## Independent checks and retained denominators

`check_static_delta.py` reads original and candidate source as bytes/AST only.
It does not import either generator. It proves the original `ask`,
`norm_begin`, `text_begin`, `key_cache_save/restore`, normalization, sorting,
numeric and authoring pipeline bodies are unchanged. It reverses only the
five documented requests and their fact consumers, then requires complete
original preflight/encode AST equality. It separately checks the entire
original observer/capability and step/observe/run bodies by raw source.

The new runtime trace oracle is independently expressed in the test file. It
compares protocol 03 with 04 retaining opcode, handle, index, count, part and
next phase. Sequence numbers must each be contiguous. Every deletion must
be a key SUMMARY for a handle already summarized, present in the actual final
cache, whose actual retained object is an exact str of at most 32 codepoints.
All other requests must remain in the same order. The number of deletions
must equal the actual HIA cache-hit counter. Original outcome and cache-text
statistics must agree. A same-object key/value fixture explicitly preserves
every value summary.

The original seven `WireCacheNativeTests` IDs are retained. Only
`test_ordinary_entry_selects_cache_without_retained_encoder` changes its
strict expected protocol from 03 to 04; the old
`test_repeated_immutable_keys_reduce_only_codepoint_observations` still runs
03 and still requires every non-POINTS request to match 02. All other six
method bodies and the remaining body of the changed method remain byte
identical. This is an explicit contract update, not a claim that all seven
method ASTs are unchanged.

The original wire89 method IDs, 256-case workload, 5 s assertion, original
source controls and original native components are not changed or replaced.
New controls have separate exact denominators: six source/Core-VM methods,
then six native methods. The first planned execution is only the source six
under one original 180 s qualification / 3 s cleanup owner, with native image
loading, compiler execution and subprocess entry poisoned. Native6, old7,
the full original wire components, full wire89, matching-cold and installation
remain later execution requirements. No historical result satisfies them.

## Remaining risks

The new HIA source is not generated yet. It must pass the original
1 MiB source / 16384 lines / 128 functions / 1536 blocks / 8192 operations /
256 blocks per function / 2048 SSA names / 16 arguments and edge arguments /
3 results limits without any increase. Native compilation must retain the
original 20 wall / 10 CPU / 1 MiB limits. The finite request savings are not a
measured speedup, and may be insufficient to satisfy the original CI 5 s
assertion. Ordinary Python object transport and the broader hosted runtime
remain explicit dependencies.
