# Real INIReader component: partial implementation migration and callback repair

This increment uses the real [`benhoyt/inih`](https://github.com/benhoyt/inih)
C++ `INIReader` component, with complete component source files and its BSD
license preserved. It does not substitute the repository's authored paired-buffer
examples for a historical third-party project.

## Source identity and changed upstream behavior

| Role | Immutable upstream commit |
| --- | --- |
| Previous component | `de720a6f4066587618edfba3960ea9ed4132c665` |
| Actual read-error correction | `2d5ec7b59abbb8e1797e48060965001aaac6996a` |

The second commit adds `-3` for stdio file-read failures in `ini_parse_file()`
and updates `INIReader::ParseErrorMessage()`. It changes the actual library
implementation and error contract. The qualifier observes a Linux directory
read return success under the old source and `-3` with the new source, through
both the original and migrated components.

The captured graph is `ini.c`, `ini.h`, `cpp/INIReader.cpp`, `cpp/INIReader.h`
and `LICENSE.txt`, for each revision. `UPSTREAM.json` records upstream Git blob
identities and lengths. The extractor pins that manifest's SHA-256, verifies
every blob, and records SHA-256 too. It uses those checked in-memory bytes for
generation. This is the complete source graph of this component, not a capture
of the entire upstream repository or every build configuration.

## What actually executes as Hepta

`hepta/inih_component.py` is a closed, source-specific extractor. It accepts only
the two pinned revisions and rejects an unknown member, unaccounted top-level
work, changed source, ambiguous predicate, or escaping callback logic. It is
not a general C++ parser or a claim that Clang accepted arbitrary new input.

All 18 member definitions, and the corresponding public/protected callable
inventory, have a disposition. Three decision-bearing bodies are partially
migrated:

| Actual upstream member | Executed Hepta portion | Explicit retained foreign portion |
| --- | --- | --- |
| `GetBoolean` | A generated finite byte recognizer for the exact source literals and default branch | Map lookup, `std::string`, the original locale-sensitive `tolower` transform, iteration |
| `ParseErrorMessage` | Source-derived error-code dispatch, including the real `-3` upgrade | String creation, decimal formatting, concatenation |
| `ValueHandler` | Name/value presence and newline/append decisions | Borrowed C character pointers, key normalization, `std::map` and string mutations |

The two constructors retain the real C parser calls and use the authored
callback lease adapter. The other 13 definitions and the class layout remain
C++. This is **partial implementation migration with an explicit foreign
boundary**, not an entire C++ component rewrite. The STL storage ownership has
not become native Hepta ownership merely because decisions run in Hepta.

The generated `.hepta` source is parsed and checked by the actual frontend,
then compiled through the existing independent C11/GCC backend into an object
linked with the original C parser and adapted C++ implementation. There is no
handwritten replacement C implementation of the five generated Hepta functions.
No Rust compiler, Clang importer, or direct LLVM qualification is claimed by
this route. The original C++ executable uses the unmodified pinned bodies as
the independent native comparator.

## Actual callback lifecycle contract

The native adapter registers a stack-owned lease before calling the parser.
The parser receives an opaque, process-unique integer token through its `void*`
user slot. The actual owner pointer stays in a fixed-size thread-local registry.
Before accessing the owner, the callback looks up the token and executes the
Hepta lease-state transition. It rejects stale, forged, wrong-thread, reentrant,
and duplicate-owner access. The same callback cannot acquire a second live
lease on its owner. A normal callback returns to the idle state; leaving the
parser scope closes the lease. No tombstone allocations or recycled token IDs
are used.

The registry permits 32 simultaneous parser leases per thread. A full registry
or exhausted token space refuses registration before parsing. The native
adapter, registry, pointer/integer ABI conversion and foreign parser remain
part of the trusted boundary. The qualified domain is Linux LP64, synchronous
callbacks on the registering thread. This does not establish general async
callbacks, process-wide memory safety, arbitrary cancellation, or a theorem
about hostile C code that can modify arbitrary memory.

## A real exceptional cleanup defect and an explicit repair

With upstream `INI_USE_STACK=0`, the C parser allocates a line buffer. If
`INIReader::ValueHandler` throws `std::bad_alloc` while inserting into its C++
map, ordinary C++ unwinding leaves the C parser before its explicit `ini_free`.
The native qualifier injects that actual allocation failure. Both original
upstream revisions retain one tracked C allocation, while their C++ map
allocations balance.

The adapted callback catches the exception, records `std::exception_ptr` in
its live lease, and returns callback failure to the parser. The registered
`INI_STOP_ON_FIRST_ERROR=1` configuration lets the C parser run its own cleanup.
The constructor then rethrows the original exception, and its lease closes.
The native measurements retain **one original C allocation versus zero in the
adapted route**, with `std::bad_alloc` observed by both clients.

This is an explicit resource-behavior repair. It is not called an identical
exceptional resource trace. The test allocator releases the original observed
leak only after printing the observation, so the harness can finish cleanly;
that test cleanup is never credited to the original library.

## Reproduce and evaluate

```sh
python -m unittest discover -s tests -p 'test_cpp_inih_component.py' -v
python tools/qualify_cpp_inih_component.py \
  --output-directory /new/absolute/evidence-directory --cc gcc --cxx g++
```

The qualifier requires actual compiler and executable success. Missing tools
are failures, not passing skips. It retains commands, raw stdout/stderr, the
checked generated Hepta/C/C++ inputs, source identities, and binary hashes.
Within each revision it requires byte-identical original/migrated observations
for normal component traces, error messages, 10,780 Boolean results, five real
callback branch cases, 64 complete owner lifetimes, allocation refusal, and
file/open failure. Input buffers are overwritten while the reader remains
live to check that retained state comes from its own copied storage.

The separate callback negative controls check 11 lifecycle/authority conditions
and all 36 pairs of the tested state/event domain, including out-of-domain
inputs. A deliberately wrong Hepta Boolean rule is frontend-accepted, compiled,
linked, and executed; the same original native reference must reject its
results. A compiler failure cannot satisfy that negative control.

An executed result is recorded under `evidence/hia_cpp_inih_20261030` after
qualification. Its invocation-specific source hashes and raw outputs are the
evidence, not this documentation's description of the runner. Test counts from
overlapping executions must not be added as independent observations.

Remaining work is explicit: generalize structural C++ import beyond these pins;
translate foreign map/string ownership; validate changed data layouts and more
asynchronous resource patterns; record actual human contract/review/maintenance
time; and establish whole-program safety, backend refinement, and performance
at a separately registered scope. This increment closes none of those broader
claims by implication.
