# Live native dictionary iteration

This role implements actual dictionary iterator objects in the existing HIA
value arena. It is part of the new eight-role native value image. The shared
owner invokes the role at fixed dispatch index 8; no callback or caller-supplied
sequence decides which item is next.

## Execution status

The development author and original language verifier have run with the shared
value extension. The generated source contains 36 functions, 318 blocks and
1,405 operations, within the unchanged source-builder limits. The development
transition harness compared 3,120 calls to the running CPython dictionary in
172 cases. That run used CPython 3.12.14 and is explicitly not native execution
or the pinned CPython 3.14.4 qualification.

The same qualifier has an actual image mode. Source compilation with the pinned
494833 HIA builder, execution of the complete eight-role image, original 3.14.4
comparisons, actual kernel allocation failures, concurrent callers, private
frame guards and final consumer integration remain required. No whole-runtime
or production-installation claim follows from the development result.

## Owned object

The exact value kind is 9. It owns a 64-byte data allocation and one real graph
edge to its dictionary. Ordinary retain/drop and cycle collection use the same
capability registry as other values. The object's public scalar byte length is
zero; the internal allocation size is not exposed as a string length.

| Data offset | Meaning |
| --- | --- |
| 0 | Actual dictionary object, or zero after exhaustion |
| 8 | Original dictionary size |
| 16 | Current physical entry position |
| 24 | Number of expected remaining yields |
| 32 | Mode: 0 keys, 1 items, 2 values |
| 40 | State: 0 active, 1 sticky size error, 2 exhausted |
| 48, 56 | Zero |

The iterator is an identity object. A retained reference to the same iterator
works as the same dictionary key. A different iterator has distinct equality
even if its source dictionary and positions match. Type inspection reports
kind 9; scalar copying and length operations reject it. Its graph edge retains
the dictionary until exhaustion or destruction, including a sticky size error.
The edge is released on the actual terminal transition. Unreachable cycles
containing dictionaries and iterators are handled by the shared collector.

## Fixed value request operations

Both operations use the existing 128-byte value request and the new HIABVQ02
request domain. HIABVQ01 does not acquire these operations. Ordinary HIABVR01
replies remain in use for these two operations; the separate cleanup operations
29 through 31 use their explicitly versioned consumption reply.

Operation 27 creates an iterator. Capability A at 24/32/40 must resolve to an
actual exact dictionary. Argument 0 at 104 selects keys/items/values. All other
capabilities, argument 1, tail and reserved words are zero. Success transfers
one independently owned kind-9 capability at reply 24/32/40.

Operation 28 advances capability A, which must be an actual iterator. All other
request fields are zero. Successful reply field 64 is zero at exhaustion or one
for an item. Field 72 gives the required extent 8256 when an item exists. One
64-byte row begins at 8192:

| Row offset | Meaning |
| --- | --- |
| 0 | Actual physical dictionary entry position |
| 8 | Key kind for keys mode; value kind for items/values mode |
| 16, 24, 32 | Fresh owned key capability; zero in values mode |
| 40, 48, 56 | Fresh owned value capability; zero in keys mode |

The caller owns every published result capability independently. Results remain
valid after the iterator and original dictionary references are dropped. The
owner does not return borrowed arena addresses as value capabilities.

## Current-entry semantics

Next runs under the actual value-context mutex and reads the current dictionary
entry. It observes replacement values made after a previous next call. It does
not freeze a vector of values when the iterator is created.

If the live dictionary size differs from the original size, next returns status
14 and records a sticky size error. Restoring the original size does not reset
that iterator. A complete scan with no entry exhausts the iterator. If an entry
exists after the expected number of yields reaches zero, status 15 reports the
keys-change error and exhausts it. Later calls to an exhausted iterator return
success with zero rows. The original messages are respectively `dictionary
changed size during iteration` and `dictionary keys changed during iteration`.

Deleting and inserting keys while restoring the size does not automatically
raise an error. The iterator follows the current physical entry table. The
shared dictionary preserves tombstones through deletion, and compacts at the
actual insertion resize or Unicode-to-general conversion. It uses the original
usable fraction and pre-insertion live-size growth rule. Conversion precedes
lookup for a non-exact-string insertion, even when it overwrites an equal key.
The iterator position is not adjusted after compaction.

All required key/value references are allocated unpublished first. Any failed
allocation rolls them back before retry or failure. Only after all references
publish does next advance its position and remaining count. An output shorter
than 8256 returns status 13 before allocating or advancing. Partial getrandom
and EINTR continuations preserve the same operation; allocation growth never
replays an already published item.

## Consumer and build requirements

The background bridge constructor must interleave a next call with that item's
actual path coercion and filesystem resolution. A first path method can mutate
the second value; the next call must observe the changed value. The parent
retains the iterator, source dictionary, actual value context and executable
closure until all calls and cleanup finish.

Production construction compiles result_value_dict_iterator.hepta and uses
result_value_native_packer.hepta. The Python author and qualifier are development
tools. The old seven-role packer and its request bytes remain unchanged.

The development qualifier executes the exact author functions and compares
against CPython, rather than copying dictionary mutation rules into an oracle.
Its allocation controls are author-level injected refusals. They are useful for
checking rollback and continuation state, and do not substitute for actual
native mmap/mremap/getrandom fault qualification.
