# Native ELF64 object inventory and direct-backend ABI gate

## Status and ownership

This is a new source-only component. No new AST, generation, B3, VM or native
result is claimed in this document. The independent CI is designed to build
two real HIA images and run the cases below. A completed earlier ELF-writer or
Emitter suite is not inherited by this combination.

The production semantic owner is tools/hia_elf_object_inventory.py. It
implements the exact ELF64, machine 62 branch of the original object inspection
used by hia_program_native._inspect_object. This is one pure value leaf in the
general direct native backend. It does not replace admission, machine-plan
validation, foreign export normalization, the Emitter, implementation-identity
checks, file ownership, shared linking, publication or installed dispatch.

Exact original references:

- hepta/object_structure.py, Git 5231ee37ef4ca65a3175a1162178ea21b9503082,
  SHA256 4fb0b3d962e4b7f6ba508257bf605f4403d402e4f3d7e05cffa084b91651f5a8.
- hepta/object_symbols.py, Git 9476bc3346cdc5e778a145f50c46c30190112780,
  SHA256 aff81d724d08ed4a8c3189e3370f75e234daa010ec9e9855aedc1019d55a693f.
- hepta/hia_program_native.py, Git 1d0e0344f8300b11b5dd505cbea655170aba5be1,
  SHA256 bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c.
- hepta/hia_machine_elf.py, Git cad2e6d21dccc95ad3cfd368da42964ec52d4bb7,
  SHA256 c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101.

The AVL routines are copied at authoring time from the exact native ELF writer
3f92d9e185f17f6df8b45d91a4201ce968723073. Every copied routine appears in the
expanded HIA authoring and canonical HIA assembly retained by the build.
There is no Python dictionary, symbol sort or inventory decision at runtime.

## Pure entry and source custody

The entry is R/R/W: first buffer is the complete actual object, second buffer
is the command and exact expected-export bytes, third buffer is private work.
The public HIA f0 signature is R/W/W solely to permit the existing entry ABI;
it immediately borrows the second argument read-only. Both input mappings
must be protected read-only for the complete call. This is a synchronous
inspection of actual privately issued bytes, not an arbitrary foreign frame
authentication scheme.

The caller owns the object and expected-export leases. Lease IDs in the
header are correlation fields, not authentication. The expected export vector
must come from the original sorted-export computation on the actual Emitter
state, or an equivalent native issuer that has preserved the same values.
The inspector does not manufacture authority from an object digest or a
caller-provided name vector. Tests intentionally supply foreign private
fixtures and explicitly do not elevate them into a public producer proof.

Both inputs remain immutable through every GROW retry. The work buffer has
no persistent identity: each call zeros its private header and recomputes
from the two current inputs. A new independent invocation can intentionally
use different inputs. There is no pending-operation registry or persistent
poison promise. The fixed surrounding runtime must retain the correct input
leases during a retry. An identical command header does not establish that
two object payloads were identical.

On GROW the returned output view is empty. The caller supplies at least the
reported number of work bytes and re-enters with the same inputs. No object
symbol, result or external state is committed. Registry capacity grows
geometrically, then publication measures the complete inventory JSON and
reports its exact extent. A finite development retry watchdog is not a new
public object quota.

## Command: HIAMIC01

All words are unsigned 64-bit little endian. The first 128 bytes are:

| Word | Meaning |
| --- | --- |
| 0 | HIAMIC01 |
| 1 | Version 1 |
| 2 | Nonzero actual object lease |
| 3 | Nonzero logical request |
| 4 | Nonzero actual expected-export lease |
| 5 | Exact first-buffer byte length |
| 6 | Expected-name row count |
| 7 | Row array offset, exactly 128 |
| 8 | Scalar start, exactly 128 + 16 * count |
| 9 | Complete scalar byte length |
| 10 | Complete second-buffer length |
| 11–15 | Zero |

Each expected-name row is two words: absolute offset in the second buffer and
byte length. Every row is validated to fall completely inside the scalar
pool, including valid empty spans. Overlap and duplicate names are allowed;
the original frozenset comparison ignores duplicate expected names.
The bytes encode the original exact str value as UTF-8 with surrogatepass.
The object side accepts ASCII only, so bytewise name comparison preserves
equality and inequality for this domain, including unexpected Unicode and
lone-surrogate expected names. This component does not accept arbitrary
Python subclasses or claim to implement generic Python object capture.

The header, scalar base and every row are checked before object semantics.
Incorrect private transport produces BAD; malformed object bytes in a valid
private command produce the original semantic exception class and text.

## Event: HIAMIE01

The event occupies work[0:128]:

| Word | Meaning |
| --- | --- |
| 0 | HIAMIE01 |
| 1 | Version 1 |
| 2 | Action: 0 success, 1 GROW, 2 semantic rejection, 3 BAD |
| 3 | Actual object lease from the accepted command |
| 4 | Logical request |
| 5 | Actual expected-export lease |
| 6 | Domain: 0 none, 1 ObjectSymbolsRejected, 2 HIAProgramNativeRejected |
| 7 | Semantic error ID, otherwise zero |
| 8 | Required workspace bytes |
| 9 | Result offset in this work buffer |
| 10 | Complete result byte length |
| 11 | Defined-name count observed |
| 12 | Undefined-name count observed |
| 13 | Unique registry-node count |
| 14 | Inspection phase |
| 15 | Private ABI reason, otherwise zero |

Return values are 128 for success or ordinary semantic rejection,
0xfffffffe for GROW and 0xfffffffd for BAD. Work capacity below 4096 returns
BAD without writing any bytes. Semantic errors publish complete immutable
ASCII text in the same work buffer. Success publishes the complete compact
JSON object with keys defined and undefined and sorted name arrays. Its
private wire contract is json.dumps(..., sort_keys=True,
separators=(",", ":"), ensure_ascii=False). All ASCII control characters,
quotes and backslashes are escaped; ASCII DEL follows that exact wire policy.

Views remain valid only while the actual work mapping is held unchanged.
Consumers must copy or synchronously borrow them before another call.
The event does not grant a permanent handle.

Phases are 1 structure, 2 complete symbol scan, 3 closed ABI, 4 output
measurement and 5 completed publication. Partial diagnostic counts are
observations, not successful symbol inventory.

## Semantic order

The implementation first runs the complete qualified-object structure pass.
Only ELF64 little endian, ET_REL, x86-64 and the original section-table shape
are admitted. The original code does not inspect EI_VERSION, e_version or
the section-name-table index; this owner does not add those checks.

Every section is checked before any symbol. A NULL section is allowed only
at index zero with zero size. Its irrelevant offset remains ignored.
SHT_NOBITS has no file byte extent and remains exempt. A zero-size ordinary
section has no enforced payload offset. Nonzero ordinary extents retain the
original 64-byte lower bound and complete file bound. No extra overlap,
relocation or load-policy check is introduced here.

All SHT_SYMTAB sections are processed in original section order. The link,
24-byte entry size and exact multiple are checked before the linked
string-section kind and extent. All symbols then retain original entry order:

1. A zero name offset skips the entry before binding validation.
2. Only binding LOCAL/GLOBAL/WEAK has original semantics. Unknown bindings
   reject. LOCAL skips all subsequent name and definition checks.
3. Nonlocal names validate offset, then find the terminating NUL, then check
   ASCII. A non-ASCII unterminated string reports unterminated first.
4. Empty names skip the later undefined/defined policy.
5. Undefined nonempty names detect prior export conflict; duplicate imports
   remain allowed, including weak imports.
6. A defined nonempty symbol must have function kind. A weak function rejects
   before its section is inspected. Section index and actual executable
   PROGBITS coverage precede duplicate-name conflict.
7. Other defined nonempty global kinds reject.

After every symbol table completes, absence of a symbol table precedes
absence of exports. Only then does the direct-backend gate compare the
defined set with the expected set and require the undefined set to be a
subset of abort, calloc, malloc, free, memset, memcpy and memmove.

No 65,536 symbol quota is added to this inspector. That is a separate
original writer limit. No 128 export quota or 64 MiB input limit is added
here either. The actual outer emit_program_machine applies its object
byte check before calling _inspect_object. Independent tests beyond those
outer bounds check this leaf's original behavior and do not qualify such
objects for public construction.

## Error IDs

The full error text is authoritative; IDs are the private compact transport.

| ID | Domain | Complete text |
| --- | --- | --- |
| 1 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_SHAPE: unqualified object structure |
| 2 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_TABLE: invalid ELF symbol inventory |
| 3 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_TABLE: ELF symbol strings missing |
| 4 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_TABLE: ELF names outside file |
| 5 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_EXPORT_KIND: unreviewed ELF symbol binding |
| 6 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_NAME: bad ELF name |
| 7 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_NAME: unterminated name |
| 8 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_NAME: non-ASCII symbol |
| 9 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_DUPLICATE: export also imported |
| 10 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_WEAK: checked C function export cannot be interposed |
| 11 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_LOCATION: invalid ELF function section |
| 12 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_LOCATION: ELF function outside executable section |
| 13 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_DUPLICATE: ELF function identity reused |
| 14 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_EXPORT_KIND: unexpected defined ELF global |
| 15 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_TABLE: no ELF symbol table |
| 16 | ObjectSymbolsRejected | E_OBJECT_SYMBOL_EXPORT: no defined function exports |
| 17 | HIAProgramNativeRejected | E_HIA_PROGRAM_NATIVE: object import/export inventory differs from the closed ABI |

The original generic _name bad-name-offset branch cannot be reached after
this ELF branch's successful positive name_off, names_size and string extent
checks. No reachable error is removed. COFF and Mach-O have independent
additional errors and are outside this exact direct Linux backend leaf.

## Fresh validation plan

The independent gate has 20 separately bounded groups and 579 planned
cases, including 27 malformed-private-command cases and eight actual HIA
ELF-producer-to-inspector joins. These counts are a plan until the exact
CI run reports them. Each successful case compares the complete inventory
wire or the complete original exception class and message.

The test oracle loads the complete original structure/symbol modules and
the unchanged original _inspect_object, _reject, exception class and IMPORTS
assignment AST nodes. Their full original source bytes are retained.
The oracle runs only before native execution; the original object inspector
and writer are replaced by failing sentinels throughout actual native calls.
No Python semantic fallback can satisfy a native result.

Coverage includes all header truncations through 64 bytes, 4,096 sections,
complete section-versus-symbol error priority, every binding and defined
kind, all nonzero ASCII bytes and all non-ASCII bytes, empty/local/zero-offset
skips, weak and duplicate ordering, multiple tables, all seven imports and
unexpected exports, geometric GROW, 65,537 duplicate and unique imports,
one-MiB names, 1,024 private expected exports and exactly 64 MiB / 64 MiB+1
opaque padded input. The latter scope tests this pure inspector only.

The eight producer joins feed complete actual native ELF output opaquely
into the inspector. Fixture machine bytes and symbol records are input test
data. The actual object is written by the existing native ELF owner; Python's
original writer is an independent reference. These are not eleven-image
Emitter joins and are explicitly not claimed as such.

All three logical buffers are read completely before and after every native
entry. Full-page CAS retains exact bytes, reconstructed delta descriptors,
actual returns/events, hardware read-only inputs, guard pages and canaries.
The CI independently reads every page and snapshot, all result payloads,
actual image/source bytes and before/after source modes. No valid interval
is omitted. The new seal uses a streaming tar and complete JSONL member
ledger; it does not accumulate unbounded TarInfo objects.

Two B3 builds are fresh. Each retains 10 CPU seconds / 20 wall seconds /
256 MiB. Every generation and test group retains 90 CPU seconds / 180 wall
seconds / 1 GiB / core disabled. Original bootstrap limits are 128 functions,
1,536 blocks, 8,192 operations, 256 blocks per function, 16 block parameters
and SSA suffix below 2,048. Maximum block operations is recorded, not
invented as a new 128-operation gate.

## Remaining outer work

The eleven-image Emitter's own fresh CI is separate. It has to finish
before any completed result can be joined and counted here. The original
outer emit_program_machine still requires actual immutable Core re-admission,
normalized foreign manifest, checked plan, exact implementation identity,
artifact budget, actual inspector and final implementation recheck.

compile_program_machine adds independent rederivation and equality, target
host and destination checks, linker identity and subprocess ownership,
complete object/shared inspection, exact original publication and readbacks,
failure withdrawal, cleanup and the full final report. Shared-library
inspection in elf_shared_abi.py and COFF/Mach-O support are not supplied by
this component. Full public build, installed dispatch and whole-stack
closure remain OPEN.
