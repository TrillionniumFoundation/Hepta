# HIA-emitted observer for linked successor ELF

Status: an unselected development component. The compact second layout passed fourteen actual native tests with a fresh test-local B0/B1 generation and complete independent VM output observation. It is not yet integrated into the full qualification, installed, enabled by default, or evidence of a whole-stack rewrite.

## Scope and trust boundary

The current qualification invokes each linked successor through a fresh Python process using `ctypes.CDLL`. This component removes Python from that child while keeping the actual operating-system dynamic loader. It creates a sealed memfd containing every supplied shared-object byte, invokes system `dlopen` with `RTLD_LOCAL | RTLD_NOW`, resolves the exported `f0` with `dlsym`, closes the image fd, and calls the existing six-argument byte ABI. It does not extract `.text`, emulate relocation, reuse a process, or replace the independent B0/seed loader.

The actual executable is produced by compiling and executing `linked_observer_packer.hiaasm` with the HIA compiler. The emitter writes the complete ELF header, program headers, dynamic records and fixed platform adapter. The Python generator is an authoring/reference tool; the accompanying assembly is an independent readable reference for the fixed adapter. Neither runs in a native observation child. This still has a fixed machine-code operating-system adapter, hosted supervision and hosted independent oracles; it is not a claim that all system code was authored in HIA.

The normal supported qualification input is the closed linked-successor object profile already checked by `inspect_selfhost_object` and GNU ld. Foreign objects are used for explicit loader and kernel controls. The tests do not prove equivalence for every arbitrary hostile shared library, its constructors, environment introspection or invalid private caller input. This helper is not a security sandbox.

## Exact byte protocol

Input is `HIALDS01`, six little-endian unsigned 64-bit fields, then the complete image and source bytes:

| Field | Meaning and bound |
| --- | --- |
| image bytes | 1 through 4 MiB |
| source bytes | 0 through 1 MiB |
| output capacity | 0 through 1 MiB |
| workspace bytes | 0 through 1 MiB |
| workspace fill | 0 through 255 |
| output fd | unsigned all-ones for private A5-filled output, otherwise 3 through INT32_MAX |

All framing, lengths, overflow cases and unexpected arguments are checked before loading a supplied object. A shared output fd comes from the fixed parent, is sealed against size changes, and remains writable so an actual store before a native signal is observable. The supplied-image memfd receives all four Linux seals before `dlopen`; the child checks them back.

Successful output is `HIALDR01`, the full unsigned 64-bit return, actual monotonic native-call nanoseconds, then the actual post-call source, complete output and complete workspace. Source immutability is observed, not assumed. The parent rejects trailing or missing bytes, wrong magic and unexpected stderr, saves original malformed response bytes, hashes the full output, and rereads the executable, supplied image and saved source after the child exits. The parent does not memoize digests or native results.

Exit codes are 2 for invalid framing, 3 for an oversized incoming frame, 4 for a mechanical operating-system error, 5 for `dlopen`/`dlsym` refusal and 64 for arguments. Native signals, including deliberate UD2/SIGILL, remain real child termination. These private mechanical exit diagnostics are not Python traceback equivalence. Public language refusals still come from the actual HIA entry and are compared with the independent legacy observations.

## Kernel limits and ELF layout

Each child retains 10 CPU seconds, 256 MiB address space, an 8 MiB stack, 16 MiB file-size limit, 32 open fds and a 20-second parent wall timeout. Core size is zero and `PR_GET_DUMPABLE` verifies the process is not dumpable. Limits are set before reading or loading the supplied program. The parent retains the existing observer's fixed environment and fresh sealed executable transport.

The executable uses the existing Linux x86-64 glibc system profile: `/lib64/ld-linux-x86-64.so.2` and `libdl.so.2`. Symbol relocations are resolved before entry. There are distinct RX and writable virtual pages; the GOT/data page becomes read-only under GNU_RELRO, and the stack is non-executable. The second layout packs two different private virtual mappings into the same file page. Relocation writes are private and cannot modify the RX mapping. Actual `/proc/self/maps` observations check RX, RELRO, stack permissions and absence of writable-executable mappings.

The second executable is 2256 bytes, SHA-256 `95dbe2af13367b9a54655f80e535364c3769d42ba1f1f558d955e2015e37796c`. Its eighteen independent VM windows compare every emitted byte. The first layout was 4304 bytes and needed thirty-four windows; its successful original records remain separately preserved. The compact layout reduces repeated reference execution work without skipping any emitted byte.

## Actual development evidence

The second component run executed all fourteen selected tests, in order, with no failure, error, skip, expected failure or unexpected success: 9.868249870 seconds and maximum parent RSS 78344 KiB. Every native compilation and invocation retained its original 10 CPU / 20 wall / 256 MiB limits. The test-local seed and B1 were freshly created after that setup's independent VM reference; this is distinct from the separate development compile that used the retained historical B3.

Controls include full 64-bit foreign returns, every workspace-header boundary, observed source/output/workspace mutation, custom output preimages, real post-store SIGILL capture, fresh PIDs and reset dynamic state, frame/argument refusals, immutable-input readback after execution and exact malformed stdout retention. Actual shared objects exercise a constructor before a nonzero-offset `f0`, external `getpid` relocation, an unused unresolved lazy symbol rejected by RTLD_NOW, missing `f0`, all six kernel resource limits and dumpability, image seals observed in a constructor, and actual memory permissions. An actual HIA-emitted ELF compiler self-rebuilds through this loader and matches both the flat compiler bytes and legacy loader output; ordinary sample execution and native compiler rejection also match.

Raw sources, commands, compiled objects, before-B0 references, seed and successor receipts, output files and individual observations are retained. The runtime tests use ordinary external GNU assembler/linker tools only for explicit foreign control fixtures, as the existing qualification already does for independent host witnesses. They do not generate the observer used for execution.

## Integration obligations still open

Before selection, include the exact source set in the source contract; build a fresh observer from the current original successor; bind its immutable bytes into each of the same thirty-eight phase requests; route only linked successor calls to it; retain flat and B0/generation controls; run every original suite with zero skips; and pass the original 180-second cold gate with two oracle workers. Full archive custody, installed-source tests, independent review and complete current-source qualification remain required. Development timings do not stand in for that qualification, and no legacy owner is removed by this component.

## Source custody correction after independent review

Independent review of stage2 reproduced two real build races: after the actual HIA compilation, changing a copied source or compiler still allowed the old wrapper to publish an observer with a top-level source/compiler hash different from its actual compilation receipt. A separate nineteen-call VM control showed that changing the source's first emitted ELF byte after its first observation window could yield a mixed-source reference accepted by the old per-window source reads. These original failures remain preserved; none was a production activation or a successful complete qualification.

The third transport revision captures the complete source/compiler bytes once, requires the reference source identity to match, verifies actual compile input/output and emission input identities, and rereads source, compiler and emitter before publishing. Every VM window uses the same source snapshot and the final source readback must agree. The executable publication is read back as actual bytes. The HIA source and 2256-byte executable are unchanged.

All sixteen native component tests passed after this correction in 16.581089802 seconds. This includes the original fourteen cases, two real source/compiler modification attempts after successful native compilation, and a complete VM snapshot mutation control. The same inherited custody defect was also corrected in the existing flat observer in the isolated integration; both complete observer modules then passed all thirty-eight tests in 24.037136978 seconds, with no failure/error/skip/xfail/xpass and unchanged native limits. Full source/cold qualification and independent review still govern selection.
