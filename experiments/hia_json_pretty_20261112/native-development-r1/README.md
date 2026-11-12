# Native development for the new HIA JSON layout owner

The product input is the complete immutable acffa9262f31d073f8f0a6f0201eae201039f619 tree. This directory adds a new development component and a separately owned test operation; it does not modify the product checkout, default selector, original CLI callers, cold gate, or retained qualification.

## Source correction

The previous source-r1 at ad4f2a983f95307a70e1161b2113371593d5ebff passed a development V8 IR interpreter only. Its public f0 returned u64. The actual unchanged compiler support contract requires public f0 to return exactly u32. This revision changes that declaration and the three status return sites, adding one explicit wrap cast of the existing bounded status. Internal workspace words and helper returns remain u64. The old source and its limited observations remain intact. No prior native result is claimed.

The revised source has six functions, 67 blocks, 249 operations and at most 426 distinct SSA names per function, within every original limit. Its 31 fixed development cases have just passed the mechanical V8 interpreter, with actual input and output/workspace guards checked. That observation is independent of the native operation, which is still unexecuted at this commit.

## Component contract

The HIA program owns layout of already admitted compact JSON: structural traversal, quoted and escaped byte preservation, empty containers, two-space indentation, colon spacing, measurement, output and stack checks, and original status/offset reporting. It preserves incoming key order and number/string spellings. Full JSON and foreign-object admission, key sorting and floating rendering remain upstream. Arbitrary raw byte strings must not gain public JSON admission through this component.

Workspace is 32 header bytes followed by one byte per live container. Header words are mode at 0, output length at 8, error input offset at 16 and error code at 24. Mode 0 measures with no output; mode 1 emits into the exact measured allocation using the same source bytes. Ordinary admitted depth 128 uses 161 workspace bytes. It adds no trailing newline; that remains a publication/stdio responsibility. Failed output may have a prefix and must be discarded.

## New actual validation requested

The unchanged public Core assembler and verifier must agree on the exact HIA assembly and IR. The original current-source build_seed produces a new B0, then the original compile_stage produces B1 and B2 and compares their actual bytes. B2 compiles this new HIA source. This is explicit development bootstrap, not completed B3/mutation/cold qualification and not reuse of an old qualified binary.

A disposable process directly invokes the resulting flat native image for exactly 31 new component cases under a new five-second child deadline. The 17 positive cases measure and emit exact expected bytes; 14 refusal cases cover layout structure, header/mode, output/stack capacity and the unchanged 8 MiB wire ceiling. Both source and allocation guard bytes are checked. No Python formatting implementation is invoked by the native test entry. Loaded and executed IDs must match exactly; all five failure/skip categories must be zero. These are new development cases, not renamed original CLI tests.

The complete source tree, physical namespace, Python and linker identities are checked before and after. The original external 180-second owner and three-second cleanup are unchanged. The two-GiB reserve is explicitly a development prerequisite, not the formal eight-GiB gate. Read-only bounded diagnostics print 17 fixed originals after the exact ECHILD boundary. Any missing originals, nonzero child, timeout, changed input or absent final marker stays HOLD.

A separate workflow commit and independent review are still required before the one exact create event. This commit does not create that trigger. The old Python presentation owner remains until full domain, original caller, installation, complete retained suite and current-source cold closure are established.
