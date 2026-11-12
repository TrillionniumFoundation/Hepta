# Worker program services: fixed native P16 / P17 / P18 development revision 1

## Status and ownership

This is newly authored, unexecuted source. No AST, HIA generation, B3 compile, packer entry, native application process or test has run for this new composition. The independent CI is the next gate. Earlier Core, public assembly, initializer and P12 counts are not inherited.

The service provides complete program verification, complete public assembly rendering with mandatory independent roundtrip admission, complete public assembly syntax/admission, and the original assembly diagnostic object. All mode/schema/validation/diagnostic/result choices are HIA-owned. The x86-64 carrier transports immutable bytes, manages finite child contexts and performs mechanical syscalls.

This is the value service needed by initializer peers P16 verify, P17 render and P18 assemble. Joining their actual issued Graph registry, namespace result leases and the full initializer is still a separate required integration. It does not activate an ordinary Worker or a public CLI.

## Source-bound images and carrier

The immutable table has 63 slots and 41 live images:

| Roles | Identity and purpose |
| --- | --- |
| 1–28, 40–46, 55 | 36 complete retained program/composite/raw/Core-diagnostic images, each exact source/image SHA and size from original-role-map.json |
| 56 | New Worker service controller |
| 59 | Method-adapted complete assembly continuation controller |
| 61 | Complete public assembly syntax owner |
| 62 | Complete primitive assembly renderer |
| 63 | Complete issued-object snapshot/structure/canonical prefix |

All other rows are zero and unreachable from the emitted service call graph. Image roles and mutable slot indices are different namespaces. The top-level role mask keeps 61 and 62 as R/R/W and makes 63 R/W/W; retained masks are otherwise exact.

The carrier's instruction text from input_exact through the end is preserved byte-for-byte from source 8163cf41059b38260f66dbc5a89d5676b1f7f121. Only the initial private command plus one immutable source-view framing and role mask change. It retains the original program-child → ordinary-child finite nesting, error/capacity ACKs, mprotect, slot cleanup and actual child receipt transfer. The new carrier has not yet executed.

The source-bound original 63-row packer algorithm is reused, removing only the rule that every row is nonempty. A native HIA entry copies the complete immutable ELF prefix, every image, all zero padding and all table addresses. The development builder independently compares every resulting byte. It does not substitute a Python runtime executable assembler.

Six fresh B3 compiles are required: roles 56/59/61/62/63 and the HIA ELF packer. The retained 36 images are verified as retained image/source pairs, not relabelled fresh compiles.

## Immutable input frame

stdin contains a 64-byte, eight-little-endian-u64 HIAWPI01 command immediately followed by exactly inputBytes source bytes and EOF. The executable accepts no extra arguments.

| Word | Field |
| --- | --- |
| 0 | HIAWPI01 |
| 1 | Nonzero private lease, at most u64 maximum minus three |
| 2 | Nonzero caller request |
| 3 | Integer decimal digit limit: 0 or at least 640, and no more than u32 maximum |
| 4 | Exact inputBytes |
| 5 | Mode: 1 verify, 2 render, 3 assemble, 4 diagnose assembly |
| 6 | tree: 0 raw byte input; 1 issued object transport, permitted only for verify/render |
| 7 | Zero |

The header is framing, not a new program language or public serializer. For tree=1 the issuer must supply the complete immutable insertion-preserving integer/UTF-8 transport for the original caller-owned tree. No general arbitrary Python object, tuple, custom mapping, lone-surrogate, float or object identity capture is claimed by this private transport. The initializer's complete integer-domain examples can use it after actual Graph encoding; that adapter is not included in this first service gate.

The top-level initial private slots are 0: one-byte read-only empty view, 1: exact read-only input, 2: 1 MiB controller workspace. Other slots must be empty. The controller checks its full initial workspace and exact advertised lengths. A malformed ABI is a private refusal and the caller must discard its lease; it is not translated into a public language diagnostic.

## Native order

### Verify

For raw input, the actual program child performs original raw byte/UTF-8/integer JSON checks and true primitive v1–v8 versus structured v1–v4 dispatch. It invokes the complete structured normalization owners where appropriate and complete final primitive Core admission.

For an issued tree, the complete object snapshot/structure/canonical prefix runs first. Its original depth/node/queued-node and final byte-budget order is preserved. The resulting immutable canonical bytes then enter the same actual program child.

The parent validates the actual 256-byte HIAPRV01 program receipt, copies actual Core bytes, runs actual native SHA on them and checks that digest against the receipt. Both original normalized input SHA and final Core SHA are copied from the actual child result.

### Render

The same complete initial verification occurs first. The renderer then checks the original primitive representation profile. It produces complete assembly text, which runs through the full public syntax owner, issued-object prefix and a new independent complete program/Core child. Every byte of the roundtrip canonical Core is compared with the first Core. The original receipt and original Core remain the returned authority; the second successful admission is not used to fabricate the first receipt.

This preserves the original distinction between verified structured programs and renderable primitive v6/v7/v8. Primitive v1–v5 and structured inputs receive the original representation refusal at the original post-verification point.

### Assemble and diagnose

The full public syntax owner preserves its original 1 MiB source, 16,384 lines, 16,384 bytes per line, 256 functions, 4,096 blocks, 16,384 operations and 256 list-item bounds. It preserves strict UTF-8/control/CRLF handling, full explicit grammar, attribute JSON and return-loans preflight/error order. It does not use the selfhost compiler's smaller parser as a public assembler.

Syntax success is only construction data. The complete object prefix and independent program/Core child must still accept it. Assemble returns the actual checked canonical Core. Diagnose returns the complete canonical original diagnostic JSON, with accepted/source/hash fields produced by HIA and no Core authority on refusal.

### Error coverage

Already available complete raw group 7 and the available group 10 diagnostic and complete group 8 HIACDT01 Core diagnostics are forwarded only after their original actual event validation. Assembly syntax/representation/Core phases and line numbers are preserved. Error text comes from actual native owners, not a Python reason-to-text fallback.

Inherited program groups 1–6 and 9 do not yet have a confirmed complete public diagnostic renderer in this composition. They remain explicit OPEN coverage and cannot be declared successful public behavior. Root owns the subsequent full diagnostic integration.

## Immutable result

On a successful value result, stdout is the exact result frame and stderr is the mechanical 128-byte HIACDE01 terminal. On a semantic refusal, stdout is empty and stderr is that terminal followed by the complete result frame; process exit is 2. Success exits 0. Framing/mechanical failures retain the carrier's private HIAXER01 path; they are not public program errors.

The result is a read-only owned slot 30. Its header is 256 bytes / 32 little-endian u64 words:

| Words | Content |
| --- | --- |
| 0–4 | HIAWPE01, ABI 1, actual private lease, caller request, mode |
| 5–8 | Result kind, error domain, error phase, optional line |
| 9 | Complete frame bytes |
| 10–11 | Actual program receipt offset and bytes |
| 12–13 | Actual canonical Core offset and bytes |
| 14–15 | Complete result payload offset and bytes |
| 16–17 | Error-code substring offset and bytes, otherwise zero |
| 18–31 | All zero |

Kinds are 1 program, 2 assembly text, 3 diagnostic JSON, 4 complete error text. Domains are 0 success, 1 HIAProgramRejected, 2 HIAAssemblyRejected. Phases are 0 none, 1 syntax, 2 Core verification, 3 representation. No hosted exception object is materialized by this native byte service.

When a program is present, the actual receipt occupies bytes 256–511 and Core begins at 512. Program payload aliases that complete Core. Assembly text or accepted diagnostic JSON follows Core. A rejected diagnose result has no receipt or Core and its complete JSON begins at 256. A semantic error likewise contains only its complete text from 256 and an error-code subview of that text.

The receipt magic is HIAPRV01, not a synthetic Worker receipt. The parent validates and copies the actual child receipt unchanged, including actual child lease, structured flag, original and Core versions, lengths and both 32-byte digests. A native hash check binds the copied Core bytes. Private lease correlation is not external authentication and never grants Store/file/publication authority.

## Independent gate plan

Five original-budget groups run independently. All public reference outcomes are computed before native application execution, and every successful comparison checks complete bytes, exact public exception code/text/phase/line where present, and the actual program receipt fields/digests.

| Group | Cases | Actual fixed ELF processes | Direct private root entries |
| --- | ---: | ---: | ---: |
| semantic | 45 | 45 | 0 |
| assembly-boundary | 22 | 22 | 0 |
| object-boundary | 8 | 8 | 0 |
| private-protocol | 35 | 5 | 38 |
| example-chain | 3 | 3 | 0 |

The semantic group includes primitive v1–v8, structured v1–v4, render-profile refusals, stored-loan/task examples, complete raw errors, undefined-value Core rejection and a 120,000-byte Unicode opcode diagnostic. Boundaries exercise 128/129/256/257 public assembly functions, byte/line/integer/attribute edges, 8 MiB/+1 raw input, exact total-node and depth limits, and issued-tree render. The example chain feeds the actual output of P16 into P17 and the actual P17 text into P18, comparing the final actual Core.

All actual application processes have empty PATH/HOME and run only the fixed native ELF. Python is the independent oracle and process/evidence harness; it supplies no runtime schema, JSON, assembly, verification, rendering or diagnostic callback. The direct private controls exercise complete bad initial frames/workspaces, ACK identity and permanent refusal. This gate does not claim strace evidence, arbitrary public object capture, an installed command route, or full initializer registry connection.

Each compile uses the exact historical 668608-byte B3 SHA256 0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8 with 10 CPU / 20 wall / 256 MiB. Each runtime group remains 90 CPU / 180 wall / 1 GiB, plus measured aggregate process-tree CPU below 90. The original HIA limits remain 128 functions, 1536 blocks, 8192 operations, 256 blocks per function, 16 block parameters and SSA numeric suffix below 2048. No failure can be reclassified as a pass merely because another group succeeds.

The builder preserves source, image, compiler, compile receipts, generated assembly, actual packed ELF, full canaries and every byte comparison. Tests preserve inputs, stdout/stderr, process records, pending entries, compressed raw CAS and unchanged source/image/executable pins. Common CI seals both successful and failing runs. All unexecuted earlier test/build drafts remain historical source, not failed or successful test evidence.
