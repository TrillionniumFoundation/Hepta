# Inspect qualification R2: complete streaming evidence admission

This is an independent author-only successor to the retained R1 parent failure. It changes no product file, test method, assertion, Native or VM case, compiler, runtime, source closure or execution budget. Root remains the sole preparer and product launcher.

## Actual problem and retained result

R1 completed Source18. Its Native phase then completed the Inspect build and all ten methods in the first Native group. The parent failed while capturing the group's 28,066,785-byte `controls/machine/INDEX.json`, which contains 12,376 complete calls. The original `capture()` accepts at most 16 MiB. The first Native group's qualification therefore remains FAIL, and the later eight owners did not start. Its source, outputs and reports are left unchanged.

R2 uses a new `/workspace/hia-cli-as-dict-inspect-qualification-r2-dda7` scope and must execute its own complete Source18 followed by separately admitted Native17/VM12. No R1 PASS or actual image is imported into those results. The source remains the actual 3210-file op8 tree `7f694b80c7ab76eb9d62402aeea4c331503ddc16`.

## Exact changed boundary

The original `capture()` implementation and its 16 MiB default remain byte identical. The existing per-frame and six-buffer decompression, complete hash, before/after and source-binding assertions in `audit_frames()` remain intact. Its temporary list now contains AFTER paths. The new reader parses each INDEX frame under the same 16 MiB per-value bound and compares it with that AFTER object freshly read through the original capture/checked/decode path. Every frame and both original call-count predicates remain mandatory. A missing, extra, reordered, incomplete or unequal frame is rejected; duplicate JSON keys are rejected. There is no digest or payload cache.

The INDEX itself receives three complete fresh reads: two held-FD passes establish and read back its descriptor, and a third pass parses and verifies that descriptor. Each pass reads at most 64 KiB per system read, hashes every byte, and compares complete length, Git/SHA identity, ordinary-file mode, unique link count and seven-stat named/FD bindings before and after. Aggregate file size is not used as the per-value limit. The new reader is confined to fixed UTF-8 JSON emitted by the retained writer, without a BOM; it is not a replacement general JSON API.

The same complete INDEX would otherwise fail later in `record_predecessor()`. That routine therefore captures every regular predecessor file with two fresh streaming passes. It retains the complete original pathset, order, seven stats, four-MiB descriptor shards and source bindings. `read_predecessor()` reads every bound file again and verifies the same complete identity. Large STATE metadata is written/read one mapping value at a time, and canonical ordered-descriptor pins are calculated using the original JSON serialization parameters without joining the complete encoded byte string. STATE mappings and descriptor lists are still ordinary metadata objects; this proposal does not claim constant total memory for all metadata.

Only `audit_frames()`, `record_predecessor()` and `read_predecessor()` change behavior, plus the explicit new scope literal, helper import and full control bindings. Whole forward/reverse byte projections are supplied. All other retained functions and all original Native/VM helper/test files remain byte identical.

## Later consumers and limits

The original `inspect_exec_vm.make_catalog()` and VM tests use their own complete `read_bytes()` and full JSON decoding. They did not use the 16 MiB capture gate, and their full bodies are retained. R2 does not claim that these original consumers are streaming or give them a new qualification. The original twelve-witness selection, full Native frame inputs and VM catalog order remain unchanged.

The current source, base3210, mother3211, prior3210, protected3180, runtime2496, old and new generator evidence, actual R5/Patch14 maps, ordinary B3 and cooperative fences retain their complete prior guards. The new author directory is added to the already protected roots; no old protected root or explicit compiler path is removed.

The original two Source owners and ten Native/VM owners remain separate 180+3 scopes. The compile limit remains 20 seconds, capacity 1 MiB, and VM limits remain 10 million steps, 8 MiB heap and depth128. The original 1 GiB actual-filesystem floor and 1800+3 outer watchdog remain unchanged. Parent metadata verification is after each original owner and does not extend its budget, issue a machine call, ACK or retire a frame. Any parent error remains a failure and stops later owners.

## Root-only validation and execution

`INDEX-VALIDATION-LAUNCH.json` is a data-only optional reader of the retained R1 INDEX and every actual AFTER object. It has not been executed by this author. It does not reread the payload buffers, execute a product, or convert R1 into a PASS. A new output path retains any failure. It is not an added product gate or a substitute for executing the original R2 matrix.

`SOURCE-PREPARATION-LAUNCH.json` prepares the new Source phase only. Its actual product launch is written by that preparer. Only after a real successful R2 Source18 result may Root substitute its actual SHA into the reviewed Native preparation command. No future image, result or receipt is prefilled.

R6 will need its own explicit successor: it must consume the real R2 predecessor and preserve complete metadata reads using this boundary. The frozen R6 R1 author is unchanged. Default activation, matching-current-cold and whole-stack qualification remain outside this scope.
