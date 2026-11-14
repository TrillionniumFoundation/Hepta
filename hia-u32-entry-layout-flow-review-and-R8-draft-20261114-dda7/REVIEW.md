# Entry-layout executable-flow review

Status: **static review completed; no deterministic runner blocker found in the examined normal path**. This is not an executed gate. No product module, compiler, VM, generator or CI was run. The fourteen original author leaves and original recipe remain unchanged.

The review read the actual runner, support, transport, projected entry function, copied frame loader and their frozen product callees. `review_flow.py` only parses those files with the standard-library AST and checks the relationships described below. Its recorded run took 0.080 seconds, made no product import and produced `FLOW-REVIEW.json`. The report also pins every file read. This review adds three documentation clarifications, without replacing the original author package.

## The operation that will run

Use **`FINAL-COMMAND-INTENT.json`**, not the earlier `REVIEWED-COMMAND-INTENT.json` named in the original PLAN prose. The current exact execution-plan SHA is `6c2b0cb2d21284345d8acca1c8e5ddd5547bc236c0bcd495b0d330a9e29797a1`. The earlier intent is retained evidence of the original author-metadata attempt; its SHA would be rejected before the owner starts.

The parent calls the original `run_owned` exactly once with a new output directory, the fixed CPython 3.14.4 executable, `-I -S -B`, the reviewed child command, the explicit environment, and 180/3. The child performs its source/runtime/input guards, installs the temporary observation bindings and calls the explicit entry function once. It does not select the ordinary unittest class, run its expensive setUpClass, or invoke any other full qualifier.

The explicit function preserves the complete original body through the three recorded inverse replacements. `_construct_reordered_blocks` comes from the actual frozen `hia_selfhost_names` module. Its local consumer imports occur when the function is called, after the observation wrappers have been installed; they therefore reach the intended wrapped functions. The CFG helper similarly imports its compile/invoke/link functions inside its own function body. There is no stale module-level alias bypass for these call sites.

## Original loops, predicates and 1M VM budget

The original four combinations are unmutated/mutated u32 source and last/middle entry placement. The original `cases()` contains exactly one `queued-owner-and-local-loan` row and one `queued-chain-move-drop` row. The explicit entry function selects those two rows, retains the full returned values and resource predicates, and supplies an empty refusals list to the later CFG helper.

The first loop constructs all four compiler permutations and all eight VM references before appending them to the prepared list. The second loop performs native work. For each combination it calls four direct compilation sites (R1, R2, canonical, E1), four-in-total original ELF execute sites, and two accepted resource case compilation/run/link sequences. This gives exactly 24 compile calls, 32 native invokes, eight linker calls, four ELF executions, eight VM references and one mutation.

The VM reference imports `hepta.hia_program.execute_program` and calls it with three positional arguments and no keyword. Its original facade imports the actual runtime and forwards the same empty keyword dictionary. The inspected runtime's `max_steps` default is exactly 1,000,000. The observation wrapper delegates once with the same args/kwargs and does not call the VM again. It captures the existing VerifiedProgram immutable byte fields directly. The runner checks the default before entering the gate and requires every observed reference to have this original argument shape.

All original check predicates remain inside the byte-exact projected body, including same-source fixed points, canonical reproduction, actual ELF output equality and original resource results. Admission preserves the original method's reference-before-compile, four-reference, 20-check, all-true and false-whole assertions. It additionally requires the original false all-input flag, all twenty boolean values, exact ordered IDs and complete call labels. It does not remove a predicate, turn a missing return into success, or substitute a precomputed answer.

## Which timer covers which work

The 180-second owner request deadline is established before the child is launched. Consequently it covers the child imports/guards, all eight references, all 24 compilations, all eight links, all four ELF calls, wrapper/capture overhead and the child's final source/identity/frame readback. Each native compiler/resource subprocess retains its original 20-second timeout and loader limits (10 CPU seconds, 256 MiB address space, 8 MiB stack, 16 MiB file size, 32 FDs). Link subprocesses retain 20 seconds. The four ELF executions retain the original 15-second owner and three-second cleanup.

Parent preflight, the parent after-owner guards and final raw-inventory scan are **outside** that 180-second product deadline. They do not contain another VM/native/ELF gate. The original `run_owned` transport also retains its existing wait overhead around the owner deadline. Therefore “180+3” describes the unchanged qualification/cleanup deadlines, not a guarantee that total external launcher wall time is at most 183 seconds. The original PLAN table's phrase “all observations” should be read with this distinction.

The parent requires the actual owner receipt and returned wrapper fields to match, complete cleanup and ECHILD, no timeout, an exit observed before the deadline, and the actual successful child result. A child reporting successful checks but failing its final frame readback cannot produce a successful parent result.

## The 32 six-buffer witnesses are actually connected

The child requires both native-observer selectors to be None, then temporarily points `qualifier.CHILD` at the exact copied private loader. The original `invoke` reads that binding when creating each subprocess. All 24 compiler calls delegate through this original `invoke`; all eight resource calls also do, including the linked-selfhost branch. Both loader formats converge before the two capture sites around the sole machine entry call.

Each successful invocation writes actual source, output and workspace before and after bytes plus two metadata files. These are reads of the real ctypes/mmap regions. For linked resource cases, workspace extent zero is preserved as an actual empty span; the output starts from the original initial hex bytes and the original shared-output observation remains active. The compiler's resource-build workspace fill 0x5a is preserved as well.

The child's final `frame_inventory` reads the original requests and actual raw files. It checks metadata/schema/request equality, child PID and real return/elapsed values, the exact stdout-to-final-receipt field projection (including compile-produced fields and resource shared-output fields), empty stderr on complete returns, source preservation, output-file equality, actual output/workspace preimages, CPU/extents and produced-image prefixes. Success requires all eight files for every invocation, exactly the complete sorted 32-label inventory and 32 complete witnesses.

A trap or kill can leave before-only or partially written real files. The runner retains those files and does not fabricate an after frame. Such a run cannot satisfy complete admission. The four direct ELF executions are a different observation boundary: their stdin/stdout/stderr and original owner records are captured, but their internal workspaces are not observed and are not counted among the 32 six-buffer witnesses.

## Temporary bindings and restoration

The original prose saying CHILD is the “only temporary product binding” is too narrow. `GateJournal` temporarily wraps six existing functions: VM facade, compile, invoke, linker observer, mutation and ELF execute. `RuntimeBridge` temporarily wraps `owner.run_owned`, and CHILD is changed to the capture loader. The wrappers call each retained function once. Context-manager unwinding restores the six functions and owner binding; the child's finally restores CHILD and confirms the original SOURCE object was never rebound. The original module functions are compared again after restoration. A killed child has no continuing interpreter in which to restore these bindings; original files remain unchanged and the parent owner must finish descendant cleanup.

The runtime bridge preserves the original command/request and five original environment entries, while supplying the separately pinned libpython directory to fresh child and supervisor dictionaries. Only the four fixed CLI launch sites are reached in this gate. Its historical handling of a returned failing/incomplete nested owner is unchanged: it does not introduce an immediate-stop rule before the enclosing original function can continue. Final admission nevertheless rejects every incomplete nested cleanup. This review does not claim a new early-abort property.

## Remaining limits

No future completion time is inferred from this static review. Frame/journal/source hashing consumes the existing limits. The complete 3180-file manifest is the frozen actual R19-derived u32 lineage, not R20. Earlier hosted 5052/38 success is input provenance and a separate finite gate; it does not fill entry-layout, ordinary regression, matching-current cold, R8 semantics or aggregate qualification. Runtime file/env pins are checked; the runner does not claim a separate `/proc/maps` loaded-library attestation.

The review found three documentation clarifications, not a reason to alter the original function, VM arguments, timers, frame producer or test predicates. Actual execution remains separately authorized and must retain any real failure without a retry.
