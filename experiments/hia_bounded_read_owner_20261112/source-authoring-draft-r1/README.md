# Bounded-read source-authoring draft

This is an unparsed, unexecuted source-worker draft for the bounded-read static revision 54c9f04cfd3e15d23aafdfdfa62943c568fc1086. It has no workflow, trigger, h request, frozen runtime or launch authorization. No source or native result exists.

The included fixed manifest records every exact acffa base leaf (4023 files, 408149624 bytes) and the two independent candidate overlays. A future outer controller must materialize a separate private source copy and run the worker under the original 180-second owner/3-second cleanup, with the source-authoring child bounded to 60 seconds. Those constraints are specified here but not falsely claimed as enforced by a complete launcher.

The worker performs Python syntax checks, invokes the actual candidate generator using the canonical Builder, saves its complete Core document and HIA assembly, calls the public whole-program verifier/assembly roundtrip, checks deterministic regeneration, and measures the original compiler caps. SSA capacity uses the count of distinct names, not the largest number in a name. All function/block parameters, branch/jump edges, operation operands and return values are counted. It verifies every source member before and after and retains its SHA256, Git blob, canonical mode and filesystem identity. Generated outputs stay outside the source copy.

This does not compile or map an executable, run native file IO, run the old/new finish controls, replace the original read_bounded entry, or satisfy a cold/installed/whole-stack gate. The diagnostic helper replacement semantics and finalizer/temporary-release schedule remain open; successful future source generation would not close those semantic gaps.

Before dispatch the outer controller must be implemented and independently reviewed, actual runtime and source-custody inputs frozen, the Python worker actually parsed, and all request bytes canonicalized. Original ELF caller failure evidence has priority over this draft.
