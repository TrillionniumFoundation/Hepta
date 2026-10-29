# Prospective public-feedback repair study, v5

The v4 results remain failures on their original source and first-response
protocol. This is a new, explicitly adaptive follow-up, registered before its
first model response. It retains the same three baseline tasks, four main tasks,
hidden inputs, strict interfaces, ownership checks and native execution gates.

Both calibration and all HIA/Rust full/query cells now allow at most three
submissions with the same token, context, wall and tool budgets. Only actual
compiler/admission diagnostics and the already public cases can trigger an
automatic repair. Hidden validation runs once after the first public pass;
hidden failure ends that cell and never enters inference. No manual answer
editing, task substitution or within-cell model change is permitted. A model
must pass all three complete baseline task gates before the 16-cell cohort.
This qualifies a bounded repair workflow, not single-response model competence.

A syntax-only envelope allows a short model-generated requirement self-check
before both complete replacement files. Its contents have no edit authority or
acceptance weight. No reference implementation, correct opcode inventory or
hidden input is added to a prompt or output grammar. The same presentation
change and workflow apply to both languages and interfaces.

The new transport uses the existing owned, hash-bound, Unix-socket llama.cpp
process and its model chat template. Its native `/completion` streaming format
is documented in [the pinned b11669 server README](https://github.com/ggml-org/llama.cpp/blob/b11669/tools/server/README.md).
Every received SSE byte is retained before parsing. Complete final events must
match the requested token IDs, output limit, greedy settings and active grammar.
On interruption, exact prompt tokens and received output-token IDs survive;
unreceived output and terminal-token usage remain unknown. A lower bound is
never silently reported as a complete total. The owned server is stopped before
the next distinct cell after a timeout.

Calibration receipts must bind the current protocol, prompt and implementation
hashes and the pinned model; eligibility is recomputed from all three actual
cell records. This is integrity checking of retained local evidence, not a
signed attestation or an untrusted-party authentication mechanism.

The four physical source files still compose one HIA Core module. Query is a
whole-function context slice, not a node-level edit API. The study is a small
purpose-built project cohort, not long-term production maintenance evidence.
Host measurements are from the available shared development environment; dot
runtime is not observable and no physical-machine performance claim is made.

Run the actual workflow with `tools/qualify_hia_agent_repair.py`. A clean source
commit is required before inference and all source/model/tool identities are
checked again at cell boundaries and termination. Any result is tied to that
recorded source, not a later publication commit.

Before model loading, a real memfd seal/write-refusal preflight checks the Python
build and kernel interface. The interpreter and `fcntl` extension bytes join
the recorded tool identities. The first diagnostic run exposed a bundled
Python build without `F_ADD_SEALS`; it is retained as infrastructure-incomplete,
including its five actual responses, and cannot qualify a model. No integer
constant is guessed and no sealing requirement is relaxed to accommodate it.

The imported v4 fixture protocol is also a bound input: its hidden seed is read
by the unchanged fixture builder. V5 refuses a mismatch between the two declared
seeds or case counts. The earlier 9f555cb calibration predates this transitive
binding fix and is retained separately; it cannot replace qualification on the
corrected source. Tasks, prompts, response budgets and outcomes are unchanged.
