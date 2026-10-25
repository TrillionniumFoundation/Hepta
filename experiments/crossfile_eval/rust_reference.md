# Rust study profile

Pinned rustc 1.90.0, edition 2021, std available, native opt-level 3,
overflow checks enabled, panic=abort. The root is compiled as a module named
`candidate` inside a separate submission crate; sibling modules may use
`crate::candidate::<name>`. The trusted native driver is a different crate and
its measurement/control state is not accessible from candidate Rust code. No Cargo,
dependencies, build scripts, or edits to the frozen main/native inputs.

Use ordinary Rust ownership, Result, Vec::try_reserve_exact, borrowing, and
std::thread where required. Semantic arms expose the same function, body, and
declaration query/replace operations as Hepta. The Rust declaration index is a
strict bounded token/delimiter scanner for this fixture profile, not a complete
Rust AST/type server. Every accepted multi-file update must pass native rustc.
Plain arms replace complete editable file contents and use the same validation.

The task's `interface_policy` applies to both Rust arms: the API and owned-Result
tasks authorize declaration changes; other tasks preserve signatures and type
declarations. The bounded index compares signature tokens conservatively, while
rustc checks typing and borrowing. Indexing/materialization run in bounded child
capsules. Initialization, compilation and public tests use one shared wall cap.
