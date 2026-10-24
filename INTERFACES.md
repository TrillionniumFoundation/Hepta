# Hepta bootstrap compiler shared implementation contract

All implementation is under this standalone project. Python standard library only for the bootstrap frontend; generated programs are native Rust-compiled code. This is a prototype, not a claim of a completed production language. All passes consume `hepta.ast`.

## Grammar v0.1

`module name;` optional. `struct Name { field: Type, ... }`; `repr(C) struct Name ...`.
`[pub] [export "C"] fn name(params) -> Type effects { effect, ... } [resources { key = literal; ... }] { statements }`
`extern "C" fn name(params) -> Type effects { ffi, ... };`
All function declarations require an explicit effects clause. Parameter `x: read Type`, `x: mut Type`, `x: take Type`, or `x: Type`.
Types: integer types, f32/f64, bool, Unit, structs, `[T; integer]`, `[T]`, `Buffer<T>`, `raw const T`, `raw mut T`.
Statements: typed/inferred `let [mut] x [: Type] = expression;`, assignment to name/field/index, `return [expression];`, `for i in start..end { ... }`, `while expr { ... }`, `if expr { ... } else { ... }`, `unsafe { ... }`, expression statement. Semicolon required except blocks.
Expressions: integer/float/bool literals; names; ordinary named calls; unary `-`, `!`, `read`, `mut`, `move`; binary operators; array literal; index; field; `expr as Type`; `Name { field: expr, ... }`.
No arbitrary Rust escape or macros. Unknown syntax/types/functions/effects fail closed. Field access does not allow method calls.

## AST shapes

Expr kinds: `int` value integer; `float` value float; `bool` value bool; `name` value str; `call` value function str children args; `unary` value operator children [operand]; `binary` value operator children [lhs,rhs]; `array` children elements; `index` children [base,index]; `field` value field children [base]; `cast` value Type children [expr]; `struct` value {name: str, fields: list[str]} children values in order.
Stmt: `let` data name,type (Type or None),mutable,expr; `assign` target,expr; `return` expr (or None); `for` name,start,end,body; `while` condition,body; `if` condition,then,else; `unsafe` body; `expr` expr.
Parser: `parse(source: str, path='<input>') -> Program`, raises HeptaError with precise Diagnostic for lexical/parse failures. No source splicing into generated Rust.

## Checker interface

`check(program: Program) -> CheckResult` with fields diagnostics: list[Diagnostic], effects: dict[str,set[str]], expr_types: dict[int,Type] (key=id(expr)), assumptions: list[dict]. `.ok` property. Resolve all declared funcs/structs, duplicates, unknown names. Validate C-compatible boundary types (primitive numeric/pointer/repr(C) aggregate; no bool/Unit fields/slice/Buffer at C boundary; Unit fn return allowed). Validate exact effects, computes transitive call effects. Allowed effects: alloc, panic, io, block, spawn, ffi, unsafe, write. Local mutation does not produce write; mutation of borrowed inputs does. Unsafe operations need explicit unsafe block, and unsafe/ffi effects.
All arithmetic overflow checks always enabled in generated Rust. Integer +/-/*, divide/modulo and indexing are conservatively panic effects. Explicit wrapping intrinsics avoid arithmetic panic. Rust backend will also check types/borrows; frontend must report its checked scope accurately and never call a frontend-only result complete borrow validation.
Builtins: `len(x)->usize`; `wrapping_add/sub/mul(a,b)` same integer; `buffer(n)->Buffer<u8>` effects alloc,panic; `release(move x)->Unit` for Buffer; `assert(bool)->Unit` effect panic; `print_i64(i64)->Unit` io; `load(ptr,index)`/`store(ptr,index,val)` unsafe; `ptr_read(read slice)` / `ptr_mut(mut slice)` -> raw pointer unsafe; `size_of(Type)` not in v0.1 grammar (use ABI C harness); `min/max(a,b)` same integer; `abs` not supported. `buffer` elements zero-initialized. Buffer is linear; requires take mode for owning params and `move` at owning calls/return. Borrow modes never consume. Resource checker tracks movement on all normal exits, branches, loops; no reassignment of linear values and no unsupported nested linear values. Rust compiler authoritative for lifetime/borrow checks.
Resource clauses supported: heap_allocations=0, may_block=false, may_suspend=false (no suspend supported), may_spawn=false. Reject unsupported numeric bounds instead of treating as proved.

## Owners

Parser agent: lexer.py, parser.py, parser tests only. Checker agent: checker.py, checker tests only. Root: ast.py, backend.py, cli.py, protocol.py, __init__.py, packaging, docs. Validation agent: toolchain setup, tools/validate.py, benchmarks/, examples/ffi/, tests/test_native.py. Do not overwrite other owner files without messaging.
