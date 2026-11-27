# Installed Runtime frontend: native component checkpoint

This checkpoint replaces the embedded Runtime frontend body with one fixed
installed child. It preserves the actual Value arena, Runtime registry,
constructor handles, generation effects and terminal borrow ledger of the
qualified parent. It does not qualify the complete public Runtime constructor.

## Actual products and evidence

The 47-role parent has a 13,773,273-byte .text section and a 13,783,824-byte DSO
with SHA256 4ad50e282214379dd9e1cab642daa12cbd390970ebc294cef9d46a22ceff78ea.
The 14-role child has a 2,696,780-byte .text section and a 2,708,240-byte DSO with
SHA256 a987744376ea830ec4dcef66a2505bc97dc9fd5f3bb03eb08589ee3a5b7496cb.
Both were produced by the original native compiler, native packers and native
linker. The packers' actual output equals the independent development reference.

The current parent passed the original seven frontend semantic stages plus
three installed-loader/session stages, and all thirteen original Directory
cases. The Directory cases additionally verify idempotent session retirement
both before and after child unloading. They retain their original cap counts,
FD counts, lifecycle and callback assertions.

The current dependency is the previously qualified Value115 image:
4,046,235 bytes, SHA256
075b6d8cfd1797b662940cd6600f31e2f952e967a5ee4172827d58f781f54d25.
Later Value profiles require a new source-bound qualification; their availability
does not change this checkpoint's dependency.

## Stable ownership layout

The original parent context remains exactly 2048 bytes. Its native global
allocation remains 8 MiB, captured at parent offsets 1088/1096.

| Global offset | Size | Owner |
| --- | ---: | --- |
| 7340544 | 512 | Background binder; untouched |
| 7341056 | 512 | Runtime terminal borrow ledger; untouched |
| 7341568 | 512 | Installed Runtime frontend |

The frontend anchor has the following fields. All addresses and nonces are
captured by native initialization. No ordinary frontend request supplies them.

| Offset | Meaning |
| ---: | --- |
| 0/8/16/24 | HIARTAM1, PID, actual parent self address, fixed install entry |
| 32/40 | Native owned mapping and exact extent 27262976 |
| 48/56/64/72 | State, continuation stage, exclusive control, active child calls |
| 80/88 | Actual parent and sidecar guard ownership |
| 96..112 | Actual global resource borrow capability |
| 128..144 | Actual fixed-loader capability |
| 184..216 | Five catalog-authenticated child entry addresses |
| 232 | Actual parent Value binding nonce |
| 248..304 | Borrowed tool FDs, source FD, threshold mapping and digit policy |
| 336/344/352 | Fixed global, loader and sole Value entry |
| 368/376/384 | Fixed parent, absolute-path and tempdir entry |
| 392 | Nonzero nonce obtained from native getrandom |
| 400 | Count of real bound frontend sessions |

The first page of the owned mapping is reserved; the fixed loader owns the
25 MiB subspan starting at 4096. Parent and sidecar guards are acquired under
the actual parent mutex and are released only after the loader, mapping and
global resource borrow have all reached confirmed terminal states.

The native loader reuses the parent's fixed loader policy, SHA, mapping
identity policy and the global capsule's complete stable-file entry. The child
has its own fixed catalog. The existing prepare and Background catalogs are
not changed. The child contains no second Value or parent Runtime registry.

## Control

The six-word entry hia_generation_runtime_frontend_install uses:

- Input: 128 bytes, HIARTIQ1, op at 8, all remaining fields zero.
- Operations: 0 initialize, 1 close, 2 query, 4 retry.
- Output: at least 3 MiB.
- Work: the actual 2048-byte native parent context.

HIARTIR1 reports status at 8, state at 16, known at 24, pending at 32,
retired at 40, detail at 48, active calls at 56, stage at 64, held guards at 72,
actual support mask at 80, global/loader capability presence at 88/96,
sessions at 104, and native nonce at 112.

States are 1 initializing, 2 ready, 3 closing, 4 retired, and 5 quarantined.
Busy calls, active child calls and held sessions prevent close. Unknown
ownership preserves the mapping, loader, global borrow and guards. The control
does not enable another resource kind.

## Child exports and original protocols

| Fixed export | .text offset | Wrapper bytes |
| --- | ---: | ---: |
| hia_generation_runtime_frontend_child_bind | 0 | 1183 |
| hia_generation_runtime_frontend_child_options | 1184 | 483 |
| hia_generation_runtime_frontend_child_verify | 1680 | 519 |
| hia_generation_runtime_frontend_child_directory | 2704 | 992 |
| hia_generation_runtime_frontend_child_directory_policy | 3696 | 5 |

The actual installed parent retains the original bind/options/verify exports.
Their HIARTBQ1, HIARTOQ1, HIARTVQ1 and HIARTXQ1 request and response contracts
remain unchanged. Directory handling still occurs after real scalar admission
and the original optional proof, through the actual HC1 coordinator path.

Each bound frontend still owns its own actual Value context token, global
resource borrow and parent guard. The installed proxy adds a loader session
count; this does not replace any of those original resources.

The last 64 KiB of the stable 1 MiB frontend allocation is reserved for native
session metadata. The 128-byte record begins at offset 983040:

| Offset | Meaning |
| ---: | --- |
| 0/8/16/24 | HIARTSM1, PID, exact frontend self address, exact parent address |
| 32 | Captured installed-child nonce |
| 40/48/56 | Held or retired state, exclusive operation, owned session |
| 64/72 | Fixed parent and sole Value entry |

Calls authenticate the exact self address and PID, obtain the actual parent
mutex, and increment the active child count before releasing the mutex and
entering the child. The count is decremented only after the child returns.
Receipt processing remains in native custody if mutex waiting fails; it uses
actual CAS and sched_yield to reacquire before committing ownership facts.

A bind retirement is accepted only from the actual HIARTBR1 known/retired
receipt. A later repeated close verifies the retired native session,
frontend header, zero token/borrow/guard ownership, and the preserved actual
retirement receipt. It does not reload or reenter an unloaded child and does
not fabricate a new ownership transition.

## Qualified behavior and limits

The thirteen Directory cases cover absolute and relative strings, None,
string subclasses, actual PosixPath and subclass layout, actual __fspath__
return and same-exception raise, admission before callback, Path subclass
shortcut precedence, wrong callback return, and Windows parts/Unicode drives.
Their final cleanup verifies the original actual Runtime/Lease registry,
Value capability count, parent/sidecar guards, artifacts and FDs.

The native frontend stages cover defaults and explicit option boundaries,
the original nine option rejection comparisons, actual argument retains,
default clang as a real string Value, raw bytes/text fresh VFY3, actual
VerifiedProgram class36 with both fields reverified through VFY4, and complete
session/loader/parent retirement.

The public Runtime factory, later public mutation wrappers, immediate
generation-cache pruning, final same-source Background fusion and complete
release DAG remain unqualified. The current Directory FS output bound of
4045 bytes also remains an explicit unfinished public-domain issue.
No whole-runtime or whole-release claim follows from this component checkpoint.
