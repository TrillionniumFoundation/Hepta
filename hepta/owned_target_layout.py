"""Compile-time ABI/data-model probe for the finite Owned LLVM CPU targets.

This is an independent C compiler observation of the pointer/length layout
assumed by the current `%hepta.bytes = type { ptr, i64 }` emitter. It uses no
system headers or target runtime; it cannot prove LLVM lowering, C ABI calls,
ownership soundness, actual target execution, or physical device behavior.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import tempfile

from .llvm_ssa_backend import _clang_run
from .object_structure import qualified_object
from .object_symbols import ObjectSymbolsRejected, inspect_object_symbols


_TARGETS = {
    "x86_64-unknown-linux-gnu": 62,
    "aarch64-unknown-linux-gnu": 183,
}
_MAX_OBJECT_BYTES = 1_048_576
_SOURCE = """\
typedef __UINT8_TYPE__ hepta_byte;
typedef __UINT64_TYPE__ hepta_u64;
typedef __SIZE_TYPE__ hepta_usize;
struct hepta_owned_bytes { hepta_byte *data; hepta_u64 len; };
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error Hepta Owned LLVM supports only little-endian targets in this profile
#endif
_Static_assert(__CHAR_BIT__ == 8, "byte width");
_Static_assert(sizeof(hepta_byte) == 1, "u8 width");
_Static_assert(sizeof(hepta_u64) == 8, "length width");
_Static_assert(sizeof(hepta_usize) == 8, "usize width");
_Static_assert(sizeof(long) == 8, "LP64 long width");
_Static_assert(sizeof(void *) == 8, "pointer width");
_Static_assert(_Alignof(void *) == 8, "pointer alignment");
_Static_assert(sizeof(struct hepta_owned_bytes) == 16, "pointer plus i64 size");
_Static_assert(_Alignof(struct hepta_owned_bytes) == 8, "aggregate alignment");
_Static_assert(__builtin_offsetof(struct hepta_owned_bytes, data) == 0, "pointer offset");
_Static_assert(__builtin_offsetof(struct hepta_owned_bytes, len) == 8, "length offset");
int hepta_owned_layout_probe(void) { return (int)sizeof(struct hepta_owned_bytes); }
"""
_LAYOUT_DECL = "%hepta.bytes = type { ptr, i64 }"


class OwnedTargetLayoutRejected(ValueError):
    pass


def probe_owned_target_layout(clang: str | Path, target: str, llvm_text: str) -> dict:
    """Compile and inspect one exact target-model C assertion unit.

    A successful result means the *selected compiler* checked this finite
    representation under the same explicit CPU target as Hepta codegen; it
    does not make any unproved cross-language or hardware claims.
    """
    if type(target) is not str or target not in _TARGETS:
        raise OwnedTargetLayoutRejected("E_OWNED_LAYOUT_TARGET: unsupported CPU ABI")
    if (type(llvm_text) is not str or not llvm_text.isascii()
            or len(llvm_text) > 8 * 1024 * 1024
            or llvm_text.count(_LAYOUT_DECL + "\n") != 1
            or llvm_text.count('target triple = "' + target + '"\n') != 1
            or "target datalayout" in llvm_text):
        raise OwnedTargetLayoutRejected("E_OWNED_LAYOUT_SOURCE: unrecognized Owned LLVM layout/triple")
    compiler = Path(clang)
    if not compiler.is_file():
        raise OwnedTargetLayoutRejected("E_OWNED_LAYOUT_COMPILER: selected Clang does not exist")
    with tempfile.TemporaryDirectory(prefix=".hepta-owned-layout-") as directory:
        source = Path(directory) / "model.c"
        output = Path(directory) / "model.o"
        source.write_text(_SOURCE, encoding="ascii")
        command = [str(compiler), "--target=" + target, "-x", "c",
                   "-std=c11", "-ffreestanding", "-nostdinc",
                   "-Wall", "-Wextra", "-Werror",
                   "-c", str(source), "-o", str(output)]
        result = _clang_run(command, timeout=30)
        if result.returncode != 0:
            raise OwnedTargetLayoutRejected(
                "E_OWNED_LAYOUT_ASSERT: C compiler rejected CPU layout assumptions: " +
                result.stderr[:1500])
        if (not output.is_file() or output.is_symlink()
                or not 0 < output.stat().st_size <= _MAX_OBJECT_BYTES):
            raise OwnedTargetLayoutRejected("E_OWNED_LAYOUT_OBJECT: no bounded regular native object")
        data = output.read_bytes()
        if not qualified_object(data, "ELF64", _TARGETS[target]):
            raise OwnedTargetLayoutRejected("E_OWNED_LAYOUT_OBJECT: wrong machine/ELF data model")
        try:
            symbols = inspect_object_symbols(data, "ELF64", _TARGETS[target])
        except ObjectSymbolsRejected as exc:
            raise OwnedTargetLayoutRejected(
                "E_OWNED_LAYOUT_OBJECT: incomplete native probe symbol inventory") from exc
        if (symbols["defined"] != frozenset({"hepta_owned_layout_probe"})
                or symbols["undefined"]):
            raise OwnedTargetLayoutRejected(
                "E_OWNED_LAYOUT_OBJECT: unexpected probe exports or runtime dependency")
        return {
            "schema": "hepta.owned-target-layout.v1",
            "status": "target_c_static_assertions_compiled_not_executed",
            "target": target,
            "machine": _TARGETS[target],
            "c_source_sha256": sha256(_SOURCE.encode("ascii")).hexdigest(),
            "bound_llvm_sha256": sha256(llvm_text.encode("ascii")).hexdigest(),
            "probe_object_sha256": sha256(data).hexdigest(),
            "probe_object_bytes": len(data),
            "compiler_checked": True,
            "observed_requirements": {
                "little_endian": True,
                "char_bits": 8,
                "pointer_bits": 64,
                "usize_bits": 64,
                "long_bits": 64,
                "buffer_bytes": 16,
                "buffer_alignment": 8,
                "data_offset": 0,
                "len_offset": 8,
            },
            "llvm_layout_equivalence_proved": False,
            "native_abi_execution_qualified": False,
            "physical_target_executed": False,
        }
