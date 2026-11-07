target triple = "x86_64-unknown-linux-gnu"
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)
declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1 immarg)
declare void @abort() noreturn
define void @empty() {
entry:
  call void @llvm.memset.p0.i64(ptr align 1 null, i8 37, i64 0, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 null, ptr align 1 null, i64 0, i1 false)
  ret void
}
define void @copy_checked(ptr %dest, ptr %source, i64 %destlen, i64 %sourcelen, i64 %n) {
entry:
  %destok = icmp ule i64 %n, %destlen
  br i1 %destok, label %checksource, label %bad
checksource:
  %sourceok = icmp ule i64 %n, %sourcelen
  br i1 %sourceok, label %copy, label %bad
copy:
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %dest, ptr align 1 %source, i64 %n, i1 false)
  ret void
bad:
  call void @abort()
  unreachable
}
