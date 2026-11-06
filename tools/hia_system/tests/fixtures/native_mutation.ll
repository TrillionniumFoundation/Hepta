; A native semantic mutation probe. The HIA edit add -> sub must change
; the generated executable's exit status from 24 to 14.
target triple = "x86_64-unknown-linux-gnu"
define i32 @main() {
entry:
  %changed_by_hia = add i32 19, 5
  ret i32 %changed_by_hia
}
