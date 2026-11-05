#!/usr/bin/env python3
"""Independent exhaustive mock selection-timer check; requires sibling reproducer.

Reads hash-pinned upstream ssl.c as text and compiles only bounded mock C.
No OpenVPN, TLS, DCO, network, or artifact binaries are executed.
"""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile
import reproduce_dco_promotion_schedule as d

CHECK = r"""
int main(void) {
 unsigned cases=0;
 for(int a=0;a<7;++a) for(int b=0;b<7;++b) for(int c=0;c<7;++c) {
   struct tls_multi m={0}; int choices[]={a,b,c}; now=100;
   for(int i=0;i<3;++i) {
     m.keys[i].state=choices[i]==0 ? S_INITIAL : S_GENERATED_KEYS;
     m.keys[i].authenticated=choices[i]==1 ? KS_AUTH_FALSE : KS_AUTH_TRUE;
     m.keys[i].crypto_options.key_ctx_bi.initialized=true;
     m.keys[i].auth_deferred_expire=97+choices[i];
   }
   struct key_state *initial=tls_select_encryption_key(&m);
   interval_t wakeup=10; candidate_promotion_timer(&m,&wakeup);
   int expected=10;
   for(now=101;now<=104;++now) if(tls_select_encryption_key(&m)!=initial) {
     expected=now-100; break;
   }
   if(wakeup!=expected) {
     printf("FAIL %d %d %d expected=%d got=%d\n",a,b,c,expected,wakeup); return 1;
   }
   ++cases;
 }
 printf("PASS %u three-key mock states: candidate equals earliest selection change.\n",cases);
 return 0;
}
"""

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ssl_source",type=Path)
    parser.add_argument("--cc",default="cc")
    args=parser.parse_args()
    raw=args.ssl_source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=d.SSL_SHA256:
        parser.error("source differs from pinned ssl.c")
    source=raw.decode()
    functions="\n".join(d.function(source,decl) for decl in (
        "static inline void\ncompute_earliest_wakeup(",
        "static int\nauth_deferred_expire_window(",
        "struct key_state *\ntls_select_encryption_key("))
    begin=source.index("    /* When should we wake up again? */",source.index("static bool\ntls_process("))
    end=source.index('    dmsg(D_TLS_DEBUG, "TLS: tls_process: timeout set',begin)
    harness=d.PREAMBLE+functions+"\nstatic void original_schedule(struct key_state *ks, const struct tls_session *session, interval_t *wakeup) {\n"+source[begin:end]+"}\n"+d.CHECKS.replace("int main(void)","int original_main(void)")+CHECK
    with tempfile.TemporaryDirectory(prefix="review-promotion-") as tmp:
        p=Path(tmp)
        (p/"review.c").write_text(harness)
        subprocess.run([args.cc,"-std=c11","-Wall","-Wextra","-Werror","-O2",str(p/"review.c"),"-o",str(p/"review")],check=True,timeout=30)
        subprocess.run([str(p/"review")],check=True,timeout=5)

if __name__=="__main__":
    main()
