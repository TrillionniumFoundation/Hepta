#!/usr/bin/env python3
"""Execute pinned upstream timer/key functions with controlled clock and mocks.

This is not the full OpenVPN event loop, TLS handshake, kernel or target.
No networking, privilege, source replacement, or artifact execution occurs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

COMMIT = 'dc1f569087135894ac2703aeabd7a960ee9452d4'
SOURCES = {
 'ssl.c': ('67ee11ca19cd8bc6622a93a4996717e02122befcb560624ca5443f3992d3ce58', 'a2eee6a72c59b658aaa0308ebc8f2983efac1ffe'),
 'dco.c': ('597ea856a3c139005349a26b25df8c6cebc55cfd42f7027e1e1f439645af6aa6', '88b18386fd3ec1b652c108448804a27a3306997a'),
 'forward.c': ('71d9d69fb769950d87e9081c823d1a5ba581be8c9dff531e8867127f0c08c952', 'c1330b4a8dd163e378ed816a5cd54ec08a5dd08b'),
 'interval.c': ('b49971a1d7b88bcee4f34c2fa41e627026d33e96a691f546015ba5511990c799', 'c40a29a52f5d1dd7279dc8d7426482e848c349df'),
 'interval.h': ('9c5582f571cad1578f25f078816fb302c68ebb16f6437188cef93da7e709d900', 'f6d3503d91a7778ed9eb7c9d6d13fa0a6f335432'),
 'otime.h': ('a718a474646beccb83d22b946090d62156c8a39ccf04f78cdc4f3d006664e47b', 'ad79120b0ec218f940b4ba61c9a3022d0634bdbc'),
 'ssl_common.h': ('32b70f280625659c1fc9b5d13fd43fcbf6c5866b49ff2c5136be85095e2440fd', '9c90242fa381d10d96c42d83e76d385273b169e5'),
}


def function(source, declaration):
    begin=source.index(declaration)
    brace=source.index('{', begin)
    depth=1;end=brace+1
    while depth:
        depth += (source[end]=='{') - (source[end]=='}')
        end+=1
    return source[begin:end]


CANDIDATE = r'''
/* This helper and its call are the only candidate intervention. They exist
   solely in the generated controlled-timer translation unit. */
static void candidate_promotion_timer(struct tls_multi *multi, interval_t *wakeup)
{
 const struct key_state *selected=tls_select_encryption_key(multi);
 if(!selected) return;
 const bool mature=selected->auth_deferred_expire<=now;
 for(int i=0;i<KEY_SCAN_SIZE;++i) {
  const struct key_state *ks=get_key_scan(multi,i);
  if(ks==selected && mature) break;
  if(ks!=selected && ks->state>=S_GENERATED_KEYS && ks->authenticated==KS_AUTH_TRUE
     && ks->auth_deferred_expire>now
     && (mature || ks->auth_deferred_expire<selected->auth_deferred_expire))
   compute_earliest_wakeup(wakeup,ks->auth_deferred_expire-now);
 }
}
'''


def build_source(sources, candidate):
    pieces=[]
    def add(name, decl):
        pieces.append(function(sources[name], decl))
    add('ssl_common.h', 'static inline struct key_state *\nget_key_scan(')
    add('ssl.c', 'static inline void\ncompute_earliest_wakeup(')
    add('ssl.c', 'struct key_state *\ntls_select_encryption_key(')
    add('ssl.c', 'static int\nauth_deferred_expire_window(')
    add('otime.h', 'static inline void\ninterval_earliest_wakeup(')
    add('interval.c', 'void\ninterval_init(')
    for name in ['interval_test','interval_schedule_wakeup','interval_future_trigger','interval_action']:
        typ='bool' if name=='interval_test' else 'void'
        add('interval.h',f'static inline {typ}\n{name}(')
    add('dco.c','static struct key_state *\ndco_get_secondary_key(')
    add('dco.c','bool\ndco_update_keys(')
    # Exact final scheduler fragment, explicitly not a full tls_multi_process.
    ssl=sources['ssl.c'];begin=ssl.index('    /* When should we wake up again? */',ssl.index('static bool\ntls_process('))
    end=ssl.index('    dmsg(D_TLS_DEBUG, "TLS: tls_process: timeout set',begin)
    callback='''
/* Protocol callback stub: executes only the original final timer calculation.
   The fixture has empty reliable queues, no retirement in the test interval,
   and no TLS bytes. Real protocol/retirement/renegotiation is not executed. */
static int tls_multi_process(struct tls_multi *multi, struct buffer *buf,
 struct link_socket_actual **addr, struct link_socket_info *info, interval_t *wakeup)
{
 (void)buf;(void)addr;(void)info;++tls_calls;
 const struct tls_session *session=&multi->session[TM_ACTIVE];
 struct key_state *ks=&multi->session[TM_ACTIVE].key[KS_PRIMARY];
'''+ssl[begin:end]+'''
 /* Explicit ordering model: real tls_multi_process generates keys after its
    tls_process calls. This is a stubbed state change, not real TLS generation. */
 if(generation_pending) {
  ks->state=S_GENERATED_KEYS;ks->crypto_options.key_ctx_bi.initialized=true;
  ks->dco_status=DCO_INSTALLED_SECONDARY;multi->dco_keys_installed=2;
  multi->dco->slots[OVPN_KEY_SLOT_SECONDARY]=ks->key_id;generation_pending=0;
 }
 return callback_status;
}
'''
    pieces.append(callback)
    add('forward.c','static inline void\ncontext_reschedule_sec(')
    add('forward.c','void\ncheck_dco_key_status(')
    check=function(sources['forward.c'],'static void\ncheck_tls(')
    if candidate:
        marker='    interval_schedule_wakeup(&c->c2.tmp_int, &wakeup);'
        if check.count(marker)!=1:raise ValueError('candidate insertion anchor changed')
        check=check.replace(marker,marker+'''
    if (dco_enabled(&c->options) && c->c2.tls_multi->dco_peer_id != -1
        && c->c2.tls_multi->dco_keys_installed > 0)
    {
        candidate_promotion_timer(c->c2.tls_multi, &wakeup);
    }
''')
        pieces.append(CANDIDATE)
    pieces.append(check)
    root=Path(__file__).resolve().parent
    return f'#define CANDIDATE {int(candidate)}\n'+(root/'preamble.c').read_text()+'\n'+'\n\n'.join(pieces)+'\n'+(root/'checks.c').read_text()


def load_sources(directory):
    sources={}
    for name,(sha,blob) in SOURCES.items():
        raw=(directory/name).read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if hashlib.sha256(raw).hexdigest()!=sha or actual!=blob:
            raise ValueError('source differs from pinned official bytes: '+name)
        sources[name]=raw.decode()
    return sources


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_dir',type=Path)
    parser.add_argument('--cc',default='cc')
    args=parser.parse_args()
    try:
        sources=load_sources(args.source_dir)
    except ValueError as error:
        parser.error(str(error))
    compiler=subprocess.run([args.cc,'--version'],check=True,capture_output=True,text=True,timeout=5).stdout.splitlines()[0]
    result=[]
    with tempfile.TemporaryDirectory(prefix='dco-timer-chain-') as temp:
        temp=Path(temp)
        for candidate in [False,True]:
            source=build_source(sources,candidate)
            c=temp/('candidate.c' if candidate else 'original.c');c.write_text(source)
            for level in ['-O0','-O3']:
                binary=temp/('timer-'+str(int(candidate))+level[1:])
                subprocess.run([args.cc,'-std=c11','-Wall','-Wextra','-Werror',level,'-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(binary)],check=True,timeout=30)
                run=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=5)
                row=json.loads(run.stdout);row['optimization']=level;row['generated_c_sha256']=hashlib.sha256(source.encode()).hexdigest()
                punctual=subprocess.run([str(binary),'--require-promotion-deadline'],capture_output=True,text=True,timeout=5)
                expected=0 if candidate else 23
                if punctual.returncode!=expected:raise RuntimeError(f'wrong deadline counterexample outcome: {punctual}')
                row['deadline_requirement_exit']=punctual.returncode
                result.append(row)
    print(json.dumps({'upstream_commit':COMMIT,'official_source_identities':SOURCES,'compiler':compiler,
                      'mock_files_sha256':{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ['preamble.c','checks.c']},
                      'results':result,'target_qualified':False,'full_event_loop_executed':False},indent=2))

if __name__=='__main__':main()
