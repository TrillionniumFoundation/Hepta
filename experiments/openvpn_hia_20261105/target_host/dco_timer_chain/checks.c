struct fixture { struct tls_options opt; struct tls_multi multi; struct tuntap tun; struct signal_info sig; struct context ctx; };
static void fixture_init(struct fixture *f)
{
 memset(f,0,sizeof(*f)); now=100; tls_calls=0;callback_status=TLSMP_INACTIVE;generation_pending=0;
 f->opt.handshake_window=60;f->opt.renegotiate_seconds=10;
 f->multi.session[TM_ACTIVE].opt=&f->opt;
 for(int i=0;i<2;++i) {
  struct key_state *k=&f->multi.session[TM_ACTIVE].key[i];
  k->state=S_GENERATED_KEYS;k->authenticated=KS_AUTH_TRUE;
  k->crypto_options.key_ctx_bi.initialized=true;k->send_reliable=BIG_TIMEOUT;
 }
 struct key_state *newkey=get_key_scan(&f->multi,0),*oldkey=get_key_scan(&f->multi,1);
 newkey->key_id=1;newkey->established=100;newkey->auth_deferred_expire=100+auth_deferred_expire_window(&f->opt);newkey->dco_status=DCO_INSTALLED_SECONDARY;
 oldkey->key_id=0;oldkey->established=90;oldkey->auth_deferred_expire=95;oldkey->dco_status=DCO_INSTALLED_PRIMARY;
 f->multi.dco=&f->tun.dco;f->multi.dco_peer_id=0;f->multi.dco_keys_installed=2;
 f->tun.dco.slots[0]=0;f->tun.dco.slots[1]=1;
 f->ctx.options.dco=true;f->ctx.options.mode=MODE_SERVER;
 f->ctx.sig=&f->sig;f->ctx.c1.tuntap=&f->tun;f->ctx.c2.tls_multi=&f->multi;
 interval_init(&f->ctx.c2.tmp_int,2,15);
}
static void service(struct fixture *f, int other_timer)
{
 /* Driver supplies an independent timeout; no actual OS event wait or coarse
    timer engine is executed. The exact check_tls preserves the smaller limit. */
 f->ctx.c2.timeval.tv_sec=other_timer;f->ctx.c2.timeval.tv_usec=0;
 check_tls(&f->ctx);
}
static unsigned assertions=0;
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1; } ++assertions; } while(0)
int main(int argc,char **argv)
{
 struct fixture f;fixture_init(&f);service(&f,BIG_TIMEOUT);
 const int initial_timeout=(int)f.ctx.c2.timeval.tv_sec;
 if(argc==2 && strcmp(argv[1],"--require-promotion-deadline")==0) {
  printf("initial_timeout=%d expected_max=5 candidate=%d\n",initial_timeout,CANDIDATE);
  return initial_timeout<=5 ? 0 : 23;
 }
 CHECK(initial_timeout==(CANDIDATE ? 5 : 10));CHECK(tls_calls==1);CHECK(f.tun.dco.swap_calls==0);
 CHECK(f.ctx.c2.tmp_int.future_trigger==110);
 now=105;CHECK(tls_select_encryption_key(&f.multi)->key_id==1);CHECK(f.tun.dco.slots[0]==0);
 if(CANDIDATE) { service(&f,BIG_TIMEOUT);CHECK(tls_calls==1);CHECK(f.tun.dco.slots[0]==1);CHECK(f.tun.dco.last_swap==105); }
 else { CHECK(initial_timeout>now-100);CHECK(f.tun.dco.swap_calls==0); }
 /* An unrelated readiness callback at t=106 masks lateness. This is before
    next renegotiation, so this harness never pretends to execute a soft reset. */
 now=106;service(&f,BIG_TIMEOUT);CHECK(f.tun.dco.slots[0]==1);CHECK(tls_calls==1);
 CHECK(f.tun.dco.swap_calls==1);CHECK(f.tun.dco.last_swap==(CANDIDATE ? 105 : 106));
 const int first_swap=(int)f.tun.dco.last_swap;
 /* Timely external service masks the absent dedicated timer in both variants. */
 fixture_init(&f);service(&f,1);CHECK(f.ctx.c2.timeval.tv_sec==1);
 now=105;service(&f,1);CHECK(f.tun.dco.last_swap==105);CHECK(tls_calls==1);CHECK(f.ctx.c2.timeval.tv_sec==1);
 /* Other earlier TLS deadlines retain priority. */
 fixture_init(&f);get_key_scan(&f.multi,0)->send_reliable=3;service(&f,BIG_TIMEOUT);CHECK(f.ctx.c2.timeval.tv_sec==3);
 fixture_init(&f);get_key_scan(&f.multi,0)->must_negotiate=102;service(&f,BIG_TIMEOUT);CHECK(f.ctx.c2.timeval.tv_sec==2);
 /* Without old/mature secondary, new key is already the fallback selection. */
 fixture_init(&f);get_key_scan(&f.multi,1)->state=S_UNDEF;get_key_scan(&f.multi,0)->dco_status=DCO_INSTALLED_PRIMARY;
 f.multi.dco_keys_installed=1;f.tun.dco.slots[0]=1;f.tun.dco.slots[1]=-1;service(&f,BIG_TIMEOUT);
 CHECK(f.ctx.c2.timeval.tv_sec==10);CHECK(f.tun.dco.swap_calls==0);
 fixture_init(&f);get_key_scan(&f.multi,0)->authenticated=KS_AUTH_FALSE;service(&f,BIG_TIMEOUT);
 CHECK(f.ctx.c2.timeval.tv_sec==10);CHECK(f.tun.dco.swap_calls==0);
 fixture_init(&f);get_key_scan(&f.multi,0)->authenticated=KS_AUTH_DEFERRED;service(&f,BIG_TIMEOUT);
 CHECK(f.ctx.c2.timeval.tv_sec==10);CHECK(f.tun.dco.swap_calls==0);
 /* No polling overhead is added when DCO or its peer is absent. */
 fixture_init(&f);f.ctx.options.dco=false;service(&f,BIG_TIMEOUT);CHECK(f.ctx.c2.timeval.tv_sec==10);CHECK(f.tun.dco.swap_calls==0);
 fixture_init(&f);f.multi.dco_peer_id=-1;service(&f,BIG_TIMEOUT);CHECK(f.ctx.c2.timeval.tv_sec==10);CHECK(f.tun.dco.swap_calls==0);
 /* Kernel failures and inconsistent installed state retain exact fail-closed path. */
 fixture_init(&f);service(&f,BIG_TIMEOUT);now=105;f.tun.dco.swap_failure=1;service(&f,BIG_TIMEOUT);
 CHECK(f.sig.signal_received==SIGUSR1);CHECK(strcmp(f.sig.reason,"dco update keys error")==0);
 CHECK(f.tun.dco.slots[0]==0);CHECK(get_key_scan(&f.multi,0)->dco_status==DCO_INSTALLED_SECONDARY);
 fixture_init(&f);service(&f,BIG_TIMEOUT);now=105;get_key_scan(&f.multi,0)->dco_status=DCO_NOT_INSTALLED;service(&f,BIG_TIMEOUT);
 CHECK(f.sig.signal_received==SIGUSR1);CHECK(f.tun.dco.swap_calls==0);
 fixture_init(&f);get_key_scan(&f.multi,0)->authenticated=KS_AUTH_FALSE;get_key_scan(&f.multi,1)->authenticated=KS_AUTH_FALSE;service(&f,BIG_TIMEOUT);
 CHECK(f.multi.dco_keys_installed==0);CHECK(f.tun.dco.delete_calls==2);
 /* Generation after the timer calculation is explicitly simulated by callback.
    This mirrors ordering only; it does not execute real TLS key generation. */
 fixture_init(&f);get_key_scan(&f.multi,0)->state=S_ACTIVE;get_key_scan(&f.multi,0)->dco_status=DCO_NOT_INSTALLED;
 get_key_scan(&f.multi,0)->crypto_options.key_ctx_bi.initialized=false;f.multi.dco_keys_installed=1;f.tun.dco.slots[1]=-1;
 generation_pending=1;service(&f,BIG_TIMEOUT);
 CHECK(get_key_scan(&f.multi,0)->state==S_GENERATED_KEYS);CHECK(f.ctx.c2.timeval.tv_sec==(CANDIDATE ? 5 : 10));
 /* Already-mature key swaps immediately; repeated same-time service cannot spin
    on a past promotion deadline or perform a second successful swap. */
 fixture_init(&f);get_key_scan(&f.multi,0)->auth_deferred_expire=99;service(&f,BIG_TIMEOUT);
 CHECK(f.tun.dco.swap_calls==1);CHECK(f.ctx.c2.timeval.tv_sec==10);service(&f,BIG_TIMEOUT);
 CHECK(f.tun.dco.swap_calls==1);CHECK(f.ctx.c2.timeval.tv_sec==10);
 printf("{\"candidate\":%d,\"assertions\":%u,\"initial_timeout\":%d,\"controlled_first_swap\":%d,\"scope\":\"exact timer/key functions with explicit protocol/kernel/clock mocks\"}\n",CANDIDATE,assertions,initial_timeout,first_swap);
 return 0;
}
