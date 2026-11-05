#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#define ASSERT assert
#define CLEAR(x) memset(&(x),0,sizeof(x))
#define dmsg(...) ((void)0)
#define msg(...) ((void)0)
#define INTERVAL_DEBUG 0
#define BIG_TIMEOUT 604800
#define S_ERROR_PRE (-1)
#define S_UNDEF 0
#define S_INITIAL 1
#define S_ACTIVE 7
#define S_GENERATED_KEYS 8
#define KS_AUTH_FALSE 0
#define KS_AUTH_DEFERRED 1
#define KS_AUTH_TRUE 2
#define KS_PRIMARY 0
#define KS_LAME_DUCK 1
#define KS_SIZE 2
#define TM_ACTIVE 0
#define TM_LAME_DUCK 2
#define TM_SIZE 3
#define KEY_SCAN_SIZE 3
#define DCO_NOT_INSTALLED 0
#define DCO_INSTALLED_PRIMARY 1
#define DCO_INSTALLED_SECONDARY 2
#define OVPN_KEY_SLOT_PRIMARY 0
#define OVPN_KEY_SLOT_SECONDARY 1
#define MODE_SERVER 1
#define TLSMP_INACTIVE 0
#define TLSMP_ACTIVE 1
#define TLSMP_RECONNECT 3
#define TLSMP_KILL 2
#define TLSMP_RESTART 4
typedef int interval_t;
typedef long tv_sec_t;
static time_t now;
struct interval { interval_t refresh,horizon; time_t future_trigger,last_action,last_test_true; };
struct key_ctx_bi { bool initialized; };
struct key_state { int state,authenticated,key_id,dco_status; time_t auth_deferred_expire,must_negotiate,established; interval_t send_reliable; struct { struct key_ctx_bi key_ctx_bi; } crypto_options; };
struct tls_options { int handshake_window,renegotiate_seconds; };
struct tls_session { const struct tls_options *opt; struct key_state key[KS_SIZE]; };
struct dco_context;
struct tls_multi { struct dco_context *dco; struct tls_session session[TM_SIZE]; int dco_keys_installed,dco_peer_id; const char *client_reason; };
struct dco_context { int slots[2],swap_calls,delete_calls,swap_failure; time_t last_swap; };
typedef struct dco_context dco_context_t;
struct buffer { int len; };
struct link_socket_actual { int unused; };
struct link_socket_info { int unused; };
struct event_timeout { int unused; };
struct signal_info { int signal_received; const char *reason; };
struct tuntap { dco_context_t dco; };
struct options { int mode; bool dco; };
struct context { struct options options; struct signal_info *sig; struct { struct tuntap *tuntap; } c1; struct { struct tls_multi *tls_multi; struct interval tmp_int; struct buffer to_link; struct link_socket_actual *to_link_addr; struct event_timeout wait_for_connect; struct timeval timeval; } c2; };
static int tls_calls,callback_status,generation_pending;
static bool dco_enabled(const struct options *o) { return o->dco; }
static void register_signal(struct signal_info *s,int sig,const char *reason) { s->signal_received=sig; s->reason=reason; }
static void update_time(void) { }
static struct link_socket_info *get_link_socket_info(struct context *c) { (void)c; return NULL; }
static void event_timeout_init(struct event_timeout *et,int sec,time_t timestamp) { (void)et;(void)sec;(void)timestamp; }
static void reset_coarse_timers(struct context *c) { (void)c; }
static void send_auth_failed(struct context *c,const char *reason) { (void)c;(void)reason; }
static interval_t reliable_send_timeout(interval_t value) { return value; }
static int dco_swap_keys(dco_context_t *d,int peer) { (void)peer; ++d->swap_calls; if(d->swap_failure) return -EIO; int t=d->slots[0];d->slots[0]=d->slots[1];d->slots[1]=t;d->last_swap=now;return 0; }
static int dco_del_key(dco_context_t *d,int peer,int slot) { (void)peer; ++d->delete_calls;d->slots[slot]=-1;return 0; }
