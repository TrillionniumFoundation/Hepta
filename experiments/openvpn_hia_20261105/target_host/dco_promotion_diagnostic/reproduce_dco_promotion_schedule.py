#!/usr/bin/env python3
"""Offline source-derived DCO key-promotion scheduling counterexample.

Reads the pinned official ssl.c, compiles only selected pure scheduling/key
selection functions against explicit mock state, and checks a candidate timer.
No OpenVPN application, TLS connection, DCO device, or archive code is executed.
This is a diagnostic reproduction, not a protocol repair or target qualification.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

UPSTREAM_COMMIT = "dc1f569087135894ac2703aeabd7a960ee9452d4"
SSL_GIT_BLOB = "a2eee6a72c59b658aaa0308ebc8f2983efac1ffe"
SSL_SHA256 = "67ee11ca19cd8bc6622a93a4996717e02122befcb560624ca5443f3992d3ce58"


def function(source, declaration):
    start = source.index(declaration)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ssl_source", type=Path, help="official pinned src/openvpn/ssl.c")
    parser.add_argument("--cc", default="cc", help="installed C compiler")
    args = parser.parse_args()
    raw = args.ssl_source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SSL_SHA256:
        parser.error("source differs from the pinned, reviewed OpenVPN 2.7.8 ssl.c")
    git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if git_blob != SSL_GIT_BLOB:
        parser.error("source differs from the official upstream Git blob")
    source = raw.decode("utf-8")
    functions = "\n\n".join(function(source, decl) for decl in (
        "static inline void\ncompute_earliest_wakeup(",
        "static int\nauth_deferred_expire_window(",
        "struct key_state *\ntls_select_encryption_key(",
    ))
    begin = source.index("    /* When should we wake up again? */", source.index("static bool\ntls_process("))
    end = source.index('    dmsg(D_TLS_DEBUG, "TLS: tls_process: timeout set', begin)
    timers = source[begin:end]
    harness = PREAMBLE + functions + "\nstatic void original_schedule(struct key_state *ks, const struct tls_session *session, interval_t *wakeup) {\n" + timers + "}\n" + CHECKS
    with tempfile.TemporaryDirectory(prefix="openvpn-promotion-offline-") as tmp:
        tmp = Path(tmp)
        c = tmp / "schedule.c"
        binary = tmp / "schedule"
        c.write_text(harness)
        subprocess.run([args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(c), "-o", str(binary)], check=True, timeout=30)
        result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=5)
        print(result.stdout, end="")
    print("Pinned upstream:", UPSTREAM_COMMIT)
    print("Scope: pure extracted functions and mock state only; no target repair established.")


PREAMBLE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define ASSERT assert
#define S_UNDEF 0
#define S_ERROR_PRE 1
#define S_INITIAL 2
#define S_GENERATED_KEYS 3
#define KS_AUTH_FALSE 0
#define KS_AUTH_TRUE 1
#define KEY_SCAN_SIZE 3
#define BIG_TIMEOUT 100000
static time_t now;
typedef int interval_t;
struct tls_options { int handshake_window; int renegotiate_seconds; };
struct crypto_options { struct { bool initialized; } key_ctx_bi; };
struct key_state {
    int state, authenticated;
    time_t auth_deferred_expire, must_negotiate, established;
    interval_t send_reliable;
    struct crypto_options crypto_options;
};
struct tls_multi { struct key_state keys[KEY_SCAN_SIZE]; };
struct tls_session { const struct tls_options *opt; };
static struct key_state *get_key_scan(struct tls_multi *m, int i) { return &m->keys[i]; }
static interval_t reliable_send_timeout(interval_t value) { return value; }
"""

CHECKS = r"""
/* Candidate policy in this harness only. Not applied to official sources.
 * Revisit a future deadline that can change the selection. An already-mature
 * selection can only be displaced by an earlier scan key. If selection is the
 * fallback (no key mature yet), a later key can mature before that fallback.
 * Already-passed deadlines cannot cause busy loops.
 */
static void candidate_promotion_timer(struct tls_multi *multi, interval_t *wakeup)
{
    const struct key_state *selected = tls_select_encryption_key(multi);
    if (!selected) { return; }
    const bool mature = selected->auth_deferred_expire <= now;
    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        const struct key_state *ks = get_key_scan(multi, i);
        if (ks == selected && mature) { break; }
        if (ks != selected && ks->state >= S_GENERATED_KEYS
            && ks->authenticated == KS_AUTH_TRUE && ks->auth_deferred_expire > now
            && (mature || ks->auth_deferred_expire < selected->auth_deferred_expire))
        {
            compute_earliest_wakeup(wakeup, ks->auth_deferred_expire - now);
        }
    }
}

static struct tls_multi fixture(void)
{
    struct tls_multi m = {0};
    for (int i = 0; i < 2; ++i)
    {
        m.keys[i].state = S_GENERATED_KEYS;
        m.keys[i].authenticated = KS_AUTH_TRUE;
        m.keys[i].crypto_options.key_ctx_bi.initialized = true;
        m.keys[i].send_reliable = BIG_TIMEOUT;
    }
    m.keys[0].established = 100;
    m.keys[0].auth_deferred_expire = 105;
    m.keys[1].established = 90;
    m.keys[1].auth_deferred_expire = 95;
    return m;
}
static unsigned checks = 0;
#define CHECK(condition) do { assert(condition); ++checks; } while (0)
int main(void)
{
    const struct tls_options opt = {60, 10};
    const struct tls_session session = {&opt};
    struct tls_multi m = fixture();
    now = 100;
    CHECK(auth_deferred_expire_window(&opt) == 5);
    CHECK(tls_select_encryption_key(&m) == &m.keys[1]);
    interval_t wakeup = BIG_TIMEOUT;
    original_schedule(&m.keys[0], &session, &wakeup);
    CHECK(wakeup == 10);
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 5);
    now = 104;
    CHECK(tls_select_encryption_key(&m) == &m.keys[1]);
    now = 105;
    CHECK(tls_select_encryption_key(&m) == &m.keys[0]);
    wakeup = 5;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 5);
    now = 106;
    wakeup = 4;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 4);
    now = 100;
    m = fixture();
    m.keys[1].state = S_UNDEF;
    CHECK(tls_select_encryption_key(&m) == &m.keys[0]);
    wakeup = 10;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 10);
    m = fixture();
    m.keys[0].authenticated = KS_AUTH_FALSE;
    wakeup = 10;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 10);
    m = fixture();
    m.keys[0].state = S_INITIAL;
    wakeup = 10;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 10);
    m = fixture();
    m.keys[0].must_negotiate = 102;
    wakeup = BIG_TIMEOUT;
    original_schedule(&m.keys[0], &session, &wakeup);
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 2);
    m = fixture();
    m.keys[0].send_reliable = 1;
    wakeup = BIG_TIMEOUT;
    original_schedule(&m.keys[0], &session, &wakeup);
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 1);
    m = fixture();
    m.keys[0].authenticated = KS_AUTH_FALSE;
    m.keys[1].authenticated = KS_AUTH_FALSE;
    CHECK(tls_select_encryption_key(&m) == NULL);
    wakeup = 10;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 10);
    /* With no mature key, the fallback can be displaced by a later key. */
    m = fixture();
    m.keys[0].auth_deferred_expire = 110;
    m.keys[1].auth_deferred_expire = 105;
    CHECK(tls_select_encryption_key(&m) == &m.keys[0]);
    wakeup = 20;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 5);
    now = 105;
    CHECK(tls_select_encryption_key(&m) == &m.keys[1]);
    wakeup = 20;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 5);
    now = 110;
    CHECK(tls_select_encryption_key(&m) == &m.keys[0]);
    wakeup = 20;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 20);
    /* Equal deadlines do not displace the first scan key. */
    now = 100;
    m.keys[1].auth_deferred_expire = 110;
    wakeup = 20;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 20);
    /* Nor does a later key that matures after the fallback. */
    m.keys[1].auth_deferred_expire = 115;
    wakeup = 20;
    candidate_promotion_timer(&m, &wakeup);
    CHECK(wakeup == 20);
    printf("PASS %u offline assertions: original wakeup 10 s; candidate promotion wakeup 5 s.\n", checks);
    return 0;
}
"""

if __name__ == "__main__":
    main()
