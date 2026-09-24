/* brisk.h - Brisk-SSL public API. Zero-dependency C99 TLS/QUIC client library for Linux IoT.
 *
 * This header is the API reference. Everything not declared here is internal and may change.
 * Contexts are plain structs owned by the caller: the library never allocates behind your back
 * and keeps no global state, so separate contexts may be used from separate threads.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef BRISK_H
#define BRISK_H

#include <stddef.h>
#include <stdint.h>

#include "brisk_config.h"

#define BRISK_SSL_VERSION_MAJOR  0
#define BRISK_SSL_VERSION_MINOR  1
#define BRISK_SSL_VERSION_PATCH  0
#define BRISK_SSL_VERSION_STRING "0.1.0-dev"

/* Symbol export: only a shared-library build (BRISK_SHARED_BUILD) exports the API. In a static
 * build it stays empty so a .so that embeds libbrisk.a keeps its own visibility policy.
 * Define BRISK_API yourself to override. */
#ifndef BRISK_API
#    if defined(BRISK_SHARED_BUILD) && defined(__GNUC__) && __GNUC__ >= 4
#        define BRISK_API __attribute__((visibility("default")))
#    else
#        define BRISK_API
#    endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------------------------------
 * Errors: functions return BRISK_OK (0) or a negative code.
 */
enum {
    BRISK_OK = 0,
    BRISK_E_ARG = -1,   /* invalid argument: unknown algorithm, length out of range, ... */
    BRISK_E_RNG = -2,   /* kernel randomness unavailable; seccomp filters must allow getrandom */
    BRISK_E_AUTH = -3,  /* a cryptographic check failed on data the peer sent: AEAD authentication
                         * (TLS bad_record_mac; no plaintext released), a signature that does not
                         * verify (TLS decrypt_error), or a certificate that is not acceptable. Never
                         * a caller mistake - that is BRISK_E_ARG. */
    BRISK_E_PROTO = -4, /* the peer violated the TLS protocol: a message out of order, a bad
                         * length, a field or extension the RFC forbids. The connection is dead
                         * and the fatal alert has been chosen; retrying the same peer will not
                         * help. Never a caller mistake (BRISK_E_ARG) or a failed check on the
                         * peer's credentials (BRISK_E_AUTH). */
    BRISK_E_PEER_ALERT = -5, /* the peer ended the connection with a fatal TLS alert (RFC 9846
                              * 6.2; its AlertDescription is kept on the connection, see
                              * brisk_alert). The connection is dead and every key is wiped;
                              * nothing is sent back. Whether a retry helps depends on the alert:
                              * internal_error may be transient, handshake_failure or
                              * bad_certificate are not. A close_notify or user_canceled that
                              * arrives BEFORE the handshake completed is reported here too
                              * (never as a clean end of data: nothing was authenticated yet).
                              * brisk_h2_*: the HTTP/2 server reset the stream (RST_STREAM with a
                              * code other than NO_ERROR / REFUSED_STREAM) or ended the connection
                              * with a GOAWAY carrying an error code. */
    BRISK_E_IO = -6,         /* the network failed (blocking API only): DNS, socket or connect
                              * error, a send/recv error, the peer's TCP FIN before its
                              * close_notify (a truncation, RFC 9846 6.1 - never reported as a clean
                              * EOF), or the connection's one malloc failing. */
    BRISK_E_TIMEOUT = -7,    /* a blocking call waited cfg.timeout_ms without progress. From
                              * brisk_read it is harmless - nothing is lost, call it again. From
                              * brisk_connect the attempt failed and *out is NULL (nothing to
                              * close; retrying is up to you). From brisk_write it is final: a
                              * half-sent record may be on the wire, so the connection only
                              * accepts brisk_close, and later brisk_read / brisk_write calls
                              * return BRISK_E_IO. */
    BRISK_E_WANT = -8,       /* sans-I/O only, and not a failure: "feed me more bytes first" -
                              * brisk_status while the handshake is still running, brisk_app_read
                              * when no application data has arrived yet. */
    BRISK_E_RETRY = -9       /* HTTP/2 only: the server guaranteed it did NOT process this request
                              * (RFC 9113 8.7: RST_STREAM REFUSED_STREAM, a stream above a GOAWAY's
                              * last stream id, or a request made after a GOAWAY). Safe to retry on
                              * a NEW connection, even a POST. */
};

/* Library version, e.g. "0.1.0-dev". */
BRISK_API const char *brisk_version(void);

/* What this binary was compiled with, e.g. "0.1.0-dev profile=DEFAULT". The same text is embedded
 * as "@(#)BRISKCFG ..." so `strings firmware.bin | grep BRISKCFG` works on a shipped image. */
BRISK_API const char *brisk_build_info(void);

/* ------------------------------------------------------------------------------------------------
 * Hashes: SHA-256, SHA-384, SHA-512 (FIPS 180-4).
 *
 * Streaming: *_init, then *_update any number of times with any lengths, then *_final, which
 * writes the digest and wipes the context. One-shot helpers do all three.
 */
#define BRISK_SHA256_LEN   32
#define BRISK_SHA384_LEN   48
#define BRISK_SHA512_LEN   64
#define BRISK_HASH_MAX_LEN 64

typedef struct {
    uint32_t h[8];
    uint64_t len; /* bytes hashed so far */
    uint8_t buf[64];
} brisk_sha256_ctx;

typedef struct {
    uint64_t h[8];
    uint64_t len; /* bytes hashed so far (messages must be < 2^61 bytes) */
    uint8_t buf[128];
} brisk_sha512_ctx;

typedef brisk_sha512_ctx brisk_sha384_ctx; /* SHA-384 is SHA-512 with other IVs, truncated */

BRISK_API void brisk_sha256_init(brisk_sha256_ctx *c);
BRISK_API void brisk_sha256_update(brisk_sha256_ctx *c, const void *data, size_t len);
BRISK_API void brisk_sha256_final(brisk_sha256_ctx *c, uint8_t out[BRISK_SHA256_LEN]);
BRISK_API void brisk_sha256(const void *data, size_t len, uint8_t out[BRISK_SHA256_LEN]);

BRISK_API void brisk_sha384_init(brisk_sha384_ctx *c);
BRISK_API void brisk_sha384_update(brisk_sha384_ctx *c, const void *data, size_t len);
BRISK_API void brisk_sha384_final(brisk_sha384_ctx *c, uint8_t out[BRISK_SHA384_LEN]);
BRISK_API void brisk_sha384(const void *data, size_t len, uint8_t out[BRISK_SHA384_LEN]);

BRISK_API void brisk_sha512_init(brisk_sha512_ctx *c);
BRISK_API void brisk_sha512_update(brisk_sha512_ctx *c, const void *data, size_t len);
BRISK_API void brisk_sha512_final(brisk_sha512_ctx *c, uint8_t out[BRISK_SHA512_LEN]);
BRISK_API void brisk_sha512(const void *data, size_t len, uint8_t out[BRISK_SHA512_LEN]);

/* ------------------------------------------------------------------------------------------------
 * HMAC (RFC 2104) over SHA-256/384/512. Useful on its own for cloud auth tokens
 * (e.g. Azure IoT SAS tokens, AWS SigV4).
 */
typedef enum { BRISK_HASH_SHA256 = 1, BRISK_HASH_SHA384 = 2, BRISK_HASH_SHA512 = 3 } brisk_hash_alg;

/* Digest length in bytes of `alg`, or 0 if `alg` is not a valid brisk_hash_alg. */
BRISK_API size_t brisk_hash_len(brisk_hash_alg alg);

typedef union {
    brisk_sha256_ctx sha256;
    brisk_sha512_ctx sha512;
} brisk_hash_ctx;

typedef struct {
    brisk_hash_ctx inner, outer; /* keyed states */
    int alg;
} brisk_hmac_ctx;

/* Returns BRISK_OK, or BRISK_E_ARG for an unknown algorithm. The key may be any length. */
BRISK_API int brisk_hmac_init(brisk_hmac_ctx *c, brisk_hash_alg alg, const void *key,
                              size_t key_len);
BRISK_API void brisk_hmac_update(brisk_hmac_ctx *c, const void *data, size_t len);
/* Writes brisk_hash_len(alg) bytes and wipes the context. */
BRISK_API void brisk_hmac_final(brisk_hmac_ctx *c, uint8_t *out);
BRISK_API int brisk_hmac(brisk_hash_alg alg, const void *key, size_t key_len, const void *data,
                         size_t len, uint8_t *out);

/* ------------------------------------------------------------------------------------------------
 * Client-certificate signing hook (mTLS, BRISK_ENABLE_MTLS).
 *
 * The library can sign with its own ECDSA P-256 key, but a device key is better off in a secure
 * element, a TPM or an HSM, where this process never sees it. Set this callback on the client
 * config (M3) and the handshake calls it once, for CertificateVerify, synchronously from inside
 * the call that fed the server's Finished - a slow element blocks that call. Declared in every
 * profile (a typedef costs nothing) so config structs keep one layout; a build without
 * BRISK_ENABLE_MTLS refuses a client certificate at setup.
 */
#define BRISK_SIG_ECDSA_P256_LEN 64 /* raw r || s; the DER wrap is the handshake layer's job */

/*   ctx      opaque, passed through unchanged.
 *   scheme   a TLS SignatureScheme code point (RFC 9846 4.3.3). 0x0403 = ecdsa_secp256r1_sha256
 *            is the only value this client offers today; reject anything else with BRISK_E_ARG.
 *   tbs      the raw to-be-signed bytes, NOT a digest: a secure element that hashes internally
 *            needs them, and a software signer hashes them with the scheme's own H.
 *   sig      output buffer of sig_cap bytes. Write the RAW signature - r || s, 64 bytes for
 *            P-256 - and set *sig_len. Deliberately not DER: the handshake layer already owns
 *            one ECDSA-Sig-Value encoder, and returning DER here would make every integrator
 *            write a second one for a PKCS#11 or TPM output that is raw to begin with. Writing
 *            more than sig_cap is a failure, never a truncation.
 * Return BRISK_OK, or a negative BRISK_E_* to abort the handshake (BRISK_E_ARG for an
 * unsupported scheme, BRISK_E_AUTH if the element refused to sign). */
typedef int (*brisk_sign_fn)(void *ctx, uint16_t scheme, const uint8_t *tbs, size_t tbs_len,
                             uint8_t *sig, size_t sig_cap, size_t *sig_len);

/* ------------------------------------------------------------------------------------------------
 * Session resumption (RFC 9846 2.2, 4.7.1): a NewSessionTicket is exported as one opaque blob of
 * at most BRISK_TICKET_MAX bytes, which the caller stores and hands back on the next connection
 * to the same host. A fixed size, not a knob; a ticket that does not fit is simply not
 * resumable (never an error for the connection).
 *
 * THE BLOB IS KEY MATERIAL: it holds the resumption PSK, and anyone who has it can resume as
 * this client until it expires (at most 7 days, RFC 9846 4.7.1). Store it like a private key and
 * delete it once it has been offered - a ticket is single-use (RFC 9846 C.4).
 */
#define BRISK_TICKET_MAX 2048

/* Called with each exported ticket blob (len <= BRISK_TICKET_MAX), synchronously, from inside
 * the brisk_feed / brisk_read that received the NewSessionTicket. The blob lives on the stack
 * and is wiped when this returns: copy it. Store it for at most 7 days and hand it back as
 * cfg.ticket on the next connection to the SAME host string; delete it once offered. Tickets
 * that cannot be exported (too large, lifetime 0) never reach this and never hurt the
 * connection. */
typedef void (*brisk_ticket_fn)(void *ctx, const uint8_t *blob, size_t len);

/* ------------------------------------------------------------------------------------------------
 * TLS 1.3 client connection (RFC 9846).
 *
 * The connection is a byte stream: brisk_connect, brisk_write, brisk_read, brisk_close. What you
 * send over it - MQTT, HTTP/1.1, anything - is yours; nothing here speaks an application
 * protocol, and nothing switches protocols behind your back (ALPN is only a list you offer and
 * an answer you read).
 *
 * SECURE BY DEFAULT: a zero brisk_cfg (BRISK_DEFAULTS) is the recommended configuration - the
 * system CA bundle, full chain + RFC 9525 host name checks, no ALPN, no resumption, no client
 * certificate, 10 s timeouts. Certificate verification cannot be switched off. There is no
 * 0-RTT, renegotiation, compression or non-AEAD suite in this library.
 *
 * LIFETIMES: nothing in the config is copied. ca_file, ca_mem, alpn, client_chain, client_key
 * and ticket must stay valid and unchanged until the connection is closed (the ticket is re-read
 * if the server sends a HelloRetryRequest, the anchors whenever a chain is verified).
 * client_key is never copied and never wiped by the library: protecting and wiping it is yours.
 */
typedef struct {
    /* Trust anchors (RFC 5280 6.1). Which store is used:
     *   ca_file NULL, ca_mem NULL   the system bundle, autodetected (Debian/OpenWrt/Alpine/Fedora
     *                               /openSUSE paths; $SSL_CERT_FILE is deliberately ignored).
     *   ca_mem only                 ONLY those anchors - a private IoT CA does not also trust the
     *                               whole Web PKI. To add the system store, set ca_file too.
     *   ca_file set                 that PEM bundle file (plus ca_mem when set).
     * Fewer anchors can only refuse more connections, never accept one the rule above would not.
     * A bundle that cannot be read holds no anchors: the handshake fails with bad_certificate. */
    const char *ca_file;   /* path of a PEM bundle, scanned per lookup (never cached in RAM) */
    const uint8_t *ca_mem; /* concatenated DER certificates (first byte 0x30), or PEM text with
                            * one or more BEGIN CERTIFICATE blocks; used in place, not copied */
    size_t ca_mem_len;
    /* ALPN (RFC 7301) as one comma-separated string, preference order: "h2,http/1.1", "mqtt",
     * "x-amzn-http-ca". NULL = no ALPN extension. Each name is 1..255 bytes; an empty name
     * ("", ",", "a,,b", a leading or trailing comma) or an encoded list over 256 bytes is
     * BRISK_E_ARG. A name that itself contains a comma cannot be expressed. The server's choice
     * is brisk_alpn(); whether "none" is acceptable is your decision. */
    const char *alpn;
    /* mTLS, ECDSA P-256 only (BRISK_ENABLE_MTLS; a build without it refuses these with
     * BRISK_E_ARG). client_chain: concatenated DER certificates, leaf first, whose leaf key is
     * P-256. Then EXACTLY ONE of client_key (the 32-byte big-endian private scalar d) or sign
     * (a callback, e.g. into a secure element; sign_ctx is passed through). The chain is sent
     * only when the server asks for a certificate and accepts ecdsa_secp256r1_sha256. */
    const uint8_t *client_chain;
    size_t client_chain_len;
    const uint8_t *client_key;
    brisk_sign_fn sign;
    void *sign_ctx;
    /* Resumption (RFC 9846 2.2): ticket = a blob from a previous on_ticket for this host, or
     * NULL. A blob that is malformed, for another host, expired (7 days at most) or too large to
     * offer is silently ignored and a full handshake runs; brisk_resumed() tells which happened.
     * on_ticket receives the server's new tickets (NULL = tickets are ignored). */
    const uint8_t *ticket;
    size_t ticket_len;
    brisk_ticket_fn on_ticket;
    void *ticket_ctx;
    /* Blocking API only, in ms; 0 = 10000. brisk_connect: TCP connect + handshake together
     * (DNS resolution comes before and is NOT bounded by it: getaddrinfo has no timeout).
     * brisk_read / brisk_write: the longest wait without any progress. */
    uint32_t timeout_ms;
    /* No runtime certificate-time floor yet: the clock policy is compile-time
     * (BRISK_X509_TIME_POLICY / BRISK_X509_TIME_FLOOR in brisk_config.h). A device that stores a
     * last-known-good time must NOT pass it off as the clock - see docs/ROADMAP.md. */
} brisk_cfg;

#define BRISK_DEFAULTS {0}

/* One connection. Opaque: its size is brisk_conn_size(), and nothing about it depends on
 * brisk_config.h. Not thread-safe: one connection, one thread at a time. */
typedef struct brisk_conn brisk_conn;

/* ---- blocking API (Linux) ----------------------------------------------------------------------
 * One malloc per connection (brisk_conn_size() + 6 KB of socket buffers), nothing else. */

/* Resolve `host`, connect over TCP (IPv4 or IPv6, each address in turn) and complete the TLS 1.3
 * handshake: returns once the server is authenticated and our last handshake flight is sent.
 * `host` is ONE string used for DNS, SNI (omitted for an IP literal), the RFC 9525 certificate
 * name check and ticket matching: a DNS name (A-labels for IDNs, one trailing dot allowed) or an
 * IP literal, 1..255 bytes.
 * BRISK_OK with *out set, else *out = NULL and: BRISK_E_ARG (bad cfg/host), BRISK_E_RNG,
 * BRISK_E_IO, BRISK_E_TIMEOUT, BRISK_E_AUTH (the server's certificate or signature is not
 * acceptable), BRISK_E_PROTO or BRISK_E_PEER_ALERT. Needs -lrt on glibc older than 2.17. */
BRISK_API int brisk_connect(const brisk_cfg *cfg, const char *host, uint16_t port,
                            brisk_conn **out);

/* Up to min(cap, INT_MAX) bytes of application data. Returns > 0 bytes, 0 once the server sent
 * close_notify (clean end of data), or < 0: BRISK_E_TIMEOUT (nothing lost, retry), BRISK_E_IO
 * (also a TCP close without close_notify: possible truncation, or a stuck send of an owed
 * KeyUpdate answer), BRISK_E_AUTH / BRISK_E_PROTO /
 * BRISK_E_PEER_ALERT / BRISK_E_ARG (the connection is dead). Post-handshake messages
 * (NewSessionTicket, KeyUpdate) are handled inside. */
BRISK_API int brisk_read(brisk_conn *c, void *buf, size_t cap);

/* Send all `len` bytes, or fail: BRISK_OK or < 0. Any failure is final (a record may be half
 * sent). Writing after the server's close_notify is allowed (RFC 9846 6.1). */
BRISK_API int brisk_write(brisk_conn *c, const void *buf, size_t len);

/* Send close_notify (best effort, waiting at most 1 s), close the socket, wipe and free
 * everything. For connections from brisk_connect only. NULL is a no-op. */
BRISK_API void brisk_close(brisk_conn *c);

/* ---- sans-I/O API: your own event loop, your own memory --------------------------------------
 * The same connection with no socket and no allocation: you move bytes between the network and
 * brisk_feed / brisk_pull. Typical loop:
 *   brisk_conn_init(mem, sizeof mem, &cfg, host, &c);
 *   loop: send what brisk_pull gives; recv and brisk_feed; drain brisk_app_read;
 *         brisk_app_write to send data, then send its output.
 * Errors are sticky: after one, every call returns it, and brisk_pull yields the single fatal
 * alert to send (RFC 9846 6.2) - send it, then close the transport. */

/* Bytes of memory brisk_conn_init needs (any alignment). Most of it is the 16.6 KB receive
 * record buffer RFC 9846 5.2 requires and the handshake reassembly buffer, which stays alive
 * for post-handshake messages. */
BRISK_API size_t brisk_conn_size(void);

/* Set up a connection in mem[0..mem_len) (mem_len >= brisk_conn_size()) and queue the
 * ClientHello. Draws its randomness from the kernel and reads the wall clock ONCE: that time is
 * used for the certificate check and to stamp received tickets for the whole connection, so a
 * connection that lives for days stamps late tickets as older than they are (the only effect: a
 * server may refuse to resume from them). Same `host` rules as brisk_connect. BRISK_OK and *out
 * (pointing into mem), or BRISK_E_ARG / BRISK_E_RNG with *out = NULL. Linux only. */
BRISK_API int brisk_conn_init(void *mem, size_t mem_len, const brisk_cfg *cfg, const char *host,
                              brisk_conn **out);

/* Take bytes received from the server, in any split. *used = bytes consumed; it is short of len
 * while decrypted application data waits to be read (brisk_app_read, then feed the rest).
 * BRISK_OK, or a sticky BRISK_E_AUTH / BRISK_E_PROTO / BRISK_E_ARG (then brisk_pull the alert)
 * or BRISK_E_PEER_ALERT. */
BRISK_API int brisk_feed(brisk_conn *c, const void *in, size_t len, size_t *used);

/* Bytes to send to the server: whole TLS records only, as many as fit in cap. 0 = nothing to
 * send, or the next record does not fit (give more room; handshake records shrink to fit any
 * cap above 28 bytes, and 4 KB always suffices). Call it after init, after every brisk_feed and
 * after brisk_close_notify. */
BRISK_API size_t brisk_pull(brisk_conn *c, void *out, size_t cap);

/* BRISK_OK once connected, BRISK_E_WANT while handshaking, else the sticky error. */
BRISK_API int brisk_status(const brisk_conn *c);

/* Received application data: BRISK_OK with *n > 0 bytes; BRISK_OK with *n == 0 = the server
 * sent close_notify (clean end); BRISK_E_WANT = nothing yet; else the sticky error. cap > 0. */
BRISK_API int brisk_app_read(brisk_conn *c, void *out, size_t cap, size_t *n);

/* Encrypt application data into out[0..cap): *used = plaintext bytes taken, *out_len = bytes to
 * send (it may also carry owed handshake records). A short *used means out is full: send, then
 * call again with the rest. BRISK_E_ARG before the handshake completed or after
 * brisk_close_notify; else the sticky error. */
BRISK_API int brisk_app_write(brisk_conn *c, const void *data, size_t len, size_t *used, void *out,
                              size_t cap, size_t *out_len);

/* Queue close_notify (RFC 9846 6.1) for brisk_pull. Nothing can be written after it; the
 * server's remaining data can still be read. BRISK_E_ARG before the handshake completed (to
 * abandon a handshake, just brisk_conn_wipe); the sticky error once failed. */
BRISK_API int brisk_close_notify(brisk_conn *c);

/* The TLS AlertDescription that ended the connection - the one we sent, or the server's (with
 * BRISK_E_PEER_ALERT; 0 then means close_notify) - or 0 while nothing ended it. */
BRISK_API int brisk_alert(const brisk_conn *c);

/* The ALPN protocol the server selected: *name (not NUL-terminated, valid while c lives) and
 * *len; *len == 0 = none. BRISK_E_ARG before the handshake completed. */
BRISK_API int brisk_alpn(const brisk_conn *c, const char **name, size_t *len);

/* 1 if the handshake resumed a session from cfg.ticket (no certificate was checked on this
 * connection: the ticket vouches for the server it was issued by), else 0. */
BRISK_API int brisk_resumed(const brisk_conn *c);

/* The protocol version once the handshake completed: 0x0304 (TLS 1.3) or 0x0303 (TLS 1.2, only
 * in a build with BRISK_ENABLE_TLS12, when the server does not speak TLS 1.3). BRISK_E_ARG
 * before. TLS 1.2 here is ECDHE + AEAD with the extended main secret, no resumption (so
 * brisk_resumed() is 0) and no renegotiation: a server's HelloRequest gets one warning
 * no_renegotiation alert and the connection goes on. As in TLS 1.3, answer the server's
 * close_notify with brisk_close / brisk_close_notify (RFC 5246 7.2.1). mTLS over TLS 1.2 needs
 * client_key: with a `sign` callback a TLS 1.2 server asking for the certificate fails the
 * handshake with internal_error (the callback contract is raw to-be-signed bytes, and TLS 1.2
 * signs the whole handshake transcript). */
BRISK_API int brisk_tls_version(const brisk_conn *c);

/* Wipe every key, secret and buffer of a sans-I/O connection; afterwards the memory given to
 * brisk_conn_init is all zero again (bar bytes it held before init that alignment skipped) and
 * may be freed or reused. NULL-safe. Closes nothing. */
BRISK_API void brisk_conn_wipe(brisk_conn *c);

/* ------------------------------------------------------------------------------------------------
 * HTTP/2 client (RFC 9113), BRISK_ENABLE_H2 (DEFAULT / FULL). Declared in every profile; a build
 * without it simply has no brisk_h2_* symbols.
 *
 * An optional module you call explicitly over a connected brisk_conn whose ALPN you chose
 * (cfg.alpn = "h2" or "h2,http/1.1") and the server selected: brisk_alpn() must say exactly "h2".
 * Nothing switches protocols for you. Blocking, single-threaded, no malloc: all state lives in
 * the brisk_h2_size() bytes you pass to brisk_h2_open. Typical use:
 *   brisk_connect(&cfg, "api.example.com", 443, &c);
 *   brisk_h2_open(c, mem, sizeof mem, &h);
 *   brisk_h2_request(h, "GET", "/v1/status", hdrs, 1, NULL, 0, &s);
 *   brisk_h2_response(s, &status, on_header, ctx);
 *   while ((n = brisk_h2_read(s, buf, sizeof buf)) > 0) { ... }   (0 = complete, < 0 = error)
 *   brisk_h2_stream_close(s); brisk_h2_close(h); brisk_close(c);
 *
 * Up to BRISK_H2_MAX_STREAMS requests (and never more than the server's
 * SETTINGS_MAX_CONCURRENT_STREAMS) may be open at once; reading one stream buffers the others'
 * headers and data (up to BRISK_H2_STREAM_WINDOW bytes each - the flow-control window this client
 * advertises, so nothing is ever dropped). A slot is held until brisk_h2_stream_close.
 *
 * ERRORS. A connection-level protocol violation by the server sends GOAWAY and makes every later
 * call on the handle and all its streams return BRISK_E_PROTO. A malformed response (RFC 9113
 * 8.1.1: bad :status, uppercase or connection-specific fields, content-length that does not match
 * the DATA...) resets only that stream: its calls return BRISK_E_PROTO, the others continue.
 * BRISK_E_RETRY: see the error list. BRISK_E_PEER_ALERT: the server reset the stream or sent
 * GOAWAY with an error. BRISK_E_IO: the TLS connection ended (close_notify or failure) before the
 * stream completed. BRISK_E_TIMEOUT from brisk_h2_response / brisk_h2_read is harmless (call
 * again); from brisk_h2_request it cancels that request (RST_STREAM). A failed write is final for
 * the whole handle. BRISK_E_ARG is always a caller mistake (or a local limit named below).
 *
 * LIMITS (documented deviations): a response header section is limited to
 * BRISK_H2_MAX_HEADER_LIST octets (default 8192, our SETTINGS_MAX_HEADER_LIST_SIZE; a larger one
 * is a connection error, COMPRESSION_ERROR); one request header field (name + value) must stay
 * 16 octets under that limit; interim 1xx responses and
 * trailers are validated and discarded; frames for a stream you already closed are ignored.
 * Server push is disabled (SETTINGS_ENABLE_PUSH = 0), priority signals are ignored, CONNECT and
 * extended CONNECT are not supported. brisk_h2_open is Linux-only (blocking brisk_conn).
 */
typedef struct brisk_h2 brisk_h2;               /* opaque, lives in the caller's memory */
typedef struct brisk_h2_stream brisk_h2_stream; /* opaque, a slot inside that memory */

typedef struct {
    const char *name;  /* lowercase field name, NUL-terminated; no pseudo-headers (":...") */
    const char *value; /* NUL-terminated; no CR / LF, no leading or trailing SP / HTAB */
} brisk_h2_header;

/* Called once per response header field (never for :status), synchronously from
 * brisk_h2_response, in the order the server sent them. name / value are NUL-terminated copies
 * valid only during the call. It must not call any brisk_h2_* function. */
typedef void (*brisk_h2_header_fn)(void *ctx, const char *name, size_t name_len, const char *value,
                                   size_t value_len);

/* Bytes of memory brisk_h2_open needs (any alignment). About 66 KB with the defaults
 * (4 streams x (8 KB window + 4 KB headers) + 17 KB of frame, HPACK and I/O buffers). */
BRISK_API size_t brisk_h2_size(void);

/* Start HTTP/2 on c (from brisk_connect, whose ALPN answer is "h2"): send the connection preface
 * and our SETTINGS, then wait for the server's SETTINGS. mem[0..mem_len) must stay valid until
 * brisk_h2_close. BRISK_OK and *out, else *out = NULL and: BRISK_E_ARG (NULL / short mem, a
 * sans-I/O connection, ALPN not "h2"), brisk_read / brisk_write errors, BRISK_E_PROTO (the server
 * preface is not a valid SETTINGS frame). The :authority of every request is the host c was
 * opened with (IPv6 literals in brackets, ":port" appended when it is not 443). Linux only. */
BRISK_API int brisk_h2_open(brisk_conn *c, void *mem, size_t mem_len, brisk_h2 **out);

/* Send one request: :method = method (a token; CONNECT is refused), :scheme https, :authority,
 * :path = path ("/..." or "*" for OPTIONS), then hdrs[0..n) in order, then body[0..body_len)
 * with flow control (END_STREAM on the last frame; on the HEADERS when body_len is 0). Returns
 * once everything is sent, reading server frames meanwhile when a flow-control window is shut.
 * BRISK_OK and *out, else *out = NULL and:
 *   BRISK_E_ARG   bad method / path / header (uppercase or invalid octets, any ":" name, "host",
 *                 connection / keep-alive / proxy-connection / transfer-encoding / upgrade, "te"
 *                 other than "trailers", content-length != body_len), a header section larger
 *                 than the server's SETTINGS_MAX_HEADER_LIST_SIZE, all streams held (at most
 *                 BRISK_H2_MAX_STREAMS and the server's limit - close one first), or stream ids
 *                 exhausted (2^31: open a new connection);
 *   BRISK_E_RETRY the server sent GOAWAY (or refused this stream): retry on a new connection;
 *   others        as listed above.
 * authorization / proxy-authorization / cookie / set-cookie are sent never-indexed (RFC 7541
 * 7.1.3). The server may answer before the upload ends: a complete response followed by
 * RST_STREAM NO_ERROR stops the upload and is still a success (RFC 9113 8.1). */
BRISK_API int brisk_h2_request(brisk_h2 *h, const char *method, const char *path,
                               const brisk_h2_header *hdrs, size_t n, const void *body,
                               size_t body_len, brisk_h2_stream **out);

/* Wait for the final response HEADERS of s (1xx interim responses are skipped): *status is the
 * :status (200..599), each header field goes to fn(ctx, ...) (fn may be NULL). Once per stream;
 * a second call is BRISK_E_ARG. BRISK_OK, or < 0 as described above. */
BRISK_API int brisk_h2_response(brisk_h2_stream *s, int *status, brisk_h2_header_fn fn, void *ctx);

/* Response content after brisk_h2_response: > 0 bytes (at most min(cap, INT_MAX)), 0 = the
 * stream ended and matched any content-length, or < 0. BRISK_E_ARG before brisk_h2_response
 * succeeded, for cap 0, or for a closed stream handle. Trailers are discarded. */
BRISK_API int brisk_h2_read(brisk_h2_stream *s, void *buf, size_t cap);

/* Release the stream's slot: RST_STREAM CANCEL when either direction is still open, unread data
 * dropped (its flow-control credit returned). The handle is invalid afterwards. NULL-safe. */
BRISK_API void brisk_h2_stream_close(brisk_h2_stream *s);

/* Send GOAWAY (NO_ERROR, best effort) and wipe all of mem. Does NOT close the brisk_conn: call
 * brisk_close yourself. Every stream handle becomes invalid. NULL-safe. */
BRISK_API void brisk_h2_close(brisk_h2 *h);

#ifdef __cplusplus
}
#endif

#endif /* BRISK_H */
