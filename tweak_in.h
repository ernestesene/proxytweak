#ifndef TWEAK_H
#define TWEAK_H 1

/* change parameters with "#tweak" in comment. */

/* program listen address */
/* use INADDR_LOOPBACK or INADDR_ANY or see "netinet/in.h" */
#define LISTEN_ADDR INADDR_ANY /* #tweak */
/* program listen port */
#define LISTEN_PORT 8888 /* #tweak */

/* bypass worker for "http" methods supported by peer
 * note: only GET,POST,HEAD methods is implemented */
#define TWEAK_BYPASS_WORKER_FOR_HTTP /* #tweak comment to disable */

/* web worker request information */
#define WORKER_HOST "router.eroken.workers.dev"
extern const char *const req_hdr_fmt_worker1;
extern const char *const req_hdr_fmt_worker2;
extern const char *const req_hdr_fmt_1;
extern const char *const req_hdr_fmt_2;

extern const char *const req_hdr_fmt_connect;
/* allowed HTTP methods for peers */
#define PEER_METHOD_GET 0x01
#define PEER_METHOD_POST 0x02
#define PEER_METHOD_HEAD 0x04
#define PEER_METHOD_CONNECT 0x08
#define PEER_METHOD_ALL 0xff

/* peer information
 * peer could be an HTTP proxy or reverse proxy.
 */
#define PEER_HOST "127.0.0.1"        /* #tweak ip address or host name */
#define PEER_TYPE_CLOUDFLARE 0       /* #tweak boolean*/
#define PEER_PORT 8080               /* #tweak int */
#define PEER_USE_TLS 0               /* #tweak boolean */
#define PEER_METHODS PEER_METHOD_ALL /* #tweak allowed methods */
#if PEER_TYPE_CLOUDFLARE
#define PEER_CUSTOM_HOST WORKER_HOST
#else
#define PEER_CUSTOM_HOST "host.net:443" /* #tweak */
#endif
#if (PEER_METHODS & PEER_METHOD_CONNECT)
#define PEER_CONNECT_CUSTOM_HOST "connect.host.net:443" /* #tweak */
#endif

/* --- catch obvious error in tweak */
#if !PEER_METHODS
#error no known peer method given
#endif
#if (PEER_TYPE_CLOUDFLARE && !(PEER_METHODS & PEER_METHOD_POST))
#warning cloulfare supports POST method
#endif
#if (PEER_TYPE_CLOUDFLARE && (PEER_METHODS & PEER_METHOD_CONNECT))
#warning cloulfare does not support CONNECT method
#endif
#if (PEER_TYPE_CLOUDFLARE && PEER_PORT != 443)
#warning cloulfare should use port 443
#endif
#if (PEER_PORT == 443 && !PEER_USE_TLS)
#warning port 443 should use TLS
#endif

/* --- */

/* --- anti-collision measures */
#ifdef TWEAK_BYPASS_WORKER_FOR_HTTP

#if PEER_TYPE_CLOUDFLARE
#warning "TWEAK_BYPASS_WORKER_FOR_HTTP disabled: CLOUDFLARE not an http proxy"
#undef TWEAK_BYPASS_WORKER_FOR_HTTP
#endif /* if PEER_TYPE_CLOUDFLARE */

#if PEER_METHODS == PEER_METHOD_CONNECT
#warning "TWEAK_BYPASS_WORKER_FOR_HTTP disabled: http not supported"
#undef TWEAK_BYPASS_WORKER_FOR_HTTP
#endif

#endif /* ifdef TWEAK_BYPASS_WORKER_FOR_HTTP */
/* --- */

#endif /* ifndef TWEAK_H */
