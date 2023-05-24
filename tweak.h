#ifndef TWEAK_H
#define TWEAK_H 1

/* change parameters with "#tweak" in comment. */

/* program listen address */
/* use INADDR_LOOPBACK or INADDR_ANY or see "netinet/in.h" */
#define LISTEN_ADDR INADDR_LOOPBACK /* #tweak */
/* program listen port */
#define LISTEN_PORT 8888 /* #tweak */

/* web worker request information */
#define WORKER_HOST "router.eroken.workers.dev"
extern const char *const req_hdr_fmt_worker1;
extern const char *const req_hdr_fmt_worker2;

extern const char *const req_hdr_fmt_connect;
/* allowed HTTP methods for peers */
#define PEER_METHOD_GET 0b00000001
#define PEER_METHOD_POST 0b00000010
#define PEER_METHOD_CONNECT 0x10000000
#define PEER_METHOD_ALL 0x11111111

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

/* catch obvious error in tweak */
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

#define CONNECT_HEADER "User-Agent: connect"

#endif /* ifndef TWEAK_H */
