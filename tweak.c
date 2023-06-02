#include "tweak.h"
#include "http_helper.h"

#if PEER_TYPE_CLOUDFLARE
#define PRE_PATH
#else
#define PRE_PATH HTTP_PROTO WORKER_HOST
#endif

/* TODO: better method detection needed */
#if (PEER_METHODS & PEER_METHOD_POST)
#define MY_METHOD
#else
#define MY_METHOD "mymethod: %s\r\n"
#endif

#define TMP1                                                                   \
  "%s " PRE_PATH "/proxs/%s%s HTTP/1.1\r\nHost: " PEER_CUSTOM_HOST "\r\n%s"
#define TMP2 "\r\n" MY_METHOD "\r\n"

/* includes header2 */
const char *const req_hdr_fmt_worker1 = TMP1 "\r\n%s" TMP2;
/* no header2 */
const char *const req_hdr_fmt_worker2 = TMP1 TMP2;

/* for custom connect */
#ifdef PEER_CONNECT_CUSTOM_HOST
const char *const req_hdr_fmt_connect =
    "CONNECT %s:%hu HTTP/1.1\r\nHost: " PEER_CONNECT_CUSTOM_HOST
    "\r\nUser-Agent: native_app/0.00.0\r\n"
    "Proxy-Connection: Keep-Alive\r\n\r\n";
#endif
