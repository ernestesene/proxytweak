/* To understand what's going on here pass this file through the preprocessor
 * $gcc -E tweak.c -o /tmp/tweak.cc
 * then check /tmp/tweak.cc for req_hdr* variables
 *
 * values of req_hdr* variables depends on configurations in tweak_in.h
 */

#include "tweak.h"

#include "http_helper.h"

/* worker request formats */
/* TODO only to confuse upstream proxy
 * do better by using random number or date at program startup */
#define PROXS "/proxs/custom/deafdead.txt"

#if PEER_TYPE_CLOUDFLARE
#define PATH PROXS
#else
#define PATH HTTP_PROTO WORKER_HOST PROXS
#endif

/* TODO: better method detection needed */
#if (PEER_METHODS & PEER_METHOD_POST)
#define MY_METHOD
#else
#define MY_METHOD "mymethod: %s\r\n"
#endif

/* worker request format */
#define TMP1 "%s " PATH " HTTP/%s\r\nHost: " PEER_CUSTOM_HOST "\r\n%s"
#define TMP2 "\r\nmypath: %s%s\r\n" MY_METHOD "\r\n"
const char *const req_hdr2_fmt_worker = TMP1 "\r\n%s" TMP2;
const char *const req_hdr1_fmt_worker = TMP1 TMP2;

/* worker bypass format */
#ifdef TWEAK_BYPASS_WORKER_FOR_HTTP
#undef PATH
#undef TMP1
#undef TMP2
#define PATH HTTP_PROTO
#define TMP1 "%s " PATH "%s%s HTTP/%s\r\nHost: " PEER_CUSTOM_HOST "\r\n%s"
#define TMP2 "\r\n\r\n"
const char *const req_hdr2_fmt_bypassed = TMP1 "\r\n%s" TMP2;
const char *const req_hdr1_fmt_bypassed = TMP1 TMP2;
#endif

/* for custom connect */
#ifdef PEER_CONNECT_CUSTOM_HOST
const char *const req_hdr_fmt_connect
    = "CONNECT %s:%hu HTTP/1.1\r\nHost: " PEER_CONNECT_CUSTOM_HOST
      "\r\nUser-Agent: native_app/0.00.0\r\n"
      "Proxy-Connection: Keep-Alive\r\n\r\n";
#endif
