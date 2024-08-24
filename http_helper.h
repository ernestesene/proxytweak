#ifndef HTTP_HELPER_H
#define HTTP_HELPER_H 1

#include <stdbool.h>
#include <sys/types.h>

#include "tweak.h"

#define HTTP_PROTO "http://"
#define HTTPS_PROTO "https://"
#define PROTO_SEPERATOR "://"

#define REQUEST_MAX 16384  /* 16KB */
#define RESPONSE_MAX 16384 /* 16KB */

#define HOST_MAX 64

/* TODO change bad_request to match HTTP RESPONSE */
extern short parse_connect_request (char *__restrict const req,
                                    char *__restrict const host,
                                    unsigned short *__restrict const port)
    __attribute__ ((nonnull));

/* returns len of out or -1 on error */
extern ssize_t transform_req (char *__restrict const in, const size_t in_len,
                              char *__restrict const out, const size_t out_max,
                              const char **__restrict const payload,
                              size_t *__restrict const payload_len
#ifndef REDIRECT_HTTP
                              ,
                              const bool https_mode
#endif
                              ) __attribute__ ((nonnull));

/* returns pointer to url without protocol */
char *http_bare_url (char *__restrict const request) __attribute__ ((nonnull));
#endif /* ifndef HTTP_HELPER_H */
