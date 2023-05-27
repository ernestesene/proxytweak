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
extern int parse_connect_request(char *req, char *host, int *port);

/* returns len of out or -1 on error */
extern ssize_t transform_req(char *const in, const size_t in_len,
                             char *const out, const size_t out_max,
                             const char **const payload,
                             size_t *const payload_len
#ifndef REDIRECT_HTTP
                             ,
                             bool https_mode
#endif
);

/* returns pointer to url without protocol */
char *http_bare_url(char *request);
#endif /* ifndef HTTP_HELPER_H */
