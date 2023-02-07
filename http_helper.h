#ifndef HTTP_HELPER_H
#define HTTP_HELPER_H 1

#include <sys/types.h>

#define REQUEST_MAX 16384  /* 16KB */
#define RESPONSE_MAX 16384 /* 16KB */

#define HOST_MAX 64

struct request {
  size_t content_length; /* equivalent to payload_length */
  const char *payload;
  size_t payload_length;
  const char *method;
  const char *path;
  const char *host;
  const char *header1; /* before "Host: foo.bar" */
  const char *header2; /* after "Host: foo.bar\r\n" */
};

/* TODO change bad_request to match HTTP RESPONSE */
extern int parse_connect_request(char *req, char *method, char *host);
extern int parse_request(char *request, size_t request_len,
                         struct request *req);

#endif /* ifndef HTTP_HELPER_H */
