#ifndef HTTP_HELPER_H
#define HTTP_HELPER_H 1

#include <stdbool.h>
#include <sys/types.h>

#define REQUEST_MAX 16384  /* 16KB */
#define RESPONSE_MAX 16384 /* 16KB */

/**
 * chunked_not_eof() - not end of chunk
 * @a: char* buffer to check
 * @b: size_t length of content in buffer
 * @returns: %TRUE if not end of chunk
 *
 * check current buffer for end of chunk
 * TODO: check for trailer and chunk-extension. See #RFC 2616
 */
#define chunked_not_eof(a, b) strncmp((a + b - 5), "0\r\n\r\n", 5)

#define HOST_MAX 64

struct request {
  size_t content_length; /* equivalent to payload_length */
  bool chunked;
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
extern int parse_request(const char *const request, size_t request_len,
                         struct request *req);

#endif /* ifndef HTTP_HELPER_H */
