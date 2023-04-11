#include "http_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tweak.h"

struct request {
  const char *payload;
  size_t payload_length;
  const char *method;
  const char *path;
  const char *host;
  const char *header1; /* before "Host: foo.bar" */
  const char *header2; /* after "Host: foo.bar\r\n" */
};

/* TODO: possible buffer overflow here */
int parse_connect_request(char *req, char *host, int *port) {
  char *_host = NULL, *_port = NULL;
  strtok(req, " ");
  _host = strtok(NULL, ":");
  _port = strtok(NULL, " ");
  *port = atoi(_port);
  if (_host == NULL || *port == 0) return 1;
  strcpy(host, _host);
  return 0;
}

static int parse_request(const char *const request, size_t request_len,
                         struct request *req) {
  char *needle;
  int err = -1;

  /* only if payload is part of header */
  needle = strstr(request, "\r\n\r\n") + 4;
  if (*needle == '\0')
    req->payload = NULL;
  else {
    req->payload = needle;
    req->payload_length = request + request_len - needle;
  }

  req->method = strtok_r((char *)request, " ", &needle);
  req->path = strtok_r(NULL, " ", &needle);
  strtok_r(NULL, "\n", &needle); /* HTTP/1.1\r\n */

  err = strncmp(needle, "Host: ", 6);
  if (err == 0) {
    req->header2 = NULL;
    needle += 6;
    req->host = strtok_r(NULL, "\r", &needle);
  } else {
    req->header2 = needle;
    needle = strstr(needle, "\r\nHost:");
    *needle = '\0'; /* Null terminate req->header2 */
    needle += 8;
    req->host = strtok_r(NULL, "\r", &needle);
  }
  needle++;
  req->header1 = needle;
  needle = strstr(needle, "\r\n\r\n");
  *needle = '\0'; /* Null terminate req->header1 */

  if (req->method && req->path && req->host && req->header1) return 0;
  return 1;
}
ssize_t transform_req(char *const in, const size_t in_len, char *const out,
                      const size_t out_max, const char **const payload,
                      size_t *const payload_len) {
  struct request req = {0};
  ssize_t len;

  if (!in || !out || in_len < 1 || out_max < in_len || !payload ||
      !payload_len) {
    fprintf(stderr, "transform_request: invalid input\n");
    return -1;
  }
  if (parse_request(in, in_len, &req)) return -1;
  if (req.payload_length > 0 && req.payload) {
    *payload = req.payload;
    *payload_len = req.payload_length;
  }
#if (PEER_METHODS & PEER_METHOD_POST)
#define REQ_METHOD req.method
#define REQ_MYMETHOD
#else
#define REQ_METHOD "GET"
#define REQ_MYMETHOD , req.method
#endif
  if (req.header2 != NULL)
    len = snprintf(out, out_max, req_hdr_fmt_worker1, REQ_METHOD, req.host,
                   req.path, req.header1, req.header2 REQ_MYMETHOD);
  else
    len = snprintf(out, out_max, req_hdr_fmt_worker2, REQ_METHOD, req.host,
                   req.path, req.header1 REQ_MYMETHOD);

  if (len < 1)
    perror("Error:transform_request(): snprintf");
  else if ((size_t)len >= out_max) {
    fprintf(stderr, "Error:transform_request(): output overflow\n");
    len = -1;
  }
  return len;
}
