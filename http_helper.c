#include "http_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tweak.h"

/* maximum port number from "/etc/services" */
#define PORT_MAX 49150
/* maximum string to hold PORT_MAX with null byte */
#define PORT_MAX_STR 6

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
short parse_connect_request(char *req, char *host, unsigned short *port) {
  char *tmp, *saveptr;
  unsigned int port_;

  if (!strtok_r(req, " ", &saveptr)) return -1;

  tmp = strtok_r(NULL, ":", &saveptr);
  if (!tmp) return -1;
  if ((saveptr - tmp) > HOST_MAX - 1) return -1;
  /* buffer overflow already handled by previous line, hence strcpy() */
  strcpy(host, tmp);

  tmp = strtok_r(NULL, " ", &saveptr);
  if (!tmp) return -1;
  if ((saveptr - tmp) > PORT_MAX_STR) return -1;
  port_ = atoi(tmp);
  if (port_ > PORT_MAX || port_ == 0) return -1;
  *port = port_;

  return 0;
}

/* TODO: possible buffer overflow here */
static short parse_request(char *const _request, size_t request_len,
                           struct request *req
#ifndef REDIRECT_HTTP
                           ,
                           bool https_mode
#endif
) {

  char *needle;
  const char *request = _request;
  int err;

  /* only if payload is part of header */
  needle = strstr(request, "\r\n\r\n");
  if (!needle) return -1;
  needle += 4;
  if (needle < request + request_len) {
    req->payload = needle;
    req->payload_length = request + request_len - needle;
  } else if (needle > request + request_len)
    return -1;

  req->method = strtok_r((char *)request, " ", &needle);
  if (!req->method) return -1;
  req->path = strtok_r(NULL, " ", &needle);
  if (!req->path) return -1;
#ifndef REDIRECT_HTTP
  if (!https_mode) {
    req->path += sizeof(HTTP_PROTO) - 1;
    req->path = strchr(req->path, '/');
    if (!req->path) return -1;
  }
#endif
  /* HTTP/1.1\r\n */
  if (!strtok_r(NULL, "\n", &needle)) return -1;

  err = strncmp(needle, "Host: ", 6);
  if (err == 0) {
    /* case 1 "Host: " comes first before other headers */
    req->header2 = NULL;
    needle += 6;
    req->host = strtok_r(NULL, "\r", &needle);
    if (!req->host) return -1;
  } else {
    /* case 2 "Host: " may be within other headers or last, see case 3 */
    req->header2 = needle;
    needle = strstr(needle, "\r\nHost: ");
    if (!needle) return -1;
    *needle = '\0'; /* Null terminate req->header2 */
    needle += 8;
    req->host = strtok_r(NULL, "\r", &needle);
    if (!req->host) return -1;
  }
  needle++;
  req->header1 = needle;
  needle = strstr(needle, "\r\n\r\n");
  if (!needle) {
    /* case 3 "Host: \r\n\r\n" is last header */
    req->header1 = req->header2;
    req->header2 = NULL;
  } else
    *needle = '\0'; /* Null terminate req->header1 */

  return 0;
}
ssize_t transform_req(char *const in, const size_t in_len, char *const out,
                      const size_t out_max, const char **const payload,
                      size_t *const payload_len
#ifndef REDIRECT_HTTP
                      ,
                      bool https_mode
#endif
) {
  struct request req = {0};
  ssize_t len;

  if (!in || !out || in_len < 1 || out_max < in_len || !payload ||
      !payload_len) {
    fprintf(stderr, "transform_request: invalid input\n");
    return -1;
  }
  if (parse_request(in, in_len, &req
#ifndef REDIRECT_HTTP
                    ,
                    https_mode
#endif
                    ))
    return -1;
  *payload = req.payload;
  *payload_len = req.payload_length;

  const char *req_fmt1 = req_hdr_fmt_worker1;
  const char *req_fmt2 = req_hdr_fmt_worker2;
#ifdef TWEAK_BYPASS_WORKER_FOR_HTTP
  bool bypassed = false;
  if (!https_mode) {
    if ((PEER_METHODS & PEER_METHOD_GET) && (*req.method == 'G'))
      goto bypass_worker;
    else if ((PEER_METHODS & PEER_METHOD_POST) && (*req.method == 'P'))
      goto bypass_worker;
    else if ((PEER_METHODS & PEER_METHOD_HEAD) && (*req.method == 'H'))
      goto bypass_worker;
    else
      goto out;

  bypass_worker:
    req_fmt1 = req_hdr_fmt_1;
    req_fmt2 = req_hdr_fmt_2;
    bypassed = true;
  out:
  }
#endif /* ifdef TWEAK_BYPASS_WORKER_FOR_HTTP */

#if (PEER_METHODS & PEER_METHOD_POST)
#define REQ_METHOD req.method
#define REQ_MYMETHOD
#else
#define REQ_METHOD "GET"
#define REQ_MYMETHOD , req.method
#endif
  if (req.header2 != NULL)
    len = snprintf(out, out_max, req_fmt1, REQ_METHOD, req.host, req.path,
                   req.header1, req.header2 REQ_MYMETHOD);
  else
    len = snprintf(out, out_max, req_fmt2, REQ_METHOD, req.host, req.path,
                   req.header1 REQ_MYMETHOD);

  if (len < 1) {
    perror("Error:transform_request(): snprintf");
    return -1;
  } else if ((size_t)len >= out_max) {
    fprintf(stderr, "Error:transform_request(): output overflow\n");
    return -1;
  }

#ifdef TWEAK_BYPASS_WORKER_FOR_HTTP
  if (bypassed) goto ret;
#endif
#ifndef REDIRECT_HTTP
  if (!https_mode) {
    /* change /proxs/ to /proxh/ */
    char *tmp = strstr(out, "/proxs/");
    if (tmp == NULL) {
      fprintf(stderr, "can't change /proxs/ to /proxh/");
      return -1;
    }
    tmp += 5;
    *tmp = 'h';
  }
#endif

ret:
  return len;
}

char *http_bare_url(char *request) {
  char *buff = strstr(request, PROTO_SEPERATOR);
  if (buff == NULL) goto err;
  buff += sizeof(PROTO_SEPERATOR) - 1;
  buff = strtok(buff, " ");
  if (buff != NULL) return buff;

err:
  return NULL;
}
