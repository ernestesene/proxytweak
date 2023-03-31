#include "http_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* TODO check for errors */
int parse_request(const char *const request, size_t request_len,
                  struct request *req) {
  char *needle;
  int err = -1;

  /* Content-Length: */
  const char content_length[] = "Content-Length: ";
  needle = strstr(request, content_length);
  if (needle != NULL) {
    needle += sizeof(content_length) - 1; /* strlen(content_length); */
    req->content_length = atoi(needle);
  }
  /* Transfer-Encoding: chunked */
  const char transfer_encoding[] = "Transfer-Encoding: chunked";
  needle = strstr(request, transfer_encoding);
  if (needle != NULL) req->chunked = true;

  /* only if payload is part of header */
  if (req->content_length || req->chunked) {
    needle = strstr(request, "\r\n\r\n") + 4;
    if (*needle == '\0')
      req->payload = NULL;
    else {
      req->payload = needle;
      req->payload_length = request + request_len - needle;
      if (req->content_length && req->payload_length > req->content_length) {
        fprintf(stderr, "payload_length: %zu > content_length: %zu\n",
                req->payload_length, req->content_length);
        return -1;
      }
    }
  }

  req->method = strtok_r((char *)request, " ", &needle);
  req->path = strtok_r(NULL, " ", &needle);
  strtok_r(NULL, "\n", &needle); /* HTTP/1.1\r\n */

  err = strncmp(needle, "Host:", 5);
  if (err == 0)
    req->header2 = NULL;
  else {
    req->header2 = needle;
    needle = strstr(needle, "\r\nHost:");
    *needle = '\0';      /* Null terminate req->header2 */
    needle = needle + 2; /* advandce to "Host:" */
  }
  needle = strstr(needle, "\n");
  needle++;
  req->header1 = needle;
  needle = strstr(needle, "\r\n\r\n");
  *needle = '\0'; /* Null terminate req->header1 */

  return 0;
}
