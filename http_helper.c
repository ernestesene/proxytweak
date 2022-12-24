#include "http_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* TODO: possible buffer overflow here */
int parse_connect_request(char *req, char *method, char *host) {
  char *_method = NULL, *_host = NULL;
  _method = strtok(req, " ");
  _host = strtok(NULL, ": ");
  if (_method == NULL || _host == NULL) return 1;
  strcpy(method, _method);
  strcpy(host, _host);
  return 0;
}

/* TODO check for errors */
int parse_request(char *request, size_t request_len, struct request *req) {
  char *needle;
  int err = -1;

  /* content length and payload first */
  const char content_length[] = "Content-Length: ";
  needle = strstr(request, content_length);
  if (needle == NULL)
    req->content_length = 0;
  else {
    /* needle += strlen(content_length); */
    needle += sizeof(content_length) - 1;
    req->content_length = atoi(needle);

    /* only if payload is part of header */
    needle = strstr(request, "\r\n\r\n") + 4;
    if (*needle == '\0')
      req->payload = NULL;
    else {
      req->payload = needle;
      /* check if payload_length == content_length */
      req->payload_length = request + request_len - needle;
      if (req->payload_length != req->content_length) {
        fprintf(stderr, "payload_length: %ld != content_length: %ld\n",
                req->payload_length, req->content_length);
        return -1;
      }
    }
  }

  req->method = strtok_r(request, " ", &needle);
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
