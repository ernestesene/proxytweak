#include "http_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tweak.h"

/* maximum port number from "/etc/services" */
#define PORT_MAX 49150
/* maximum string to hold PORT_MAX with null byte */
#define PORT_MAX_STR 6

struct request
{
  const char *payload;
  size_t payload_length;
  const char *method;
  const char *path;
  const char *host;
  const char *httpVer; /* Version in "HTTP/1.1" is "1.1" */
  bool treatAsHTTPS;   /* Treat invalid HTTP request as HTTPS */
  const char *header1; /* before "Host: foo.bar" */
  const char *header2; /* after "Host: foo.bar\r\n" */
};

/* TODO: possible buffer overflow here */
short
parse_connect_request (char *restrict const req, char *restrict const host,
                       unsigned short *restrict const port)
{
  char *tmp, *saveptr;
  unsigned int port_;

  if (!strtok_r (req, " ", &saveptr))
    return -1;

  tmp = strtok_r (NULL, ":", &saveptr);
  if (!tmp)
    return -1;
  if ((saveptr - tmp) > HOST_MAX - 1)
    return -1;
  /* buffer overflow already handled by previous line, hence strcpy() */
  strcpy (host, tmp);

  tmp = strtok_r (NULL, " ", &saveptr);
  if (!tmp)
    return -1;
  if ((saveptr - tmp) > PORT_MAX_STR)
    return -1;
  port_ = atoi (tmp);
  if (port_ > PORT_MAX || port_ == 0)
    return -1;
  *port = port_;

  return 0;
}

/* TODO: possible buffer overflow here */
__attribute__ ((nonnull)) static short
parse_request (char *restrict const _request, const size_t request_len,
               struct request *restrict const req, const bool https_mode)
{

  char *needle;
  const char *request = _request;
  int err;

  /* only if payload is part of header */
  needle = strstr (request, "\r\n\r\n");
  if (!needle)
    return -1;
  needle += 4;
  if (needle < request + request_len)
    {
      req->payload = needle;
      req->payload_length = request + request_len - needle;
    }
  else if (needle > request + request_len)
    return -1;

  req->method = strtok_r ((char *)request, " ", &needle);
  if (!req->method)
    return -1;
  req->path = strtok_r (NULL, " ", &needle);
  if (!req->path)
    return -1;
  if (!https_mode)
    {
      /* if path begins with http://a.b/ab.c but not /ab.c
       * then it is a valid http request to proxy
       *
       * else treat this request at invalid HTTPS request (without CONNECT)
       */
      if ('/' != *req->path)
        {
          /* Some client send "GET https://a.b/ab.c" instead of using CONNECT
           * Detect this and treat as HTTPS */
          if (0 == strncmp (req->path, HTTPS_PROTO, sizeof (HTTPS_PROTO) - 1))
            req->treatAsHTTPS = true;

          /* strip http://host.com from path of proxied http requests
           * Example: "GET http://host.com/path/to/file.txt HTTP/1.1"
           * shall select path as "/path/to/file.txt"
           */
          req->path += sizeof (HTTP_PROTO);
          const char *const tmp = strchr (req->path, '/');
          if (tmp)
            req->path = tmp;
          else
            req->path = "/";
        }
      else
        req->treatAsHTTPS = true;
    }
  /* HTTP/1.1\r\n */
  req->httpVer = needle + 5;
  needle = strchr (req->httpVer, '\r');
  if (!needle)
    return -1;
  *needle = '\0';
  needle += 2;

  err = strncmp (needle, "Host: ", 6);
  if (err == 0)
    {
      /* case 1 "Host: " comes first before other headers */
      req->header2 = NULL;
      needle += 6;
      req->host = strtok_r (NULL, "\r", &needle);
      if (!req->host)
        return -1;
    }
  else
    {
      /* case 2 "Host: " may be within other headers or last, see case 3 */
      req->header2 = needle;
      needle = strstr (needle, "\r\nHost: ");
      if (!needle)
        return -1;
      *needle = '\0'; /* Null terminate req->header2 */
      needle += 8;
      req->host = strtok_r (NULL, "\r", &needle);
      if (!req->host)
        return -1;
    }
  needle++;
  req->header1 = needle;
  needle = strstr (needle, "\r\n\r\n");
  if (!needle)
    {
      /* case 3 "Host: \r\n\r\n" is last header */
      req->header1 = req->header2;
      req->header2 = NULL;
    }
  else
    *needle = '\0'; /* Null terminate req->header1 */

  /*  Only on some clients, example simple-obfs plugin for shadowsocks-libev
   * obfs-local -s 127.0.0.1 -p 8888 --obfs http -l 8887 -v \
   *  --obfs-host uk.opensocks.site:1234
   *
   *  will send host as uk.opensocks.site:1234:8888
   *  trailing ":8888" should be removed
   */
  needle = strchr (req->host, ':');
  if (needle)
    {
      needle++;
      needle = strchr (needle, ':');
      if (needle)
        *needle = 0;
    }

  return 0;
}
ssize_t
transform_req (char *restrict const in, const size_t in_len,
               char *restrict const out, const size_t out_max,
               const char **restrict const payload,
               size_t *restrict const payload_len, const bool https_mode)
{
  struct request req = { 0 };
  ssize_t len;

  if (in_len < 1 || out_max < in_len)
    {
      fprintf (stderr, "transform_request: invalid input\n");
      return -1;
    }
  if (parse_request (in, in_len, &req, https_mode))
    return -1;
  *payload = req.payload;
  *payload_len = req.payload_length;

  const char *req_fmt1 = req_hdr1_fmt_worker;
  const char *req_fmt2 = req_hdr2_fmt_worker;
#ifdef TWEAK_BYPASS_WORKER_FOR_HTTP
  if (!https_mode && !req.treatAsHTTPS)
    {
      if (((PEER_METHODS & PEER_METHOD_GET) && (*req.method == 'G'))
          || ((PEER_METHODS & PEER_METHOD_POST) && (*req.method == 'P'))
          || ((PEER_METHODS & PEER_METHOD_HEAD) && (*req.method == 'H')))
        {
          /* bypass worker here */
          req_fmt1 = req_hdr1_fmt_bypassed;
          req_fmt2 = req_hdr2_fmt_bypassed;
          if (req.header2 != NULL)
            len = snprintf (out, out_max, req_fmt2, req.method, req.host,
                            req.path, req.httpVer, req.header1, req.header2);
          else
            len = snprintf (out, out_max, req_fmt1, req.method, req.host,
                            req.path, req.httpVer, req.header1);
          if ((len < 1) || (len >= (ssize_t)out_max))
            {
              perror ("Error:bypass:transform_request(): snprintf");
              return -1;
            }
          goto ret;
        }
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
    len = snprintf (out, out_max, req_fmt2, REQ_METHOD, req.httpVer,
                    req.header1, req.header2, req.host, req.path REQ_MYMETHOD);
  else
    len = snprintf (out, out_max, req_fmt1, REQ_METHOD, req.httpVer,
                    req.header1, req.host, req.path REQ_MYMETHOD);
  if ((len < 1) || (len >= (ssize_t)out_max))
    {
      perror ("Error:transform_request(): snprintf");
      return -1;
    }

  if (!https_mode && !req.treatAsHTTPS)
    {
      /* change /proxs/ to /proxh/ */
      char *tmp = strstr (out, "/proxs/");
      if (tmp == NULL)
        {
          fprintf (stderr, "can't change /proxs/ to /proxh/");
          return -1;
        }
      tmp += 5;
      *tmp = 'h';
    }

#ifdef TWEAK_BYPASS_WORKER_FOR_HTTP
ret:
#endif
  return len;
}

char *
http_bare_url (char *restrict const request)
{
  char *buff = strstr (request, PROTO_SEPERATOR);
  if (buff == NULL)
    goto err;
  buff += sizeof (PROTO_SEPERATOR) - 1;
  buff = strtok (buff, " ");
  if (buff != NULL)
    return buff;

err:
  return NULL;
}
