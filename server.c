#include "server.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "helper.h"

#define RESQUEST_MAX 16384 /* 16KB */
#define RESPONSE_MAX 16384 /* 16KB */

#define HOST_MAX 64

#define HOST_REMOTE "router.eroken.workers.dev"

struct request {
  size_t content_length; /* equivalent to payload_length */
  const char *payload;
  size_t payload_length;
  const char *method;
  const char *path;
  const char *host;
  const char *header1; /* before Host: foo.bar */
  const char *header2; /* after Host: foo.bar\r\n */
};

/* includes header2 */
static const char *req_hdr_fmt1 =
    "%s /prox1/%s%s HTTP/1.1\r\nHost: router.eroken.workers.dev\r\n"
    "%s\r\n%s\r\nConnection: close\r\n\r\n";
/* no header2 */
static const char *req_hdr_fmt2 =
    "%s /prox1/%s%s HTTP/1.1\r\nHost: router.eroken.workers.dev\r\n"
    "%s\r\nConnection: close\r\n\r\n";
/* TODO may cause race condition */
static SSL_CTX *ctx_server = NULL, *ctx_client = NULL;
/* TODO change bad_request to match HTTP RESPONSE */
static char response_err[] = "Bad request\r\n\r\n";
static char response_ok[] = "HTTP/1.1 200 OK\r\n\r\n";

enum ssl_method { client_method, server_method };

SSL_CTX *ssl_create_context(enum ssl_method method) {
  const SSL_METHOD *_method = NULL;
  SSL_CTX *ctx = NULL;

  if (method == client_method)
    _method = TLS_client_method();
  else
    _method = TLS_server_method();
  ctx = SSL_CTX_new(_method);
  if (!ctx) {
    perror("SSL create context error");
    ERR_print_errors_fp(stderr);
    return NULL;
  }
  return ctx;
}

int ssl_configure_context(SSL_CTX *ctx, enum ssl_method method) {
  /* Set the key and cert to use */
  if (method == server_method) {
    if (SSL_CTX_use_certificate_file(ctx, "selfsign.crt", SSL_FILETYPE_PEM) <=
        0) {
      ERR_print_errors_fp(stderr);
      return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "selfsign.key", SSL_FILETYPE_PEM) <=
        0) {
      ERR_print_errors_fp(stderr);
      return 1;
    }
    /* check if private key matches the certificate public key */
    if (SSL_CTX_check_private_key(ctx) != 1) {
      ERR_print_errors_fp(stderr);
      return 1;
    }
  } else if (method == client_method) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2);
  } else
    return 1;
  return 0;
}

// static void proxy_nossl(int fd, const char *request){}
/* TODO check for errors */
static int parse_request(char *request, size_t request_len,
                         struct request *req) {
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
static void proxy_ssl(int fd, const char *host) {
  /* TODO connect to remote proxy server (web worker) */
  int err = -1;
  char request[RESQUEST_MAX] = {0};
  size_t request_len = -1;
  char req_hdr_remote[RESQUEST_MAX] = {0};
  size_t req_hdr_remote_len = -1;

  int fd_remote = -1;
  SSL *ssl_remote = NULL;

  char response_buf[RESPONSE_MAX] = {0};
  size_t response_len = -1;

  write(fd, response_ok, sizeof(response_ok));
  // read perform TLS handshake with client
  if (ctx_server == NULL) ctx_server = ssl_create_context(server_method);
  if (ctx_server == NULL) {
    write(fd, response_err, sizeof(response_err));
    close(fd);
    return;
  }
  err = ssl_configure_context(ctx_server, server_method);
  if (err) {
    write(fd, response_err, sizeof(response_err));
    close(fd);
    return;
  }

  /* local server SSL  and handshake */
  SSL *ssl_local = SSL_new(ctx_server);
  SSL_set_fd(ssl_local, fd);
  err = SSL_accept(ssl_local);
  if (err <= 0) {
    err = SSL_get_error(ssl_local, err);
    if (err == SSL_ERROR_SYSCALL)
      perror("SSL_accept");
    else
      ERR_print_errors_fp(stderr);
    goto ssl_cleanup;
  }

  // STEP:5
  while (1) {
    fprintf(stderr, "While_loop\n");
    // read request from client(GOTO clean_up on error)
    request_len = SSL_read(ssl_local, (void *)request, sizeof(request));

    fprintf(stderr, "While_ssl_localread\n");
    if (request_len <= 0) {
      ERR_print_errors_fp(stderr);
      goto ssl_cleanup;
    }
    *(request + request_len) = '\0';
    /* TODO ##PAYLOAD
     *
     * sometimes, only header is read on first read.
     * payload can be read by re-reading the fd.
     * it will block if no payload is present. (undesired behaviour)
     *
     * read header, parse header for value of "Content-Length: "
     * if content_length > 0 then read payload if no payload in header

        char PAYLOAD[RESQUEST_MAX] = {'\0'};
        int payload_length = SSL_read(ssl_local, (void *)PAYLOAD,
     sizeof(PAYLOAD));
    */

#ifdef DEBUG

    fprintf(stderr, "While_debug\n");
    printf("RESQUEST_MAX is: %ldbytes\n", sizeof(request));
    printf("Request length is: %ldbytes\n", (long)request_len);
    printf("Request is \n\n%s\n", request);
#endif
    // parse request
    struct request req = {0};
    req.host = host;
    err = parse_request(request, request_len, &req);
    if (err) {
      SSL_write(ssl_local, response_err, sizeof(response_err));
      continue;
    }
    if (req.header2 != NULL)
      req_hdr_remote_len =
          snprintf(req_hdr_remote, sizeof(req_hdr_remote), req_hdr_fmt1,
                   req.method, req.host, req.path, req.header1, req.header2);
    else
      req_hdr_remote_len =
          snprintf(req_hdr_remote, sizeof(req_hdr_remote), req_hdr_fmt2,
                   req.method, req.host, req.path, req.header1);

    if (req_hdr_remote_len < 1) {
      SSL_write(ssl_local, response_err, sizeof(response_err));
      continue;
    }
    // #warning "reusing variable request[] for storing payload"
    if (req.content_length > 0) {
      /* payload not part of header */
      if (req.payload_length != req.content_length) {
        req.payload_length =
            SSL_read(ssl_local, (void *)request, req.content_length);
        if (req.payload_length < req.content_length) {
          /* TODO ## payload may be partial, re-read instead */
          fprintf(stderr, "req.payload_length < req.content_length\n");
          goto ssl_cleanup;
        }
        *(request + req.payload_length) =
            '\0'; /* only for debug and printing */
        req.payload = request;
      } /* payload not part of header */
    }

#ifdef DEBUG
    fprintf(stderr, "req_hdr_remote ==>\n%s\nreq_hdr_remote_len: %ld\n",
            req_hdr_remote, req_hdr_remote_len);
    fprintf(stderr,
            "req_hdr_remote_payload:\n%s\nreq_hdr_remote_payload_length: %ld\n",
            req.payload, req.payload_length);
#endif

    // Connect to remote proxy
    if (fd_remote < 0) fd_remote = connect_remote_server();
    if (fd_remote < 0) {
      /* TODO reply "can't connect to upstream proxy" */
      SSL_write(ssl_local, response_err, sizeof(response_err));
      continue;
    }
    if (ctx_client == NULL) {
      ctx_client = ssl_create_context(client_method);
      ssl_configure_context(ctx_client, client_method);
    }
    if (ssl_remote == NULL) {
      ssl_remote = SSL_new(ctx_client);
      /* TODO handle err */
      err = SSL_set_tlsext_host_name(ssl_remote, HOST_REMOTE);
      SSL_set_fd(ssl_remote, fd_remote);
      err = SSL_connect(ssl_remote);
      if (err != 1) {
        ERR_print_errors_fp(stderr);
        /* TODO */
        SSL_write(ssl_local, response_err, sizeof(response_err));
        goto ssl_cleanup;
      }
      /* TODO: certificate check here */
    }

    // send request to remote proxy server(web worker)
    SSL_write(ssl_remote, req_hdr_remote, req_hdr_remote_len);
    /* TODO check payload and payload_len againt trailing null */
    if (req.payload_length > 0)
      SSL_write(ssl_remote, req.payload, req.payload_length);

    // wait for response

    // read response from remote and send to client(GOTO clean_up on error)
    do {
      /* TODO ##
       * instead of relying on header "Connection: close" to know when data
       * transfer is complete, use header "Content-Length: " to determine
       * payload size and re-fetch till size is reached.
       *
       * this will allow for reuse of both ssl_remote and ssl_client
       * connections
       *
       * only header is always sent on first read, parse "Content-Length: "
       * then re-fetch if content_len > 0 till the length is reached,
       * OR broken connection, in later case terminate both upstream and local
       * connections via "goto ssl_cleanup"
       *
       * NOTE: "Content-Length: " does not apply to "HEAD" request.
       */
      response_len = SSL_read(ssl_remote, response_buf, sizeof(response_buf));
      if (response_len > 0) SSL_write(ssl_local, response_buf, response_len);

    } while (response_len > 0);
    break;
    // GOTO STEP:5
  }
  //
  // Clean_up: (handle error here)

ssl_cleanup:
  SSL_shutdown(ssl_local);
  SSL_free(ssl_local);
  close(fd);
  if (ssl_remote) {
    SSL_shutdown(ssl_remote);
    SSL_free(ssl_remote);
  }
  if (fd_remote > -1) {
    close(fd_remote);
  }
  return;
}

/* TODO: possible buffer overflow here */
static int parse_connect_request(char *req, char *method, char *host) {
  char *_method = NULL, *_host = NULL;
  _method = strtok(req, " ");
  _host = strtok(NULL, ": ");
  if (_method == NULL || _host == NULL) return 1;
  strcpy(method, _method);
  strcpy(host, _host);
  return 0;
}

int server(int fd) {
  int err = -1;
  char request[RESQUEST_MAX] = {0};
  ssize_t request_len = 0;

  char host[HOST_MAX] = {0};
  char method[16] = {0};

  while (1) {
    request_len = read(fd, (void *)request, sizeof(request));
    if (request_len < 1) {
      perror("Server read error, or connection closed");
      break;
    }
    *(request + request_len) = '\0';

#ifdef DEBEG
    printf("RESQUEST_MAX is: %ldbytes\n", sizeof(request));
    printf("Request length is: %ldbytes\n", (long)request_len);
    printf("Request is \n\n%s\n", request);
#endif

    err = strncmp(request, "CONNECT", 7);
    if (err == 0) {
      err = parse_connect_request(request, method, host);
      if (err) {
        write(fd, response_err, sizeof(response_err));
        continue;
      }
#ifdef DEBUG
      fprintf(stderr, "Received connect request to host %s\n", host);
#endif
      proxy_ssl(fd, host);
      // write(fd, response_ok, sizeof(response_ok));
    } else {
      //    proxy_nossl(fd, request);
    }
  }
  return 0;
}
