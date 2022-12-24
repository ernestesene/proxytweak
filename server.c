#include "server.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "http_helper.h"
#include "socket_helper.h"
#include "tls_helper.h"
#include "tweak.h"

static const char response_err[] = "HTTP/1.1 400 Bad request\r\n\r\n";
static const char response_ok[] = "HTTP/1.1 200 OK\r\n\r\n";

/* TODO may cause race condition */
static SSL_CTX *ctx_server = NULL, *ctx_client = NULL;

// static void proxy_nossl(int fd, const char *request){}

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

  write(fd, response_ok, sizeof(response_ok) - 1);
  // read perform TLS handshake with client
  if (ctx_server == NULL) ctx_server = ssl_create_context(server_method);
  if (ctx_server == NULL) {
    write(fd, response_err, sizeof(response_err) - 1);
    close(fd);
    return;
  }
  err = ssl_configure_context(ctx_server, server_method);
  if (err) {
    write(fd, response_err, sizeof(response_err) - 1);
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
      SSL_write(ssl_local, response_err, sizeof(response_err) - 1);
      continue;
    }
    if (req.header2 != NULL)
      req_hdr_remote_len = snprintf(
          req_hdr_remote, sizeof(req_hdr_remote), req_hdr_fmt1, req.method,
          req.host, req.path, HOST_REMOTE, req.header1, req.header2);
    else
      req_hdr_remote_len =
          snprintf(req_hdr_remote, sizeof(req_hdr_remote), req_hdr_fmt2,
                   req.method, req.host, req.path, HOST_REMOTE, req.header1);

    if (req_hdr_remote_len < 1) {
      SSL_write(ssl_local, response_err, sizeof(response_err) - 1);
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
      SSL_write(ssl_local, response_err, sizeof(response_err) - 1);
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
        SSL_write(ssl_local, response_err, sizeof(response_err) - 1);
        goto ssl_cleanup;
      }

      X509 *cert = SSL_get_peer_certificate(ssl_remote);
      if (cert)
        X509_free(cert);
      else {
        fprintf(stderr, "SSL: no remote peer's certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_write(ssl_local, response_err, sizeof(response_err) - 1);
        goto ssl_cleanup;
      }
      err = SSL_get_verify_result(ssl_remote);
      if (X509_V_OK != err) {
        /* TODO better err message via ERR_reason_error_string(err); */
        fprintf(stderr, "SSL: verify remote peer's certificate error\n");
        SSL_write(ssl_local, response_err, sizeof(response_err) - 1);
        goto ssl_cleanup;
      }
      /* TODO remote peer host name verification */
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
       * NOTE: Watch out for header "Transfer-Encoding: chunked", when present,
       * there is no "Content-Length:" header. It ends in "\r\n\r\n" check
       * RFC-2616 for details.
       *
       * NOTE: "Content-Length: " does not apply to "HEAD" request.
       */
      response_len = SSL_read(ssl_remote, response_buf, sizeof(response_buf));
      if (response_len > 0) {
        err = SSL_write(ssl_local, response_buf, response_len);
        if (err != (int)response_len) goto ssl_cleanup;
      }
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
        write(fd, response_err, sizeof(response_err) - 1);
        continue;
      }
#ifdef DEBUG
      fprintf(stderr, "Received connect request to host %s\n", host);
#endif
      proxy_ssl(fd, host);
      // write(fd, response_ok, sizeof(response_ok) - 1);
    } else {
      //    proxy_nossl(fd, request);
    }
  }
  return 0;
}
