#include "server.h"

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "http_helper.h"
#include "socket_helper.h"
#include "tls_helper.h"
#include "tweak.h"

#define FD_REMOTE 0
#define FD_LOCAL 1
#define POLLFDS 2

static const char response_err[] = "HTTP/1.1 400 Bad request\r\n\r\n";
static const char response_ok[] = "HTTP/1.1 200 OK\r\n\r\n";

#if defined REDIRECT_HTTP || defined REDIRECT_HTTPS
static void redirect(int fd, char *req_buff, size_t buff_len) {

  const char response_redirect[] =
      "HTTP/1.1 301 Moved Permanently\r\nConnection: Close\r\nLocation: "
#ifdef REDIRECT_HTTP
      HTTPS_PROTO
#elif defined REDIRECT_HTTPS
      HTTP_PROTO
#endif
      "%s\r\n\r\n";

  ssize_t len;
  len = read(fd, req_buff, buff_len);
  if (len < 1) goto err;
  *(req_buff + buff_len) = '\0';

  char *bare_url = http_bare_url(req_buff);
  if (bare_url == NULL) goto err;
  char buff[RESPONSE_MAX];
  len = snprintf(buff, sizeof(buff), response_redirect, bare_url);
  if (len < 1) {
    perror("redirect generator");
    goto err;
  }
#ifdef DEBUG
  fprintf(stderr, "http redirect ===> \n%s\n", buff);
#endif
  /* redirect to https */
  write(fd, buff, len);
  goto ret;

err:
  write(fd, response_err, sizeof(response_err) - 1);
ret:
  close(fd);
}
#endif

#if (PEER_METHODS != PEER_METHOD_CONNECT)
static void proxy_ssl(int fd) {
  /* Use macro WRITE and READ to read/write to remote peer
   * TODO: better error message for WRITE and READ */
  int err = -1;
  char buffer[REQUEST_MAX] = {0};
  int buff_len = -1;
  char request[REQUEST_MAX] = {0};
  int req_len = -1;
  const char *payload = NULL;
  size_t payload_len = 0;
  int fd_remote = -1;
  SSL *ssl_local = NULL;

#if (PEER_USE_TLS)
  SSL *ssl_remote = NULL;
#define WRITE SSL_write
#define READ SSL_read
#else

#define ssl_remote fd_remote
#define WRITE write
#define READ read
#endif
  // Connect to remote proxy
  fd_remote = connect_remote_server();
  if (fd_remote < 0) goto end;
#if (PEER_USE_TLS)
  // remote SSL connect
  ssl_remote = tls_connect(fd_remote);
  if (!ssl_remote) goto end;
#endif

  write(fd, response_ok, sizeof(response_ok) - 1);
  ssl_local = tls_accept(fd);
  if (!ssl_local) goto end;

  // proxy_https main loop
  struct pollfd pfd[POLLFDS] = {0};
  pfd[FD_REMOTE].fd = fd_remote;
  pfd[FD_REMOTE].events = POLLIN;
  pfd[FD_LOCAL].fd = fd;
  pfd[FD_LOCAL].events = POLLIN;

  bool FD_LOCAL_not_last_read = true;
  do {
    if (poll(pfd, POLLFDS, -1) < 1) {
      perror("poll failed");
      break;
    }
    if (pfd[FD_LOCAL].revents & POLLIN) {
      if (FD_LOCAL_not_last_read) {
        // read request from local fd
        buff_len = SSL_read(ssl_local, buffer, sizeof(buffer) - 1);
        if (buff_len < 1) {
          ERR_print_errors_fp(stderr);
          goto end;
        }
        *(buffer + buff_len) = '\0';
#ifdef DEBUG
        printf("REQUEST_MAX is: %zubytes\n", sizeof(buffer));
        printf("Request length is: %dbytes\n", buff_len);
        printf("Request is \n\n%s\n", buffer);
#endif
        // modify request
        req_len = transform_req(buffer, buff_len, request, sizeof(request),
                                &payload, &payload_len);
        if (req_len < 1) {
          err = SSL_write(ssl_local, response_err, sizeof(response_err) - 1);
          if (err < 1) goto end;
        } else {
#ifdef DEBUG
          fprintf(stderr, "Remote request ==>\n%s\nreq_len: %d\n", request,
                  req_len);
          fprintf(stderr, "payload:\n%s\npayload_length: %zu\n", payload,
                  payload_len);
#endif
          // send to remote
          err = WRITE(ssl_remote, request, req_len);
          if (err < 1) {
            perror("WRITE error");
            goto end;
          } else if (err < (int)req_len) {
            perror("partial write");
            goto end; // TODO may want to rewrite remaining instead
          }

          if (payload_len > 0 && payload) {
            err = WRITE(ssl_remote, payload, payload_len);
            if (err < (int)payload_len) {
              perror("WRITE error");
              goto end;
            }
          }
          FD_LOCAL_not_last_read = false;
        }
      } else {
        // continue reading local fd
        buff_len = SSL_read(ssl_local, buffer, sizeof(buffer));
        if (buff_len < 1) {
          ERR_print_errors_fp(stderr);
          goto end;
        }
        // send to remote
        WRITE(ssl_remote, buffer, buff_len);
        if (err < 1) {
          perror("WRITE error");
          goto end;
        }
      }
    }
    if (pfd[FD_REMOTE].revents & POLLIN) {
      FD_LOCAL_not_last_read = true;
      // read remote via READ
      buff_len = READ(ssl_remote, buffer, sizeof(buffer));
      if (buff_len < 1) {
        perror("read:remote");
        goto end;
      }
      // write local via SSL_write
      err = SSL_write(ssl_local, buffer, buff_len);
      if (err != (int)buff_len) goto end;
    }
  } while (1);
end:
  if (ssl_local) tls_shutdown(ssl_local);
  close(fd);
#if (PEER_USE_TLS)
  if (ssl_remote) tls_shutdown(ssl_remote);
#endif
  if (fd_remote > -1) {
    close(fd_remote);
  }
  return;
}
#endif /* (PEER_METHODS != PEER_METHOD_CONNECT) */

#ifdef PEER_CONNECT_CUSTOM_HOST
/* use case for ssh using openbsd-netcat:
 * ssh ssh.host.net -o ProxyUseFdpass=yes\
 * -o ProxyCommand="nc -FXconnect -x127.0.0.1:8888 %h %p"
 *
 * use case curl:
 * https_proxy="http://127.0.0.1:8888" curl https://host.net -A connect
 */
static void proxy_connect(int fd, const char *host, int port) {
#ifdef DEBUG
  fprintf(stderr, "proxy_connect mode\n");
#endif
  int fd_remote = -1;
  fd_remote = connect_remote_server();
  if (fd_remote < 0) {
    // TODO: give better error code
    write(fd, response_err, sizeof(response_err) - 1);
    close(fd);
    return;
  }

  // send custom CONNECT request on remote peer
  char buffer[REQUEST_MAX] = {0};
  int len = 0;
  len = snprintf(buffer, sizeof(buffer), req_hdr_fmt_connect, host, port);
#ifdef DEBUG
  fprintf(stderr, "Custom connect resquest is \n%s\n", buffer);
#endif
  if (1 > write(fd_remote, buffer, len)) {
    perror("send request");
    goto proxy_end;
  }

  // bridge local fd with remote
  struct pollfd pfd[POLLFDS] = {0};
  pfd[0].fd = fd_remote;
  pfd[0].events = POLLIN;
  pfd[1].fd = fd;
  pfd[1].events = POLLIN;

  do {
    if (poll(pfd, POLLFDS, -1) < 1) {
      perror("poll failed");
      break;
    }
    bool i = 0;
    do {
      if (pfd[i].revents & POLLIN) {
        len = read(pfd[i].fd, buffer, sizeof(buffer));
        if (len < 1) {
          perror("can't read polled fd");
          goto proxy_end;
        }
        if (len != write(pfd[!i].fd, buffer, len)) {
          perror("can't write fd");
          goto proxy_end;
        }
      }
      i = !i;
    } while (i);
  } while (1);
proxy_end:
  close(fd_remote);
  close(fd);
}
#endif

int server(int fd) {
  char request[REQUEST_MAX] = {0};

  char host[HOST_MAX] = {0};
  int port = 0;

  while (1) {
    ssize_t request_len;
    const char connect[7] = "CONNECT";

    request_len = recv(fd, (void *)request, sizeof(connect), MSG_PEEK);
    if (request_len < 1) {
#ifdef DEBUG
      perror("Server read error, or connection closed");
#endif
      break;
    }
    *(request + request_len) = '\0';

    int err = -1;
    err = strncmp(request, connect, sizeof(connect));
    if (err == 0) {
      request_len = read(fd, (void *)request, sizeof(request));
#ifdef DEBUG
      printf("Request is \n%s\n", request);
#endif
#if defined PEER_CONNECT_CUSTOM_HOST && (PEER_METHODS == PEER_METHOD_CONNECT)
/* nothing, only to skip the #elif block */
#elif defined PEER_CONNECT_CUSTOM_HOST
      int use_connect = 0;
      if (strstr(request, CONNECT_HEADER) || !strstr(request, "Host: "))
        use_connect = 1;
#endif
      err = parse_connect_request(request, host, &port);
      if (err) {
        write(fd, response_err, sizeof(response_err) - 1);
        continue;
      }
#if defined PEER_CONNECT_CUSTOM_HOST && (PEER_METHODS == PEER_METHOD_CONNECT)
      proxy_connect(fd, host, port);
#elif defined PEER_CONNECT_CUSTOM_HOST
      if (use_connect)
        proxy_connect(fd, host, port);
      else
        proxy_ssl(fd);
#else
      proxy_ssl(fd);
#endif
    } else {
#if defined REDIRECT_HTTP
      redirect(fd, request, sizeof(request));
#else
      fprintf(stderr, "no http support\n");
      close(fd);
#endif
    }
  }
  return 0;
}
