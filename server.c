#include "server.h"

#ifdef __WIN32__
#include <winsock2.h>
#define poll WSAPoll
#define read read_winsock
#define write write_winsock

#else
#include <poll.h>
#include <sys/socket.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "http_helper.h"
#include "socket_helper.h"
#include "tls_helper.h"
#include "tweak.h"

#define FD_LOCAL 0
#define FD_REMOTE 1
#define POLLFDS 2

static const char response_err[] = "HTTP/1.1 400 Bad request\r\n\r\n";
static const char response_ok[] = "HTTP/1.1 200 OK\r\n\r\n";

#if defined REDIRECT_HTTP || defined REDIRECT_HTTPS
__attribute__ ((nonnull)) static void
redirect (int const fd, char *restrict const req_buff, size_t const buff_len)
{
  const char response_redirect[]
      = "HTTP/1.1 301 Moved Permanently\r\nConnection: Close\r\nLocation: "
#ifdef REDIRECT_HTTP
      HTTPS_PROTO
#elif defined REDIRECT_HTTPS
      HTTP_PROTO
#endif
        "%s\r\n\r\n";

  ssize_t len;
  len = read (fd, req_buff, buff_len);
  if (len < 1)
    goto err;
  *(req_buff + buff_len) = '\0';

  char *bare_url = http_bare_url (req_buff);
  if (bare_url == NULL)
    goto err;
  char buff[RESPONSE_MAX];
  len = snprintf (buff, sizeof (buff), response_redirect, bare_url);
  if (len < 1)
    {
      perror ("redirect generator");
      goto err;
    }
#ifdef DEBUG
  fprintf (stderr, "http redirect ===> \n%s\n", buff);
#endif
  /* redirect to https */
  write (fd, buff, len);
  goto ret;

err:
  write (fd, response_err, sizeof (response_err) - 1);
ret:
  close (fd);
}
#endif

typedef ssize_t (*WRITE_fn) (long fd, const void *buf, size_t n);
typedef int (*READ_fn) (long fd, void *buf, int n);
struct ssl_obj
{
  SSL *ssl_local;
  SSL *ssl_remote;
};

/*
 * bridges two file descriptors in pfd
 * will only return on error without closing fd in pfd
 *
 * pfd must be an array of size two. Eg. struct pollfd pfd[2]
 * and filled with two different fd and pfd->events equals POLLIN
 * see sanity checks inside this function for more insight
 *
 * ssl_objs can be null if not dealing with ssl.
 * 	It's members must default to NULL (zero).
 */
__attribute__ ((nonnull (1, 2))) static void
bridge_fds (struct pollfd const pfd[], void *const buffer, const size_t buflen,
            struct ssl_obj *ssl_objs)
{
  // TODO these should be macros
  // #define WRITE_L(buf,len) WRITE_LOCAL(ssl_local, buf, len)
  WRITE_fn WRITE_LOCAL = write, WRITE_REMOTE = write;
  READ_fn READ_LOCAL = read, READ_REMOTE = read;

  /* sanity checks */
  if (POLLIN != pfd[0].events || POLLIN != pfd[1].events
      || pfd[0].fd == pfd[1].fd || 32 > buflen)
    {
      fprintf (stderr, "%s:%d sanity checks failed\n", __FILE__, __LINE__);
      return;
    }

  SSL *ssl_local = (SSL *)(long)pfd[FD_LOCAL].fd;
  SSL *ssl_remote = (SSL *)(long)pfd[FD_REMOTE].fd;
  if (NULL != ssl_objs)
    {
      void *tmp = ssl_objs->ssl_local;
      if (tmp && (tmp != (void *)(long)pfd[FD_LOCAL].fd))
        {
          ssl_local = tmp;
          READ_LOCAL = SSL_read;
          WRITE_LOCAL = SSL_write;
        }
      tmp = ssl_objs->ssl_remote;
      if (tmp && (tmp != (void *)(long)pfd[FD_REMOTE].fd))
        {
          ssl_remote = tmp;
          READ_REMOTE = SSL_read;
          WRITE_REMOTE = SSL_write;
        }
    }

    // sanity check
#ifndef NDEBUG
  if (ssl_remote == ssl_local)
    fprintf (stderr, "ssl_romote and ssl_local is same\n");
#endif

  do
    {
      if (poll ((struct pollfd *)pfd, POLLFDS, -1) < 1)
        {
          perror ("poll failed");
          break;
        }
      if (pfd[FD_LOCAL].revents & POLLIN)
        {
          const ssize_t len = READ_LOCAL (ssl_local, buffer, buflen);
          if (len < 1)
            {
              if (&SSL_read == READ_LOCAL)
                tls_print_error (ssl_local, len);
              else
                perror ("can't read polled fd");
              break;
            }

          if (WRITE_REMOTE (ssl_remote, buffer, len) != len)
            {
              perror ("can't write fd");
              break;
            }
        }
      if (pfd[FD_REMOTE].revents & POLLIN)
        {
          const ssize_t len = READ_REMOTE (ssl_remote, buffer, buflen);
          if (len < 1)
            {
              perror ("can't read polled fd");
              break;
            }

          if (WRITE_LOCAL (ssl_local, buffer, len) != len)
            {
              perror ("can't write fd");
              break;
            }
        }
    }
  while (1);
}

#ifndef REDIRECT_HTTP
#define HTTPS_MODE true
#define HTTP_MODE false
#endif

#if (PEER_METHODS != PEER_METHOD_CONNECT)
static void
proxy (int const fd
#ifndef REDIRECT_HTTP
       ,
       /* https_mode: use macro HTTPS_MODE (CONNECT request) or HTTP_MODE */
       bool const https_mode
#endif
)
{
  /* Use macro WRITE_REMOTE and READ_REMOTE to read/write to remote peer
   * TODO: better error message for WRITE_REMOTE and READ_REMOTE */
  int err = -1;
  char buffer[REQUEST_MAX] = { 0 };
  int buff_len = -1;
  char request[REQUEST_MAX] = { 0 };
  int req_len = -1;
  const char *payload = NULL;
  size_t payload_len = 0;
  int fd_remote = -1;
  SSL *ssl_local = NULL;

#if (PEER_USE_TLS)
  SSL *ssl_remote = NULL;
#define WRITE_REMOTE SSL_write
#define READ_REMOTE SSL_read
#else

#define ssl_remote fd_remote
#define WRITE_REMOTE write
#define READ_REMOTE read
#endif
  // Connect to remote proxy
  fd_remote = connect_remote_server ();
  if (fd_remote < 0)
    goto end;
#if (PEER_USE_TLS)
  // remote SSL connect
  ssl_remote = tls_connect (fd_remote);
  if (!ssl_remote)
    goto end;
#endif

#define LOCAL_HANSHAKE()                                                      \
  {                                                                           \
    write (fd, response_ok, sizeof (response_ok) - 1);                        \
    ssl_local = tls_accept (fd);                                              \
    if (!ssl_local)                                                           \
      goto end;                                                               \
  }

/* if https only */
#ifndef REDIRECT_HTTP
  WRITE_fn WRITE_LOCAL = SSL_write;
  READ_fn READ_LOCAL = SSL_read;

  if (https_mode)
    {
      LOCAL_HANSHAKE ();
    }
  else
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
      /* TODO: dirty code here */
      WRITE_LOCAL = write;
      READ_LOCAL = read;
#pragma GCC diagnostic pop

      ssl_local = (SSL *)(long)fd;
    }
#else
#define WRITE_LOCAL SSL_write
#define READ_LOCAL SSL_read
  LOCAL_HANSHAKE ();

#endif

  // proxy_https main loop
  struct pollfd pfd[POLLFDS] = { 0 };
  pfd[FD_REMOTE].fd = fd_remote;
  pfd[FD_REMOTE].events = POLLIN;
  pfd[FD_LOCAL].fd = fd;
  pfd[FD_LOCAL].events = POLLIN;

  bool transform_next_local_read = true;
  do
    {
      if (poll (pfd, POLLFDS, -1) < 1)
        {
          perror ("poll failed");
          break;
        }
      if (pfd[FD_LOCAL].revents & POLLIN)
        {
          // read from local fd
          buff_len = READ_LOCAL (ssl_local, buffer, sizeof (buffer) - 1);
          if (buff_len < 1)
            {
              ERR_print_errors_fp (stderr);
              goto end;
            }

          if (transform_next_local_read)
            {
              *(buffer + buff_len) = '\0';
#ifdef DEBUG
              printf ("REQUEST_MAX is: %zubytes\n", sizeof (buffer));
              printf ("Request length is: %dbytes\n", buff_len);
              printf ("Request is \n\n%s\n", buffer);
#endif
              // modify request
              req_len = transform_req (buffer, buff_len, request,
                                       sizeof (request), &payload, &payload_len
#ifndef REDIRECT_HTTP
                                       ,
                                       https_mode
#endif
              );
              if (req_len < 1)
                {
                  err = WRITE_LOCAL (ssl_local, response_err,
                                     sizeof (response_err) - 1);
                  if (err < 1)
                    goto end;
                }
              else
                {
#ifdef DEBUG
                  fprintf (stderr, "Remote request ==>\n%s\nreq_len: %d\n",
                           request, req_len);
                  fprintf (stderr, "payload:\n%s\npayload_length: %zu\n",
                           payload, payload_len);
#endif
                  // send to remote
                  err = WRITE_REMOTE (ssl_remote, request, req_len);
                  if (err < 1)
                    {
                      perror ("WRITE_REMOTE error");
                      goto end;
                    }
                  else if (err < (int)req_len)
                    {
                      perror ("partial write");
                      goto end; // TODO may want to rewrite remaining instead
                    }

                  if (payload_len > 0 && payload)
                    {
                      err = WRITE_REMOTE (ssl_remote, payload, payload_len);
                      if (err < (int)payload_len)
                        {
                          perror ("WRITE_REMOTE error");
                          goto end;
                        }
                    }
                  transform_next_local_read = false;
                }
            }
          else
            {
              // send to remote
              WRITE_REMOTE (ssl_remote, buffer, buff_len);
              if (err < 1)
                {
                  perror ("WRITE_REMOTE error");
                  goto end;
                }
            }
        }
      if (pfd[FD_REMOTE].revents & POLLIN)
        {
          // read remote via READ
          buff_len = READ_REMOTE (ssl_remote, buffer, sizeof (buffer));
          if (buff_len < 1)
            {
              perror ("READ_REMOTE error");
              goto end;
            }

          // write local via SSL_write
          err = WRITE_LOCAL (ssl_local, buffer, buff_len);
          if (err != (int)buff_len)
            goto end;

          /* Process HTTP response header from remote
           * Useful for detecting web socket or errors from remote
           *
           * only on "first remote read since last local read"
           */
          if (!transform_next_local_read)
            {
              transform_next_local_read = true;
              if (0 == strncmp (buffer, "HTTP/1.1 101 ", 13))
                {
                  // web socket detected
#ifndef NDEBUG
                  write (STDERR_FILENO, buffer, buff_len);
                  fprintf (stderr, "\nWeb socket mode activated\n");
#endif
                  struct ssl_obj sslobj = { ssl_local, ssl_remote };
                  bridge_fds (pfd, buffer, sizeof (buffer), &sslobj);
                  goto end;
                }
            }
        }
    }
  while (1);
end:
  if (
#ifndef REDIRECT_HTTP
      https_mode &&
#endif
      ssl_local)
    tls_shutdown (ssl_local);
  close (fd);
#if (PEER_USE_TLS)
  if (ssl_remote)
    tls_shutdown (ssl_remote);
#endif
  if (fd_remote > -1)
    {
      close (fd_remote);
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
 * https_proxy="http://127.0.0.1:8888" curl https://host.net
 */
__attribute__ ((nonnull)) static void
proxy_connect (int const fd, const char *restrict const host,
               unsigned short const port)
{
#ifdef DEBUG
  fprintf (stderr, "proxy_connect mode\n");
#endif
  int fd_remote = -1;
  fd_remote = connect_remote_server ();
  if (fd_remote < 0)
    {
      // TODO: give better error code
      write (fd, response_err, sizeof (response_err) - 1);
      close (fd);
      return;
    }

  // send custom CONNECT request on remote peer
  char buffer[REQUEST_MAX] = { 0 };
  int len = 0;
  len = snprintf (buffer, sizeof (buffer), req_hdr_fmt_connect, host, port);
#ifdef DEBUG
  fprintf (stderr, "Custom connect resquest is \n%s\n", buffer);
#endif
  if (1 > write (fd_remote, buffer, len))
    {
      perror ("send request");
      goto proxy_end;
    }

  // bridge local fd with remote
  struct pollfd pfd[POLLFDS] = { 0 };
  pfd[FD_REMOTE].fd = fd_remote;
  pfd[FD_REMOTE].events = POLLIN;
  pfd[FD_LOCAL].fd = fd;
  pfd[FD_LOCAL].events = POLLIN;

  bridge_fds (pfd, buffer, sizeof (buffer), NULL);

proxy_end:
  close (fd_remote);
  close (fd);
}
#endif

int
server (int const fd)
{
  char request[REQUEST_MAX] = { 0 };

  char host[HOST_MAX] = { 0 };
  unsigned short port = 0;

  while (1)
    {
      ssize_t request_len;
      const char connect[7] = "CONNECT";

      request_len = recv (fd, (void *)request, sizeof (connect), MSG_PEEK);
      if (request_len < 1)
        {
#ifdef DEBUG
          perror ("Server read error, or connection closed");
#endif
          break;
        }
      *(request + request_len) = '\0';

      int err = -1;
      err = strncmp (request, connect, sizeof (connect));
      if (err == 0)
        {
          request_len = read (fd, (void *)request, sizeof (request));
          if (request_len < 1)
            {
#ifdef DEBUG
              perror ("Proxy read request");
#endif
              break;
            }
#ifdef DEBUG
          printf ("Request is \n%s\n", request);
#endif

          err = parse_connect_request (request, host, &port);
          if (err)
            {
              write (fd, response_err, sizeof (response_err) - 1);
              continue;
            }
#if defined PEER_CONNECT_CUSTOM_HOST
          proxy_connect (fd, host, port);
#else
          proxy (fd
#ifndef REDIRECT_HTTP
                 ,
                 HTTPS_MODE
#endif
          );

#endif
        }
      else
        {
#if defined REDIRECT_HTTP
          redirect (fd, request, sizeof (request));
#elif (PEER_METHODS == PEER_METHOD_CONNECT)
#warning "http not supported"
          fprintf (stderr, "http not supported\n");
          close (fd);
#else
          proxy (fd, HTTP_MODE);
#endif
        }
    }
  return 0;
}
