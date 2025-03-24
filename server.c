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

typedef int (*WRITE_fn) (SSL *fd, const void *buf, int n);
typedef int (*READ_fn) (SSL *ssl, void *buf, int n);
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
  /* Macro READ_L/READ_R, WRITE_L/WRITE_R read/write to local/remote peers
   * using READ_LOCAL/READ_REMOTE, WRITE_LOCAL/WRITE_REMOTE function pointers
   * variable ssl_local/ssl_remote must be locally define as (SSL *) and should
   * be a file descriptor for read/write or pointer to SSL * object for
   * SSL_read/SSL_write
   * TODO: better error message for WRITE_REMOTE and READ_REMOTE
   * TODO: WRITE_fn should be global variable (only threaded not
   * multiplexed-io)*/
#define WRITE_L(buf, len) WRITE_LOCAL (ssl_local, (buf), (len))
#define WRITE_R(buf, len) WRITE_REMOTE (ssl_remote, (buf), (len))
#define READ_L(buf, len) READ_LOCAL (ssl_local, (buf), (len))
#define READ_R(buf, len) READ_REMOTE (ssl_remote, (buf), (len))
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
  WRITE_fn WRITE_LOCAL = write, WRITE_REMOTE = write;
  READ_fn READ_LOCAL = read, READ_REMOTE = read;
#pragma GCC diagnostic pop

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
          const ssize_t len = READ_L (buffer, buflen);
          if (len < 1)
            {
              if (&SSL_read == READ_LOCAL)
                tls_print_error (ssl_local, len);
              else
                perror ("can't read polled fd");
              break;
            }

          if (WRITE_R (buffer, len) != len)
            {
              perror ("can't write fd");
              break;
            }
        }
      if (pfd[FD_REMOTE].revents & POLLIN)
        {
          const ssize_t len = READ_R (buffer, buflen);
          if (len < 1)
            {
              perror ("can't read polled fd");
              break;
            }

          if (WRITE_L (buffer, len) != len)
            {
              perror ("can't write fd");
              break;
            }
        }
    }
  while (1);
}

#define HTTPS_MODE true
#define HTTP_MODE false

#if (PEER_METHODS != PEER_METHOD_CONNECT)
__attribute__ ((nonnull)) static void
proxy (int const fd,
       /* https_mode: use macro HTTPS_MODE (CONNECT request) or HTTP_MODE */
       bool const https_mode, char *const buffer, const size_t buflen)
{
  int err = -1;
  int buff_len = -1;
  char request[REQUEST_MAX] = { 0 };
  int req_len = -1;
  const char *payload = NULL;
  size_t payload_len = 0;
  int fd_remote = -1;
  SSL *ssl_local = NULL;

  // Connect to remote proxy
  fd_remote = connect_remote_server ();
  if (fd_remote < 0)
    goto end2;

#if (PEER_USE_TLS)
  // remote SSL connect
  SSL *ssl_remote = tls_connect (fd_remote);
  if (!ssl_remote)
    goto end;
#define WRITE_REMOTE SSL_write
#define READ_REMOTE SSL_read
#else

#define ssl_remote fd_remote
#define WRITE_REMOTE write
#define READ_REMOTE read
#endif

#define LOCAL_HANSHAKE()                                                      \
  {                                                                           \
    write (fd, response_ok, sizeof (response_ok) - 1);                        \
    ssl_local = tls_accept (fd);                                              \
    if (!ssl_local)                                                           \
      goto end;                                                               \
  }

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
          buff_len = READ_L (buffer, buflen - 1);
          if (buff_len < 1)
            {
              ERR_print_errors_fp (stderr);
              goto end;
            }

          if (transform_next_local_read)
            {
              *(buffer + buff_len) = '\0';
#ifndef NDEBUG
              printf ("REQUEST_MAX is: %zubytes\n", buflen);
              printf ("Request length is: %dbytes\n", buff_len);
              printf ("Request is \n\n%s\n", buffer);
#endif
              // modify request
              req_len
                  = transform_req (buffer, buff_len, request, sizeof (request),
                                   &payload, &payload_len, https_mode);
              if (req_len < 1)
                {
                  err = WRITE_L (response_err, sizeof (response_err) - 1);
                  goto end;
                }
              else
                {
#ifndef NDEBUG
                  fprintf (stderr, "Remote request ==>\n%s\nreq_len: %d\n",
                           request, req_len);
                  fprintf (stderr, "payload:\n%s\npayload_length: %zu\n",
                           payload, payload_len);
#endif
                  // send to remote
                  err = WRITE_R (request, req_len);
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
                      err = WRITE_R (payload, payload_len);
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
              WRITE_R (buffer, buff_len);
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
          buff_len = READ_R (buffer, buflen);
          if (buff_len < 1)
            {
              perror ("READ_REMOTE error");
              goto end;
            }

          // write local via SSL_write
          err = WRITE_L (buffer, buff_len);
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
                  struct ssl_obj sslobj
                      = { ssl_local, (SSL *)(long)ssl_remote };
                  bridge_fds (pfd, buffer, buflen, &sslobj);
                  goto end;
                }
            }
        }
    }
  while (1);
end:
  if (https_mode && ssl_local)
    tls_shutdown (ssl_local);
#if (PEER_USE_TLS)
  if (ssl_remote)
    tls_shutdown (ssl_remote);
#endif
  if (fd_remote > -1)
    {
      close (fd_remote);
    }
end2:
  close (fd);
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
               unsigned short const port, char *const buffer,
               const size_t buflen)
{
#ifndef NDEBUG
  fprintf (stderr, "proxy_connect mode\n");
#endif
  const int fd_remote = connect_remote_server ();
  if (fd_remote < 0)
    {
      // TODO: give better error code
      write (fd, response_err, sizeof (response_err) - 1);
      close (fd);
      return;
    }

  // send custom CONNECT request on remote peer
  int len = 0;
  len = snprintf (buffer, buflen, req_hdr_fmt_connect, host, port);
#ifndef NDEBUG
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

  bridge_fds (pfd, buffer, buflen, NULL);

proxy_end:
  close (fd_remote);
  close (fd);
}
#endif

int
server (int const fd)
{
  char buffer[REQUEST_MAX] = { 0 };

  char host[HOST_MAX] = { 0 };
  unsigned short port = 0;

  while (1)
    {
      ssize_t request_len;
      const char connect[7] = "CONNECT";

      request_len = recv (fd, (void *)buffer, sizeof (connect), MSG_PEEK);
      if (sizeof (connect) != request_len)
        {
#ifndef NDEBUG
          perror ("proxy request read error");
#endif
          break;
        }
      *(buffer + request_len) = '\0';

      int err = -1;
      err = strncmp (buffer, connect, sizeof (connect));
      if (err == 0)
        {
          request_len = read (fd, (void *)buffer, sizeof (buffer));
          if (request_len < 1)
            {
#ifndef NDEBUG
              perror ("Proxy read request");
#endif
              break;
            }
#ifndef NDEBUG
          printf ("Request is \n%s\n", buffer);
#endif

          err = parse_connect_request (buffer, host, &port);
          if (err)
            {
              write (fd, response_err, sizeof (response_err) - 1);
              continue;
            }
#if defined PEER_CONNECT_CUSTOM_HOST
          proxy_connect (fd, host, port, buffer, sizeof (buffer));
#else
          proxy (fd, HTTPS_MODE, buffer, sizeof (buffer));

#endif
        }
      else
        {
#if (PEER_METHODS == PEER_METHOD_CONNECT)
#warning "http not supported"
          fprintf (stderr, "http not supported\n");
          close (fd);
#else
          proxy (fd, HTTP_MODE, buffer, sizeof (buffer));
#endif
        }
    }
  return 0;
}
