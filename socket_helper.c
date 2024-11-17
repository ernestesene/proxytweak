#ifdef __WIN32__
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <stdio.h>

#include "tweak.h"

int
connect_remote_server ()
{
  int fd = -1, err = -1;
  struct sockaddr_in addr = { 0 };
  struct hostent *hostnt = NULL;

  hostnt = gethostbyname (PEER_HOST);
  if (hostnt == NULL)
    {
      fprintf (stderr,
               "Can't resolve host to address. Check network connection.\n");
      return -1;
    }

  fd = socket (PF_INET, SOCK_STREAM, 0);
  addr.sin_family = AF_INET;
  addr.sin_port = htons (PEER_PORT);
  addr.sin_addr = *(struct in_addr *)hostnt->h_addr;
  /* TODO check for error */
  err = connect (fd, (struct sockaddr *)&addr, sizeof (addr));
  if (err == -1)
    {
      perror ("Connect to remote err");
      return -1;
    }
  return fd;
}

#ifdef __WIN32__
__attribute__ ((nonnull)) int
write_winsock (int fd, const void *buf, unsigned int count)
{
  return send (fd, buf, count, 0);
}

__attribute__ ((nonnull)) int
read_winsock (int fd, void *buf, unsigned int count)
{
  return recv (fd, buf, count, 0);
}
#endif
