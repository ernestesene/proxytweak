#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

#include "tweak.h"

/* TODO: change to getaddrinfo(3) */
#include <netdb.h>
extern int h_errno;

int connect_remote_server() {
  int fd = -1, err = -1;
  struct sockaddr_in addr = {0};
  struct hostent *hostnt = NULL;

  hostnt = gethostbyname(PEER_HOST);
  if (hostnt == NULL) {
    fprintf(stderr,
            "Can't resolve host to address. Check network connection.\n");
    return -1;
  }

  fd = socket(PF_INET, SOCK_STREAM, 0);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PEER_PORT);
  addr.sin_addr = *(struct in_addr *)hostnt->h_addr;
  /* TODO check for error */
  err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (err == -1) {
    perror("Connect to remote err");
    return -1;
  }
  return fd;
}
