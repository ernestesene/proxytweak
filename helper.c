#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

/* gethostbyname trick */
#include <netdb.h>
extern int h_errno;

#define INETADDR_REMOTE_HOST 0x68152e93 /* 104.21.46.147 */

int connect_remote_server() {
  int fd = -1, err = -1;
  struct sockaddr_in addr = {0};

  /* TRICK: only to trick uptream network to enable connection */
  void *hostent = gethostbyname("ncdc.gov.ng");
  if (hostent == NULL) return -1;

  fd = socket(PF_INET, SOCK_STREAM, 0);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(443);
  addr.sin_addr.s_addr = htonl(INETADDR_REMOTE_HOST);
  /* TODO check for error */
  err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (err == -1) {
    perror("Connect to remote err");
    return -1;
  }
  return fd;
}
