#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "server.h"
#include "tls_helper.h"

#define PORT 8888

void *thread_function(void *arg) {
  int *newfd = NULL;
  int err = 0;

  newfd = (int *)arg;
  err = server(*newfd);
  if (err != 0) {
    /* do something */
  }

  // ret:
  close(*newfd);
  free(newfd);
  return NULL;
}
static void initialize() {
  if (init_tls_helper()) exit(EXIT_FAILURE);
}

int main(void) {
  int sockfd = -1, *newfd = NULL;
  int yes = 1;
  int err;

  initialize();

  signal(SIGPIPE, SIG_IGN);

  sockfd = socket(PF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    perror("Socket create error");
    exit(EXIT_FAILURE);
  }
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
    perror("Set sock opt SO_REUSEADDR Error");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  err = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
  if (err == -1) {
    perror("Bind error");
    close(sockfd);
    exit(EXIT_FAILURE);
  }
  err = listen(sockfd, 15);
  if (err == -1) {
    perror("Listen error");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  while (1) {
    struct sockaddr_in client_addr = {0};
    socklen_t addr_len = sizeof(client_addr);
    newfd = (int *)malloc(sizeof(*newfd));
    *newfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len);
    if (*newfd == -1) {
      perror("Accept Error");
      free(newfd);
      continue;
    }
    /*
      char client_ip[INET_ADDRSTRLEN] = {0};
      inet_ntop(AF_INET, (void *)&client_addr.sin_addr, client_ip,
      sizeof(client_ip)); printf("Got connection from %s\n", client_ip);
    */
    pthread_t athread;
    /* Thread must close and free newfd */
    err = pthread_create(&athread, NULL, &thread_function, (void *)newfd);
    if (err != 0) {
      perror("pthread_create error");
      close(*newfd);
      free(newfd);
    }
  }

  close(sockfd);

  return 0;
}
