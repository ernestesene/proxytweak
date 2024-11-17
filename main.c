#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __WIN32__
#include <winsock2.h>
typedef int socklen_t;
#else
/* unix */
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include "server.h"
#include "tls_helper.h"
#include "tweak.h"

__attribute__ ((nonnull)) void *
thread_function (void *restrict const arg)
{
  int *newfd = NULL;
  int err = 0;

  newfd = (int *)arg;
  err = server (*newfd);
  if (err != 0)
    {
      /* do something */
    }

  // ret:
  close (*newfd);
  free (newfd);
  return NULL;
}
static void
initialize ()
{
  if (init_tls_helper ())
    exit (EXIT_FAILURE);
}

int
main (void)
{
  int sockfd = -1, *newfd = NULL;
  int yes = 1;
  int err;

  initialize ();

  signal (SIGPIPE, SIG_IGN);

#ifdef __WIN32__
  WSADATA wsaData;
  err = WSAStartup (MAKEWORD (2, 2), &wsaData);
  if (0 != err)
    {
      fprintf (stderr, "WSAStartup error: %d\n", err);
      return 1;
    }
#endif

  sockfd = socket (PF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
    {
      perror ("Socket create error");
      exit (EXIT_FAILURE);
    }
  if (setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof (yes))
      == -1)
    {
      perror ("Set sock opt SO_REUSEADDR Error");
      close (sockfd);
      exit (EXIT_FAILURE);
    }

  struct sockaddr_in addr = { 0 };
  addr.sin_family = AF_INET;
  addr.sin_port = htons (LISTEN_PORT);
  addr.sin_addr.s_addr = htonl (LISTEN_ADDR);
  err = bind (sockfd, (struct sockaddr *)&addr, sizeof (addr));
  if (err == -1)
    {
      perror ("Bind error");
      close (sockfd);
      exit (EXIT_FAILURE);
    }
  err = listen (sockfd, 15);
  if (err == -1)
    {
      perror ("Listen error");
      close (sockfd);
      exit (EXIT_FAILURE);
    }

  fprintf (stderr, "Listening on port %d\n", LISTEN_PORT);
  while (1)
    {
      struct sockaddr_in client_addr = { 0 };
      socklen_t addr_len = sizeof (client_addr);
      newfd = (int *)malloc (sizeof (*newfd));
      if (newfd == NULL)
        {
          perror ("malloc newfd");
          sleep (5);
          continue;
        }
      *newfd = accept (sockfd, (struct sockaddr *)&client_addr, &addr_len);
      if (*newfd == -1)
        {
          perror ("Accept Error");
          free (newfd);
          continue;
        }
      /*
        char client_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, (void *)&client_addr.sin_addr, client_ip,
        sizeof(client_ip)); printf("Got connection from %s\n", client_ip);
      */
      pthread_t athread;
      /* Thread must close and free newfd */
      err = pthread_create (&athread, NULL, &thread_function, (void *)newfd);
      if (err != 0)
        {
          perror ("pthread_create error");
          close (*newfd);
          free (newfd);
        }
    }

  close (sockfd);

  return 0;
}
