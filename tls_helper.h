#ifndef TLS_HELPER_H
#define TLS_HELPER_H 1

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "tweak.h"

/* return 0 on success */
extern int init_tls_helper ();
extern void tls_shutdown (SSL *__restrict const ssl) __attribute__ ((nonnull));

/**
 * tls_accept() - set up server TLS and do handshake
 * @fd: int socket file descriptor to use
 * @returns: NULL on failure
 *
 * caller must call tls_shutdown() after use
 */
extern SSL *tls_accept (int const fd);
#if (PEER_USE_TLS)
extern SSL *tls_connect (int const fd_remote);
#endif

extern void tls_print_error (SSL *__restrict const ssl, int const err)
    __attribute__ ((nonnull));
#endif /* ifndef TLS_HELPER_H */
