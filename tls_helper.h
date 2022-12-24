#ifndef TLS_HELPER_H
#define TLS_HELPER_H 1

#include <openssl/err.h>
#include <openssl/ssl.h>

enum ssl_method { client_method, server_method };
extern SSL_CTX *ssl_create_context(enum ssl_method method);
extern int ssl_configure_context(SSL_CTX *ctx, enum ssl_method method);

#endif /* ifndef TLS_HELPER_H */
