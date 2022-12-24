#include "tls_helper.h"

SSL_CTX *ssl_create_context(enum ssl_method method) {
  const SSL_METHOD *_method = NULL;
  SSL_CTX *ctx = NULL;

  if (method == client_method)
    _method = TLS_client_method();
  else
    _method = TLS_server_method();
  ctx = SSL_CTX_new(_method);
  if (!ctx) {
    perror("SSL create context error");
    ERR_print_errors_fp(stderr);
    return NULL;
  }
  return ctx;
}

int ssl_configure_context(SSL_CTX *ctx, enum ssl_method method) {
  /* Set the key and cert to use */
  if (method == server_method) {
    if (SSL_CTX_use_certificate_file(ctx, "selfsign.crt", SSL_FILETYPE_PEM) <=
        0) {
      ERR_print_errors_fp(stderr);
      return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "selfsign.key", SSL_FILETYPE_PEM) <=
        0) {
      ERR_print_errors_fp(stderr);
      return 1;
    }
    /* check if private key matches the certificate public key */
    if (SSL_CTX_check_private_key(ctx) != 1) {
      ERR_print_errors_fp(stderr);
      return 1;
    }
  } else if (method == client_method) {
    SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt",
                                  NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2);
  } else
    return 1;
  return 0;
}
