#include "tls_helper.h"

#include "tweak.h"

enum ssl_method
{
  client_method,
  server_method
};

/* race condition. MT-Unsafe */
static SSL_CTX *ctx_client = NULL;
static SSL_CTX *ctx_server = NULL;

static int ssl_configure_context (SSL_CTX *restrict const ctx,
                                  enum ssl_method const method)
    __attribute__ ((nonnull));
void
tls_shutdown (SSL *const ssl)
{
  SSL_shutdown (ssl);
  SSL_free (ssl);
}
__attribute__ ((nonnull)) static void
tls_print_error (SSL *restrict const ssl, int const err)
{
  ERR_print_errors_fp (stderr);
  if (SSL_ERROR_SYSCALL == SSL_get_error (ssl, err))
    perror ("tls_error");
}

static SSL_CTX *
ssl_create_context (enum ssl_method const method)
{
  const SSL_METHOD *_method = NULL;
  SSL_CTX *ctx = NULL;

  if (method == client_method)
    _method = TLS_client_method ();
  else
    _method = TLS_server_method ();
  ctx = SSL_CTX_new (_method);
  if (!ctx)
    {
      ERR_print_errors_fp (stderr);
      return NULL;
    }
  if (ssl_configure_context (ctx, method))
    {
      SSL_CTX_free (ctx);
      ctx = NULL;
    }
  return ctx;
}

int
init_tls_helper ()
{
  ctx_server = ssl_create_context (server_method);
  ctx_client = ssl_create_context (client_method);
  if (ctx_server && ctx_client)
    return 0;
  return 1;
}
static int
ssl_configure_context (SSL_CTX *restrict const ctx,
                       enum ssl_method const method)
{
  /* Set the key and cert to use */
  if (method == server_method)
    {
      if (SSL_CTX_use_certificate_file (ctx, "selfsign.crt", SSL_FILETYPE_PEM)
          <= 0)
        {
          ERR_print_errors_fp (stderr);
          return 1;
        }
      if (SSL_CTX_use_PrivateKey_file (ctx, "selfsign.key", SSL_FILETYPE_PEM)
          <= 0)
        {
          ERR_print_errors_fp (stderr);
          return 1;
        }
      /* check if private key matches the certificate public key */
      if (SSL_CTX_check_private_key (ctx) != 1)
        {
          ERR_print_errors_fp (stderr);
          return 1;
        }
    }
  else if (method == client_method)
    {
      SSL_CTX_load_verify_locations (ctx, "/etc/ssl/certs/ca-certificates.crt",
                                     NULL);
      SSL_CTX_set_options (ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2);
    }
  else
    {
      fprintf (stderr, "invalid SSL method\n");
      return 1;
    }
  return 0;
}

SSL *
tls_accept (int const fd)
{
  int err = -1;
  SSL *ssl_local = NULL;

  if (ctx_server == NULL)
    goto ret;
  /* local server SSL  and handshake */
  ssl_local = SSL_new (ctx_server);
  if (ssl_local == NULL)
    goto ret;
  SSL_set_fd (ssl_local, fd);
  err = SSL_accept (ssl_local);
  if (err != 1)
    goto ret_err;

  goto ret;
ret_err:
  tls_print_error (ssl_local, err);
  tls_shutdown (ssl_local);
  ssl_local = NULL;
ret:
  return ssl_local;
}

#if (PEER_USE_TLS)
SSL *
tls_connect (int const fd_remote)
{
  SSL *ssl_remote = NULL;
  int err = -1;

  if (ctx_client == NULL)
    goto ret;
  ssl_remote = SSL_new (ctx_client);
  if (ssl_remote == NULL)
    {
      ERR_print_errors_fp (stderr);
      goto ret;
    }
  /* TODO handle err */
  SSL_set_tlsext_host_name (ssl_remote, PEER_CUSTOM_HOST);
  if (SSL_set_fd (ssl_remote, fd_remote) != 1)
    goto ret_err;
  err = SSL_connect (ssl_remote);
  if (err != 1)
    goto ret_err;

  X509 *cert = SSL_get_peer_certificate (ssl_remote);
  if (cert)
    X509_free (cert);
  else
    {
      fprintf (stderr, "SSL: no remote peer's certificate\n");
      goto ret_err;
    }
  err = SSL_get_verify_result (ssl_remote);
  if (X509_V_OK != err)
    {
      /* TODO better err message via ERR_reason_error_string(err); */
      fprintf (stderr, "SSL: verify remote peer's certificate error\n");
      goto ret_err;
    }
  /* TODO remote peer host name verification */
  goto ret;
ret_err:
  tls_print_error (ssl_remote, err);
  tls_shutdown (ssl_remote);
  ssl_remote = NULL;
ret:
  return ssl_remote;
}
#endif
