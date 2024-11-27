#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> /* gai_strerror() */
#include <io.h> /* write() */
#include <fcntl.h> /* O_BINARY */
#define strncasecmp _strnicmp
#else
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "rustls.h"
#include "common.h"

/* Set by client.c's and server.c's main() */
const char *programname;

void
print_error(const char *prefix, rustls_result result)
{
  char buf[256];
  size_t n;
  rustls_error(result, buf, sizeof(buf), &n);
  LOG("%s: %.*s", prefix, (int)n, buf);
}

#ifdef _WIN32
const char *
ws_strerror(int err)
{
  static char ws_err[50];

  if(err >= WSABASEERR) {
    snprintf(ws_err, sizeof(ws_err), "Winsock err: %d", err);
    return ws_err;
  }
  /* Assume a CRT error */
  return (strerror)(err);
}
#endif

/*
 * Set a socket to be nonblocking.
 *
 * Returns DEMO_OK on success, DEMO_ERROR on error.
 */
enum demo_result
nonblock(int sockfd)
{
#ifdef _WIN32
  u_long nonblock = 1UL;

  if(ioctlsocket(sockfd, FIONBIO, &nonblock) != 0) {
    perror("Error setting socket nonblocking");
    return DEMO_ERROR;
  }
#else
  int flags;
  flags = fcntl(sockfd, F_GETFL, 0);
  if(flags < 0) {
    perror("getting socket flags");
    return DEMO_ERROR;
  }
  flags = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
  if(flags < 0) {
    perror("setting socket nonblocking");
    return DEMO_ERROR;
  }
#endif
  return DEMO_OK;
}

int
read_cb(void *userdata, unsigned char *buf, size_t len, size_t *out_n)
{
  struct conndata *conn = (struct conndata *)userdata;
  ssize_t n = recv(conn->fd, buf, len, 0);
  if(n < 0) {
    return errno;
  }
  if(out_n != NULL) {
    *out_n = n;
  }
  return 0;
}

int
write_cb(void *userdata, const unsigned char *buf, size_t len, size_t *out_n)
{
  struct conndata *conn = (struct conndata *)userdata;

  ssize_t n = send(conn->fd, buf, len, 0);
  if(n < 0) {
    return errno;
  }
  if(out_n != NULL) {
    *out_n = n;
  }
  return 0;
}

rustls_io_result
write_tls(struct rustls_connection *rconn, struct conndata *conn, size_t *n)
{
#ifdef _WIN32
  return rustls_connection_write_tls(rconn, write_cb, conn, n);
#else
  if(getenv("VECTORED_IO")) {
    return rustls_connection_write_tls_vectored(
      rconn, write_vectored_cb, conn, n);
  }
  else {
    return rustls_connection_write_tls(rconn, write_cb, conn, n);
  }
#endif /* _WIN32 */
}

#ifndef _WIN32
rustls_io_result
write_vectored_cb(void *userdata, const struct rustls_iovec *iov, size_t count,
                  size_t *out_n)
{
  struct conndata *conn = (struct conndata *)userdata;

  // safety: narrowing conversion from `size_t count` to `int` is safe because
  // writev return -1 and sets errno to EINVAL on out of range input (<0 || >
  // IOV_MAX).
  ssize_t n = writev(conn->fd, (const struct iovec *)iov, (int)count);
  if(n < 0) {
    return errno;
  }
  *out_n = n;
  return 0;
}
#endif /* _WIN32 */

size_t
bytevec_available(struct bytevec *vec)
{
  return vec->capacity - vec->len;
}

char *
bytevec_writeable(struct bytevec *vec)
{
  return vec->data + vec->len;
}

void
bytevec_consume(struct bytevec *vec, size_t n)
{
  vec->len += n;
}

// Ensure there are at least n bytes available between vec->len and
// vec->capacity. If this requires reallocating, this may return
// DEMO_ERROR.
enum demo_result
bytevec_ensure_available(struct bytevec *vec, size_t n)
{
  size_t available = vec->capacity - vec->len;
  size_t newsize;
  void *newdata;
  if(available < n) {
    newsize = vec->len + n;
    if(newsize < vec->capacity * 2) {
      newsize = vec->capacity * 2;
    }
    newdata = realloc(vec->data, newsize);
    if(newdata == NULL) {
      fprintf(stderr, "out of memory trying to get %zu bytes\n", newsize);
      return DEMO_ERROR;
    }
    vec->data = newdata;
    vec->capacity = newsize;
  }
  return DEMO_OK;
}

/**
 * Copy all available plaintext from rustls into our own buffer, growing
 * our buffer as much as needed.
 */
int
copy_plaintext_to_buffer(struct conndata *conn)
{
  unsigned int result;
  size_t n;
  struct rustls_connection *rconn = conn->rconn;

  if(bytevec_ensure_available(&conn->data, 1024) != DEMO_OK) {
    return DEMO_ERROR;
  }

  for(;;) {
    char *buf = bytevec_writeable(&conn->data);
    size_t avail = bytevec_available(&conn->data);
    result = rustls_connection_read(rconn, (uint8_t *)buf, avail, &n);
    if(result == RUSTLS_RESULT_PLAINTEXT_EMPTY) {
      /* This is expected. It just means "no more bytes for now." */
      return DEMO_OK;
    }
    if(result != RUSTLS_RESULT_OK) {
      print_error("error in rustls_connection_read", result);
      return DEMO_ERROR;
    }
    if(n == 0) {
      LOG_SIMPLE("got 0-byte read, cleanly ending connection");
      return DEMO_EOF;
    }
    bytevec_consume(&conn->data, n);
    if(bytevec_ensure_available(&conn->data, 1024) != DEMO_OK) {
      return DEMO_ERROR;
    }
  }
}

/**
 * Since memmem is not cross-platform compatible, we bring our own.
 * Copied from https://www.capitalware.com/rl_blog/?p=5847.
 *
 * Function Name
 *  memmem
 *
 * Description
 *  Like strstr(), but for non-text buffers that are not NULL delimited.
 *
 *  public domain by Bob Stout
 *
 * Input parameters
 *  haystack    - pointer to the buffer to be searched
 *  haystacklen - length of the haystack buffer
 *  needle      - pointer to a buffer that will be searched for
 *  needlelen   - length of the needle buffer
 *
 * Return Value
 *  pointer to the memory address of the match or NULL.
 */
void *
memmem(const void *haystack, size_t haystacklen, const void *needle,
       size_t needlelen)
{
  const char *bf = haystack;
  const char *pt = needle;
  const char *p = bf;

  while(needlelen <= (haystacklen - (p - bf))) {
    if(NULL != (p = memchr(p, (int)(*pt), haystacklen - (p - bf)))) {
      if(0 == memcmp(p, needle, needlelen)) {
        return (void *)p;
      }
      else {
        ++p;
      }
    }
    else {
      break;
    }
  }

  return NULL;
}

char *
body_beginning(struct bytevec *vec)
{
  const void *result = memmem(vec->data, vec->len, "\r\n\r\n", 4);
  if(result == NULL) {
    return NULL;
  }
  else {
    return (char *)result + 4;
  }
}

const char *
get_first_header_value(const char *headers, size_t headers_len,
                       const char *name, size_t name_len, size_t *n)
{
  const void *result;
  const char *current = headers;
  size_t len = headers_len;
  size_t skipped;

  while(len > name_len + 3) {
    // Find the next header line.
    result = memmem(current, len, "\r\n", 2);
    if(result == NULL) {
      return NULL;
    }
    skipped = (char *)result - current + 2;
    len -= skipped;
    current += skipped;

    // Check if the line contains the desired header.
    if(len >= name_len + 2 && strncasecmp(name, current, name_len) == 0 &&
       current[name_len] == ':') {
      current += name_len + 1;
      len -= name_len + 1;

      // Find the end of the header value.
      result = memmem(current, len, "\r\n", 2);
      if(result == NULL) {
        *n = len;
        return current;
      }

      *n = (char *)result - current;
      return current;
    }
  }

  return NULL;
}

int
extract_headers(const char *headers, size_t headers_len,
                const char **content_length, size_t *content_length_len,
                const char **transfer_encoding, size_t *transfer_encoding_len)
{
  const char *current = headers;
  const void *result;
  size_t len = headers_len;

  *content_length = NULL;
  *transfer_encoding = NULL;

  while(len > 0) {
    // Find the end of the current header line.
    result = memmem(current, len, "\r\n", 2);
    if(result == NULL) {
      break;
    }

    size_t line_len = (char *)result - current;
    len -= line_len + 2; // Advance past this line and the trailing \r\n
    const char *line = current;
    current += line_len + 2;

    // Check for Content-Length.
    if(line_len > strlen("Content-Length:") &&
       strncasecmp(line, "Content-Length:", strlen("Content-Length:")) == 0) {
      *content_length = line + strlen("Content-Length:");
      *content_length_len = strcspn(*content_length, "\r\n");
    }

    // Check for Transfer-Encoding.
    if(line_len > strlen("Transfer-Encoding:") &&
       strncasecmp(line, "Transfer-Encoding:", strlen("Transfer-Encoding:")) ==
         0) {
      *transfer_encoding = line + strlen("Transfer-Encoding:");
      *transfer_encoding_len = strcspn(*transfer_encoding, "\r\n");
    }

    // Stop if we have all desired headers.
    if(*content_length || *transfer_encoding) {
      break;
    }
  }

  return 0;
}

void
log_cb(void *userdata, const struct rustls_log_params *params)
{
  struct conndata *conn = (struct conndata *)userdata;
  struct rustls_str level_str = rustls_log_level_str(params->level);
  LOG("[fd %d][%.*s]: %.*s",
      conn->fd,
      (int)level_str.len,
      level_str.data,
      (int)params->message.len,
      params->message.data);
}

enum demo_result
read_file(const char *filename, char *buf, size_t buflen, size_t *n)
{
  FILE *f = fopen(filename, "r");
  if(f == NULL) {
    LOG("opening %s: %s", filename, strerror(errno));
    return DEMO_ERROR;
  }
  *n = fread(buf, 1, buflen, f);
  if(!feof(f)) {
    LOG("reading %s: %s", filename, strerror(errno));
    fclose(f);
    return DEMO_ERROR;
  }
  fclose(f);
  return DEMO_OK;
}

const struct rustls_certified_key *
load_cert_and_key(const char *certfile, const char *keyfile)
{
  char certbuf[10000];
  size_t certbuf_len;
  char keybuf[10000];
  size_t keybuf_len;

  unsigned int result =
    read_file(certfile, certbuf, sizeof(certbuf), &certbuf_len);
  if(result != DEMO_OK) {
    return NULL;
  }

  result = read_file(keyfile, keybuf, sizeof(keybuf), &keybuf_len);
  if(result != DEMO_OK) {
    return NULL;
  }

  const struct rustls_certified_key *certified_key;
  result = rustls_certified_key_build((uint8_t *)certbuf,
                                      certbuf_len,
                                      (uint8_t *)keybuf,
                                      keybuf_len,
                                      &certified_key);
  if(result != RUSTLS_RESULT_OK) {
    print_error("parsing certificate and key", result);
    return NULL;
  }

  if(rustls_certified_key_keys_match(certified_key) != RUSTLS_RESULT_OK) {
    fprintf(stderr,
            "private key %s does not match certificate %s public key\n",
            keyfile,
            certfile);
    rustls_certified_key_free(certified_key);
    return NULL;
  }

  return certified_key;
}

const struct rustls_crypto_provider *
default_provider_with_custom_ciphersuite(const char *custom_ciphersuite_name)
{
  const struct rustls_supported_ciphersuite *custom_ciphersuite = NULL;
  rustls_crypto_provider_builder *provider_builder = NULL;
  const struct rustls_crypto_provider *custom_provider = NULL;

  size_t num_supported = rustls_default_crypto_provider_ciphersuites_len();
  for(size_t i = 0; i < num_supported; i++) {
    const struct rustls_supported_ciphersuite *suite =
      rustls_default_crypto_provider_ciphersuites_get(i);
    if(suite == NULL) {
      fprintf(stderr, "failed to get ciphersuite %zu\n", i);
      goto cleanup;
    }

    const rustls_str suite_name = rustls_supported_ciphersuite_get_name(suite);
    if(strncmp(suite_name.data, custom_ciphersuite_name, suite_name.len) ==
       0) {
      custom_ciphersuite = suite;
      break;
    }
  }

  if(custom_ciphersuite == NULL) {
    fprintf(stderr,
            "failed to select custom ciphersuite: %s\n",
            custom_ciphersuite_name);
    goto cleanup;
  }

  rustls_result result =
    rustls_crypto_provider_builder_new_from_default(&provider_builder);
  if(result != RUSTLS_RESULT_OK) {
    fprintf(stderr, "failed to create provider builder\n");
    goto cleanup;
  }

  result = rustls_crypto_provider_builder_set_cipher_suites(
    provider_builder, &custom_ciphersuite, 1);
  if(result != RUSTLS_RESULT_OK) {
    fprintf(stderr, "failed to set custom ciphersuite\n");
    goto cleanup;
  }

  result =
    rustls_crypto_provider_builder_build(provider_builder, &custom_provider);
  if(result != RUSTLS_RESULT_OK) {
    fprintf(stderr, "failed to build custom provider\n");
    goto cleanup;
  }

cleanup:
  rustls_crypto_provider_builder_free(provider_builder);
  return custom_provider;
}

// hex encode the given data buffer, returning a new NULL terminated buffer
// with the result, or NULL if memory allocation fails.
//
// Caller owns the returned buffer and must free it.
static char *
hex_encode(const unsigned char *data, size_t len)
{
  // Two output chars per input char, plus the NULL terminator.
  char *hex_str = (char *)malloc((len * 2) + 1);
  if(!hex_str) {
    return NULL;
  }

  for(size_t i = 0; i < len; i++) {
    snprintf(hex_str + (i * 2), 3, "%02x", data[i]);
  }

  hex_str[len * 2] = '\0';
  return hex_str;
}

void
stderr_key_log_cb(rustls_str label, const unsigned char *client_random,
                  size_t client_random_len, const unsigned char *secret,
                  size_t secret_len)
{
  char *client_random_str = NULL;
  char *secret_str = NULL;

  client_random_str = hex_encode(client_random, client_random_len);
  if(client_random_str == NULL) {
    goto cleanup;
  }

  secret_str = hex_encode(secret, secret_len);
  if(secret_str == NULL) {
    goto cleanup;
  }

  fprintf(stderr,
          "SSLKEYLOG: label=%.*s client_random=%s secret=%s\n",
          (int)label.len,
          label.data,
          client_random_str,
          secret_str);

cleanup:
  if(client_random_str != NULL) {
    free(client_random_str);
  }
  if(secret_str != NULL) {
    free(secret_str);
  }
}

// TLS 1.2 and TLS 1.3, matching Rustls default.
const uint16_t default_tls_versions[] = { 0x0303, 0x0304 };

// Declare the length of the TLS versions array as a global constant
const size_t default_tls_versions_len =
  sizeof(default_tls_versions) / sizeof(default_tls_versions[0]);
