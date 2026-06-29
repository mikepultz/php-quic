/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: shared helpers (UDP sockets, ALPN encoding, OpenSSL glue).
 */

#ifndef PHP_QUIC_UTIL_H
#define PHP_QUIC_UTIL_H

#include "php_quic.h"

#include <openssl/bio.h>

/*
 * create a non-blocking UDP socket connected to host:port and, on
 * success, hand back a duplicated BIO_ADDR for the peer (caller frees with
 * BIO_ADDR_free).  returns the fd, or -1 with errbuf populated.
 */
int php_quic_udp_client(const char *host, const char *port,
	BIO_ADDR **peer_out, char *errbuf, size_t errlen);

/*
 * create a non-blocking UDP socket bound to host:port for server use.
 * host may be NULL/empty to bind the wildcard address.  returns the fd, or
 * -1 with errbuf populated.
 */
int php_quic_udp_server(const char *host, const char *port,
	bool reuse_port, char *errbuf, size_t errlen);

/*
 * drive a non-blocking QUIC handshake on ssl/fd with an overall deadline of
 * timeout_ms.  returns 1 on success, 0 on a handshake error (caller pulls the
 * OpenSSL error queue), or -1 if the deadline elapsed.  leaves the connection
 * in blocking mode on return.
 */
int php_quic_connect_timed(SSL *ssl, int fd, zend_long timeout_ms);

/*
 * encode an ALPN specification (a PHP string, or an array of strings) into
 * the QUIC/TLS wire format (each protocol prefixed by a single length
 * byte).  on success *out holds a new zend_string (caller releases with
 * zend_string_release).  returns SUCCESS or FAILURE with errbuf populated.
 */
zend_result php_quic_alpn_from_zval(zval *spec, zend_string **out,
	char *errbuf, size_t errlen);

/*
 * per-SSL settings derived from the options array that must be applied to
 * the SSL object (not the SSL_CTX) by the caller after SSL_new().
 */
typedef struct {
	zend_string *peer_name;       /* expected name / SNI (NULL => use host) */
	bool         verify_peer;
	bool         verify_peer_name;
	bool         sni_enabled;     /* send SNI (default true) */
} php_quic_tls_setup;

/*
 * verify the peer certificate against a peer_fingerprint specification: a
 * hex-digest string (algorithm inferred from length) or an array of
 * algo => hex-digest pairs (all must match).  returns SUCCESS on match,
 * FAILURE with errbuf populated otherwise.
 */
zend_result php_quic_check_fingerprint(SSL *ssl, zval *spec,
	char *errbuf, size_t errlen);

/*
 * apply the SSL_CTX-level connection options shared by connect() and
 * listen(): peer verification (verify_peer, verify_peer_name,
 * allow_self_signed, cafile, capath), local identity (local_cert,
 * local_pk, passphrase), and TLS tuning (ciphers/ciphersuites, groups,
 * security_level, sigalgs).  For servers, local_cert is required.
 *
 * On success, *out carries the per-SSL bits the caller still needs to set
 * (peer_name for SNI / SSL_set1_host).  Returns SUCCESS or FAILURE with
 * errbuf populated.  opts may be NULL.
 */
zend_result php_quic_configure_ctx(SSL_CTX *ctx, HashTable *opts,
	bool is_server, php_quic_tls_setup *out, char *errbuf, size_t errlen);

#endif /* PHP_QUIC_UTIL_H */
