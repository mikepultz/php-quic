/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: Quic\Connection (client + server-accepted QUIC connections).
 */

#include "php_quic.h"
#include "quic_util.h"

#include "Zend/zend_exceptions.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

static zend_object_handlers quic_connection_handlers;

/*
 * PEM-encode an X509 certificate into a new zend_string (NULL on failure).
 */
static zend_string *php_quic_x509_to_pem(X509 *cert)
{
	BIO         *bio;
	char        *data = NULL;
	long         len;
	zend_string *out;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		return NULL;
	}
	if (PEM_write_bio_X509(bio, cert) == 0) {
		BIO_free(bio);
		return NULL;
	}
	len = BIO_get_mem_data(bio, &data);
	out = zend_string_init(data, (size_t)len, 0);
	BIO_free(bio);

	return out;
}

#define QUIC_CONNECTION_THIS() \
	php_quic_connection_from_obj(Z_OBJ_P(ZEND_THIS))

static zend_object *quic_connection_create(zend_class_entry *ce)
{
	php_quic_connection *obj = zend_object_alloc(sizeof(php_quic_connection), ce);

	zend_object_std_init(&obj->std, ce);
	object_properties_init(&obj->std, ce);

	obj->ssl     = NULL;
	obj->fd      = -1;
	obj->owns_fd = false;
	obj->closed  = false;
	ZVAL_UNDEF(&obj->listener);

	obj->std.handlers = &quic_connection_handlers;

	return &obj->std;
}

static void quic_connection_free(zend_object *object)
{
	php_quic_connection *obj = php_quic_connection_from_obj(object);

	/*
	 * runs only after every Quic\Stream that referenced this connection
	 * has been destroyed (each holds a zval ref), so the stream SSL
	 * objects are already freed by the time we free the connection.
	 */
	if (obj->ssl != NULL) {
		SSL_free(obj->ssl);
		obj->ssl = NULL;
	}

	/*
	 * the datagram BIO was created with BIO_NOCLOSE, so the fd is ours to
	 * close (client connections only; accepted connections borrow the
	 * listener's socket).
	 */
	if (obj->owns_fd && obj->fd != -1) {
		BIO_closesocket(obj->fd);
		obj->fd = -1;
	}

	/* release our reference to the owning listener, if any. */
	if (!Z_ISUNDEF(obj->listener)) {
		zval_ptr_dtor(&obj->listener);
		ZVAL_UNDEF(&obj->listener);
	}

	zend_object_std_dtor(&obj->std);
}

/*
 * expose the embedded listener zval (server-accepted connections) to the
 * cycle collector.
 */
static HashTable *quic_connection_get_gc(zend_object *object, zval **table, int *n)
{
	php_quic_connection *obj = php_quic_connection_from_obj(object);
	zend_get_gc_buffer  *buf = zend_get_gc_buffer_create();

	if (!Z_ISUNDEF(obj->listener)) {
		zend_get_gc_buffer_add_zval(buf, &obj->listener);
	}
	zend_get_gc_buffer_use(buf, table, n);

	return zend_std_get_properties(object);
}

void php_quic_connection_configure(SSL *ssl)
{
	/*
	 * explicit (multi-)stream mode: SSL_read/SSL_write operate on stream
	 * objects, never implicitly on the connection.  accept peer-initiated
	 * streams so acceptStream() can return them.
	 */
	SSL_set_default_stream_mode(ssl, SSL_DEFAULT_STREAM_MODE_NONE);
	SSL_set_incoming_stream_policy(ssl, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
}

void php_quic_connection_init_object(zval *zv, SSL *ssl, int fd, bool owns_fd,
	zval *listener_zv)
{
	php_quic_connection *obj;

	object_init_ex(zv, quic_ce_connection);

	obj = Z_QUIC_CONNECTION_P(zv);
	obj->ssl     = ssl;
	obj->fd      = fd;
	obj->owns_fd = owns_fd;
	obj->closed  = false;

	if (listener_zv != NULL) {
		ZVAL_COPY(&obj->listener, listener_zv);
	}
}

/*
 * Quic\Connection::__construct(string $host, int $port, array $options = [])
 *
 * opens a QUIC client connection and completes the handshake.
 */
PHP_METHOD(Quic_Connection, __construct)
{
	char       *host;
	size_t      host_len;
	zend_long   port;
	zval       *options = NULL;

	zval       *opt;
	zval       *alpn_spec = NULL;
	zend_long   idle_timeout_ms = 0;
	zend_long   connect_timeout_ms = 0;
	php_quic_tls_setup setup;
	const char *peer_name;

	zend_string *alpn = NULL;
	char        portbuf[16];
	char        errbuf[256];
	BIO_ADDR   *peer = NULL;
	int         fd = -1;
	SSL_CTX    *ctx = NULL;
	SSL        *ssl = NULL;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_STRING(host, host_len)
		Z_PARAM_LONG(port)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY_OR_NULL(options)
	ZEND_PARSE_PARAMETERS_END();

	if (port < 1 || port > 65535) {
		php_quic_throw("port must be between 1 and 65535, got " ZEND_LONG_FMT, port);
		RETURN_THROWS();
	}

	if (strlen(host) != host_len) {
		php_quic_throw("host must not contain null bytes");
		RETURN_THROWS();
	}

	if (QUIC_CONNECTION_THIS()->ssl != NULL) {
		php_quic_throw("connection is already established");
		RETURN_THROWS();
	}

	if (options != NULL) {
		HashTable *ht = Z_ARRVAL_P(options);

		alpn_spec = zend_hash_str_find(ht, "alpn", sizeof("alpn") - 1);
		if (alpn_spec == NULL) {
			alpn_spec = zend_hash_str_find(ht, "alpn_protocols", sizeof("alpn_protocols") - 1);
		}

		if ((opt = zend_hash_str_find(ht, "idle_timeout_ms", sizeof("idle_timeout_ms") - 1)) != NULL) {
			idle_timeout_ms = zval_get_long(opt);
		}
		if ((opt = zend_hash_str_find(ht, "connect_timeout_ms", sizeof("connect_timeout_ms") - 1)) != NULL) {
			connect_timeout_ms = zval_get_long(opt);
		}
	}

	if (alpn_spec == NULL) {
		php_quic_throw("the 'alpn' option is required");
		RETURN_THROWS();
	}
	if (php_quic_alpn_from_zval(alpn_spec, &alpn, errbuf, sizeof(errbuf)) == FAILURE) {
		php_quic_throw("%s", errbuf);
		RETURN_THROWS();
	}

	snprintf(portbuf, sizeof(portbuf), ZEND_LONG_FMT, port);

	fd = php_quic_udp_client(host, portbuf, &peer, errbuf, sizeof(errbuf));
	if (fd == -1) {
		zend_string_release(alpn);
		php_quic_throw("%s", errbuf);
		RETURN_THROWS();
	}

	ctx = SSL_CTX_new(OSSL_QUIC_client_method());
	if (ctx == NULL) {
		goto ssl_error;
	}

	if (php_quic_configure_ctx(ctx, options != NULL ? Z_ARRVAL_P(options) : NULL,
			false, &setup, errbuf, sizeof(errbuf)) == FAILURE) {
		php_quic_throw("%s", errbuf);
		goto cleanup;
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		goto ssl_error;
	}

	/* SSL holds its own reference to the CTX from here on. */
	SSL_CTX_free(ctx);
	ctx = NULL;

	/*
	 * attach the UDP socket via a datagram BIO created with BIO_NOCLOSE so
	 * that we, not OpenSSL, own the fd's lifetime.  SSL_set_bio takes
	 * ownership of the BIO object itself (freed by SSL_free).
	 */
	{
		BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
		if (bio == NULL) {
			goto ssl_error;
		}
		SSL_set_bio(ssl, bio, bio);
	}

	/* NOTE: SSL_set_alpn_protos returns 0 on SUCCESS. */
	if (SSL_set_alpn_protos(ssl, (const unsigned char *)ZSTR_VAL(alpn),
			(unsigned int)ZSTR_LEN(alpn)) != 0) {
		goto ssl_error;
	}

	if (SSL_set1_initial_peer_addr(ssl, peer) == 0) {
		goto ssl_error;
	}

	peer_name = setup.peer_name != NULL ? ZSTR_VAL(setup.peer_name) : host;

	if (setup.verify_peer && setup.verify_peer_name) {
		if (SSL_set1_host(ssl, peer_name) == 0) {
			goto ssl_error;
		}
	}
	if (setup.sni_enabled) {
		if (SSL_set_tlsext_host_name(ssl, peer_name) == 0) {
			goto ssl_error;
		}
	}

#ifdef SSL_VALUE_QUIC_IDLE_TIMEOUT
	if (idle_timeout_ms > 0) {
		SSL_set_feature_request_uint(ssl, SSL_VALUE_QUIC_IDLE_TIMEOUT,
			(uint64_t)idle_timeout_ms);
	}
#else
	(void)idle_timeout_ms;
#endif

	php_quic_connection_configure(ssl);

	if (connect_timeout_ms > 0) {
		int hs = php_quic_connect_timed(ssl, fd, connect_timeout_ms);

		if (hs == -1) {
			php_quic_throw("QUIC handshake with %s:" ZEND_LONG_FMT
				" timed out after " ZEND_LONG_FMT "ms", host, port,
				connect_timeout_ms);
			goto cleanup;
		}
		if (hs == 0) {
			php_quic_throw_ssl("QUIC handshake with %s:" ZEND_LONG_FMT " failed",
				host, port);
			goto cleanup;
		}
	} else if (SSL_connect(ssl) != 1) {
		php_quic_throw_ssl("QUIC handshake with %s:" ZEND_LONG_FMT " failed",
			host, port);
		goto cleanup;
	}

	/* optional certificate pinning (peer_fingerprint), post-handshake. */
	if (options != NULL) {
		zval *fp = zend_hash_str_find(Z_ARRVAL_P(options),
			"peer_fingerprint", sizeof("peer_fingerprint") - 1);

		if (fp != NULL &&
				php_quic_check_fingerprint(ssl, fp, errbuf, sizeof(errbuf)) == FAILURE) {
			php_quic_throw("%s", errbuf);
			goto cleanup;
		}
	}

	zend_string_release(alpn);
	BIO_ADDR_free(peer);

	{
		php_quic_connection *obj = QUIC_CONNECTION_THIS();
		obj->ssl     = ssl;
		obj->fd      = fd;
		obj->owns_fd = true;
		obj->closed  = false;
	}
	return;

ssl_error:
	php_quic_throw_ssl("failed to set up QUIC client connection");

cleanup:
	zend_string_release(alpn);
	if (peer != NULL) {
		BIO_ADDR_free(peer);
	}
	if (ssl != NULL) {
		SSL_free(ssl);
	}
	if (ctx != NULL) {
		SSL_CTX_free(ctx);
	}
	if (fd != -1) {
		BIO_closesocket(fd);
	}
	RETURN_THROWS();
}

/*
 * Quic\Connection::openStream(bool $bidirectional = true): Quic\Stream
 */
PHP_METHOD(Quic_Connection, openStream)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	bool      bidirectional = true;
	uint64_t  flags;
	SSL      *stream;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(bidirectional)
	ZEND_PARSE_PARAMETERS_END();

	if (obj->ssl == NULL) {
		php_quic_throw("connection is closed");
		RETURN_THROWS();
	}

	flags = bidirectional ? 0 : SSL_STREAM_FLAG_UNI;

	stream = SSL_new_stream(obj->ssl, flags);
	if (stream == NULL) {
		php_quic_throw_ssl("failed to open QUIC stream");
		RETURN_THROWS();
	}

	php_quic_stream_init_object(return_value, stream, ZEND_THIS);
}

/*
 * Quic\Connection::acceptStream(): ?Quic\Stream
 */
PHP_METHOD(Quic_Connection, acceptStream)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	SSL *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		RETURN_NULL();
	}

	stream = SSL_accept_stream(obj->ssl, 0);
	if (stream == NULL) {
		RETURN_NULL();
	}

	php_quic_stream_init_object(return_value, stream, ZEND_THIS);
}

/*
 * Quic\Connection::close(int $errorCode = 0, string $reason = ""): void
 */
PHP_METHOD(Quic_Connection, close)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	zend_long   error_code = 0;
	char       *reason = NULL;
	size_t      reason_len = 0;

	ZEND_PARSE_PARAMETERS_START(0, 2)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(error_code)
		Z_PARAM_STRING(reason, reason_len)
	ZEND_PARSE_PARAMETERS_END();

	if (obj->ssl != NULL && !obj->closed) {
		SSL_SHUTDOWN_EX_ARGS args;

		memset(&args, 0, sizeof(args));
		args.quic_error_code = (uint64_t)error_code;
		args.quic_reason     = reason_len > 0 ? reason : NULL;

		SSL_shutdown_ex(obj->ssl, 0, &args, sizeof(args));
		obj->closed = true;
	}
}

/*
 * Quic\Connection::getCloseInfo(): ?array
 */
PHP_METHOD(Quic_Connection, getCloseInfo)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	SSL_CONN_CLOSE_INFO  info;

	ZEND_PARSE_PARAMETERS_NONE();

	memset(&info, 0, sizeof(info));

	if (obj->ssl == NULL ||
			SSL_get_conn_close_info(obj->ssl, &info, sizeof(info)) != 1) {
		RETURN_NULL();
	}

	array_init(return_value);
	add_assoc_long(return_value, "error_code", (zend_long)info.error_code);
	add_assoc_long(return_value, "frame_type", (zend_long)info.frame_type);
	add_assoc_stringl(return_value, "reason",
		info.reason != NULL ? info.reason : "", info.reason_len);
	add_assoc_bool(return_value, "local",
		(info.flags & SSL_CONN_CLOSE_FLAG_LOCAL) != 0);
	add_assoc_bool(return_value, "transport",
		(info.flags & SSL_CONN_CLOSE_FLAG_TRANSPORT) != 0);
}

/*
 * Quic\Connection::getFd(): int
 */
PHP_METHOD(Quic_Connection, getFd)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	RETURN_LONG(obj->fd);
}

/*
 * Quic\Connection::setBlocking(bool $blocking): void
 */
PHP_METHOD(Quic_Connection, setBlocking)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	bool blocking;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_BOOL(blocking)
	ZEND_PARSE_PARAMETERS_END();

	if (obj->ssl == NULL) {
		php_quic_throw("connection is closed");
		RETURN_THROWS();
	}

	if (SSL_set_blocking_mode(obj->ssl, blocking ? 1 : 0) == 0) {
		php_quic_throw_ssl("failed to set blocking mode");
		RETURN_THROWS();
	}
}

/*
 * Quic\Connection::wantsRead(): bool
 */
PHP_METHOD(Quic_Connection, wantsRead)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	RETURN_BOOL(obj->ssl != NULL && SSL_net_read_desired(obj->ssl));
}

/*
 * Quic\Connection::wantsWrite(): bool
 */
PHP_METHOD(Quic_Connection, wantsWrite)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	RETURN_BOOL(obj->ssl != NULL && SSL_net_write_desired(obj->ssl));
}

/*
 * Quic\Connection::getTimeout(): ?float
 */
PHP_METHOD(Quic_Connection, getTimeout)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	struct timeval tv;
	int is_infinite = 0;

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		RETURN_NULL();
	}

	if (SSL_get_event_timeout(obj->ssl, &tv, &is_infinite) == 0) {
		php_quic_throw_ssl("failed to query QUIC event timeout");
		RETURN_THROWS();
	}

	if (is_infinite) {
		RETURN_NULL();
	}

	RETURN_DOUBLE((double)tv.tv_sec + (double)tv.tv_usec / 1000000.0);
}

/*
 * Quic\Connection::handleEvents(): void
 */
PHP_METHOD(Quic_Connection, handleEvents)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl != NULL) {
		SSL_handle_events(obj->ssl);
	}
}

/*
 * Quic\Connection::getCryptoInfo(): array
 *
 * mirrors the keys of stream_get_meta_data()['crypto'].
 */
PHP_METHOD(Quic_Connection, getCryptoInfo)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	const SSL_CIPHER    *cipher;
	const char          *protocol;
	const unsigned char *alpn = NULL;
	unsigned int         alpn_len = 0;

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		php_quic_throw("connection is closed");
		RETURN_THROWS();
	}

	array_init(return_value);

	protocol = SSL_get_version(obj->ssl);
	if (protocol != NULL) {
		add_assoc_string(return_value, "protocol", protocol);
	}

	cipher = SSL_get_current_cipher(obj->ssl);
	if (cipher != NULL) {
		add_assoc_string(return_value, "cipher_name", SSL_CIPHER_get_name(cipher));
		add_assoc_long(return_value, "cipher_bits", SSL_CIPHER_get_bits(cipher, NULL));
		add_assoc_string(return_value, "cipher_version", SSL_CIPHER_get_version(cipher));
	}

	SSL_get0_alpn_selected(obj->ssl, &alpn, &alpn_len);
	if (alpn_len > 0) {
		add_assoc_stringl(return_value, "alpn_protocol", (char *)alpn, alpn_len);
	}
}

/*
 * Quic\Connection::getNegotiatedAlpn(): ?string
 */
PHP_METHOD(Quic_Connection, getNegotiatedAlpn)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	const unsigned char *alpn = NULL;
	unsigned int         alpn_len = 0;

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		RETURN_NULL();
	}

	SSL_get0_alpn_selected(obj->ssl, &alpn, &alpn_len);
	if (alpn_len == 0) {
		RETURN_NULL();
	}

	RETURN_STRINGL((char *)alpn, alpn_len);
}

/*
 * Quic\Connection::getPeerCertificate(): ?string  (PEM)
 */
PHP_METHOD(Quic_Connection, getPeerCertificate)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	X509        *cert;
	zend_string *pem;

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		RETURN_NULL();
	}

	cert = SSL_get1_peer_certificate(obj->ssl);
	if (cert == NULL) {
		RETURN_NULL();
	}

	pem = php_quic_x509_to_pem(cert);
	X509_free(cert);

	if (pem == NULL) {
		php_quic_throw_ssl("failed to encode peer certificate");
		RETURN_THROWS();
	}

	RETURN_STR(pem);
}

/*
 * Quic\Connection::getPeerCertificateChain(): array  (PEM strings)
 */
PHP_METHOD(Quic_Connection, getPeerCertificateChain)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();
	STACK_OF(X509)      *chain;
	int                  i;

	ZEND_PARSE_PARAMETERS_NONE();

	array_init(return_value);

	if (obj->ssl == NULL) {
		return;
	}

	chain = SSL_get_peer_cert_chain(obj->ssl);
	if (chain == NULL) {
		return;
	}

	for (i = 0; i < sk_X509_num(chain); i++) {
		zend_string *pem = php_quic_x509_to_pem(sk_X509_value(chain, i));

		if (pem != NULL) {
			add_next_index_str(return_value, pem);
		}
	}
}

/*
 * Quic\Connection::getVerifyResult(): int
 */
PHP_METHOD(Quic_Connection, getVerifyResult)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		php_quic_throw("connection is closed");
		RETURN_THROWS();
	}

	RETURN_LONG((zend_long)SSL_get_verify_result(obj->ssl));
}

/*
 * Quic\Connection::getVerifyResultString(): string
 */
PHP_METHOD(Quic_Connection, getVerifyResultString)
{
	php_quic_connection *obj = QUIC_CONNECTION_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		php_quic_throw("connection is closed");
		RETURN_THROWS();
	}

	RETURN_STRING(X509_verify_cert_error_string(SSL_get_verify_result(obj->ssl)));
}

void php_quic_connection_init_handlers(void)
{
	quic_ce_connection->create_object = quic_connection_create;

	memcpy(&quic_connection_handlers, zend_get_std_object_handlers(),
		sizeof(zend_object_handlers));

	quic_connection_handlers.offset    = XtOffsetOf(php_quic_connection, std);
	quic_connection_handlers.free_obj  = quic_connection_free;
	quic_connection_handlers.clone_obj = NULL;
	quic_connection_handlers.get_gc    = quic_connection_get_gc;
}
