/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: Quic\Listener (server-side QUIC listener).
 */

#include "php_quic.h"
#include "quic_util.h"

#include "Zend/zend_exceptions.h"

#include <openssl/bio.h>
#include <openssl/err.h>

static zend_object_handlers quic_listener_handlers;

#define QUIC_LISTENER_THIS() \
	php_quic_listener_from_obj(Z_OBJ_P(ZEND_THIS))

/*
 * the server's acceptable ALPN list (wire format), handed to the ALPN
 * selection callback as its argument.  owned by the listener.
 */
typedef struct {
	zend_string *alpn;
} quic_alpn_data;

static int quic_alpn_select_cb(SSL *ssl, const unsigned char **out,
	unsigned char *outlen, const unsigned char *in, unsigned int inlen,
	void *arg)
{
	quic_alpn_data *data = (quic_alpn_data *)arg;

	(void)ssl;

	if (SSL_select_next_proto((unsigned char **)out, outlen,
			(const unsigned char *)ZSTR_VAL(data->alpn),
			(unsigned int)ZSTR_LEN(data->alpn), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	return SSL_TLSEXT_ERR_OK;
}

static void quic_listener_release(php_quic_listener *obj)
{
	if (obj->ssl != NULL) {
		SSL_free(obj->ssl);
		obj->ssl = NULL;
	}

	if (obj->fd != -1) {
		BIO_closesocket(obj->fd);
		obj->fd = -1;
	}

	if (obj->ctx != NULL) {
		SSL_CTX_free(obj->ctx);
		obj->ctx = NULL;
	}

	if (obj->alpn_cb_arg != NULL) {
		quic_alpn_data *data = (quic_alpn_data *)obj->alpn_cb_arg;
		zend_string_release(data->alpn);
		efree(data);
		obj->alpn_cb_arg = NULL;
	}
}

static zend_object *quic_listener_create(zend_class_entry *ce)
{
	php_quic_listener *obj = zend_object_alloc(sizeof(php_quic_listener), ce);

	zend_object_std_init(&obj->std, ce);
	object_properties_init(&obj->std, ce);

	obj->ssl         = NULL;
	obj->ctx         = NULL;
	obj->fd          = -1;
	obj->alpn_cb_arg = NULL;

	obj->std.handlers = &quic_listener_handlers;

	return &obj->std;
}

static void quic_listener_free(zend_object *object)
{
	php_quic_listener *obj = php_quic_listener_from_obj(object);

	quic_listener_release(obj);

	zend_object_std_dtor(&obj->std);
}

/*
 * Quic\Listener::__construct(string $host, int $port, array $options)
 *
 * binds the UDP socket and starts listening.
 */
PHP_METHOD(Quic_Listener, __construct)
{
	char       *host;
	size_t      host_len;
	zend_long   port;
	zval       *options;

	zval       *alpn_spec = NULL;
	php_quic_tls_setup setup;

	zend_string    *alpn = NULL;
	quic_alpn_data *adata = NULL;
	char            portbuf[16];
	char            errbuf[256];
	int             fd = -1;
	SSL_CTX        *ctx = NULL;
	SSL            *listener = NULL;
	php_quic_listener *obj;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STRING(host, host_len)
		Z_PARAM_LONG(port)
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	if (port < 1 || port > 65535) {
		php_quic_throw("port must be between 1 and 65535, got " ZEND_LONG_FMT, port);
		RETURN_THROWS();
	}

	if (strlen(host) != host_len) {
		php_quic_throw("host must not contain null bytes");
		RETURN_THROWS();
	}

	if (QUIC_LISTENER_THIS()->ssl != NULL) {
		php_quic_throw("listener is already listening");
		RETURN_THROWS();
	}

	alpn_spec = zend_hash_str_find(Z_ARRVAL_P(options), "alpn", sizeof("alpn") - 1);
	if (alpn_spec == NULL) {
		alpn_spec = zend_hash_str_find(Z_ARRVAL_P(options),
			"alpn_protocols", sizeof("alpn_protocols") - 1);
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

	{
		zval *rp = zend_hash_str_find(Z_ARRVAL_P(options),
			"reuse_port", sizeof("reuse_port") - 1);
		bool reuse_port = rp != NULL && zend_is_true(rp);

		fd = php_quic_udp_server(host, portbuf, reuse_port, errbuf, sizeof(errbuf));
	}
	if (fd == -1) {
		zend_string_release(alpn);
		php_quic_throw("%s", errbuf);
		RETURN_THROWS();
	}

	ctx = SSL_CTX_new(OSSL_QUIC_server_method());
	if (ctx == NULL) {
		goto ssl_error;
	}

	if (php_quic_configure_ctx(ctx, Z_ARRVAL_P(options), true, &setup,
			errbuf, sizeof(errbuf)) == FAILURE) {
		php_quic_throw("%s", errbuf);
		goto cleanup_error;
	}

	/* the ALPN data takes ownership of the encoded buffer. */
	adata = emalloc(sizeof(quic_alpn_data));
	adata->alpn = alpn;
	alpn = NULL;

	SSL_CTX_set_alpn_select_cb(ctx, quic_alpn_select_cb, adata);

	listener = SSL_new_listener(ctx, 0);
	if (listener == NULL) {
		goto ssl_error;
	}

	{
		BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
		if (bio == NULL) {
			goto ssl_error;
		}
		SSL_set_bio(listener, bio, bio);
	}

	if (SSL_listen(listener) <= 0) {
		php_quic_throw_ssl("failed to start QUIC listener on %s:" ZEND_LONG_FMT,
			host_len > 0 ? host : "*", port);
		goto cleanup_error;
	}

	obj = QUIC_LISTENER_THIS();
	obj->ssl         = listener;
	obj->ctx         = ctx;
	obj->fd          = fd;
	obj->alpn_cb_arg = adata;
	return;

ssl_error:
	php_quic_throw_ssl("failed to set up QUIC listener");

cleanup_error:
	if (alpn != NULL) {
		zend_string_release(alpn);
	}
	if (adata != NULL) {
		zend_string_release(adata->alpn);
		efree(adata);
	}
	if (listener != NULL) {
		SSL_free(listener);
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
 * Quic\Listener::accept(): ?Quic\Connection
 */
PHP_METHOD(Quic_Listener, accept)
{
	php_quic_listener *obj = QUIC_LISTENER_THIS();
	SSL *conn;

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		RETURN_NULL();
	}

	conn = SSL_accept_connection(obj->ssl, 0);
	if (conn == NULL) {
		RETURN_NULL();
	}

	php_quic_connection_configure(conn);
	php_quic_connection_init_object(return_value, conn, obj->fd, false, ZEND_THIS);
}

/*
 * Quic\Listener::close(): void
 */
PHP_METHOD(Quic_Listener, close)
{
	php_quic_listener *obj = QUIC_LISTENER_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	quic_listener_release(obj);
}

/*
 * Quic\Listener::getFd(): int
 */
PHP_METHOD(Quic_Listener, getFd)
{
	php_quic_listener *obj = QUIC_LISTENER_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	RETURN_LONG(obj->fd);
}

/*
 * Quic\Listener::setBlocking(bool $blocking): void
 */
PHP_METHOD(Quic_Listener, setBlocking)
{
	php_quic_listener *obj = QUIC_LISTENER_THIS();
	bool blocking;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_BOOL(blocking)
	ZEND_PARSE_PARAMETERS_END();

	if (obj->ssl == NULL) {
		php_quic_throw("listener is closed");
		RETURN_THROWS();
	}

	if (SSL_set_blocking_mode(obj->ssl, blocking ? 1 : 0) == 0) {
		php_quic_throw_ssl("failed to set blocking mode");
		RETURN_THROWS();
	}
}

/*
 * Quic\Listener::wantsRead(): bool
 */
PHP_METHOD(Quic_Listener, wantsRead)
{
	php_quic_listener *obj = QUIC_LISTENER_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	RETURN_BOOL(obj->ssl != NULL && SSL_net_read_desired(obj->ssl));
}

/*
 * Quic\Listener::wantsWrite(): bool
 */
PHP_METHOD(Quic_Listener, wantsWrite)
{
	php_quic_listener *obj = QUIC_LISTENER_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	RETURN_BOOL(obj->ssl != NULL && SSL_net_write_desired(obj->ssl));
}

/*
 * Quic\Listener::getTimeout(): ?float
 */
PHP_METHOD(Quic_Listener, getTimeout)
{
	php_quic_listener *obj = QUIC_LISTENER_THIS();
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
 * Quic\Listener::handleEvents(): void
 */
PHP_METHOD(Quic_Listener, handleEvents)
{
	php_quic_listener *obj = QUIC_LISTENER_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl != NULL) {
		SSL_handle_events(obj->ssl);
	}
}

void php_quic_listener_init_handlers(void)
{
	quic_ce_listener->create_object = quic_listener_create;

	memcpy(&quic_listener_handlers, zend_get_std_object_handlers(),
		sizeof(zend_object_handlers));

	quic_listener_handlers.offset    = XtOffsetOf(php_quic_listener, std);
	quic_listener_handlers.free_obj  = quic_listener_free;
	quic_listener_handlers.clone_obj = NULL;
}
