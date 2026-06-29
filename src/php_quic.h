/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: raw QUIC transport for PHP, built on OpenSSL 3.5+ native QUIC.
 */

#ifndef PHP_QUIC_H
#define PHP_QUIC_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <php.h>

#include <openssl/opensslv.h>

/*
 * the native QUIC client+server API used by this extension landed in
 * OpenSSL 3.5; refuse to build against anything older.
 */
#if OPENSSL_VERSION_NUMBER < 0x30500000L
# error "php-quic requires OpenSSL >= 3.5.0 for native QUIC support"
#endif

#include <openssl/ssl.h>

#define PHP_QUIC_VERSION "1.0.0"

extern zend_module_entry quic_module_entry;
#define phpext_quic_ptr &quic_module_entry

#if defined(ZTS) && defined(COMPILE_DL_QUIC)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

/*
 * class entries
 */
extern zend_class_entry *quic_ce_connection;
extern zend_class_entry *quic_ce_listener;
extern zend_class_entry *quic_ce_stream;
extern zend_class_entry *quic_ce_exception;

/*
 * SSL_CTX ex_data slot holding the per-context allow-self-signed flag,
 * consumed by the certificate verification callback.  allocated in MINIT.
 */
extern int php_quic_ctx_allow_self_signed_index;

/*
 * per-object storage.  the embedded zend_object MUST remain the last
 * member so the create/free handlers can recover the wrapper from a
 * zend_object* via the handler offset.
 */
typedef struct _php_quic_connection {
	SSL         *ssl;       /* OpenSSL QUIC connection object */
	int          fd;        /* underlying UDP socket (-1 if none) */
	bool         owns_fd;   /* did we create the fd (client) or borrow it? */
	bool         closed;    /* has close()/shutdown already been issued? */
	zval         listener;  /* owning Quic\Listener (UNDEF for clients) */
	zend_object  std;
} php_quic_connection;

typedef struct _php_quic_listener {
	SSL         *ssl;          /* OpenSSL QUIC listener object */
	SSL_CTX     *ctx;          /* server SSL_CTX */
	int          fd;           /* bound UDP socket (-1 if none) */
	void        *alpn_cb_arg;  /* heap-owned ALPN data for the select cb */
	zend_object  std;
} php_quic_listener;

typedef struct _php_quic_stream {
	SSL         *ssl;       /* OpenSSL QUIC stream object */
	zval         connection;/* owning Quic\Connection, keeps it alive */
	zend_object  std;
} php_quic_stream;

static zend_always_inline php_quic_connection *php_quic_connection_from_obj(zend_object *obj)
{
	return (php_quic_connection *)((char *)obj - XtOffsetOf(php_quic_connection, std));
}

static zend_always_inline php_quic_listener *php_quic_listener_from_obj(zend_object *obj)
{
	return (php_quic_listener *)((char *)obj - XtOffsetOf(php_quic_listener, std));
}

static zend_always_inline php_quic_stream *php_quic_stream_from_obj(zend_object *obj)
{
	return (php_quic_stream *)((char *)obj - XtOffsetOf(php_quic_stream, std));
}

#define Z_QUIC_CONNECTION_P(zv) php_quic_connection_from_obj(Z_OBJ_P(zv))
#define Z_QUIC_LISTENER_P(zv)   php_quic_listener_from_obj(Z_OBJ_P(zv))
#define Z_QUIC_STREAM_P(zv)     php_quic_stream_from_obj(Z_OBJ_P(zv))

/*
 * per-class object-handler setup, implemented in the matching translation
 * unit. The classes themselves are registered (via the generated
 * register_class_Quic_* functions) in quic.c, which owns quic_arginfo.h.
 */
void php_quic_connection_init_handlers(void);
void php_quic_listener_init_handlers(void);
void php_quic_stream_init_handlers(void);

/*
 * wrap an existing OpenSSL QUIC connection SSL object into a freshly
 * created Quic\Connection (used by Quic\Listener::accept()).  applies the
 * common stream-mode / incoming-policy configuration.  fd is informational
 * for borrowed sockets (owns_fd == false).
 */
void php_quic_connection_init_object(zval *zv, SSL *ssl, int fd, bool owns_fd,
	zval *listener_zv);

/*
 * apply the common per-connection configuration (explicit stream mode,
 * accept incoming streams).  shared by connect() and accept().
 */
void php_quic_connection_configure(SSL *ssl);

/*
 * wrap an OpenSSL QUIC stream SSL object into a freshly created
 * Quic\Stream that holds a reference to its owning connection zval.
 */
void php_quic_stream_init_object(zval *zv, SSL *stream_ssl, zval *connection_zv);

/*
 * raise a Quic\Exception, optionally appending the current OpenSSL error
 * queue.  implemented in quic_exception.c.
 */
void php_quic_throw(const char *format, ...);
void php_quic_throw_ssl(const char *format, ...);

#endif /* PHP_QUIC_H */
