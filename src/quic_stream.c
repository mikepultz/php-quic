/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: Quic\Stream (one QUIC stream within a Connection).
 */

#include "php_quic.h"

#include "Zend/zend_exceptions.h"
#include "main/php_network.h"

static zend_object_handlers quic_stream_handlers;

/*
 * php_stream adapter: a thin bytestream view over a single QUIC stream,
 * produced by Quic\Stream::asStream().  the php_stream's abstract pointer
 * is the php_quic_stream, on which we hold a reference for the lifetime of
 * the php_stream.
 */
static ssize_t quic_stream_op_write(php_stream *stream, const char *buf, size_t count)
{
	php_quic_stream *obj = stream->abstract;
	size_t written = 0;
	int    rc;

	if (obj == NULL || obj->ssl == NULL) {
		return -1;
	}

	rc = SSL_write_ex2(obj->ssl, buf, count, 0, &written);
	if (rc == 1) {
		return (ssize_t)written;
	}

	switch (SSL_get_error(obj->ssl, rc)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return 0;
		default:
			return -1;
	}
}

static ssize_t quic_stream_op_read(php_stream *stream, char *buf, size_t count)
{
	php_quic_stream *obj = stream->abstract;
	size_t readbytes = 0;
	int    rc;

	if (obj == NULL || obj->ssl == NULL) {
		return -1;
	}

	rc = SSL_read_ex(obj->ssl, buf, count, &readbytes);
	if (rc == 1) {
		return (ssize_t)readbytes;
	}

	switch (SSL_get_error(obj->ssl, rc)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return 0;
		case SSL_ERROR_ZERO_RETURN:
			stream->eof = 1;
			return 0;
		default:
			stream->eof = 1;
			return -1;
	}
}

static int quic_stream_op_close(php_stream *stream, int close_handle)
{
	php_quic_stream *obj = stream->abstract;

	(void)close_handle;

	/* drop the reference taken in asStream(); do not touch the SSL. */
	if (obj != NULL) {
		OBJ_RELEASE(&obj->std);
		stream->abstract = NULL;
	}

	return 0;
}

static int quic_stream_op_flush(php_stream *stream)
{
	(void)stream;
	return 0;
}

static int quic_stream_op_cast(php_stream *stream, int castas, void **ret)
{
	php_quic_stream     *obj = stream->abstract;
	php_quic_connection *conn;

	if (obj == NULL || Z_ISUNDEF(obj->connection)) {
		return FAILURE;
	}

	switch (castas) {
		case PHP_STREAM_AS_FD:
		case PHP_STREAM_AS_FD_FOR_SELECT:
		case PHP_STREAM_AS_SOCKETD:
		{
			conn = Z_QUIC_CONNECTION_P(&obj->connection);
			if (conn->fd == -1) {
				return FAILURE;
			}
			if (ret != NULL) {
				*(php_socket_t *)ret = conn->fd;
			}
			return SUCCESS;
		}
		default:
			return FAILURE;
	}
}

static const php_stream_ops quic_php_stream_ops = {
	quic_stream_op_write,
	quic_stream_op_read,
	quic_stream_op_close,
	quic_stream_op_flush,
	"quic_stream",
	NULL,                       /* seek */
	quic_stream_op_cast,
	NULL,                       /* stat */
	NULL                        /* set_option */
};

#define QUIC_STREAM_THIS() \
	php_quic_stream_from_obj(Z_OBJ_P(ZEND_THIS))

static zend_object *quic_stream_create(zend_class_entry *ce)
{
	php_quic_stream *obj = zend_object_alloc(sizeof(php_quic_stream), ce);

	zend_object_std_init(&obj->std, ce);
	object_properties_init(&obj->std, ce);

	obj->ssl = NULL;
	ZVAL_UNDEF(&obj->connection);

	obj->std.handlers = &quic_stream_handlers;

	return &obj->std;
}

static void quic_stream_free(zend_object *object)
{
	php_quic_stream *obj = php_quic_stream_from_obj(object);

	/*
	 * free our stream SSL object first; we still hold a reference to the
	 * owning connection (released just below), so the connection (and the
	 * QUIC engine backing this stream) is guaranteed to outlive this call.
	 */
	if (obj->ssl != NULL) {
		SSL_free(obj->ssl);
		obj->ssl = NULL;
	}

	if (!Z_ISUNDEF(obj->connection)) {
		zval_ptr_dtor(&obj->connection);
		ZVAL_UNDEF(&obj->connection);
	}

	zend_object_std_dtor(&obj->std);
}

/*
 * expose the embedded connection zval to the cycle collector.
 */
static HashTable *quic_stream_get_gc(zend_object *object, zval **table, int *n)
{
	php_quic_stream    *obj = php_quic_stream_from_obj(object);
	zend_get_gc_buffer *buf = zend_get_gc_buffer_create();

	if (!Z_ISUNDEF(obj->connection)) {
		zend_get_gc_buffer_add_zval(buf, &obj->connection);
	}
	zend_get_gc_buffer_use(buf, table, n);

	return zend_std_get_properties(object);
}

void php_quic_stream_init_object(zval *zv, SSL *stream_ssl, zval *connection_zv)
{
	php_quic_stream *obj;

	object_init_ex(zv, quic_ce_stream);

	obj = Z_QUIC_STREAM_P(zv);
	obj->ssl = stream_ssl;
	ZVAL_COPY(&obj->connection, connection_zv);
}

/*
 * Quic\Stream::write(string $data, bool $fin = false): int
 */
PHP_METHOD(Quic_Stream, write)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();
	char     *data;
	size_t    data_len;
	bool      fin = false;
	size_t    written = 0;
	int       rc;
	int       err;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STRING(data, data_len)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(fin)
	ZEND_PARSE_PARAMETERS_END();

	if (obj->ssl == NULL) {
		php_quic_throw("stream is closed");
		RETURN_THROWS();
	}

	/* a pure FIN with no payload is expressed via conclude(). */
	if (data_len == 0) {
		if (fin && SSL_stream_conclude(obj->ssl, 0) == 0) {
			php_quic_throw_ssl("failed to conclude stream");
			RETURN_THROWS();
		}
		RETURN_LONG(0);
	}

	rc = SSL_write_ex2(obj->ssl, data, data_len,
		fin ? SSL_WRITE_FLAG_CONCLUDE : 0, &written);

	if (rc == 0) {
		err = SSL_get_error(obj->ssl, rc);

		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			/* non-blocking: nothing (or only part) could be sent now. */
			RETURN_LONG((zend_long)written);
		}

		php_quic_throw_ssl("stream write failed");
		RETURN_THROWS();
	}

	RETURN_LONG((zend_long)written);
}

/*
 * Quic\Stream::read(int $length): ?string
 *
 * returns the data, "" when nothing is currently available (non-blocking),
 * or null at end-of-stream (peer FIN, all data consumed).
 */
PHP_METHOD(Quic_Stream, read)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();
	zend_long     length;
	zend_string  *buf;
	size_t        want;
	size_t        cap;
	size_t        total = 0;
	bool          blocking;
	int           rc = 0;
	int           err;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_LONG(length)
	ZEND_PARSE_PARAMETERS_END();

	if (length <= 0) {
		php_quic_throw("read length must be positive, got " ZEND_LONG_FMT, length);
		RETURN_THROWS();
	}

	if (obj->ssl == NULL) {
		RETURN_NULL();
	}

	want = (size_t)length;

	/*
	 * size the buffer to what actually arrives, not to the (possibly huge)
	 * requested length: start small and grow geometrically, capped at want.
	 * in non-blocking mode drain everything currently buffered up to want;
	 * in blocking mode return after the first read so the call does not block
	 * waiting for the full requested length.
	 */
	cap = want < 65536 ? want : 65536;
	buf = zend_string_alloc(cap, 0);

	blocking = SSL_get_blocking_mode(obj->ssl) != 0;

	for (;;) {
		size_t got = 0;

		rc = SSL_read_ex(obj->ssl, ZSTR_VAL(buf) + total, cap - total, &got);
		if (rc != 1) {
			break;
		}

		total += got;

		if (total >= want || blocking) {
			break;
		}

		/*
		 * the read filled the buffer; there may be more, so grow and retry.
		 * a short read means nothing more is ready right now.
		 */
		if (total == cap) {
			size_t newcap = cap <= want / 2 ? cap * 2 : want;
			buf = zend_string_realloc(buf, newcap, 0);
			cap = newcap;
		} else {
			break;
		}
	}

	if (total > 0) {
		buf = zend_string_truncate(buf, total, 0);
		ZSTR_VAL(buf)[total] = '\0';
		RETURN_STR(buf);
	}

	zend_string_efree(buf);

	err = SSL_get_error(obj->ssl, rc);

	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		RETURN_EMPTY_STRING();
	}

	if (err == SSL_ERROR_ZERO_RETURN) {
		/* clean end of stream (peer FIN) */
		RETURN_NULL();
	}

	/*
	 * a peer/local stream reset (or the connection closing) ends the stream
	 * abnormally; report it as end-of-stream rather than throwing, so one
	 * misbehaving peer cannot abort a server's read loop.  getResetCode()
	 * surfaces the application error code.
	 */
	switch (SSL_get_stream_read_state(obj->ssl)) {
		case SSL_STREAM_STATE_RESET_REMOTE:
		case SSL_STREAM_STATE_RESET_LOCAL:
		case SSL_STREAM_STATE_CONN_CLOSED:
			RETURN_NULL();
		default:
			break;
	}

	php_quic_throw_ssl("stream read failed");
	RETURN_THROWS();
}

/*
 * Quic\Stream::end(): void  -- conclude the send side (FIN)
 */
PHP_METHOD(Quic_Stream, end)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		php_quic_throw("stream is closed");
		RETURN_THROWS();
	}

	if (SSL_stream_conclude(obj->ssl, 0) == 0) {
		php_quic_throw_ssl("failed to conclude stream");
		RETURN_THROWS();
	}
}

/*
 * Quic\Stream::reset(int $errorCode = 0): void
 */
PHP_METHOD(Quic_Stream, reset)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();
	zend_long error_code = 0;
	SSL_STREAM_RESET_ARGS args;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(error_code)
	ZEND_PARSE_PARAMETERS_END();

	if (obj->ssl == NULL) {
		php_quic_throw("stream is closed");
		RETURN_THROWS();
	}

	memset(&args, 0, sizeof(args));
	args.quic_error_code = (uint64_t)error_code;

	if (SSL_stream_reset(obj->ssl, &args, sizeof(args)) == 0) {
		php_quic_throw_ssl("failed to reset stream");
		RETURN_THROWS();
	}
}

/*
 * Quic\Stream::getResetCode(): ?int
 */
PHP_METHOD(Quic_Stream, getResetCode)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();
	uint64_t code = 0;

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		RETURN_NULL();
	}

	/* read side first (a peer RESET_STREAM), then the write side (STOP_SENDING). */
	if (SSL_get_stream_read_error_code(obj->ssl, &code) == 1 ||
			SSL_get_stream_write_error_code(obj->ssl, &code) == 1) {
		RETURN_LONG((zend_long)code);
	}

	RETURN_NULL();
}

/*
 * Quic\Stream::getId(): int
 */
PHP_METHOD(Quic_Stream, getId)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		php_quic_throw("stream is closed");
		RETURN_THROWS();
	}

	RETURN_LONG((zend_long)SSL_get_stream_id(obj->ssl));
}

/*
 * Quic\Stream::isBidirectional(): bool
 */
PHP_METHOD(Quic_Stream, isBidirectional)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		RETURN_FALSE;
	}

	RETURN_BOOL(SSL_get_stream_type(obj->ssl) == SSL_STREAM_TYPE_BIDI);
}

/*
 * Quic\Stream::getConnection(): Quic\Connection
 */
PHP_METHOD(Quic_Stream, getConnection)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();

	ZEND_PARSE_PARAMETERS_NONE();

	if (Z_ISUNDEF(obj->connection)) {
		php_quic_throw("stream is not associated with a connection");
		RETURN_THROWS();
	}

	RETURN_COPY(&obj->connection);
}

/*
 * Quic\Stream::asStream()  -- wrap this QUIC stream as a php_stream resource
 */
PHP_METHOD(Quic_Stream, asStream)
{
	php_quic_stream *obj = QUIC_STREAM_THIS();
	php_stream      *stream;

	ZEND_PARSE_PARAMETERS_NONE();

	if (obj->ssl == NULL) {
		php_quic_throw("stream is closed");
		RETURN_THROWS();
	}

	/* keep this Stream object alive for the lifetime of the php_stream. */
	GC_ADDREF(&obj->std);

	stream = php_stream_alloc(&quic_php_stream_ops, obj, NULL, "r+");
	if (stream == NULL) {
		GC_DELREF(&obj->std);
		php_quic_throw("failed to allocate stream");
		RETURN_THROWS();
	}

	php_stream_to_zval(stream, return_value);
}

/*
 * Quic\Stream::__construct(Quic\Connection $connection, bool $bidirectional = true)
 *
 * opens a new locally-initiated stream on the given connection.  (Streams
 * that are peer-initiated are obtained from Connection::acceptStream() and
 * are built internally without running this constructor.)
 */
PHP_METHOD(Quic_Stream, __construct)
{
	php_quic_stream     *obj = QUIC_STREAM_THIS();
	zval                *conn_zv;
	bool                 bidirectional = true;
	php_quic_connection *conn;
	SSL                 *stream;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_OBJECT_OF_CLASS(conn_zv, quic_ce_connection)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(bidirectional)
	ZEND_PARSE_PARAMETERS_END();

	if (obj->ssl != NULL) {
		php_quic_throw("stream is already open");
		RETURN_THROWS();
	}

	conn = Z_QUIC_CONNECTION_P(conn_zv);
	if (conn->ssl == NULL) {
		php_quic_throw("connection is closed");
		RETURN_THROWS();
	}

	stream = SSL_new_stream(conn->ssl, bidirectional ? 0 : SSL_STREAM_FLAG_UNI);
	if (stream == NULL) {
		php_quic_throw_ssl("failed to open QUIC stream");
		RETURN_THROWS();
	}

	obj->ssl = stream;
	ZVAL_COPY(&obj->connection, conn_zv);
}

void php_quic_stream_init_handlers(void)
{
	quic_ce_stream->create_object = quic_stream_create;

	memcpy(&quic_stream_handlers, zend_get_std_object_handlers(),
		sizeof(zend_object_handlers));

	quic_stream_handlers.offset    = XtOffsetOf(php_quic_stream, std);
	quic_stream_handlers.free_obj  = quic_stream_free;
	quic_stream_handlers.clone_obj = NULL;
	quic_stream_handlers.get_gc    = quic_stream_get_gc;
}
