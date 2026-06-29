/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: Quic\Exception and the throw helpers.
 */

#include "php_quic.h"

#include "Zend/zend_exceptions.h"

#include <stdarg.h>

#include <openssl/err.h>

/*
 * throw a Quic\Exception with a printf-style message.
 */
void php_quic_throw(const char *format, ...)
{
	va_list args;
	char    message[1024];

	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);

	zend_throw_exception(quic_ce_exception, message, 0);
}

/*
 * throw a Quic\Exception with a printf-style message, then append the
 * head of the OpenSSL error queue (most recent error) and drain it.
 */
void php_quic_throw_ssl(const char *format, ...)
{
	va_list      args;
	char         message[1024];
	size_t       len;
	unsigned long err;

	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);

	err = ERR_get_error();
	if (err != 0) {
		char errbuf[256];

		ERR_error_string_n(err, errbuf, sizeof(errbuf));

		len = strlen(message);
		snprintf(message + len, sizeof(message) - len, ": %s", errbuf);

		/*
		 * drain any remaining queued errors so they do not leak into a
		 * later, unrelated operation.
		 */
		ERR_clear_error();
	}

	zend_throw_exception(quic_ce_exception, message, 0);
}
