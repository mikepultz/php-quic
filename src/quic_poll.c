/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: Quic\poll(): wait for QUIC events across a set of objects.
 */

#include "php_quic.h"

#include "Zend/zend_exceptions.h"

/*
 * recover the underlying SSL object from a Quic\Connection, Quic\Listener,
 * or Quic\Stream (the classes are final, so exact ce comparison suffices).
 */
static SSL *php_quic_obj_ssl(zval *zv)
{
	zend_class_entry *ce;

	if (Z_TYPE_P(zv) != IS_OBJECT) {
		return NULL;
	}

	ce = Z_OBJCE_P(zv);
	if (ce == quic_ce_connection) {
		return php_quic_connection_from_obj(Z_OBJ_P(zv))->ssl;
	}
	if (ce == quic_ce_listener) {
		return php_quic_listener_from_obj(Z_OBJ_P(zv))->ssl;
	}
	if (ce == quic_ce_stream) {
		return php_quic_stream_from_obj(Z_OBJ_P(zv))->ssl;
	}

	return NULL;
}

/*
 * Quic\poll(array $items, ?float $timeout = null): array
 */
ZEND_FUNCTION(Quic_poll)
{
	HashTable     *items;
	double         timeout = 0.0;
	bool           timeout_is_null = true;
	zval          *entry;
	zend_ulong     num_idx;
	zend_string   *str_key;
	SSL_POLL_ITEM  stackbuf[16];
	SSL_POLL_ITEM *poll_items;
	uint32_t       n, i;
	size_t         result_count = 0;
	struct timeval tv;
	struct timeval *tvp;
	int            rc;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_ARRAY_HT(items)
		Z_PARAM_OPTIONAL
		Z_PARAM_DOUBLE_OR_NULL(timeout, timeout_is_null)
	ZEND_PARSE_PARAMETERS_END();

	n = zend_hash_num_elements(items);

	array_init(return_value);
	if (n == 0) {
		return;
	}

	/* avoid a heap allocation in the common small-fd-set event-loop case. */
	poll_items = (n <= (sizeof(stackbuf) / sizeof(stackbuf[0])))
		? stackbuf
		: emalloc((size_t)n * sizeof(SSL_POLL_ITEM));

	i = 0;
	ZEND_HASH_FOREACH_VAL(items, entry) {
		zval *obj_zv;
		zval *events_zv;
		SSL  *ssl;

		ZVAL_DEREF(entry);
		if (Z_TYPE_P(entry) != IS_ARRAY) {
			if (poll_items != stackbuf) {
				efree(poll_items);
			}
			php_quic_throw("each poll item must be an array [object, events]");
			RETURN_THROWS();
		}

		obj_zv    = zend_hash_index_find(Z_ARRVAL_P(entry), 0);
		events_zv = zend_hash_index_find(Z_ARRVAL_P(entry), 1);
		if (obj_zv == NULL || events_zv == NULL) {
			if (poll_items != stackbuf) {
				efree(poll_items);
			}
			php_quic_throw("each poll item must be [object, events]");
			RETURN_THROWS();
		}

		ssl = php_quic_obj_ssl(obj_zv);
		if (ssl == NULL) {
			if (poll_items != stackbuf) {
				efree(poll_items);
			}
			php_quic_throw("poll item #%u is not a live Quic\\Connection, "
				"Quic\\Listener, or Quic\\Stream", i);
			RETURN_THROWS();
		}

		poll_items[i].desc    = SSL_as_poll_descriptor(ssl);
		poll_items[i].events  = (uint64_t)zval_get_long(events_zv);
		poll_items[i].revents = 0;
		i++;
	} ZEND_HASH_FOREACH_END();

	if (timeout_is_null) {
		tvp = NULL;                     /* block until an event */
	} else {
		if (timeout < 0.0) {
			timeout = 0.0;
		} else if (timeout > 100000000.0) {
			/* clamp absurd values so the cast to long cannot overflow. */
			timeout = 100000000.0;
		}
		tv.tv_sec  = (long)timeout;
		tv.tv_usec = (long)((timeout - (double)tv.tv_sec) * 1000000.0);
		tvp = &tv;
	}

	/* flags == 0: SSL_poll also pumps the QUIC engine for us. */
	rc = SSL_poll(poll_items, n, sizeof(SSL_POLL_ITEM), tvp, 0, &result_count);

	if (rc == 0) {
		if (poll_items != stackbuf) {
			efree(poll_items);
		}
		php_quic_throw_ssl("SSL_poll failed");
		RETURN_THROWS();
	}

	/*
	 * map results back onto the caller's keys.  re-iterating the same hash
	 * yields the same order in which poll_items was built, so poll_items[i]
	 * lines up with the i-th key (which may be an int or a string).
	 */
	i = 0;
	ZEND_HASH_FOREACH_KEY(items, num_idx, str_key) {
		if (poll_items[i].revents != 0) {
			if (str_key != NULL) {
				add_assoc_long_ex(return_value, ZSTR_VAL(str_key),
					ZSTR_LEN(str_key), (zend_long)poll_items[i].revents);
			} else {
				add_index_long(return_value, (zend_long)num_idx,
					(zend_long)poll_items[i].revents);
			}
		}
		i++;
	} ZEND_HASH_FOREACH_END();

	if (poll_items != stackbuf) {
		efree(poll_items);
	}
}
