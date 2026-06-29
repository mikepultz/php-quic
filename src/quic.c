/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: module bootstrap (MINIT/MSHUTDOWN/MINFO + module entry).
 */

#include "php_quic.h"
#include "quic_arginfo.h"
#include "ext/standard/info.h"
#include "Zend/zend_exceptions.h"

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/quic.h>

zend_class_entry *quic_ce_connection = NULL;
zend_class_entry *quic_ce_listener   = NULL;
zend_class_entry *quic_ce_stream     = NULL;
zend_class_entry *quic_ce_exception  = NULL;

int php_quic_ctx_allow_self_signed_index = -1;

PHP_MINIT_FUNCTION(quic)
{
	/*
	 * allocate the SSL_CTX ex_data slot used to pass the allow-self-signed
	 * flag through to the verification callback.
	 */
	php_quic_ctx_allow_self_signed_index =
		SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);

	/*
	 * exception first; the connection/listener/stream classes do not
	 * depend on it at registration time, but keeping it first mirrors the
	 * runtime dependency.
	 */
	quic_ce_exception = register_class_Quic_Exception(zend_ce_exception);

	quic_ce_connection = register_class_Quic_Connection();
	php_quic_connection_init_handlers();

	quic_ce_listener = register_class_Quic_Listener();
	php_quic_listener_init_handlers();

	quic_ce_stream = register_class_Quic_Stream();
	php_quic_stream_init_handlers();

	register_quic_symbols(module_number);

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(quic)
{
	if (php_quic_ctx_allow_self_signed_index != -1) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL_CTX,
			php_quic_ctx_allow_self_signed_index);
		php_quic_ctx_allow_self_signed_index = -1;
	}

	return SUCCESS;
}

PHP_MINFO_FUNCTION(quic)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "QUIC support", "enabled");
	php_info_print_table_row(2, "Extension version", PHP_QUIC_VERSION);
	php_info_print_table_row(2, "OpenSSL header version", OPENSSL_VERSION_TEXT);
	php_info_print_table_row(2, "OpenSSL library version",
		OpenSSL_version(OPENSSL_VERSION));
	php_info_print_table_end();
}

zend_module_entry quic_module_entry = {
	STANDARD_MODULE_HEADER,
	"quic",
	ext_functions,
	PHP_MINIT(quic),
	PHP_MSHUTDOWN(quic),
	NULL,                   /* RINIT */
	NULL,                   /* RSHUTDOWN */
	PHP_MINFO(quic),
	PHP_QUIC_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_QUIC
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(quic)
#endif
