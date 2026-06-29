/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 78d018d78e213641d90e69cc47cc8dc489c03e30 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Quic_poll, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, items, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_DOUBLE, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Quic_Connection___construct, 0, 0, 2)
	ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Quic_Connection_openStream, 0, 0, Quic\\Stream, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, bidirectional, _IS_BOOL, 0, "true")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Quic_Connection_acceptStream, 0, 0, Quic\\Stream, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_close, 0, 0, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, errorCode, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, reason, IS_STRING, 0, "\"\"")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_getCloseInfo, 0, 0, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_getFd, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_setBlocking, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, blocking, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_wantsRead, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Quic_Connection_wantsWrite arginfo_class_Quic_Connection_wantsRead

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_getTimeout, 0, 0, IS_DOUBLE, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_handleEvents, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_getCryptoInfo, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_getNegotiatedAlpn, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

#define arginfo_class_Quic_Connection_getPeerCertificate arginfo_class_Quic_Connection_getNegotiatedAlpn

#define arginfo_class_Quic_Connection_getPeerCertificateChain arginfo_class_Quic_Connection_getCryptoInfo

#define arginfo_class_Quic_Connection_getVerifyResult arginfo_class_Quic_Connection_getFd

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Connection_getVerifyResultString, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Quic_Listener___construct, 0, 0, 3)
	ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, options, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Quic_Listener_accept, 0, 0, Quic\\Connection, 1)
ZEND_END_ARG_INFO()

#define arginfo_class_Quic_Listener_close arginfo_class_Quic_Connection_handleEvents

#define arginfo_class_Quic_Listener_getFd arginfo_class_Quic_Connection_getFd

#define arginfo_class_Quic_Listener_setBlocking arginfo_class_Quic_Connection_setBlocking

#define arginfo_class_Quic_Listener_wantsRead arginfo_class_Quic_Connection_wantsRead

#define arginfo_class_Quic_Listener_wantsWrite arginfo_class_Quic_Connection_wantsRead

#define arginfo_class_Quic_Listener_getTimeout arginfo_class_Quic_Connection_getTimeout

#define arginfo_class_Quic_Listener_handleEvents arginfo_class_Quic_Connection_handleEvents

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Quic_Stream___construct, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, connection, Quic\\Connection, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, bidirectional, _IS_BOOL, 0, "true")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Stream_write, 0, 1, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, fin, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Stream_read, 0, 1, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Quic_Stream_end arginfo_class_Quic_Connection_handleEvents

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Stream_reset, 0, 0, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, errorCode, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Quic_Stream_getResetCode, 0, 0, IS_LONG, 1)
ZEND_END_ARG_INFO()

#define arginfo_class_Quic_Stream_getId arginfo_class_Quic_Connection_getFd

#define arginfo_class_Quic_Stream_isBidirectional arginfo_class_Quic_Connection_wantsRead

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_class_Quic_Stream_getConnection, 0, 0, Quic\\Connection, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Quic_Stream_asStream, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_FUNCTION(Quic_poll);
ZEND_METHOD(Quic_Connection, __construct);
ZEND_METHOD(Quic_Connection, openStream);
ZEND_METHOD(Quic_Connection, acceptStream);
ZEND_METHOD(Quic_Connection, close);
ZEND_METHOD(Quic_Connection, getCloseInfo);
ZEND_METHOD(Quic_Connection, getFd);
ZEND_METHOD(Quic_Connection, setBlocking);
ZEND_METHOD(Quic_Connection, wantsRead);
ZEND_METHOD(Quic_Connection, wantsWrite);
ZEND_METHOD(Quic_Connection, getTimeout);
ZEND_METHOD(Quic_Connection, handleEvents);
ZEND_METHOD(Quic_Connection, getCryptoInfo);
ZEND_METHOD(Quic_Connection, getNegotiatedAlpn);
ZEND_METHOD(Quic_Connection, getPeerCertificate);
ZEND_METHOD(Quic_Connection, getPeerCertificateChain);
ZEND_METHOD(Quic_Connection, getVerifyResult);
ZEND_METHOD(Quic_Connection, getVerifyResultString);
ZEND_METHOD(Quic_Listener, __construct);
ZEND_METHOD(Quic_Listener, accept);
ZEND_METHOD(Quic_Listener, close);
ZEND_METHOD(Quic_Listener, getFd);
ZEND_METHOD(Quic_Listener, setBlocking);
ZEND_METHOD(Quic_Listener, wantsRead);
ZEND_METHOD(Quic_Listener, wantsWrite);
ZEND_METHOD(Quic_Listener, getTimeout);
ZEND_METHOD(Quic_Listener, handleEvents);
ZEND_METHOD(Quic_Stream, __construct);
ZEND_METHOD(Quic_Stream, write);
ZEND_METHOD(Quic_Stream, read);
ZEND_METHOD(Quic_Stream, end);
ZEND_METHOD(Quic_Stream, reset);
ZEND_METHOD(Quic_Stream, getResetCode);
ZEND_METHOD(Quic_Stream, getId);
ZEND_METHOD(Quic_Stream, isBidirectional);
ZEND_METHOD(Quic_Stream, getConnection);
ZEND_METHOD(Quic_Stream, asStream);

static const zend_function_entry ext_functions[] = {
	ZEND_RAW_FENTRY(ZEND_NS_NAME("Quic", "poll"), zif_Quic_poll, arginfo_Quic_poll, 0, NULL, NULL)
	ZEND_FE_END
};

static const zend_function_entry class_Quic_Connection_methods[] = {
	ZEND_ME(Quic_Connection, __construct, arginfo_class_Quic_Connection___construct, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, openStream, arginfo_class_Quic_Connection_openStream, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, acceptStream, arginfo_class_Quic_Connection_acceptStream, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, close, arginfo_class_Quic_Connection_close, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getCloseInfo, arginfo_class_Quic_Connection_getCloseInfo, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getFd, arginfo_class_Quic_Connection_getFd, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, setBlocking, arginfo_class_Quic_Connection_setBlocking, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, wantsRead, arginfo_class_Quic_Connection_wantsRead, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, wantsWrite, arginfo_class_Quic_Connection_wantsWrite, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getTimeout, arginfo_class_Quic_Connection_getTimeout, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, handleEvents, arginfo_class_Quic_Connection_handleEvents, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getCryptoInfo, arginfo_class_Quic_Connection_getCryptoInfo, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getNegotiatedAlpn, arginfo_class_Quic_Connection_getNegotiatedAlpn, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getPeerCertificate, arginfo_class_Quic_Connection_getPeerCertificate, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getPeerCertificateChain, arginfo_class_Quic_Connection_getPeerCertificateChain, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getVerifyResult, arginfo_class_Quic_Connection_getVerifyResult, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Connection, getVerifyResultString, arginfo_class_Quic_Connection_getVerifyResultString, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static const zend_function_entry class_Quic_Listener_methods[] = {
	ZEND_ME(Quic_Listener, __construct, arginfo_class_Quic_Listener___construct, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Listener, accept, arginfo_class_Quic_Listener_accept, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Listener, close, arginfo_class_Quic_Listener_close, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Listener, getFd, arginfo_class_Quic_Listener_getFd, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Listener, setBlocking, arginfo_class_Quic_Listener_setBlocking, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Listener, wantsRead, arginfo_class_Quic_Listener_wantsRead, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Listener, wantsWrite, arginfo_class_Quic_Listener_wantsWrite, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Listener, getTimeout, arginfo_class_Quic_Listener_getTimeout, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Listener, handleEvents, arginfo_class_Quic_Listener_handleEvents, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static const zend_function_entry class_Quic_Stream_methods[] = {
	ZEND_ME(Quic_Stream, __construct, arginfo_class_Quic_Stream___construct, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, write, arginfo_class_Quic_Stream_write, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, read, arginfo_class_Quic_Stream_read, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, end, arginfo_class_Quic_Stream_end, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, reset, arginfo_class_Quic_Stream_reset, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, getResetCode, arginfo_class_Quic_Stream_getResetCode, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, getId, arginfo_class_Quic_Stream_getId, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, isBidirectional, arginfo_class_Quic_Stream_isBidirectional, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, getConnection, arginfo_class_Quic_Stream_getConnection, ZEND_ACC_PUBLIC)
	ZEND_ME(Quic_Stream, asStream, arginfo_class_Quic_Stream_asStream, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static void register_quic_symbols(int module_number)
{
	REGISTER_LONG_CONSTANT("Quic\\POLL_READ", SSL_POLL_EVENT_R, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\POLL_WRITE", SSL_POLL_EVENT_W, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\POLL_ACCEPT_CONNECTION", SSL_POLL_EVENT_IC, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\POLL_ACCEPT_STREAM", SSL_POLL_EVENT_IS, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\POLL_ERROR", SSL_POLL_EVENT_E, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_NO_ERROR", OSSL_QUIC_ERR_NO_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_INTERNAL_ERROR", OSSL_QUIC_ERR_INTERNAL_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_CONNECTION_REFUSED", OSSL_QUIC_ERR_CONNECTION_REFUSED, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_FLOW_CONTROL_ERROR", OSSL_QUIC_ERR_FLOW_CONTROL_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_STREAM_LIMIT_ERROR", OSSL_QUIC_ERR_STREAM_LIMIT_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_STREAM_STATE_ERROR", OSSL_QUIC_ERR_STREAM_STATE_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_FINAL_SIZE_ERROR", OSSL_QUIC_ERR_FINAL_SIZE_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_FRAME_ENCODING_ERROR", OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_TRANSPORT_PARAMETER_ERROR", OSSL_QUIC_ERR_TRANSPORT_PARAMETER_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_CONNECTION_ID_LIMIT_ERROR", OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_PROTOCOL_VIOLATION", OSSL_QUIC_ERR_PROTOCOL_VIOLATION, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_INVALID_TOKEN", OSSL_QUIC_ERR_INVALID_TOKEN, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_APPLICATION_ERROR", OSSL_QUIC_ERR_APPLICATION_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_CRYPTO_BUFFER_EXCEEDED", OSSL_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_KEY_UPDATE_ERROR", OSSL_QUIC_ERR_KEY_UPDATE_ERROR, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_AEAD_LIMIT_REACHED", OSSL_QUIC_ERR_AEAD_LIMIT_REACHED, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_NO_VIABLE_PATH", OSSL_QUIC_ERR_NO_VIABLE_PATH, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_CRYPTO_BEGIN", OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN, CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("Quic\\ERR_CRYPTO_END", OSSL_QUIC_ERR_CRYPTO_ERR_END, CONST_PERSISTENT);
}

static zend_class_entry *register_class_Quic_Exception(zend_class_entry *class_entry_Exception)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Quic", "Exception", NULL);
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_Exception, 0);

	return class_entry;
}

static zend_class_entry *register_class_Quic_Connection(void)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Quic", "Connection", class_Quic_Connection_methods);
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES|ZEND_ACC_NOT_SERIALIZABLE);

	return class_entry;
}

static zend_class_entry *register_class_Quic_Listener(void)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Quic", "Listener", class_Quic_Listener_methods);
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES|ZEND_ACC_NOT_SERIALIZABLE);

	return class_entry;
}

static zend_class_entry *register_class_Quic_Stream(void)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Quic", "Stream", class_Quic_Stream_methods);
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL|ZEND_ACC_NO_DYNAMIC_PROPERTIES|ZEND_ACC_NOT_SERIALIZABLE);

	return class_entry;
}
