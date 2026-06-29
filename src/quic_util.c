/*
 * Copyright (c) 2026 Mike Pultz. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD-3-Clause license.
 * See the LICENSE file for details.
 *
 * php-quic: shared helpers (UDP sockets, ALPN encoding, OpenSSL glue).
 */

#include "quic_util.h"

#include "main/php_network.h"
#include "Zend/zend_smart_str.h"

#include <string.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>

#ifdef PHP_WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
# include <windows.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
#endif

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>

int php_quic_udp_client(const char *host, const char *port,
	BIO_ADDR **peer_out, char *errbuf, size_t errlen)
{
	BIO_ADDRINFO *res = NULL;
	const BIO_ADDRINFO *ai = NULL;
	int sock = -1;

	*peer_out = NULL;

	if (BIO_lookup_ex(host, port, BIO_LOOKUP_CLIENT, AF_UNSPEC, SOCK_DGRAM,
			IPPROTO_UDP, &res) == 0) {
		snprintf(errbuf, errlen, "failed to resolve %s:%s", host, port);
		return -1;
	}

	for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {

		sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, IPPROTO_UDP, 0);
		if (sock == -1) {
			continue;
		}

		if (BIO_connect(sock, BIO_ADDRINFO_address(ai), 0) == 0) {
			BIO_closesocket(sock);
			sock = -1;
			continue;
		}

		if (BIO_socket_nbio(sock, 1) == 0) {
			BIO_closesocket(sock);
			sock = -1;
			continue;
		}

		break;
	}

	if (sock != -1 && ai != NULL) {
		*peer_out = BIO_ADDR_dup(BIO_ADDRINFO_address(ai));
		if (*peer_out == NULL) {
			BIO_closesocket(sock);
			sock = -1;
			snprintf(errbuf, errlen, "out of memory duplicating peer address");
		}
	} else {
		snprintf(errbuf, errlen, "failed to create UDP socket to %s:%s",
			host, port);
	}

	BIO_ADDRINFO_free(res);

	return sock;
}

int php_quic_udp_server(const char *host, const char *port,
	bool reuse_port, char *errbuf, size_t errlen)
{
	BIO_ADDRINFO *res = NULL;
	const BIO_ADDRINFO *ai = NULL;
	int sock = -1;

	if (host != NULL && *host == '\0') {
		host = NULL;
	}

	if (BIO_lookup_ex(host, port, BIO_LOOKUP_SERVER, AF_UNSPEC, SOCK_DGRAM,
			IPPROTO_UDP, &res) == 0) {
		snprintf(errbuf, errlen, "failed to resolve bind address %s:%s",
			host != NULL ? host : "*", port);
		return -1;
	}

	for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {

		sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, IPPROTO_UDP, 0);
		if (sock == -1) {
			continue;
		}

#ifdef SO_REUSEPORT
		/*
		 * SO_REUSEPORT lets several independent processes bind the same
		 * UDP host:port; the kernel load-balances inbound datagrams across
		 * them.  This is how a QUIC server scales across CPU cores (one
		 * process per core), since connections cannot be handed off after
		 * accept().  Must be set before bind().
		 */
		if (reuse_port) {
			int on = 1;
			if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,
					(const void *)&on, sizeof(on)) != 0) {
				BIO_closesocket(sock);
				sock = -1;
				snprintf(errbuf, errlen, "failed to set SO_REUSEPORT");
				continue;
			}
		}
#else
		if (reuse_port) {
			BIO_closesocket(sock);
			sock = -1;
			snprintf(errbuf, errlen,
				"reuse_port is not supported on this platform");
			break;
		}
#endif

		if (BIO_bind(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_REUSEADDR) == 0) {
			BIO_closesocket(sock);
			sock = -1;
			continue;
		}

		if (BIO_socket_nbio(sock, 1) == 0) {
			BIO_closesocket(sock);
			sock = -1;
			continue;
		}

		break;
	}

	if (sock == -1) {
		snprintf(errbuf, errlen, "failed to bind UDP socket on %s:%s",
			host != NULL ? host : "*", port);
	}

	BIO_ADDRINFO_free(res);

	return sock;
}

/*
 * monotonic milliseconds, for measuring handshake deadlines without being
 * affected by wall-clock adjustments.
 */
static uint64_t php_quic_monotonic_ms(void)
{
#ifdef PHP_WIN32
	return (uint64_t)GetTickCount64();
#else
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

/*
 * drive a non-blocking QUIC handshake with an overall deadline.  returns 1 on
 * success, 0 on a handshake error (caller pulls the OpenSSL error), or -1 if
 * the deadline elapsed first.  the connection is left in blocking mode on
 * return, matching a plain blocking SSL_connect().
 */
int php_quic_connect_timed(SSL *ssl, int fd, zend_long timeout_ms)
{
	uint64_t start = php_quic_monotonic_ms();

	SSL_set_blocking_mode(ssl, 0);

	for (;;) {
		int            rc = SSL_connect(ssl);
		int            err;
		int64_t        remaining;
		int            wait_ms;
		int            events;
		struct timeval tv;
		int            is_infinite = 0;

		if (rc == 1) {
			SSL_set_blocking_mode(ssl, 1);
			return 1;
		}

		err = SSL_get_error(ssl, rc);
		if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
			SSL_set_blocking_mode(ssl, 1);
			return 0;
		}

		remaining = (int64_t)timeout_ms -
			(int64_t)(php_quic_monotonic_ms() - start);
		if (remaining <= 0) {
			SSL_set_blocking_mode(ssl, 1);
			return -1;
		}

		wait_ms = remaining > INT_MAX ? INT_MAX : (int)remaining;

		/* honour the QUIC engine's own timer so loss recovery still fires. */
		if (SSL_get_event_timeout(ssl, &tv, &is_infinite) == 1 && is_infinite == 0) {
			int ev_ms = (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
			if (ev_ms < wait_ms) {
				wait_ms = ev_ms;
			}
		}

		events = 0;
		if (SSL_net_read_desired(ssl)) {
			events |= POLLIN;
		}
		if (SSL_net_write_desired(ssl)) {
			events |= POLLOUT;
		}
		if (events == 0) {
			events = POLLIN;
		}

		php_pollfd_for_ms((php_socket_t)fd, events, wait_ms);
		SSL_handle_events(ssl);
	}
}

/*
 * append one protocol string to the ALPN wire buffer.
 */
static zend_result php_quic_alpn_append(smart_str *buf, zend_string *proto,
	char *errbuf, size_t errlen)
{
	if (ZSTR_LEN(proto) == 0 || ZSTR_LEN(proto) > 255) {
		snprintf(errbuf, errlen,
			"ALPN protocol must be 1-255 bytes, got %zu", ZSTR_LEN(proto));
		return FAILURE;
	}

	smart_str_appendc(buf, (char)ZSTR_LEN(proto));
	smart_str_appendl(buf, ZSTR_VAL(proto), ZSTR_LEN(proto));

	return SUCCESS;
}

zend_result php_quic_alpn_from_zval(zval *spec, zend_string **out,
	char *errbuf, size_t errlen)
{
	smart_str buf = {0};

	*out = NULL;

	if (Z_TYPE_P(spec) == IS_STRING) {

		/*
		 * a string may be a single protocol ("doq") or a comma-separated
		 * list ("h3,h2"), matching the ssl context 'alpn_protocols' form.
		 */
		const char *s = Z_STRVAL_P(spec);
		size_t len = Z_STRLEN_P(spec), start = 0, i;
		int count = 0;

		for (i = 0; i <= len; i++) {
			if (i == len || s[i] == ',') {
				size_t a = start, b = i;

				while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
				while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;

				if (b > a) {
					zend_string *tok = zend_string_init(s + a, b - a, 0);
					zend_result r = php_quic_alpn_append(&buf, tok, errbuf, errlen);
					zend_string_release(tok);
					if (r == FAILURE) {
						smart_str_free(&buf);
						return FAILURE;
					}
					count++;
				}
				start = i + 1;
			}
		}

		if (count == 0) {
			snprintf(errbuf, errlen, "ALPN string is empty");
			smart_str_free(&buf);
			return FAILURE;
		}

	} else if (Z_TYPE_P(spec) == IS_ARRAY) {

		zval *entry;

		if (zend_hash_num_elements(Z_ARRVAL_P(spec)) == 0) {
			snprintf(errbuf, errlen, "ALPN list must not be empty");
			return FAILURE;
		}

		ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(spec), entry) {
			zend_string *tmp;
			zend_string *proto = zval_get_tmp_string(entry, &tmp);

			if (php_quic_alpn_append(&buf, proto, errbuf, errlen) == FAILURE) {
				zend_tmp_string_release(tmp);
				smart_str_free(&buf);
				return FAILURE;
			}
			zend_tmp_string_release(tmp);
		} ZEND_HASH_FOREACH_END();

	} else {
		snprintf(errbuf, errlen, "ALPN must be a string or array of strings");
		return FAILURE;
	}

	/* hand the assembled buffer off directly, no extra copy. */
	*out = smart_str_extract(&buf);

	return SUCCESS;
}

/*
 * private-key passphrase callback; userdata is the NUL-terminated
 * passphrase set via SSL_CTX_set_default_passwd_cb_userdata().
 */
static int php_quic_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
	size_t len;

	(void)rwflag;

	if (userdata == NULL) {
		return -1;
	}

	len = strlen((const char *)userdata);
	if (len > (size_t)size) {
		len = (size_t)size;
	}
	memcpy(buf, userdata, len);

	return (int)len;
}

/*
 * certificate verification callback.  honours the per-context
 * allow-self-signed flag stashed in SSL_CTX ex_data: when set, the two
 * self-signed verification errors are downgraded to success.
 */
static int php_quic_verify_cb(int preverify_ok, X509_STORE_CTX *store)
{
	SSL     *ssl;
	SSL_CTX *ctx;
	int      err;

	if (preverify_ok) {
		return 1;
	}

	ssl = X509_STORE_CTX_get_ex_data(store,
		SSL_get_ex_data_X509_STORE_CTX_idx());
	if (ssl == NULL) {
		return preverify_ok;
	}

	ctx = SSL_get_SSL_CTX(ssl);
	if ((bool)(intptr_t)SSL_CTX_get_ex_data(ctx,
			php_quic_ctx_allow_self_signed_index) == false) {
		return preverify_ok;
	}

	err = X509_STORE_CTX_get_error(store);
	if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
		err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
		return 1;
	}

	return preverify_ok;
}

/*
 * fetch an option as a borrowed C string, or NULL if absent / not a
 * string.
 */
static const char *php_quic_opt_string(HashTable *opts, const char *key,
	size_t key_len)
{
	zval *v;

	if (opts == NULL) {
		return NULL;
	}
	v = zend_hash_str_find(opts, key, key_len);
	if (v == NULL || Z_TYPE_P(v) != IS_STRING) {
		return NULL;
	}
	/*
	 * reject embedded NUL bytes: these options become NUL-terminated C
	 * strings (file paths, cipher lists), where a NUL would silently
	 * truncate and could mask a path-injection.
	 */
	if (strlen(Z_STRVAL_P(v)) != Z_STRLEN_P(v)) {
		return NULL;
	}
	return Z_STRVAL_P(v);
}

zend_result php_quic_configure_ctx(SSL_CTX *ctx, HashTable *opts,
	bool is_server, php_quic_tls_setup *out, char *errbuf, size_t errlen)
{
	zval       *v;
	bool        verify_peer      = !is_server;
	bool        verify_peer_name;
	bool        verify_peer_name_set = false;
	bool        allow_self_signed = false;
	const char *cafile, *capath, *local_cert, *local_pk, *passphrase;
	const char *ciphersuites, *groups, *sigalgs;
	zend_long   security_level   = -1;
	zend_long   verify_depth     = -1;
	bool        sni_enabled      = true;

	out->peer_name        = NULL;
	out->verify_peer      = false;
	out->verify_peer_name = false;
	out->sni_enabled      = true;

	if (opts != NULL) {
		if ((v = zend_hash_str_find(opts, "verify_peer", sizeof("verify_peer") - 1)) != NULL) {
			verify_peer = zend_is_true(v);
		}
		if ((v = zend_hash_str_find(opts, "verify_peer_name", sizeof("verify_peer_name") - 1)) != NULL) {
			verify_peer_name = zend_is_true(v);
			verify_peer_name_set = true;
		}
		if ((v = zend_hash_str_find(opts, "allow_self_signed", sizeof("allow_self_signed") - 1)) != NULL) {
			allow_self_signed = zend_is_true(v);
		}
		if ((v = zend_hash_str_find(opts, "security_level", sizeof("security_level") - 1)) != NULL) {
			security_level = zval_get_long(v);
		}
		if ((v = zend_hash_str_find(opts, "peer_name", sizeof("peer_name") - 1)) != NULL
				&& Z_TYPE_P(v) == IS_STRING
				&& strlen(Z_STRVAL_P(v)) == Z_STRLEN_P(v)) {
			out->peer_name = Z_STR_P(v);
		}
		if ((v = zend_hash_str_find(opts, "verify_depth", sizeof("verify_depth") - 1)) != NULL) {
			verify_depth = zval_get_long(v);
		}
		if ((v = zend_hash_str_find(opts, "SNI_enabled", sizeof("SNI_enabled") - 1)) != NULL) {
			sni_enabled = zend_is_true(v);
		}
	}
	if (!verify_peer_name_set) {
		verify_peer_name = verify_peer;
	}

	cafile       = php_quic_opt_string(opts, "cafile", sizeof("cafile") - 1);
	capath       = php_quic_opt_string(opts, "capath", sizeof("capath") - 1);
	local_cert   = php_quic_opt_string(opts, "local_cert", sizeof("local_cert") - 1);
	local_pk     = php_quic_opt_string(opts, "local_pk", sizeof("local_pk") - 1);
	passphrase   = php_quic_opt_string(opts, "passphrase", sizeof("passphrase") - 1);
	ciphersuites = php_quic_opt_string(opts, "ciphersuites", sizeof("ciphersuites") - 1);
	groups       = php_quic_opt_string(opts, "groups", sizeof("groups") - 1);
	sigalgs      = php_quic_opt_string(opts, "sigalgs", sizeof("sigalgs") - 1);

	/*
	 * local identity (server certificate, or client certificate for mTLS).
	 */
	if (local_cert != NULL) {
		if (passphrase != NULL) {
			SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)passphrase);
			SSL_CTX_set_default_passwd_cb(ctx, php_quic_passwd_cb);
		}
		if (SSL_CTX_use_certificate_chain_file(ctx, local_cert) <= 0) {
			snprintf(errbuf, errlen, "failed to load local_cert '%s'", local_cert);
			return FAILURE;
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, local_pk != NULL ? local_pk : local_cert,
				SSL_FILETYPE_PEM) <= 0) {
			snprintf(errbuf, errlen, "failed to load local_pk '%s'",
				local_pk != NULL ? local_pk : local_cert);
			return FAILURE;
		}
		if (SSL_CTX_check_private_key(ctx) <= 0) {
			snprintf(errbuf, errlen, "local_cert and local_pk do not match");
			return FAILURE;
		}
		/*
		 * the key is loaded; drop the borrowed passphrase pointer so it is
		 * not retained on the long-lived SSL_CTX.
		 */
		if (passphrase != NULL) {
			SSL_CTX_set_default_passwd_cb(ctx, NULL);
			SSL_CTX_set_default_passwd_cb_userdata(ctx, NULL);
		}
	} else if (is_server) {
		snprintf(errbuf, errlen,
			"the 'local_cert' option (server certificate path) is required");
		return FAILURE;
	}

	/*
	 * peer verification.
	 */
	if (verify_peer) {
		int mode = SSL_VERIFY_PEER;

		if (is_server) {
			mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		}

		SSL_CTX_set_ex_data(ctx, php_quic_ctx_allow_self_signed_index,
			(void *)(intptr_t)allow_self_signed);
		SSL_CTX_set_verify(ctx, mode, php_quic_verify_cb);

		if (cafile != NULL || capath != NULL) {
			if (SSL_CTX_load_verify_locations(ctx, cafile, capath) <= 0) {
				snprintf(errbuf, errlen, "failed to load CA from cafile/capath");
				return FAILURE;
			}
		} else if (!is_server) {
			SSL_CTX_set_default_verify_paths(ctx);
		}

		if (verify_depth >= 0) {
			SSL_CTX_set_verify_depth(ctx, (int)verify_depth);
		}
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	}

	/*
	 * TLS 1.3 tuning (QUIC mandates TLS 1.3, so there is no version knob).
	 */
	if (ciphersuites != NULL && SSL_CTX_set_ciphersuites(ctx, ciphersuites) == 0) {
		snprintf(errbuf, errlen, "invalid ciphersuites '%s'", ciphersuites);
		return FAILURE;
	}
	if (groups != NULL && SSL_CTX_set1_groups_list(ctx, groups) == 0) {
		snprintf(errbuf, errlen, "invalid groups '%s'", groups);
		return FAILURE;
	}
	if (sigalgs != NULL && SSL_CTX_set1_sigalgs_list(ctx, sigalgs) == 0) {
		snprintf(errbuf, errlen, "invalid sigalgs '%s'", sigalgs);
		return FAILURE;
	}
	if (security_level >= 0) {
		SSL_CTX_set_security_level(ctx, (int)security_level);
	}

	out->verify_peer      = verify_peer;
	out->verify_peer_name = verify_peer_name;
	out->sni_enabled      = sni_enabled;

	return SUCCESS;
}

/*
 * map a digest name (or, for the string form, infer one from the hex
 * length) and compare the peer certificate's fingerprint.
 */
static const EVP_MD *php_quic_md_for_hexlen(size_t hexlen)
{
	/*
	 * MD5 (32) and SHA-1 (40) are intentionally not accepted: pinning to a
	 * collision-weak digest is unsafe, so require SHA-256 or stronger.
	 */
	switch (hexlen) {
		case 64:  return EVP_sha256();
		case 96:  return EVP_sha384();
		case 128: return EVP_sha512();
		default:  return NULL;
	}
}

static bool php_quic_fp_matches(X509 *cert, const EVP_MD *md,
	const char *expected)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  digest_len = 0;
	char          hex[EVP_MAX_MD_SIZE * 2 + 1];
	unsigned int  i;

	if (md == NULL || X509_digest(cert, md, digest, &digest_len) == 0) {
		return false;
	}

	for (i = 0; i < digest_len; i++) {
		snprintf(hex + i * 2, 3, "%02x", digest[i]);
	}

	return strcasecmp(hex, expected) == 0;
}

zend_result php_quic_check_fingerprint(SSL *ssl, zval *spec,
	char *errbuf, size_t errlen)
{
	X509       *cert;
	zend_result result = FAILURE;

	cert = SSL_get1_peer_certificate(ssl);
	if (cert == NULL) {
		snprintf(errbuf, errlen,
			"peer_fingerprint set but the peer presented no certificate");
		return FAILURE;
	}

	if (Z_TYPE_P(spec) == IS_STRING) {

		const char *expected = Z_STRVAL_P(spec);
		const EVP_MD *md = php_quic_md_for_hexlen(Z_STRLEN_P(spec));

		if (md == NULL) {
			snprintf(errbuf, errlen,
				"peer_fingerprint string has an unrecognized length");
		} else if (php_quic_fp_matches(cert, md, expected)) {
			result = SUCCESS;
		} else {
			snprintf(errbuf, errlen, "peer_fingerprint did not match");
		}

	} else if (Z_TYPE_P(spec) == IS_ARRAY) {

		zend_string *algo;
		zval        *digest;

		result = SUCCESS;

		ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(spec), algo, digest) {
			const EVP_MD *md;

			if (algo == NULL || Z_TYPE_P(digest) != IS_STRING) {
				snprintf(errbuf, errlen,
					"peer_fingerprint array must map algorithm => hex digest");
				result = FAILURE;
				break;
			}
			md = EVP_get_digestbyname(ZSTR_VAL(algo));
			if (md == NULL) {
				snprintf(errbuf, errlen,
					"peer_fingerprint: unknown digest algorithm '%s'",
					ZSTR_VAL(algo));
				result = FAILURE;
				break;
			}
			/*
			 * reject collision-weak digests (MD5, SHA-1, ...); require a
			 * 256-bit or larger digest for certificate pinning.
			 */
			if (EVP_MD_get_size(md) < 32) {
				snprintf(errbuf, errlen,
					"peer_fingerprint: digest '%s' is too weak; use sha256 or stronger",
					ZSTR_VAL(algo));
				result = FAILURE;
				break;
			}
			if (!php_quic_fp_matches(cert, md, Z_STRVAL_P(digest))) {
				snprintf(errbuf, errlen,
					"peer_fingerprint (%s) did not match", ZSTR_VAL(algo));
				result = FAILURE;
				break;
			}
		} ZEND_HASH_FOREACH_END();

	} else {
		snprintf(errbuf, errlen,
			"peer_fingerprint must be a string or an array");
	}

	X509_free(cert);
	return result;
}
