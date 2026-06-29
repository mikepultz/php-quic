dnl Copyright (c) 2026 Mike Pultz. Licensed under BSD-3-Clause.
dnl
dnl config.m4 for the quic extension (OpenSSL 3.5+ native QUIC).

PHP_ARG_WITH([quic],
  [for QUIC support],
  [AS_HELP_STRING([--with-quic],
    [Include QUIC support (requires OpenSSL >= 3.5 native QUIC stack)])])

if test "$PHP_QUIC" != "no"; then

  dnl
  dnl locate OpenSSL >= 3.5 via pkg-config; the path given to --with-quic
  dnl (if any) is prepended to PKG_CONFIG_PATH so a custom prefix works.
  dnl
  if test "$PHP_QUIC" != "yes" && test -n "$PHP_QUIC"; then
    export PKG_CONFIG_PATH="$PHP_QUIC/lib/pkgconfig:$PHP_QUIC/lib64/pkgconfig:$PKG_CONFIG_PATH"
  fi

  PKG_CHECK_MODULES([QUIC_SSL], [libssl >= 3.5.0 libcrypto >= 3.5.0])

  PHP_EVAL_INCLINE([$QUIC_SSL_CFLAGS])
  PHP_EVAL_LIBLINE([$QUIC_SSL_LIBS], [QUIC_SHARED_LIBADD])

  dnl
  dnl confirm the native QUIC client API is actually present in the headers
  dnl (guards against an OpenSSL that is new enough by version but built
  dnl without QUIC).
  dnl
  AC_MSG_CHECKING([for OpenSSL native QUIC support])
  old_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $QUIC_SSL_CFLAGS"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <openssl/ssl.h>
  ]], [[
    const SSL_METHOD *m = OSSL_QUIC_client_method();
    (void)m;
  ]])], [
    AC_MSG_RESULT([yes])
  ], [
    AC_MSG_ERROR([OpenSSL >= 3.5 with native QUIC support is required])
  ])
  CPPFLAGS="$old_CPPFLAGS"

  PHP_SUBST([QUIC_SHARED_LIBADD])

  PHP_NEW_EXTENSION([quic],
    [src/quic.c src/quic_connection.c src/quic_listener.c src/quic_stream.c src/quic_exception.c src/quic_util.c src/quic_poll.c],
    [$ext_shared],,
    [-DZEND_ENABLE_STATIC_TSRMLS_CACHE=1])
fi
