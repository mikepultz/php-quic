<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Shared certificate helpers for the loopback tests.
//

//
// generate a throwaway self-signed certificate + key for the loopback tests,
// using the bundled openssl extension (no openssl CLI needed); returns
// [certPath, keyPath].
//
function quic_make_cert(string $_prefix): array
{
    $pkey = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    $dn  = ['commonName' => 'localhost'];
    $csr = openssl_csr_new($dn, $pkey, ['digest_alg' => 'sha256']);
    $crt = openssl_csr_sign($csr, null, $pkey, 3650, ['digest_alg' => 'sha256']);

    openssl_x509_export($crt, $certPem);
    openssl_pkey_export($pkey, $keyPem);

    $certPath = $_prefix . '.crt';
    $keyPath  = $_prefix . '.key';

    file_put_contents($certPath, $certPem);
    file_put_contents($keyPath, $keyPem);

    return [$certPath, $keyPath];
}

//
// pick a port unlikely to collide between concurrent test runs.
//
function quic_test_port(): int
{
    return 20000 + (getmypid() % 20000);
}
