<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Inspect a QUIC endpoint's negotiated TLS session and certificate.
//
//   php -d extension=quic examples/inspect.php [host] [port] [alpn]
//

$host = $argv[1] ?? 'cloudflare-quic.com';
$port = (int)($argv[2] ?? 443);
$alpn = $argv[3] ?? 'h3';

$conn = new Quic\Connection($host, $port, ['alpn' => $alpn, 'connect_timeout_ms' => 5000]);
$info = $conn->getCryptoInfo();
$cert = openssl_x509_parse($conn->getPeerCertificate());

printf("%s:%d\n", $host, $port);
printf("  protocol : %s\n", $info['protocol']);
printf("  cipher   : %s (%d-bit, %s)\n",
    $info['cipher_name'], $info['cipher_bits'], $info['cipher_version']);
printf("  alpn     : %s\n", $conn->getNegotiatedAlpn() ?? '(none)');
printf("  verify   : %s\n", $conn->getVerifyResultString());
printf("  subject  : %s\n", $cert['name']);
printf("  issuer   : %s\n", $cert['issuer']['CN'] ?? '?');
printf("  expires  : %s\n", date('Y-m-d', $cert['validTo_time_t']));
printf("  chain    : %d cert(s)\n", count($conn->getPeerCertificateChain()));

$conn->close();
