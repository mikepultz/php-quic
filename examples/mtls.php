<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Mutual TLS: the server requires and verifies a client certificate signed by
// a CA it trusts. Supply the cert/key files first, e.g.:
//
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 -subj /CN=demo-ca
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -subj /CN=localhost
//   openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj /CN=client
//   openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
//
//   php -d extension=quic examples/mtls.php
//

$dir = __DIR__;
$pid = pcntl_fork();

if ($pid === 0)
{
    usleep(300000);

    $conn = new Quic\Connection('127.0.0.1', 4444, [
        'alpn'        => 'demo',
        'verify_peer' => false,
        'local_cert'  => "$dir/client.crt",
        'local_pk'    => "$dir/client.key",
    ]);
    $conn->openStream()->write("hello", true);
    usleep(300000);
    $conn->close();
    exit(0);
}

$listener = new Quic\Listener('127.0.0.1', 4444, [
    'alpn'        => 'demo',
    'local_cert'  => "$dir/server.crt",
    'local_pk'    => "$dir/server.key",
    'verify_peer' => true,
    'cafile'      => "$dir/ca.crt",
]);

$conn = $listener->accept();
$conn->acceptStream();

$pem = $conn->getPeerCertificate();

if ($pem === null)
{
    echo "no client certificate presented\n";
} else
{
    echo "client subject: ", openssl_x509_parse($pem)['name'], "\n";
    echo "verify: ", $conn->getVerifyResultString(), "\n";
}

$conn->close();
$listener->close();
pcntl_waitpid($pid, $status);
