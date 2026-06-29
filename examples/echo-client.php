<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Minimal blocking client for examples/echo-server.php.
//
//   php -d extension=quic examples/echo-client.php "hello quic"
//

$message = $argv[1] ?? 'hello quic';

$conn = new Quic\Connection('127.0.0.1', 4433, [
    'alpn'        => 'demo',
    // self-signed cert; drop verify_peer for a real CA-signed cert
    'verify_peer' => false,
]);

//
// open a bidirectional stream and send the message with a FIN
//
$stream = $conn->openStream();
$stream->write($message, true);

//
// read the echoed reply until end-of-stream
//
$reply = '';

while (($chunk = $stream->read(65535)) !== null)
{
    $reply .= $chunk;
}

echo $reply, "\n";

$conn->close();
