<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Horizontally scaled server: one process per core, all sharing the same UDP
// port via SO_REUSEPORT (reuse_port), so the kernel load-balances inbound
// connections across the workers. Each worker here uses a simple blocking
// loop; swap in the Quic\poll() loop from echo-server.php for concurrency
// within a worker. Supply server.crt / server.key first (see echo-server.php).
//
//   php -d extension=quic examples/scaled-server.php
//

$workers = max(1, (int)trim((string)shell_exec('nproc')));

for ($i = 1; $i < $workers; $i++)
{
    if (pcntl_fork() === 0)
    {
        break;
    }
}

$listener = new Quic\Listener('0.0.0.0', 4433, [
    'local_cert' => __DIR__ . '/server.crt',
    'local_pk'   => __DIR__ . '/server.key',
    'alpn'       => 'demo',
    'reuse_port' => true,
]);

$me = getmypid();

while (true)
{
    $conn   = $listener->accept();
    $stream = $conn->acceptStream();

    $data = '';

    while (($chunk = $stream->read(65535)) !== null)
    {
        $data .= $chunk;
    }

    $stream->write("worker $me: $data", true);
    $conn->close();
}
