<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Stream multiplexing: open many concurrent streams on one connection and
// read each reply as it arrives (no head-of-line blocking), driven by
// Quic\poll(). Run examples/echo-server.php first.
//
//   php -d extension=quic examples/multiplex.php
//

$conn = new Quic\Connection('127.0.0.1', 4433, ['alpn' => 'demo', 'verify_peer' => false]);
$conn->setBlocking(false);

$streams = [];
$buffers = [];

for ($i = 0; $i < 8; $i++)
{
    $s = $conn->openStream();
    $s->write("request #$i", true);

    $streams[spl_object_id($s)] = $s;
    $buffers[spl_object_id($s)] = '';
}

while (count($streams) > 0)
{
    $items = [];

    foreach ($streams as $id => $s)
    {
        $items[$id] = [$s, Quic\POLL_READ | Quic\POLL_ERROR];
    }

    foreach (Quic\poll($items, 1.0) as $id => $revents)
    {
        while (true)
        {
            $chunk = $streams[$id]->read(65535);

            if ($chunk === null)
            {
                echo $buffers[$id], "\n";
                unset($streams[$id], $buffers[$id]);
                break;
            }
            if ($chunk === '')
            {
                break;
            }
            $buffers[$id] .= $chunk;
        }
    }
}

$conn->close();
