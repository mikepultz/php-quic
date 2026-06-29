<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Concurrent QUIC echo server that handles many simultaneous connections in a
// single process using Quic\poll(). No threads, no forking (which doesn't work
// for QUIC: all connections share the one listener UDP socket).
//
//   # one-time: generate a self-signed cert
//   openssl req -x509 -newkey rsa:2048 -nodes \
//       -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"
//
//   php -d extension=quic examples/echo-server.php
//
// This loop is the one verified by tests/070-poll-server.phpt.
//

$listener = new Quic\Listener('127.0.0.1', 4433, [
    'local_cert' => __DIR__ . '/server.crt',
    'local_pk'   => __DIR__ . '/server.key',
    'alpn'       => 'demo',
]);
$listener->setBlocking(false);

echo "echo server listening on 127.0.0.1:4433\n";

//
// id => Quic\Connection
//
$conns = [];

//
// id => ['s' => Quic\Stream, 'cid' => connId, 'buf' => string]
//
$streams = [];

while (true)
{
    //
    // describe what we want to wait for
    //
    $items = [[$listener, Quic\POLL_ACCEPT_CONNECTION]];

    foreach ($conns as $c)
    {
        $items[] = [$c, Quic\POLL_ACCEPT_STREAM | Quic\POLL_ERROR];
    }

    foreach ($streams as $st)
    {
        $items[] = [$st['s'], Quic\POLL_READ | Quic\POLL_ERROR];
    }

    //
    // one call waits for I/O, honours QUIC timers, and pumps the engine
    //
    foreach (Quic\poll($items, 1.0) as $idx => $revents)
    {
        $obj = $items[$idx][0];

        if ($obj === $listener)
        {
            while (($c = $listener->accept()) !== null)
            {
                $c->setBlocking(false);
                $conns[spl_object_id($c)] = $c;
            }
        } else if ($obj instanceof Quic\Connection)
        {
            $cid = spl_object_id($obj);

            while (($s = $obj->acceptStream()) !== null)
            {
                $streams[spl_object_id($s)] = ['s' => $s, 'cid' => $cid, 'buf' => ''];
            }

            //
            // peer closed: drop the connection and its streams
            //
            if (($revents & Quic\POLL_ERROR) != 0)
            {
                unset($conns[$cid]);

                foreach ($streams as $sid => $st)
                {
                    if ($st['cid'] === $cid)
                    {
                        unset($streams[$sid]);
                    }
                }
            }
        } else if ($obj instanceof Quic\Stream)
        {
            $sid = spl_object_id($obj);

            if (isset($streams[$sid]) == false)
            {
                continue;
            }

            $chunk = $obj->read(65535);

            if ($chunk === null)
            {
                //
                // FIN: echo the buffered request back and conclude
                //
                $obj->write("echo: " . $streams[$sid]['buf'], true);
                unset($streams[$sid]);
            } else if ($chunk !== '')
            {
                $streams[$sid]['buf'] .= $chunk;
            }
        }
    }

    //
    // flush outbound data / advance timers for every live connection
    //
    $listener->handleEvents();

    foreach ($conns as $c)
    {
        $c->handleEvents();
    }
}
