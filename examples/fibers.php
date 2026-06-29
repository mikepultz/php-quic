<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Fibers over QUIC: run many requests concurrently in one process, each
// written as straight-line blocking-style code, cooperatively scheduled on a
// single core via Quic\poll(). Fibers add concurrency, not parallelism (to go
// faster, scale across cores with reuse_port). Run examples/echo-server.php
// first.
//
//   php -d extension=quic examples/fibers.php
//

//
// a read that suspends the running fiber until its stream is readable, so the
// task code can read as if it were blocking
//
function fiber_read(Quic\Stream $_stream): ?string
{
    while (true)
    {
        $chunk = $_stream->read(65535);

        if ($chunk !== '')
        {
            return $chunk;
        }
        Fiber::suspend($_stream);
    }
}

$conn = new Quic\Connection('127.0.0.1', 4433, ['alpn' => 'demo', 'verify_peer' => false]);
$conn->setBlocking(false);

//
// one fiber per request; the body reads like synchronous code
//
$task = function (int $_i) use ($conn): void
{
    $stream = $conn->openStream();
    $stream->write("request #$_i", true);

    $reply = '';

    while (($chunk = fiber_read($stream)) !== null)
    {
        $reply .= $chunk;
    }

    echo $reply, "\n";
};

//
// start each fiber; it runs until its first suspend, handing back the stream
// it is waiting on
//
$waiting = [];

for ($i = 0; $i < 8; $i++)
{
    $fiber  = new Fiber($task);
    $stream = $fiber->start($i);

    if ($fiber->isTerminated() == false)
    {
        $waiting[$i] = ['fiber' => $fiber, 'stream' => $stream];
    }
}

//
// scheduler: poll the streams the fibers are blocked on, resume the ready
// ones, drop the finished ones
//
while (count($waiting) > 0)
{
    $items = [];

    foreach ($waiting as $key => $w)
    {
        $items[$key] = [$w['stream'], Quic\POLL_READ | Quic\POLL_ERROR];
    }

    foreach (Quic\poll($items, 1.0) as $key => $revents)
    {
        $stream = $waiting[$key]['fiber']->resume();

        if ($waiting[$key]['fiber']->isTerminated() == true)
        {
            unset($waiting[$key]);
        } else
        {
            $waiting[$key]['stream'] = $stream;
        }
    }
}

$conn->close();
