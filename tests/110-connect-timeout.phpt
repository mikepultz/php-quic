--TEST--
quic: connect_timeout_ms aborts a stalled handshake
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (extension_loaded('pcntl') == false)
{
    die('skip pcntl required');
}
?>
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// connect_timeout_ms bounds the handshake: a peer that binds the UDP port but
// never answers must make the constructor throw a timeout, not hang.
//

require __DIR__ . '/cert_helper.inc';

$port  = quic_test_port() + 13;
$ready = sys_get_temp_dir() . '/quic_ctmo_' . getmypid() . '.ready';
@unlink($ready);

$pid = pcntl_fork();
if ($pid === 0)
{
    //
    // a plain UDP socket that receives the client's Initial packets but never
    // responds, so the QUIC handshake cannot complete
    //
    $sock = stream_socket_server('udp://127.0.0.1:' . $port, $errno, $errstr,
        STREAM_SERVER_BIND);

    if ($sock === false)
    {
        exit(1);
    }
    touch($ready);
    sleep(2);
    exit(0);
}

for ($i = 0; $i < 50 && file_exists($ready) == false; $i++)
{
    usleep(100000);
}

$start = microtime(true);

try
{
    new Quic\Connection('127.0.0.1', $port, [
        'alpn' => 'rawq', 'verify_peer' => false, 'connect_timeout_ms' => 500,
    ]);
    echo "no exception (bad)\n";
} catch (Quic\Exception $e)
{
    $elapsed_ms = (microtime(true) - $start) * 1000;

    echo (strpos($e->getMessage(), 'timed out') !== false && $elapsed_ms < 3000)
        ? "timed out as expected\n"
        : "unexpected (" . (int)$elapsed_ms . "ms): " . $e->getMessage() . "\n";
}

pcntl_waitpid($pid, $status);
?>
--CLEAN--
<?php
@unlink(sys_get_temp_dir() . '/quic_ctmo_' . getmypid() . '.ready');
?>
--EXPECT--
timed out as expected
