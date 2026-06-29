--TEST--
quic: getResetCode() returns the application error code of a stream reset
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (extension_loaded('pcntl') == false)
{
    die('skip pcntl required');
}
if (extension_loaded('openssl') == false)
{
    die('skip openssl extension required');
}
?>
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// After read() returns null, getResetCode() distinguishes a clean FIN (null)
// from a peer RESET_STREAM (the application error code).
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_rcode_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port  = quic_test_port() + 12;
$ready = $prefix . '.ready';
@unlink($ready);

$pid = pcntl_fork();
if ($pid === 0)
{
    for ($i = 0; $i < 50 && file_exists($ready) == false; $i++)
    {
        usleep(100000);
    }

    try
    {
        $c = new Quic\Connection('127.0.0.1', $port, ['alpn' => 'rawq', 'verify_peer' => false]);
        $s = $c->openStream(true);

        //
        // a live, un-reset stream has no reset code
        //
        echo "fresh: ", var_export($s->getResetCode(), true), "\n";

        $s->write("hi", false);

        while (($chunk = $s->read(65535)) !== null)
        {
        }

        echo "after reset: ", var_export($s->getResetCode(), true), "\n";

        $c->close();
    } catch (\Throwable $e)
    {
        echo "client error: ", $e->getMessage(), "\n";
    }
    exit(0);
}

$l = new Quic\Listener('127.0.0.1', $port, [
    'local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq',
]);
touch($ready);

$conn   = $l->accept();
$stream = $conn->acceptStream();

//
// drain the client's data, then abortively reset with code 123
//
while (($chunk = $stream->read(65535)) === '')
{
    usleep(10000);
}
$stream->reset(123);

for ($i = 0; $i < 6; $i++)
{
    $conn->handleEvents();
    usleep(50000);
}

$conn->close();
$l->close();
pcntl_waitpid($pid, $status);
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_rcode_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
fresh: NULL
after reset: 123
