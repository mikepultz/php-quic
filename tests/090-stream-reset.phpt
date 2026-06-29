--TEST--
quic: a peer stream reset makes read() return null, not throw
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
// A peer stream reset makes read() return null, not throw.
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_reset_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port  = quic_test_port() + 9;
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
        // some data, no FIN
        //
        $s->write("partial", false);

        //
        // abortive reset
        //
        $s->reset(42);

        //
        // let the RESET_STREAM frame flush
        //
        usleep(300000);
        $c->close();
    } catch (\Throwable $e)
    {
    }
    exit(0);
}

$l = new Quic\Listener('127.0.0.1', $port, [
    'local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq',
]);
touch($ready);

$conn   = $l->accept();
$stream = $conn->acceptStream();

$threw = false;

try
{
    //
    // read until end-of-stream; a reset must surface as null, never an
    // exception (we may receive the "partial" bytes before the reset, or
    // nothing)
    //
    while (($chunk = $stream->read(65535)) !== null)
    {
    }
} catch (\Throwable $e)
{
    $threw = true;
}

echo $threw == true ? "read threw (bad)\n" : "read returned null on reset (ok)\n";

$conn->close();
$l->close();
pcntl_waitpid($pid, $status);
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_reset_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
read returned null on reset (ok)
