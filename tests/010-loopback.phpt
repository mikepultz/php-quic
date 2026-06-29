--TEST--
quic: loopback client <-> server stream round-trip (blocking)
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
// Loopback client <-> server stream round-trip (blocking).
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_loopback_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port  = quic_test_port();
$ready = $prefix . '.ready';
@unlink($ready);

$pid = pcntl_fork();
if ($pid === 0)
{
    //
    // child: blocking server
    //
    try
    {
        $l = new Quic\Listener('127.0.0.1', $port, [
            'local_cert' => $cert,
            'local_pk'  => $key,
            'alpn' => 'rawq',
        ]);
        touch($ready);

        $conn   = $l->accept();
        $stream = $conn->acceptStream();
        $data   = '';

        while (($chunk = $stream->read(65535)) !== null)
        {
            if ($chunk === '')
            {
                continue;
            }

            $data .= $chunk;
        }

        $stream->write("echo:$data", true);
        $conn->close();
    } catch (\Throwable $e)
    {
        fwrite(STDERR, "server error: " . $e->getMessage() . "\n");
    }
    exit(0);
}

//
// parent: wait for the server to bind, then connect
//
for ($i = 0; $i < 50 && file_exists($ready) == false; $i++)
{
    usleep(100000);
}

$conn = new Quic\Connection('127.0.0.1', $port, [
    'alpn'        => 'rawq',
    'verify_peer' => false,
]);
$stream = $conn->openStream(true);
$stream->write("ping", true);

$resp = '';

while (($chunk = $stream->read(65535)) !== null)
{
    if ($chunk === '')
    {
        continue;
    }

    $resp .= $chunk;
}

$conn->close();

pcntl_waitpid($pid, $status);
echo $resp, "\n";
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_loopback_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
echo:ping
