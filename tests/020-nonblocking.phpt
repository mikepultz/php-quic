--TEST--
quic: non-blocking client driven by stream_select() against a loopback server
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
if (@fopen('php://fd/0', 'r') === false)
{
    die('skip php://fd not available');
}
?>
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Non-blocking client driven by stream_select() against a loopback server.
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_nb_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port  = quic_test_port() + 1;
$ready = $prefix . '.ready';
@unlink($ready);

$pid = pcntl_fork();
if ($pid === 0)
{
    //
    // child: blocking echo server
    //
    try
    {
        $l = new Quic\Listener('127.0.0.1', $port, [
            'local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq',
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

for ($i = 0; $i < 50 && file_exists($ready) == false; $i++)
{
    usleep(100000);
}

//
// parent: non-blocking client through a real stream_select() loop
//
$conn = new Quic\Connection('127.0.0.1', $port, [
    'alpn' => 'rawq', 'verify_peer' => false,
]);
$conn->setBlocking(false);

$stream = $conn->openStream(true);
$stream->write("ping", true);

$sock = fopen('php://fd/' . $conn->getFd(), 'r');

$resp     = '';
$deadline = microtime(true) + 10;

while (microtime(true) < $deadline)
{
    $conn->handleEvents();

    $eof = false;

    while (true)
    {
        $chunk = $stream->read(65535);

        if ($chunk === null)
        {
            $eof = true;
            break;
        }

        if ($chunk === '')
        {
            break;
        }

        $resp .= $chunk;
    }

    if ($eof == true)
    {
        break;
    }

    $to = $conn->getTimeout();
    $r  = [$sock];
    $w  = $conn->wantsWrite() == true ? [$sock] : [];
    $e  = [];
    $sec  = $to === null ? 1 : (int)$to;
    $usec = $to === null ? 0 : (int)(($to - $sec) * 1000000);
    @stream_select($r, $w, $e, $sec, $usec);
}

$conn->close();
pcntl_waitpid($pid, $status);
echo $resp, "\n";
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_nb_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
echo:ping
