--TEST--
quic: peer_fingerprint certificate pinning (match + mismatch)
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
// peer_fingerprint certificate pinning (match + mismatch).
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_fp_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$fp = openssl_x509_fingerprint(file_get_contents($cert), 'sha256');

//
// positive: correct fingerprint -> round-trip succeeds
//
$port  = quic_test_port() + 4;
$ready = $prefix . '.r1';
@unlink($ready);

$pid = pcntl_fork();
if ($pid === 0)
{
    try
    {
        $l = new Quic\Listener('127.0.0.1', $port, [
            'local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq',
        ]);
        touch($ready);

        $conn   = $l->accept();
        $stream = $conn->acceptStream();
        $data   = '';

        while (($c = $stream->read(65535)) !== null)
        {
            if ($c !== '')
            {
                $data .= $c;
            }
        }

        $stream->write("echo:$data", true);
        $conn->close();
    } catch (\Throwable $e)
    {
        fwrite(STDERR, $e->getMessage() . "\n");
    }
    exit(0);
}

for ($i = 0; $i < 50 && file_exists($ready) == false; $i++)
{
    usleep(100000);
}

$conn = new Quic\Connection('127.0.0.1', $port, [
    'alpn' => 'rawq',
    'verify_peer' => false,
    'peer_fingerprint' => ['sha256' => $fp],
]);
$stream = $conn->openStream(true);
$stream->write("ping", true);

$resp = '';

while (($c = $stream->read(65535)) !== null)
{
    if ($c !== '')
    {
        $resp .= $c;
    }
}

$conn->close();
pcntl_waitpid($pid, $status);
echo $resp, "\n";

//
// negative: wrong fingerprint -> Quic\Exception
//
$port2  = quic_test_port() + 5;
$ready2 = $prefix . '.r2';
@unlink($ready2);

$pid2 = pcntl_fork();
if ($pid2 === 0)
{
    try
    {
        $l = new Quic\Listener('127.0.0.1', $port2, [
            'local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq',
        ]);
        touch($ready2);

        $conn = $l->accept();

        //
        // keep servicing the connection so the client can complete its
        // handshake (and then its post-handshake fingerprint check); merely
        // sleeping does not flush the server's packets.
        //
        $conn->setBlocking(false);
        $deadline = microtime(true) + 2.0;

        while (microtime(true) < $deadline)
        {
            $conn->handleEvents();
            usleep(20000);
        }
    } catch (\Throwable $e)
    {
    }
    exit(0);
}

for ($i = 0; $i < 50 && file_exists($ready2) == false; $i++)
{
    usleep(100000);
}

$wrong = str_repeat('00', 32);

try
{
    new Quic\Connection('127.0.0.1', $port2, [
        'alpn' => 'rawq',
        'verify_peer' => false,
        'peer_fingerprint' => ['sha256' => $wrong],
    ]);
    echo "NOT rejected\n";
} catch (Quic\Exception $e)
{
    echo strpos($e->getMessage(), 'peer_fingerprint') !== false ? "rejected\n" : "wrong error\n";
}

pcntl_waitpid($pid2, $status);
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_fp_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
echo:ping
rejected
