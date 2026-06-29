--TEST--
quic: peer_fingerprint rejects weak digests (MD5 / SHA-1)
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
// Certificate pinning requires a strong digest: SHA-256 and stronger are
// accepted, MD5 and SHA-1 are rejected (collision-weak).
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_wfp_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port  = quic_test_port() + 14;
$ready = $prefix . '.ready';
@unlink($ready);

$sha256 = openssl_x509_fingerprint(file_get_contents($cert), 'sha256');
$md5     = openssl_x509_fingerprint(file_get_contents($cert), 'md5');

$pid = pcntl_fork();
if ($pid === 0)
{
    for ($i = 0; $i < 50 && file_exists($ready) == false; $i++)
    {
        usleep(100000);
    }

    $attempt = function ($fingerprint) use ($port)
    {
        try
        {
            $c = new Quic\Connection('127.0.0.1', $port, [
                'alpn' => 'rawq', 'verify_peer' => false,
                'peer_fingerprint' => $fingerprint,
            ]);
            $c->close();
            return "accepted";
        } catch (Quic\Exception $e)
        {
            return $e->getMessage();
        }
    };

    echo "sha256 string: ", $attempt($sha256), "\n";
    echo "md5 string:    ", $attempt($md5), "\n";
    echo "md5 array:     ", $attempt(['md5' => $md5]), "\n";
    echo "sha256 array:  ", $attempt(['sha256' => $sha256]), "\n";
    touch($prefix . '.done');
    exit(0);
}

$l = new Quic\Listener('127.0.0.1', $port, [
    'local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq',
]);
$l->setBlocking(false);
touch($ready);

//
// service every inbound connection until the client signals it is done (or a
// safety deadline), so each handshake completes regardless of timing
//
$done     = $prefix . '.done';
$conns    = [];
$deadline = microtime(true) + 5.0;

while (file_exists($done) == false && microtime(true) < $deadline)
{
    while (($c = $l->accept()) !== null)
    {
        $c->setBlocking(false);
        $conns[spl_object_id($c)] = $c;
    }

    $l->handleEvents();

    foreach ($conns as $c)
    {
        $c->handleEvents();
    }
    usleep(10000);
}

$l->close();
pcntl_waitpid($pid, $status);
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_wfp_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
sha256 string: accepted
md5 string:    peer_fingerprint string has an unrecognized length
md5 array:     peer_fingerprint: digest 'md5' is too weak; use sha256 or stronger
sha256 array:  accepted
