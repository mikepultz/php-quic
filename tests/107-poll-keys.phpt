--TEST--
quic: Quic\poll() keys results by the caller's $items keys (not positional)
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
// poll() preserves the caller's key for each ready item, including the keys
// of a non-list $items array (here a string key and a gap integer key).
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_pkey_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port  = quic_test_port() + 16;
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
        $s->write("ping", true);

        //
        // keep the connection alive long enough for the server to poll
        //
        usleep(500000);
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
$conn->setBlocking(false);

//
// a non-list $items: a string key and a non-zero integer key
//
$result = [];

for ($i = 0; $i < 50; $i++)
{
    $result = Quic\poll(['rx' => [$stream, Quic\POLL_READ | Quic\POLL_ERROR]], 0.1);

    if (array_key_exists('rx', $result) == true)
    {
        break;
    }
}

echo array_key_exists('rx', $result) == true ? "string key preserved\n" : "string key lost\n";

$gap = Quic\poll([7 => [$stream, Quic\POLL_READ | Quic\POLL_ERROR]], 0.1);
echo array_key_exists(7, $gap) == true ? "int key preserved\n" : "int key lost\n";

$conn->close();
$l->close();
pcntl_waitpid($pid, $status);
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_pkey_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
string key preserved
int key preserved
