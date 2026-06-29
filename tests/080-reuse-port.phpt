--TEST--
quic: reuse_port co-binds and a reuse_port listener serves traffic
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
if (stripos(PHP_OS, 'linux') === false)
{
    die('skip SO_REUSEPORT test is Linux-only');
}
?>
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// reuse_port co-binds and a reuse_port listener serves traffic.
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_rp_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$base = ['local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq', 'reuse_port' => true];
$port  = quic_test_port() + 8;
$ready = $prefix . '.ready';
@unlink($ready);

//
// two listeners co-bind the same port with reuse_port
//
$a = new Quic\Listener('127.0.0.1', $port, $base);
$b = new Quic\Listener('127.0.0.1', $port, $base);
echo "co-bind ok\n";
$b->close();

//
// the surviving reuse_port listener still serves a client end-to-end
//
$pid = pcntl_fork();
if ($pid === 0)
{
    usleep(200000);

    try
    {
        $c = new Quic\Connection('127.0.0.1', $port, ['alpn' => 'rawq', 'verify_peer' => false]);
        $s = $c->openStream(true);
        $s->write("ping", true);

        $r = '';

        while (($chunk = $s->read(65535)) !== null)
        {
            if ($chunk !== '')
            {
                $r .= $chunk;
            }
        }

        $c->close();
        exit($r === "echo:ping" ? 0 : 1);
    } catch (\Throwable $e)
    {
        exit(2);
    }
}

$conn   = $a->accept();
$stream = $conn->acceptStream();

$data = '';

while (($chunk = $stream->read(65535)) !== null)
{
    if ($chunk !== '')
    {
        $data .= $chunk;
    }
}

$stream->write("echo:$data", true);
$conn->close();
$a->close();

pcntl_waitpid($pid, $status);
echo "served: ", pcntl_wexitstatus($status) === 0 ? "ok" : "fail", "\n";
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_rp_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
co-bind ok
served: ok
