--TEST--
quic: getCloseInfo() reports the peer's CONNECTION_CLOSE code and reason
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
// getCloseInfo() returns the application error code and reason carried by
// the peer's CONNECTION_CLOSE.
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_close_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port  = quic_test_port() + 11;
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

        //
        // before any close, there is no close info
        //
        echo $c->getCloseInfo() === null ? "open: null\n" : "open: not null (bad)\n";

        //
        // open a stream so the server knows our handshake has completed
        // before it closes (avoids racing CONNECTION_CLOSE with the handshake)
        //
        $s = $c->openStream(true);
        $s->write("up", true);

        //
        // drive events until the server's CONNECTION_CLOSE is observed
        //
        $info = null;

        for ($i = 0; $i < 50; $i++)
        {
            $c->handleEvents();
            $info = $c->getCloseInfo();

            if ($info !== null)
            {
                break;
            }
            usleep(100000);
        }

        if ($info === null)
        {
            echo "no close info (bad)\n";
        } else
        {
            printf("code=%d reason=%s local=%d transport=%d\n",
                $info['error_code'], $info['reason'],
                (int)$info['local'], (int)$info['transport']);
        }
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

$conn = $l->accept();

//
// wait for the client's stream, which proves its handshake is complete
//
$conn->acceptStream();
$conn->close(42, "bye");

for ($i = 0; $i < 10; $i++)
{
    $conn->handleEvents();
    usleep(50000);
}

$l->close();
pcntl_waitpid($pid, $status);
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_close_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
open: null
code=42 reason=bye local=0 transport=0
