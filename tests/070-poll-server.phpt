--TEST--
quic: concurrent non-blocking echo server via Quic\poll() serving N clients
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
// Concurrent non-blocking echo server via Quic\poll() serving N clients.
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_poll_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port = quic_test_port() + 7;
$N    = 3;

$listener = new Quic\Listener('127.0.0.1', $port, [
    'local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq',
]);
$listener->setBlocking(false);

//
// fork N blocking clients
//
$kids = [];

for ($i = 0; $i < $N; $i++)
{
    $pid = pcntl_fork();

    if ($pid === 0)
    {
        //
        // let the parent enter its loop
        //
        usleep(200000);

        try
        {
            $c = new Quic\Connection('127.0.0.1', $port, ['alpn' => 'rawq', 'verify_peer' => false]);
            $s = $c->openStream(true);
            $s->write("hi-$i", true);

            $r = '';

            while (($chunk = $s->read(65535)) !== null)
            {
                if ($chunk !== '')
                {
                    $r .= $chunk;
                }
            }

            $c->close();
            exit($r === "echo:hi-$i" ? 0 : 1);
        } catch (\Throwable $e)
        {
            exit(2);
        }
    }
    $kids[] = $pid;
}

//
// parent: single-process concurrent server driven entirely by Quic\poll().
// $conns and $streams are keyed by spl_object_id.
//
$conns    = [];
$streams  = [];
$done     = 0;
$deadline = microtime(true) + 20;

while (microtime(true) < $deadline)
{
    if ($done >= $N && count($conns) === 0)
    {
        break;
    }

    //
    // build the poll set: listener + each connection + each unfinished stream
    //
    $items = [[$listener, Quic\POLL_ACCEPT_CONNECTION]];

    foreach ($conns as $c)
    {
        $items[] = [$c, Quic\POLL_ACCEPT_STREAM | Quic\POLL_ERROR];
    }

    foreach ($streams as $st)
    {
        if ($st['replied'] == false)
        {
            $items[] = [$st['s'], Quic\POLL_READ | Quic\POLL_ERROR];
        }
    }

    foreach (Quic\poll($items, 0.5) as $idx => $revents)
    {
        $obj = $items[$idx][0];

        if ($obj === $listener)
        {
            while (($c = $listener->accept()) !== null)
            {
                $c->setBlocking(false);
                $conns[spl_object_id($c)] = $c;
            }
        } else if ($obj instanceof Quic\Connection)
        {
            $cid = spl_object_id($obj);

            while (($s = $obj->acceptStream()) !== null)
            {
                $streams[spl_object_id($s)] = ['s' => $s, 'cid' => $cid, 'buf' => '', 'replied' => false];
            }

            //
            // client closed
            //
            if (($revents & Quic\POLL_ERROR) != 0)
            {
                unset($conns[$cid]);

                foreach ($streams as $sid => $st)
                {
                    if ($st['cid'] === $cid)
                    {
                        unset($streams[$sid]);
                    }
                }
            }
        } else if ($obj instanceof Quic\Stream)
        {
            $sid = spl_object_id($obj);

            if (isset($streams[$sid]) == false)
            {
                continue;
            }

            $chunk = $obj->read(65535);

            if ($chunk === null)
            {
                //
                // peer FIN, echo the buffered request back
                //
                $obj->write("echo:" . $streams[$sid]['buf'], true);
                $streams[$sid]['replied'] = true;
                $done++;
            } else if ($chunk !== '')
            {
                $streams[$sid]['buf'] .= $chunk;
            }
        }
    }

    //
    // keep every connection's engine pumping (flush outbound echoes, timers)
    //
    $listener->handleEvents();

    foreach ($conns as $c)
    {
        $c->handleEvents();
    }
}

$listener->close();

$ok = 0;

foreach ($kids as $pid)
{
    pcntl_waitpid($pid, $status);

    if (pcntl_wexitstatus($status) === 0)
    {
        $ok++;
    }
}

echo "served=$done ok=$ok\n";
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_poll_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
served=3 ok=3
