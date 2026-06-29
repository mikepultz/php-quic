--TEST--
quic: Quic\Stream::asStream() works with fwrite()/stream_get_contents()
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
// Quic\Stream::asStream() works with fwrite()/stream_get_contents().
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_as_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);
$port  = quic_test_port() + 6;
$ready = $prefix . '.ready';
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

        //
        // read exactly 4 bytes ("ping"), the client does not send FIN
        //
        $data = '';

        while (strlen($data) < 4)
        {
            $c = $stream->read(4 - strlen($data));

            if ($c === null)
            {
                break;
            }
            if ($c !== '')
            {
                $data .= $c;
            }
        }

        //
        // reply with the echo and conclude (FIN)
        //
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

$conn   = new Quic\Connection('127.0.0.1', $port, ['alpn' => 'rawq', 'verify_peer' => false]);
$stream = new Quic\Stream($conn, true);

$fp = $stream->asStream();
var_dump(is_resource($fp));

fwrite($fp, "ping");
fflush($fp);

//
// reads until the server FIN
//
$resp = stream_get_contents($fp);
echo $resp, "\n";

fclose($fp);
$conn->close();
pcntl_waitpid($pid, $status);
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_as_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
bool(true)
echo:ping
