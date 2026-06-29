--TEST--
quic: resource classes are not serializable and reject dynamic properties
--EXTENSIONS--
quic
--SKIPIF--
<?php
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
// The resource-wrapper classes wrap an OS/OpenSSL handle, so they are not
// serializable and reject dynamic properties.
//

require __DIR__ . '/cert_helper.inc';

$prefix = sys_get_temp_dir() . '/quic_flags_' . getmypid();
[$cert, $key] = quic_make_cert($prefix);

$l = new Quic\Listener('127.0.0.1', quic_test_port() + 15, [
    'local_cert' => $cert, 'local_pk' => $key, 'alpn' => 'rawq',
]);

try
{
    serialize($l);
    echo "serialize: allowed (bad)\n";
} catch (\Exception $e)
{
    echo "serialize blocked\n";
}

try
{
    $l->nope = 1;
    echo "dynprop: allowed (bad)\n";
} catch (\Error $e)
{
    echo "dynprop blocked\n";
}

$l->close();
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/quic_flags_*') as $f)
{
    @unlink($f);
}
?>
--EXPECT--
serialize blocked
dynprop blocked
