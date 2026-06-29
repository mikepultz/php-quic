--TEST--
quic: QUIC transport error-code constants (Quic\ERR_*)
--EXTENSIONS--
quic
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// The Quic\ERR_* transport error-code constants match RFC 9000 section 20.1.
//

$expected = [
    'Quic\\ERR_NO_ERROR'           => 0x00,
    'Quic\\ERR_INTERNAL_ERROR'     => 0x01,
    'Quic\\ERR_CONNECTION_REFUSED' => 0x02,
    'Quic\\ERR_FLOW_CONTROL_ERROR' => 0x03,
    'Quic\\ERR_STREAM_LIMIT_ERROR' => 0x04,
    'Quic\\ERR_FINAL_SIZE_ERROR'   => 0x06,
    'Quic\\ERR_PROTOCOL_VIOLATION' => 0x0a,
    'Quic\\ERR_APPLICATION_ERROR'  => 0x0c,
    'Quic\\ERR_NO_VIABLE_PATH'     => 0x10,
    'Quic\\ERR_CRYPTO_BEGIN'       => 0x0100,
    'Quic\\ERR_CRYPTO_END'         => 0x01ff,
];

$ok = 0;

foreach ($expected as $name => $value)
{
    if (defined($name) == true && constant($name) === $value)
    {
        $ok++;
    } else
    {
        echo "FAIL: ", $name, "\n";
    }
}

echo $ok, "/", count($expected), " constants correct\n";
echo is_int(Quic\ERR_NO_ERROR) == true ? "int type ok\n" : "int type wrong\n";
?>
--EXPECT--
11/11 constants correct
int type ok
