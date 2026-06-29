--TEST--
quic: connect() argument and option validation
--EXTENSIONS--
quic
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Constructor argument and option validation.
//

//
// missing ALPN
//
try
{
    new Quic\Connection('127.0.0.1', 443);
} catch (Quic\Exception $e)
{
    echo $e->getMessage(), "\n";
}

//
// invalid port
//
try
{
    new Quic\Connection('127.0.0.1', 70000, ['alpn' => 'h3']);
} catch (Quic\Exception $e)
{
    echo $e->getMessage(), "\n";
}

//
// empty ALPN list
//
try
{
    new Quic\Connection('127.0.0.1', 443, ['alpn' => []]);
} catch (Quic\Exception $e)
{
    echo $e->getMessage(), "\n";
}

//
// listener requires cert/key
//
try
{
    new Quic\Listener('127.0.0.1', 8853, ['alpn' => 'h3']);
} catch (Quic\Exception $e)
{
    echo $e->getMessage(), "\n";
}

//
// host with an embedded NUL byte is rejected
//
try
{
    new Quic\Connection("127.0.0.1\0evil", 443, ['alpn' => 'h3']);
} catch (Quic\Exception $e)
{
    echo $e->getMessage(), "\n";
}
?>
--EXPECT--
the 'alpn' option is required
port must be between 1 and 65535, got 70000
ALPN list must not be empty
the 'local_cert' option (server certificate path) is required
host must not contain null bytes
