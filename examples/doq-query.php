<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// DNS-over-QUIC (RFC 9250): resolve an A record against a public DoQ resolver.
// One query per bidirectional stream, 2-octet length prefix, id 0, ALPN "doq".
//
//   php -d extension=quic examples/doq-query.php [name] [resolver]
//

$name     = $argv[1] ?? 'example.com';
$resolver = $argv[2] ?? 'dns.adguard-dns.com';

function dns_name(string $_name): string
{
    $out = '';

    foreach (array_filter(explode('.', $_name)) as $label)
    {
        $out .= chr(strlen($label)) . $label;
    }

    return $out . "\x00";
}

function dns_skip(string $_msg, int $_off): int
{
    while (($len = ord($_msg[$_off])) !== 0)
    {
        if (($len & 0xc0) === 0xc0)
        {
            return $_off + 2;
        }
        $_off += 1 + $len;
    }

    return $_off + 1;
}

$query  = pack('nnnnnn', 0, 0x0100, 1, 0, 0, 0) . dns_name($name) . pack('nn', 1, 1);

$conn   = new Quic\Connection($resolver, 853, ['alpn' => 'doq', 'connect_timeout_ms' => 5000]);
$stream = $conn->openStream();
$stream->write(pack('n', strlen($query)) . $query, true);

$resp = '';

while (($chunk = $stream->read(65535)) !== null)
{
    $resp .= $chunk;
}
$conn->close();

$resp = substr($resp, 2);
$h    = unpack('nid/nflags/nqd/nan', $resp);

printf("%s via %s -> rcode=%d, %d answer(s)\n", $name, $resolver, $h['flags'] & 0x0f, $h['an']);

$off = dns_skip($resp, 12) + 4;

for ($i = 0; $i < $h['an']; $i++)
{
    $off = dns_skip($resp, $off);
    $rr  = unpack('ntype/nclass/Nttl/nrdlen', substr($resp, $off, 10));
    $off += 10;

    if ($rr['type'] === 1)
    {
        echo "  A  ", implode('.', array_values(unpack('C4', substr($resp, $off, 4)))), "\n";
    }
    $off += $rr['rdlen'];
}
