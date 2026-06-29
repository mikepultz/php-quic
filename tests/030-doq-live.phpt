--TEST--
quic: live DNS-over-QUIC query against a public resolver (RFC 9250)
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (getenv('QUIC_LIVE_DOQ') == false)
{
    die('skip set QUIC_LIVE_DOQ=1 to run live network tests');
}
?>
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Live DNS-over-QUIC query against a public resolver (RFC 9250).
//

$host = getenv('QUIC_DOQ_HOST') ?: 'dns.adguard-dns.com';

//
// RFC 9250: DNS message id MUST be 0; 2-octet length prefix; one query per
// client-initiated bidirectional stream; FIN after the query.
//
$hdr   = pack('nnnnnn', 0, 0x0100, 1, 0, 0, 0);
$qname = '';

foreach (['example', 'com'] as $label)
{
    $qname .= chr(strlen($label)) . $label;
}

$qname .= "\0";

//
// A, IN
//
$query = $hdr . $qname . pack('nn', 1, 1);

$conn   = new Quic\Connection($host, 853, ['alpn' => 'doq']);
$stream = $conn->openStream(true);
$stream->write(pack('n', strlen($query)) . $query, true);

$buf = '';

while (strlen($buf) < 2)
{
    $chunk = $stream->read(2 - strlen($buf));

    if ($chunk === null)
    {
        break;
    }

    if ($chunk === '')
    {
        continue;
    }

    $buf .= $chunk;
}

$len = unpack('n', $buf)[1];

$resp = '';

while (strlen($resp) < $len)
{
    $chunk = $stream->read($len - strlen($resp));

    if ($chunk === null)
    {
        break;
    }

    if ($chunk === '')
    {
        continue;
    }

    $resp .= $chunk;
}

$conn->close();

$h = unpack('nid/nflags/nqd/nan', substr($resp, 0, 8));
printf("id=%d qr=%d rcode=%d answers>0=%s\n",
    $h['id'],
    ($h['flags'] >> 15) & 1,
    $h['flags'] & 0xF,
    $h['an'] > 0 ? 'yes' : 'no');
?>
--EXPECT--
id=0 qr=1 rcode=0 answers>0=yes
