<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Minimal HTTP/3 GET. The extension is the QUIC transport; the HTTP/3 framing
// (control stream + SETTINGS, QPACK streams, request/response frames) is on
// top. Runs against any public HTTP/3 server.
//
//   php -d extension=quic examples/http3-get.php [host]
//

$host = $argv[1] ?? 'cloudflare-quic.com';

$conn = new Quic\Connection($host, 443, ['alpn' => 'h3', 'connect_timeout_ms' => 5000]);

//
// HTTP/3 control stream (SETTINGS) plus QPACK encoder/decoder streams; these
// must stay open for the connection's lifetime
//
$control = $conn->openStream(false);
$control->write("\x00\x04\x00");
($enc = $conn->openStream(false))->write("\x02");
($dec = $conn->openStream(false))->write("\x03");

//
// a GET is a HEADERS frame of QPACK static-table entries: GET=17, https=23,
// :authority (literal), :path /=1
//
$fields  = "\x00\x00\xD1\xD7" . "\x50" . chr(strlen($host)) . $host . "\xC1";
$request = "\x01" . chr(strlen($fields)) . $fields;

$stream = $conn->openStream(true);
$stream->write($request, true);

$resp = '';

while (($chunk = $stream->read(65535)) !== null)
{
    $resp .= $chunk;
}
$conn->close();

//
// parse HTTP/3 frames (QUIC varint type + length); collect DATA (0x00) frames
//
$varint = function (string $_d, int &$_o): int
{
    $b = ord($_d[$_o]);
    $n = 1 << ($b >> 6);
    $v = $b & 0x3f;

    for ($i = 1; $i < $n; $i++)
    {
        $v = ($v << 8) | ord($_d[$_o + $i]);
    }
    $_o += $n;

    return $v;
};

$off  = 0;
$body = '';

while ($off < strlen($resp))
{
    $type = $varint($resp, $off);
    $len  = $varint($resp, $off);

    if ($type === 0x00)
    {
        $body .= substr($resp, $off, $len);
    }
    $off += $len;
}

printf("%s: %d body bytes; first line: %s\n", $host, strlen($body), strtok($body, "\n"));
