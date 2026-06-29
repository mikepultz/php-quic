--TEST--
quic: TLS/cert introspection against a live resolver
--EXTENSIONS--
quic
--SKIPIF--
<?php
if (getenv('QUIC_LIVE_DOQ') == false)
{
    die('skip set QUIC_LIVE_DOQ=1 to run live network tests');
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
// TLS and certificate introspection against a live DoQ resolver.
//

$host = getenv('QUIC_DOQ_HOST') ?: 'dns.adguard-dns.com';
$conn = new Quic\Connection($host, 853, ['alpn' => 'doq']);

$info = $conn->getCryptoInfo();

echo "protocol=", $info['protocol'], "\n";
echo "alpn=", $info['alpn_protocol'], "\n";
echo "negotiated_alpn=", $conn->getNegotiatedAlpn(), "\n";
echo "cipher_prefix=", substr($info['cipher_name'], 0, 4), "\n";
echo "cipher_version=", $info['cipher_version'], "\n";
echo "cipher_bits>0=", $info['cipher_bits'] > 0 ? 'yes' : 'no', "\n";
echo "verify=", $conn->getVerifyResult(), "\n";

$pem    = $conn->getPeerCertificate();
$parsed = openssl_x509_parse($pem);

echo "cert_parsed=", is_array($parsed) && isset($parsed['subject']) ? 'yes' : 'no', "\n";
echo "chain>0=", count($conn->getPeerCertificateChain()) > 0 ? 'yes' : 'no', "\n";

$conn->close();
?>
--EXPECT--
protocol=QUICv1
alpn=doq
negotiated_alpn=doq
cipher_prefix=TLS_
cipher_version=TLSv1.3
cipher_bits>0=yes
verify=0
cert_parsed=yes
chain>0=yes
