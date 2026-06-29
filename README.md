# php-quic

[![CI](https://github.com/mikepultz/php-quic/actions/workflows/ci.yml/badge.svg)](https://github.com/mikepultz/php-quic/actions/workflows/ci.yml)
[![Packagist Version](https://img.shields.io/packagist/v/mikepultz/php-quic)](https://packagist.org/packages/mikepultz/php-quic)
![PHP](https://img.shields.io/badge/PHP-8.4%2B-777bb4)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.5%2B-721412)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

A PHP extension that exposes raw **QUIC transport**, client and server, with
first-class access to QUIC streams. It is built on **OpenSSL 3.5+'s native QUIC
stack**: no ngtcp2, no quiche, no Rust, no FFI. The only dependency is the
OpenSSL that PHP already links against.

It gives you `Quic\Connection`, `Quic\Listener`, and `Quic\Stream` objects plus
a `Quic\poll()` event loop, so you can build any QUIC-based protocol in PHP
(HTTP/3, DNS-over-QUIC, or your own). The extension is the transport; the
protocol framing on top is yours.

```php
// open a QUIC connection and exchange data on a stream
$conn   = new Quic\Connection('example.com', 443, ['alpn' => 'myproto']);
$stream = $conn->openStream();

// send the data, then conclude the stream (FIN)
$stream->write("hello", true);

$reply = $stream->read(65535);

$conn->close();
```

## Requirements

- **PHP 8.4+** (NTS or ZTS) on Linux and macOS; **PHP 8.5+ on Windows** (see the
  platform note below)
- **OpenSSL 3.5.0+** with native QUIC (client QUIC since 3.2, server since 3.5).
  The extension requires 3.5 because it supports both client and server.
- **Linux, macOS, and Windows** (all built and tested in CI). On Linux and macOS
  the extension links the system OpenSSL, so any PHP 8.4+ works as long as that
  OpenSSL is 3.5+. On Windows it links the OpenSSL that ships in the PHP build's
  dependency pack: PHP 8.5 bundles OpenSSL 3.5+, but PHP 8.4 bundles OpenSSL 3.0
  (which has no QUIC), so **Windows requires PHP 8.5+**.

## Installing

### With PIE (recommended)

[PIE](https://github.com/php/pie) is the modern replacement for PECL:

```sh
pie install mikepultz/php-quic
```

### From source

```sh
phpize
./configure --with-quic          # or --with-quic=/path/to/openssl-3.5-prefix
make
make test                        # runs the .phpt suite
sudo make install
```

Then enable it (`extension=quic`) in your `php.ini`.

## API

All classes live in the `Quic\` namespace.

### `Quic\Connection`

Construct with `new Quic\Connection(...)` to open a client connection;
server-accepted connections come from `Listener::accept()`.

| Method | Description |
| --- | --- |
| `__construct(string $host, int $port, array $options = [])` | Open a client connection and complete the handshake. |
| `openStream(bool $bidirectional = true): Stream` | Open a locally-initiated stream (same as `new Quic\Stream($conn, $bidirectional)`). |
| `acceptStream(): ?Stream` | Accept a peer-initiated stream (null if none pending). |
| `close(int $errorCode = 0, string $reason = ""): void` | Send `CONNECTION_CLOSE`. |
| `getCloseInfo(): ?array` | Once closed, the `CONNECTION_CLOSE` details: `error_code`, `frame_type`, `reason`, `local` (we initiated it), `transport` (a transport error vs an application code). `null` while still open. |
| `getFd(): int`, `setBlocking(bool)`, `wantsRead(): bool`, `wantsWrite(): bool`, `getTimeout(): ?float`, `handleEvents(): void` | Event-loop integration (see below). |
| `getCryptoInfo(): array` | Negotiated session info (`protocol`, `cipher_name`, `cipher_bits`, `cipher_version`, `alpn_protocol`), the same keys as `stream_get_meta_data()['crypto']`. |
| `getNegotiatedAlpn(): ?string` | The negotiated ALPN protocol. |
| `getPeerCertificate(): ?string` | The peer's leaf certificate (PEM). Bridge to ext-openssl with `openssl_x509_read()`. |
| `getPeerCertificateChain(): array` | The peer's certificate chain (array of PEM strings). |
| `getVerifyResult(): int`, `getVerifyResultString(): string` | Certificate verification result (`0` is OK) and its description. |

Constructor options use the `ssl` stream-context vocabulary. The full set:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `alpn` | string or array | (required) | ALPN protocol(s) to offer, for example `'h3'`, `'doq'`, or `['h3', 'h3-29']`. A string may be comma-separated (`'h3,h2'`). |
| `alpn_protocols` | string | | Alias for `alpn` (the `ssl` context spelling), a comma-separated list. |
| `peer_name` | string | `$host` | Name used for SNI and for certificate-name verification. |
| `verify_peer` | bool | `true` | Verify the server certificate chain against the trust store. |
| `verify_peer_name` | bool | = `verify_peer` | Verify the certificate matches `peer_name`. |
| `allow_self_signed` | bool | `false` | Accept a self-signed certificate (only the self-signed errors are downgraded; still requires `verify_peer`). |
| `cafile` | string | | Path to a PEM CA bundle used for verification. |
| `capath` | string | | Directory of hashed CA certificates. |
| `verify_depth` | int | (OpenSSL default) | Maximum certificate chain depth to accept. |
| `local_cert` | string | | PEM client certificate chain for mutual TLS (mTLS). |
| `local_pk` | string | = `local_cert` | PEM client private key (defaults to reading the key from `local_cert`). |
| `passphrase` | string | | Passphrase for `local_pk`. |
| `peer_fingerprint` | string or array | | Certificate pinning. A hex digest string (algorithm inferred from length: md5/sha1/sha256/sha384/sha512), or an array `['sha256' => 'hex', ...]` where every entry must match. Throws `Quic\Exception` on mismatch. |
| `SNI_enabled` | bool | `true` | Send the Server Name Indication extension. |
| `security_level` | int | (OpenSSL default) | OpenSSL security level (0 to 5). |
| `ciphersuites` | string | (OpenSSL default) | Colon-separated TLS 1.3 ciphersuite list, for example `'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'`. |
| `groups` | string | (OpenSSL default) | Colon-separated key-exchange groups, for example `'X25519:P-256'`. |
| `sigalgs` | string | (OpenSSL default) | Colon-separated signature algorithms. |
| `idle_timeout_ms` | int | (negotiated) | Requested maximum idle timeout in milliseconds. |
| `connect_timeout_ms` | int | 0 | Abort the handshake with a `Quic\Exception` if it does not complete within this many milliseconds (0 = block on the QUIC defaults). |

> **TLS version is fixed at 1.3.** QUIC mandates it (RFC 9001), so there is no
> version selector. The `ssl` context's `ciphers` (the pre-TLS-1.3 cipher list),
> `disable_compression`, and `crypto_method` options do not apply.

### `Quic\Listener`

Construct with `new Quic\Listener(...)` to bind a server and start listening.

| Method | Description |
| --- | --- |
| `__construct(string $host, int $port, array $options)` | Bind a server and start listening. |
| `accept(): ?Connection` | Accept an inbound connection (null if none pending). |
| `close(): void` | Stop listening and release the socket. |
| `getFd()`, `setBlocking()`, `wantsRead()`, `wantsWrite()`, `getTimeout()`, `handleEvents()` | Event-loop integration. |

Constructor options: `local_cert` (PEM chain path, **required**), `local_pk`
(PEM key path), `passphrase`, `alpn` (string or array, **required**),
`verify_peer` (request and verify a client certificate, default `false`),
`cafile`/`capath`, `reuse_port` (set `SO_REUSEPORT` so multiple processes can
share the port, see Scaling), `security_level`, `ciphersuites`, `groups`,
`sigalgs`.

### `Quic\Stream`

| Method | Description |
| --- | --- |
| `__construct(Connection $connection, bool $bidirectional = true)` | Open a local stream (same as `$conn->openStream()`). |
| `write(string $data, bool $fin = false): int` | Write data; optionally conclude (FIN). |
| `read(int $length): ?string` | Up to `$length` bytes (a single call may return fewer even when more is buffered, like `fread`), `""` if nothing available (non-blocking), or `null` at end-of-stream (FIN or reset; see `getResetCode()`). |
| `end(): void` | Conclude the send side (FIN). |
| `reset(int $errorCode = 0): void` | Abortively reset the stream. |
| `getResetCode(): ?int` | After `read()` returns `null`, the application error code if the stream was reset, or `null` for a clean FIN. |
| `getId(): int`, `isBidirectional(): bool`, `getConnection(): Connection` | Stream metadata. |
| `asStream(): resource` | Expose the stream as a PHP stream resource for `fread`/`fwrite`/`stream_get_contents`/`stream_select`. |

### `Quic\poll()`, the event-loop primitive

```php
Quic\poll(array $items, ?float $timeout = null): array
```

The native way to wait for QUIC events across many objects at once, preferred
over driving `stream_select()` on `getFd()`. Each item is `[$object, $events]`
where `$object` is a `Connection`, `Listener`, or `Stream` and `$events` is a
bitmask of the constants below. It returns a map of each ready item's `$items`
key to its revents (preserving the key of a non-list array), and it pumps the
QUIC engine in the same call.
`$timeout` is in seconds (`0.0` polls without blocking, `null` blocks until an
event). It also honours each connection's QUIC timers internally.

| Constant | Meaning |
| --- | --- |
| `Quic\POLL_READ` | stream has data to read |
| `Quic\POLL_WRITE` | stream can accept more writes |
| `Quic\POLL_ACCEPT_CONNECTION` | listener has an inbound connection (`accept()`) |
| `Quic\POLL_ACCEPT_STREAM` | connection has an inbound stream (`acceptStream()`) |
| `Quic\POLL_ERROR` | error or closed condition |

**Return value, timeouts, and errors.** The returned array maps each ready
item's `$items` key to its revents bitmask; items with no event are omitted, so
you iterate it directly. An **empty array means the timeout elapsed with nothing
ready** (there is no separate timeout return; with a `null` timeout `poll()`
blocks until an event, so it will not return empty for a non-empty item set). A
single object erroring or closing is **not** an exception, it is the
`Quic\POLL_ERROR` bit in that item's revents, so test `$revents &
Quic\POLL_ERROR`. The call **throws `Quic\Exception`** only if the poll itself
fails (an SSL error, or a malformed item that is not `[object, events]` naming a
live `Connection`/`Listener`/`Stream`).

```php
try
{
    $ready = Quic\poll($items, 1.0);

    if (count($ready) == 0)
    {
        // timed out: nothing became ready within 1.0s
    }

    foreach ($ready as $i => $revents)
    {
        if (($revents & Quic\POLL_ERROR) != 0)
        {
            // this object errored or closed
        }

        if (($revents & Quic\POLL_READ) != 0)
        {
            // readable
        }
    }
} catch (Quic\Exception $e)
{
    // the poll call itself failed
}
```

A complete concurrent, single-process echo server built on this is in
[`examples/echo-server.php`](examples/echo-server.php) (verified by the test
suite). Note that forking or threading per connection does not work for QUIC:
every connection is multiplexed over the listener's single UDP socket, so
concurrency is done in one process with `Quic\poll()`.

### Error codes

A QUIC error code lives in one of two namespaces, and `getCloseInfo()`'s
`transport` flag tells you which.

**Transport errors** (`transport => true`) are defined by QUIC itself
(RFC 9000 section 20.1) and exposed as `Quic\ERR_*` constants:

| Constant | Value | Meaning |
| --- | --- | --- |
| `Quic\ERR_NO_ERROR` | 0x00 | no error |
| `Quic\ERR_INTERNAL_ERROR` | 0x01 | internal implementation error |
| `Quic\ERR_CONNECTION_REFUSED` | 0x02 | server refuses to accept the connection |
| `Quic\ERR_FLOW_CONTROL_ERROR` | 0x03 | flow-control limits exceeded |
| `Quic\ERR_STREAM_LIMIT_ERROR` | 0x04 | too many streams opened |
| `Quic\ERR_STREAM_STATE_ERROR` | 0x05 | frame received in an invalid stream state |
| `Quic\ERR_FINAL_SIZE_ERROR` | 0x06 | final size of a stream changed |
| `Quic\ERR_FRAME_ENCODING_ERROR` | 0x07 | malformed frame |
| `Quic\ERR_TRANSPORT_PARAMETER_ERROR` | 0x08 | invalid transport parameters |
| `Quic\ERR_CONNECTION_ID_LIMIT_ERROR` | 0x09 | too many connection IDs issued |
| `Quic\ERR_PROTOCOL_VIOLATION` | 0x0a | general protocol violation |
| `Quic\ERR_INVALID_TOKEN` | 0x0b | invalid Retry token |
| `Quic\ERR_APPLICATION_ERROR` | 0x0c | application error with no application code |
| `Quic\ERR_CRYPTO_BUFFER_EXCEEDED` | 0x0d | CRYPTO data exceeded the buffer |
| `Quic\ERR_KEY_UPDATE_ERROR` | 0x0e | key update error |
| `Quic\ERR_AEAD_LIMIT_REACHED` | 0x0f | AEAD confidentiality limit reached |
| `Quic\ERR_NO_VIABLE_PATH` | 0x10 | no viable network path |
| `Quic\ERR_CRYPTO_BEGIN` to `Quic\ERR_CRYPTO_END` | 0x0100 to 0x01ff | TLS alert; the alert number is `$code - Quic\ERR_CRYPTO_BEGIN` |

**Application errors** (`transport => false`, and every `getResetCode()`,
`reset()`, and `close()` code) are defined by the protocol you run over QUIC,
not by QUIC. There is no single list: HTTP/3 has `H3_*` (RFC 9114, 0x0100+),
DNS-over-QUIC has `DOQ_*` (RFC 9250, 0x0 to 0x5), and your own protocol picks
its own. The extension does not define these; they belong in a userland
protocol library.

```php
$info = $conn->getCloseInfo();

if ($info !== null && $info['transport'] == true
        && $info['error_code'] === Quic\ERR_PROTOCOL_VIOLATION)
{
    // the peer tore down the connection for a QUIC protocol violation
}
```

## Examples

### HTTP/3 GET request

The extension is the QUIC transport; HTTP/3 framing (the control stream, the
SETTINGS frame, QPACK, and the request/response frames) is built on top. This
minimal client opens the required streams, sends a GET, and reads the response
body. It runs against any public HTTP/3 server.

```php
$host = 'cloudflare-quic.com';
$conn = new Quic\Connection($host, 443, ['alpn' => 'h3']);

//
// HTTP/3 needs a control stream with SETTINGS plus QPACK encoder/decoder
// streams. Keep these references for the connection's lifetime: closing the
// control stream is a fatal H3 error.
//

// unidirectional control stream: type 0x00 (control) + empty SETTINGS
$control = $conn->openStream(false);
$control->write("\x00\x04\x00");

// QPACK encoder (0x02) and decoder (0x03) streams
$qpackEnc = $conn->openStream(false);
$qpackEnc->write("\x02");

$qpackDec = $conn->openStream(false);
$qpackDec->write("\x03");

//
// a GET is a HEADERS frame holding a QPACK field section. Pseudo-headers come
// from the QPACK static table: GET=17, https=23, :path /=1, :authority=0.
//

// QPACK prefix
$fields  = "\x00\x00";

// :method GET
$fields .= "\xD1";

// :scheme https
$fields .= "\xD7";

// :authority (literal)
$fields .= "\x50" . chr(strlen($host)) . $host;

// :path /
$fields .= "\xC1";

// HEADERS frame
$request = "\x01" . chr(strlen($fields)) . $fields;

// request stream (bidirectional): send the request + FIN (GET has no body)
$stream = $conn->openStream(true);
$stream->write($request, true);

$resp = '';

while (($chunk = $stream->read(65535)) !== null)
{
    if ($chunk !== '')
    {
        $resp .= $chunk;
    }
}

//
// parse the HTTP/3 frames and collect DATA frames (the body)
//
$read_varint = function (string $_d, int &$_o): int
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
    $type    = $read_varint($resp, $off);
    $len     = $read_varint($resp, $off);
    $payload = substr($resp, $off, $len);
    $off    += $len;

    // type 0x00 is a DATA frame; 0x01 is the response HEADERS frame (QPACK)
    if ($type === 0x00)
    {
        $body .= $payload;
    }
}

// e.g. "<!DOCTYPE html>"
echo strlen($body), " bytes: ", strtok($body, "\n"), "\n";

$conn->close();
```

Decoding the response headers (the status and header fields) needs a QPACK
decoder, which is out of scope for a transport library and belongs in a
userland HTTP/3 client built on top of this.

### DNS-over-QUIC (RFC 9250)

One DNS query per client-initiated bidirectional stream, framed with a 2-octet
length prefix, message id 0, ALPN `doq`:

```php
$conn   = new Quic\Connection('dns.adguard-dns.com', 853, ['alpn' => 'doq']);
$stream = $conn->openStream();

// a wire-format DNS message (id 0), e.g. from a DNS library
$query = "...";

// frame with a 2-octet length prefix and conclude (FIN)
$stream->write(pack('n', strlen($query)) . $query, true);

$len  = unpack('n', $stream->read(2))[1];
$resp = $stream->read($len);

$conn->close();
```

### Echo server (blocking)

```php
$listener = new Quic\Listener('0.0.0.0', 4433, [
    'local_cert' => '/etc/ssl/server.crt',
    'local_pk'   => '/etc/ssl/server.key',
    'alpn'       => 'myproto',
]);

while (true)
{
    // blocking accept of a connection and its first stream
    $conn   = $listener->accept();
    $stream = $conn->acceptStream();

    $data = '';

    while (($chunk = $stream->read(65535)) !== null)
    {
        if ($chunk !== '')
        {
            $data .= $chunk;
        }
    }

    $stream->write("echo: $data", true);
    $conn->close();
}
```

For concurrency (many connections in one process), see
[`examples/echo-server.php`](examples/echo-server.php), which uses `Quic\poll()`.

### Non-blocking client with `Quic\poll()`

`Quic\poll()` is the native event-loop primitive. Give it the objects you care
about and it waits for readiness, drives QUIC timers, and pumps the engine in
one call. No `php://fd` wrapper, no manual timeout math.

```php
$conn = new Quic\Connection($host, $port, ['alpn' => 'myproto']);
$conn->setBlocking(false);

$stream = $conn->openStream();

// send the request + FIN
$stream->write($request, true);

$response = '';

while (true)
{
    // wait until the stream is readable (or a QUIC timer needs servicing)
    Quic\poll([[$stream, Quic\POLL_READ | Quic\POLL_ERROR]], 1.0);

    $chunk = $stream->read(65535);

    // end of stream
    if ($chunk === null)
    {
        break;
    }

    if ($chunk !== '')
    {
        $response .= $chunk;
    }
}

$conn->close();
```

> **Interop with an existing `stream_select()` loop.** If you are integrating
> QUIC into an application that already drives its own `stream_select()` over
> other descriptors, use the lower-level primitives instead: `getFd()` (wrap it
> with `fopen('php://fd/' . $conn->getFd(), 'r')`), `wantsRead()`/`wantsWrite()`
> to build the select sets, `getTimeout()` for the timeout, and `handleEvents()`
> after the select returns. For a QUIC-only loop, prefer `Quic\poll()`.

### Inspecting the TLS session and peer certificate

```php
$conn = new Quic\Connection('cloudflare-quic.com', 443, ['alpn' => 'h3']);

$info = $conn->getCryptoInfo();
// ['protocol' => 'QUICv1', 'cipher_name' => 'TLS_AES_256_GCM_SHA384',
//  'cipher_bits' => 256, 'cipher_version' => 'TLSv1.3', 'alpn_protocol' => 'h3']

// bridge the PEM leaf certificate to ext-openssl
$cert = openssl_x509_read($conn->getPeerCertificate());
$meta = openssl_x509_parse($cert);

echo $meta['subject']['CN'], "\n";

// prints "ok" on success
echo "verify: ", $conn->getVerifyResultString(), "\n";
```

### Certificate pinning

```php
$conn = new Quic\Connection($host, $port, [
    'alpn' => 'myproto',

    // throws Quic\Exception on mismatch
    'peer_fingerprint' => ['sha256' => 'aabbcc...'],
]);
```

## Scaling

A single `Quic\poll()` loop is one PHP thread, which is **one CPU core**. You
cannot fork or thread per connection (every connection is multiplexed over the
listener's one UDP socket), so you scale **horizontally with `SO_REUSEPORT`**:
run one process per core, each `new Quic\Listener(host, port, [..., 'reuse_port'
=> true])` on the same port, and the kernel load-balances inbound datagrams.
OpenSSL's native QUIC does not do connection migration, which keeps the 4-tuple
stable and makes plain `SO_REUSEPORT` hashing work well without eBPF in most
deployments.

Measured locally (single-process vs two-process `reuse_port`, localhost,
RSA-2048 cert; client and server contend for the same cores, so this is a
floor):

| mode | 1 proc (no reuse_port) | 2 procs (reuse_port) |
| --- | --- | --- |
| new connection + request | ~60 tx/s | ~85 to 100 tx/s |
| request on persistent conn | ~5k to 7k tx/s | ~6k to 9k tx/s |

`reuse_port` gives roughly 1.3x to 1.7x on this 2-core box; on a many-core host
with load from separate machines, new-connection throughput scales roughly
linearly with cores. The OpenSSL userspace QUIC data path (no UDP GSO offload)
is the per-core ceiling, and per-event work must stay non-blocking or it stalls
the whole loop.

There are no built-in caps on accepted connections or streams, and `read($len)`
allocates up to `$len`, so apply your own backpressure (bound the accept loop,
cap `$len`) for untrusted peers.

## Limitations

The OpenSSL native QUIC stack is streams-only. This extension therefore does
**not** support:

- **RFC 9221 unreliable datagrams** (not implemented in OpenSSL through 4.0)
- **0-RTT / TLS 1.3 early data**
- **connection migration**

None of these are needed for HTTP/3, DoQ, or typical request/response
protocols. If you require QUIC datagrams, you need a different engine (ngtcp2,
quiche, or msquic).

There is also no **server-side idle-timeout** control: OpenSSL 3.5 scopes the
max-idle-timeout transport parameter to a connection and requires it before the
handshake, but accepted connections come off the listener already handshaked,
and there is no listener/CTX-level transport-parameter hook. So `Listener` has
no `idle_timeout_ms`; the client-side `idle_timeout_ms` and `connect_timeout_ms`
options are unaffected.

### Per-stream memory on long-lived connections

OpenSSL's QUIC stack retains roughly 300 bytes of per-stream state on a
connection until the connection is closed, even after the stream is fully
concluded and `SSL_free`d (measured at about 308 bytes/stream, not reclaimed by
pumping events, and valgrind-clean, meaning it is freed at connection teardown
rather than being a classic leak). So a single connection that opens a very
large number of streams (for example a persistent HTTP/3 or
DoQ-over-one-connection client doing millions of requests) grows over time. The
mitigation is to recycle the connection periodically. The common
new-connection-per-request pattern is unaffected: its memory is flat across
hundreds of thousands of connections in soak testing. This is an upstream
OpenSSL characteristic, not specific to this extension.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
