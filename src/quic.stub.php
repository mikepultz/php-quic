<?php

/**
 * php-quic: raw QUIC transport for PHP, built on OpenSSL 3.5+ native QUIC.
 *
 * Userland API surface (engine-neutral: no OpenSSL types leak through).
 * Naming follows the "Namespaces in bundled extensions" RFC:
 *   top-level namespace == extension name (Quic), no vendor prefix,
 *   PascalCase classes, camelCase methods.
 *
 * @generate-class-entries
 */

namespace Quic;

/**
 * Poll-event bit: the stream has data available to read.
 * @var int
 * @cvalue SSL_POLL_EVENT_R
 */
const POLL_READ = UNKNOWN;
/**
 * Poll-event bit: the stream can accept more data to write.
 * @var int
 * @cvalue SSL_POLL_EVENT_W
 */
const POLL_WRITE = UNKNOWN;
/**
 * Poll-event bit (Listener): an inbound connection is ready to accept().
 * @var int
 * @cvalue SSL_POLL_EVENT_IC
 */
const POLL_ACCEPT_CONNECTION = UNKNOWN;
/**
 * Poll-event bit (Connection): an inbound stream is ready to acceptStream().
 * @var int
 * @cvalue SSL_POLL_EVENT_IS
 */
const POLL_ACCEPT_STREAM = UNKNOWN;
/**
 * Poll-event bit: an error/closed condition occurred on the object.
 * @var int
 * @cvalue SSL_POLL_EVENT_E
 */
const POLL_ERROR = UNKNOWN;

/**
 * QUIC transport error codes (RFC 9000 section 20.1). These are the codes
 * reported by Connection::getCloseInfo() when its 'transport' flag is true.
 * Application protocols (HTTP/3, DoQ, ...) define their own codes in a
 * separate namespace; those are not listed here.
 *
 * @var int
 * @cvalue OSSL_QUIC_ERR_NO_ERROR
 */
const ERR_NO_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_INTERNAL_ERROR
 */
const ERR_INTERNAL_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_CONNECTION_REFUSED
 */
const ERR_CONNECTION_REFUSED = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_FLOW_CONTROL_ERROR
 */
const ERR_FLOW_CONTROL_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_STREAM_LIMIT_ERROR
 */
const ERR_STREAM_LIMIT_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_STREAM_STATE_ERROR
 */
const ERR_STREAM_STATE_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_FINAL_SIZE_ERROR
 */
const ERR_FINAL_SIZE_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_FRAME_ENCODING_ERROR
 */
const ERR_FRAME_ENCODING_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_TRANSPORT_PARAMETER_ERROR
 */
const ERR_TRANSPORT_PARAMETER_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR
 */
const ERR_CONNECTION_ID_LIMIT_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_PROTOCOL_VIOLATION
 */
const ERR_PROTOCOL_VIOLATION = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_INVALID_TOKEN
 */
const ERR_INVALID_TOKEN = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_APPLICATION_ERROR
 */
const ERR_APPLICATION_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED
 */
const ERR_CRYPTO_BUFFER_EXCEEDED = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_KEY_UPDATE_ERROR
 */
const ERR_KEY_UPDATE_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_AEAD_LIMIT_REACHED
 */
const ERR_AEAD_LIMIT_REACHED = UNKNOWN;
/**
 * @var int
 * @cvalue OSSL_QUIC_ERR_NO_VIABLE_PATH
 */
const ERR_NO_VIABLE_PATH = UNKNOWN;
/**
 * First code of the CRYPTO_ERROR range (RFC 9000 section 20.1): a code in
 * [ERR_CRYPTO_BEGIN, ERR_CRYPTO_END] is a TLS alert, where the alert number
 * is (code - ERR_CRYPTO_BEGIN).
 *
 * @var int
 * @cvalue OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN
 */
const ERR_CRYPTO_BEGIN = UNKNOWN;
/**
 * Last code of the CRYPTO_ERROR range (see ERR_CRYPTO_BEGIN).
 *
 * @var int
 * @cvalue OSSL_QUIC_ERR_CRYPTO_ERR_END
 */
const ERR_CRYPTO_END = UNKNOWN;

/**
 * Wait for QUIC events across a set of Connection / Listener / Stream
 * objects, pumping the QUIC engine in the process. This is the native,
 * preferred alternative to driving stream_select() over getFd().
 *
 * Each item is [$object, $eventsMask] where $eventsMask is a bitwise-OR of
 * the POLL_* constants. Returns a map of the caller's $items key => revents
 * mask for every item that has at least one event pending (so the key of a
 * non-list $items array is preserved); items with no event are omitted.
 *
 * $timeout is in seconds: 0.0 polls without blocking, null blocks until an
 * event. An empty returned array means the timeout elapsed with nothing
 * ready (a null timeout therefore does not return empty for a non-empty
 * item set). A per-object error or close is not an exception: it is the
 * POLL_ERROR bit in that item's revents. Throws Quic\Exception if the poll
 * call itself fails (an SSL error, or an item that is not [object, events]
 * naming a live Connection / Listener / Stream).
 *
 * @param array $items
 * @return array<int, int>
 */
function poll(array $items, ?float $timeout = null): array {}

/**
 * Thrown on any QUIC transport, handshake, or stream error.
 */
class Exception extends \Exception
{
}

/**
 * A single QUIC connection. Construct one with `new Quic\Connection(...)` to
 * open a client connection; server-accepted connections come from
 * Listener::accept(). Multiplexes many Streams.
 *
 * @not-serializable
 * @strict-properties
 */
final class Connection
{
    /**
     * Open a QUIC client connection to $host:$port and complete the
     * handshake.
     *
     * $options use the ssl stream-context vocabulary:
     *   - alpn / alpn_protocols: string|array  (required) ALPN protocol(s)
     *   - peer_name:        string   SNI / cert verify name (default: $host)
     *   - verify_peer:      bool     verify the server certificate (default true)
     *   - verify_peer_name: bool     verify the peer name (default verify_peer)
     *   - allow_self_signed:bool     accept self-signed certificates
     *   - cafile / capath:  string   CA bundle file / directory
     *   - verify_depth:     int      maximum certificate chain depth
     *   - local_cert / local_pk / passphrase: string  client certificate (mTLS)
     *   - peer_fingerprint: string|array  certificate pinning
     *   - SNI_enabled:      bool     send SNI (default true)
     *   - security_level:   int      OpenSSL security level
     *   - ciphersuites / groups / sigalgs: string  TLS 1.3 tuning
     *   - idle_timeout_ms:  int      requested max idle timeout
     *   - connect_timeout_ms: int    abort the handshake if it does not
     *                                complete within this many milliseconds
     *                                (0 / unset = block on the QUIC defaults)
     *
     * @param array<string, mixed> $options
     */
    public function __construct(string $host, int $port, array $options = []) {}

    /**
     * Open a new locally-initiated stream on this connection. Equivalent to
     * new Quic\Stream($this, $bidirectional).
     */
    public function openStream(bool $bidirectional = true): Stream {}

    /**
     * Accept the next remotely-initiated stream, or null if none is
     * pending (non-blocking mode) or the connection is closing.
     */
    public function acceptStream(): ?Stream {}

    /**
     * Close the connection, sending CONNECTION_CLOSE with the given
     * application error code and optional reason.
     */
    public function close(int $errorCode = 0, string $reason = ""): void {}

    /**
     * If the connection has closed, the details of the CONNECTION_CLOSE,
     * otherwise null (still open). The array has keys: error_code (int),
     * frame_type (int), reason (string), local (bool, true if we initiated
     * the close), and transport (bool, true for a transport-level error,
     * false for an application error code).
     *
     * @return array{error_code: int, frame_type: int, reason: string, local: bool, transport: bool}|null
     */
    public function getCloseInfo(): ?array {}

    /**
     * The underlying UDP socket file descriptor (for stream_select()).
     */
    public function getFd(): int {}

    /**
     * Toggle blocking mode. In non-blocking mode, read/write/accept return
     * immediately and the caller drives events via the helpers below.
     */
    public function setBlocking(bool $blocking): void {}

    /**
     * Whether OpenSSL currently wants the UDP socket to be readable.
     */
    public function wantsRead(): bool {}

    /**
     * Whether OpenSSL currently wants the UDP socket to be writable.
     */
    public function wantsWrite(): bool {}

    /**
     * Seconds until the next QUIC timer expires (null = infinite). Use as
     * the timeout for stream_select().
     */
    public function getTimeout(): ?float {}

    /**
     * Pump the QUIC event loop once (process timeouts + network I/O).
     */
    public function handleEvents(): void {}

    /**
     * Negotiated TLS session info, mirroring the keys of
     * stream_get_meta_data()['crypto']: protocol, cipher_name, cipher_bits,
     * cipher_version, and (when negotiated) alpn_protocol.
     *
     * @return array<string, mixed>
     */
    public function getCryptoInfo(): array {}

    /**
     * The ALPN protocol negotiated for this connection, or null.
     */
    public function getNegotiatedAlpn(): ?string {}

    /**
     * The peer's leaf certificate as a PEM string, or null if the peer
     * presented none. Bridge to ext-openssl with openssl_x509_read().
     */
    public function getPeerCertificate(): ?string {}

    /**
     * The peer's certificate chain as an array of PEM strings.
     *
     * @return list<string>
     */
    public function getPeerCertificateChain(): array {}

    /**
     * The certificate verification result (an X509_V_* code; 0 == OK).
     */
    public function getVerifyResult(): int {}

    /**
     * A human-readable description of the verification result.
     */
    public function getVerifyResultString(): string {}
}

/**
 * A server-side QUIC listener bound to a UDP socket. Accepts inbound
 * connections. Construct one with `new Quic\Listener(...)`.
 *
 * @not-serializable
 * @strict-properties
 */
final class Listener
{
    /**
     * Bind a QUIC server to $host:$port and begin listening.
     *
     * $options use the ssl stream-context vocabulary:
     *   - local_cert:  string        (required) PEM certificate chain path
     *   - local_pk:    string        PEM private key path
     *   - passphrase:  string        private key passphrase
     *   - alpn / alpn_protocols: string|array  (required) acceptable ALPN protocol(s)
     *   - verify_peer: bool          request + verify a client certificate
     *   - cafile / capath: string    CA bundle for client-certificate verification
     *   - reuse_port:  bool          set SO_REUSEPORT so multiple processes can
     *                                share this host:port (scale across cores)
     *   - security_level / ciphersuites / groups / sigalgs: TLS tuning
     *
     * @param array<string, mixed> $options
     */
    public function __construct(string $host, int $port, array $options) {}

    /**
     * Accept the next inbound connection, or null if none is pending
     * (non-blocking mode).
     */
    public function accept(): ?Connection {}

    /**
     * Stop listening and release the bound socket. Safe to call with
     * connections still open (they share the listener's QUIC engine, which
     * OpenSSL keeps alive until the last one is freed), but since the bound
     * UDP socket is released here, drain in-flight connections first if you
     * need their remaining data delivered.
     */
    public function close(): void {}

    public function getFd(): int {}
    public function setBlocking(bool $blocking): void {}
    public function wantsRead(): bool {}
    public function wantsWrite(): bool {}
    public function getTimeout(): ?float {}
    public function handleEvents(): void {}
}

/**
 * A single QUIC stream (bidirectional or unidirectional) within a
 * Connection. Construct a local stream with `new Quic\Stream($conn)` (or the
 * `$conn->openStream()` shorthand); peer-initiated streams come from
 * Connection::acceptStream().
 *
 * @not-serializable
 * @strict-properties
 */
final class Stream
{
    /**
     * Open a new locally-initiated stream on $connection. Streams that are
     * peer-initiated are obtained from Connection::acceptStream() instead.
     */
    public function __construct(Connection $connection, bool $bidirectional = true) {}

    /**
     * Write $data to the stream. If $fin is true, the send side is
     * concluded (FIN) after the data. Returns the number of bytes written.
     */
    public function write(string $data, bool $fin = false): int {}

    /**
     * Read up to $length bytes. Returns the data, "" if no data is
     * currently available (non-blocking), or null at end-of-stream: either
     * a clean peer FIN, or the stream being reset/the connection closing
     * (a reset does not throw, so one peer cannot abort a read loop).
     */
    public function read(int $length): ?string {}

    /**
     * Conclude the send side of the stream (send FIN).
     */
    public function end(): void {}

    /**
     * Abortively reset the stream with the given application error code.
     */
    public function reset(int $errorCode = 0): void {}

    /**
     * If this stream was reset (by the peer, or locally), the application
     * error code carried by the RESET_STREAM / STOP_SENDING, otherwise null.
     * Use this after read() returns null to tell a clean FIN (null here) from
     * a reset (an int code here). The read side is reported in preference to
     * the write side.
     */
    public function getResetCode(): ?int {}

    /**
     * The QUIC stream id.
     */
    public function getId(): int {}

    /**
     * Whether this stream is bidirectional.
     */
    public function isBidirectional(): bool {}

    /**
     * The owning Connection.
     */
    public function getConnection(): Connection {}

    /**
     * Expose this QUIC stream as a PHP stream resource, so it can be used
     * with fread()/fwrite()/stream_get_contents()/stream_select(). The
     * returned stream keeps this Stream (and its Connection) alive.
     *
     * @return resource
     */
    public function asStream() {}
}
