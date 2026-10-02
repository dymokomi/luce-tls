# luce-tls

Native Luce Base TLS 1.3 client (and a small private-endpoint server).
MIT OR Apache-2.0.

**Experimental, not security-reviewed.** Do not rely on it where a reviewed
TLS stack is required.

## Using it

`tls_stream.TlsStream` owns a TCP connection and its TLS session and
implements `io.Reader` and `io.Writer`, so protocol code can hold a plain
`net.Connection` or a `TlsStream` behind the same interface.

```luce
import io
import net
import tls_stream

# Implicit TLS (IMAPS 993, SMTPS 465): validate against the public roots.
var stream = try tls_stream.TlsStream.connect_trusted("imap.example.com", 993)
try io.write_all(&stream, b"a1 CAPABILITY\r\n")
var buffer: u8[4096]
let count = try stream.read(buffer)       # zero: the server sent close_notify
try stream.close()                        # sends close_notify, closes the socket

# STARTTLS (IMAP 143, SMTP submission 587): upgrade a connection already
# used for plaintext. It takes ownership and closes it on failure.
var plain = try net.Connection.connect(address)
# ... plaintext greeting, STARTTLS command and reply ...
var secure = try tls_stream.TlsStream.upgrade(plain, "smtp.example.com")
```

- `TlsStream.connect(host, port, policy = Trust(), alpn = "", deadline, cancellation)`
  resolves, connects and handshakes; `connect_trusted(host, port, deadline, cancellation)`
  is `connect` with the public roots; `upgrade(connection, host, policy, alpn, deadline, cancellation)`
  is STARTTLS.
- `Trust.public_roots()` (the default), `Trust.pinned_issuer(x, y)` for a
  private server whose P-256 leaf is signed by (or self-signed with) that key,
  and `Trust.p384_root(x, y)` for a strict chain under an explicit P-384 root.
- Deadlines: the connection is kept nonblocking and every transfer waits
  through the stream's `net.Deadline` (none by default). `set_deadline(d,
  cancellation)` changes it. A read that times out fails with `net.timed_out`
  and leaves the stream usable: the partial record is kept and the next read
  continues it.
- Readiness: `pending()` counts decrypted bytes that `read` returns without
  touching the socket and that a socket poll cannot see. `wait(interest,
  deadline, cancellation)` answers readable at once when bytes are pending and
  otherwise waits on the socket. `descriptor()` is for a `net.Poller`; check
  `pending()` first and never read the descriptor directly.
- `close()` sends close_notify and closes; `destroy()` closes without it.
  `closed_by_peer()` reports a received close_notify.

The older `session` API (`connect`, `connect_public`, `connect_p384_chain`,
`connect_trusted`, `upgrade_client`, `accept`, `send`, `receive`, `pending`
with a caller-owned `net.Connection` and `Secrets`) remains for blocking use.

## Protocol coverage

- TLS 1.3 only (RFC 8446). SNI is sent for DNS names. HelloRetryRequest
  handling (cookie and group change) is implemented; it becomes reachable once
  a second key-exchange group is offered. Post-handshake NewSessionTicket is
  ignored and KeyUpdate is honoured. Records are fragmented at 2^14 bytes.
- Cipher suite: TLS_CHACHA20_POLY1305_SHA256. Key exchange: X25519.
- Server signatures: ECDSA P-256/SHA-256.
- Certificate validation: a pinned P-256 issuer, or the strict public profile
  (P-256 leaf, ECDSA P-384 issuers, explicit P-384 anchor; until the bundled
  root store lands `Trust.public_roots()` uses ISRG Root X2). Validity,
  basicConstraints and pathLen, keyUsage, EKU serverAuth, DNS SAN with
  single-label wildcards, and rejection of unknown critical extensions.

Not supported: TLS 1.2 (the next step after the TLS 1.3 work), resumption,
0-RTT, client certificates, OCSP/CRL revocation, and IP-address SANs.

## Tests

```sh
python3 tools/bootstrap.py
python3 tests/run.py
python3 tests/sanitize.py
```

Bootstrap verifies the sibling compiler/crypto revisions in `bootstrap/` and
builds tools inside this package. Both test runners accept `--base PATH` for
an existing compiler. Caches default to `build/cache` (`LUCE_CACHE` may
override). The matrix exercises native optimization levels 0–3 and C
debug/release: loopback client/server handshakes, TlsStream reads and writes
across records, pending plaintext, deadline timeouts that resume, a STARTTLS
upgrade, close_notify, a wrong pin, the captured Lucia OS Caddy/Let's Encrypt
chain, and negative chain, trust, hostname, time, extension, ordering and
tamper cases. Sanitizer checks cover generated C and the runtime. CI is
deterministic and uses no network. These checks do not establish complete
RFC 5280 policy processing, revocation coverage, leak freedom or side-channel
safety.
