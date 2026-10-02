# luce-tls

Native Luce Base TLS 1.3 client (and a small private-endpoint server).
MIT OR Apache-2.0.

**Experimental, not security-reviewed.** Do not rely on it where a reviewed
TLS stack is required.

## Using it

`tls_stream.Stream` owns one TCP connection that is either plain or TLS and
implements `io.Reader` and `io.Writer`, so IMAP or SMTP code needs no
transport glue. It upgrades in place for STARTTLS.

```luce
import io
import net
import tls_stream

# Implicit TLS (IMAPS 993, SMTPS 465), validated against the public roots.
var stream = try tls_stream.Stream.connect("imap.example.com", 993, true)
try io.write_all(&stream, b"a1 CAPABILITY\r\n")
var buffer: u8[4096]
let count = try stream.read(buffer)     # zero: end of stream (close_notify)
try stream.close()                      # close_notify, then close the socket

# STARTTLS (IMAP 143, SMTP submission 587).
var mail = try tls_stream.Stream.connect("smtp.example.com", 587, false)
# ... greeting, EHLO, STARTTLS and its 220 reply, all through `mail` ...
try mail.start_tls("smtp.example.com")
```

| Call | Meaning |
| --- | --- |
| `Stream.connect(host, port, tls, deadline = net.Deadline(), cancellation = none, policy = Trust(), alpn = "") -> Stream!` | resolve with `net.resolve_all`, try each address in order, handshake when `tls` |
| `Stream.plain(connection) -> Stream` | adopt a connected socket as a plain stream |
| `stream.start_tls(host, policy = Trust(), alpn = "") -> !` | STARTTLS on the same socket; discard plaintext buffered after the server's reply first |
| `stream.is_secure() -> bool` | whether TLS protects the stream |
| `stream.set_deadline(deadline, cancellation = none)` | absolute deadline and cancellation for the following reads, writes and close |
| `stream.read(buffer) -> usize!`, `stream.write(data) -> usize!` | Reader/Writer under the stream's deadline; `write` sends everything |
| `stream.read_within(buffer, deadline, cancellation = none) -> usize!` | one read with its own deadline and cancellation |
| `stream.write_within(data, deadline, cancellation = none) -> !` | send everything with its own deadline and cancellation |
| `stream.pending() -> usize` | decrypted bytes `read` returns without touching the socket |
| `stream.wait(interest = read, deadline, cancellation) -> net.Readiness!` | readable at once when bytes are pending, otherwise a socket wait |
| `stream.descriptor()`, `stream.peer_address()` | for a `net.Poller`; check `pending()` first, never read the descriptor |
| `stream.closed_by_peer() -> bool` | the server sent close_notify |
| `stream.close() -> !`, `stream.destroy()` | close (close_notify when secure); destroy skips close_notify |

Trust policies: `Trust.public_roots()` (the default `Trust()`),
`Trust.pinned_issuer(x, y)` for a private or test server whose P-256 leaf is
signed by (or self-signed with) that key, and `Trust.p384_root(x, y)` for a
strict chain under an explicit P-384 root.

The socket is kept nonblocking and every transfer waits through readiness like
`net.DeadlineStream`. A read that times out (`net.timed_out`) or is cancelled
(`net.cancelled`, e.g. by another thread ending an IMAP IDLE) leaves the stream
usable: a partial TLS record is kept and the next read continues it.

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
debug/release: loopback client/server handshakes, Stream reads and writes
across records, pending plaintext, deadline timeouts that resume, cancellation
from another thread, a plain exchange then an in-place STARTTLS upgrade that
answers a CertificateRequest, close_notify, a wrong pin, the captured Lucia OS Caddy/Let's Encrypt
chain, and negative chain, trust, hostname, time, extension, ordering and
tamper cases. Sanitizer checks cover generated C and the runtime. CI is
deterministic and uses no network. `python3 tools/live_smoke.py` (not in CI)
handshakes with real mail servers and runs IMAP CAPABILITY/LOGOUT or SMTP
EHLO/QUIT over implicit TLS and STARTTLS. These checks do not establish complete
RFC 5280 policy processing, revocation coverage, leak freedom or side-channel
safety.
