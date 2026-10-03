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
import luce_std.net
import luce_tls.stream as tls_stream

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

Trust policies: `Trust.public_roots()` (the default `Trust()`: the bundled
Mozilla roots),
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
  (cookie and group change) is handled. Post-handshake NewSessionTicket is
  ignored and KeyUpdate is honoured (and answered on the next write). Records are fragmented at 2^14 bytes. A
  CertificateRequest is answered with an empty Certificate.
- Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and
  TLS_CHACHA20_POLY1305_SHA256. Key exchange: X25519, and secp256r1 after a
  HelloRetryRequest.
- CertificateVerify: ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384 and
  rsa_pss_rsae_sha256/384/512. Certificate signatures: ECDSA P-256/P-384 with
  SHA-224/256/384/512, RSA PKCS#1 v1.5 with SHA-224/256/384/512 and RSA-PSS
  with SHA-256/384/512 (RSA keys 2048–8192 bits). SHA-1 and MD5 are refused.
- Certificate validation (`chain`): the leaf must match the host by a
  subjectAltName dNSName (single leftmost wildcard label; no common-name
  fallback), be within its validity period, not be a CA, and allow
  digitalSignature and TLS server authentication when it states usages. A path
  is built from the leaf to a trust anchor through the presented certificates
  in any order (extra, duplicate or unparsable ones are ignored); each issuer
  must be a CA within its validity, allow keyCertSign and server
  authentication when stated, and respect pathLenConstraint. Unknown critical
  extensions and name constraints are rejected. Certificate policies are not
  processed: a critical certificatePolicies extension is accepted only when
  its qualifiers are CPS pointers (as BearSSL does), and other critical policy
  extensions are refused.
- Trust anchors: `roots.lucb`, generated by `tools/mozilla_roots.py` from
  Mozilla NSS `certdata.txt`: 119 roots trusted for TLS server authentication
  with RSA, P-256 or P-384 keys (roots with a server distrust-after date are
  left out). Regenerate it to update the set. `Anchors.single` trusts one
  key; `Anchors.named_list` holds up to eight Name-and-key anchors (RFC 5280
  §6.1.1). An anchor is only a Name and key: its certificate's own CA flag,
  validity and EKU are not checked, and a leaf cannot be its own anchor.

Verified live with `tools/live_smoke.py` on 2026-10-02: IMAPS, SMTPS and
SMTP/IMAP STARTTLS against imap.gmail.com, smtp.gmail.com (465 and 587),
imap.mail.me.com, smtp.mail.me.com, outlook.office365.com (993 and 143),
smtp.office365.com, imap.fastmail.com and smtp.fastmail.com.

Not supported: TLS 1.2 (the next step: some older mail hosts only speak it),
resumption, 0-RTT, client certificates, OCSP/CRL revocation, fetching missing
intermediates (AIA), name constraints, IP-address SANs and the system trust
store.

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
tamper cases. `tests/chains/` holds chains captured from Gmail, iCloud,
Outlook and Fastmail mail servers (`tools/capture_chains.py`), validated against
the bundled roots at their capture time, with wrong-host, expired, not-yet-
valid, untrusted-root, broken-signature, missing-intermediate and reordered
variants. Sanitizer checks cover generated C and the runtime. CI is
deterministic and uses no network. `python3 tools/live_smoke.py` (not in CI)
handshakes with real mail servers and runs IMAP CAPABILITY/LOGOUT or SMTP
EHLO/QUIT over implicit TLS and STARTTLS. These checks do not establish complete
RFC 5280 policy processing, revocation coverage, leak freedom or side-channel
safety.

## Reference suites

Converted reference tests run in every mode (MIT or Apache-2.0 sources; data
only, see NOTICE.md; converters in `tools/` regenerate everything):

| Suite | Source | Result |
|---|---|---|
| RFC 8448 §3 1-RTT trace | `tools/rfc8448_vectors.py` | 23 HKDF steps, 48 items and all 9 records byte for byte (both directions decrypt) |
| OpenSSL TLS13-KDF | `evpkdf_tls13_kdf.txt`, `tools/openssl_tls13_kdf.py` | 154 extract + 408 expand pass |
| BearSSL X.509 | `test/x509/alltests.txt`, `tools/bearssl_x509.py` | 26 accepted, 21 rejected, all as expected |
| OpenSSL verify | `test/recipes/25-test_verify.t`, `tools/openssl_verify.py` | 21 accepted, 76 rejected, all as expected |

Every case is either run, given this client's own verdict with a reason, or
listed as out of scope:

- RFC 8448: the client writes legacy_record_version 0x0303 on every record;
  the trace's initial ClientHello uses 0x0301, which RFC 8446 §5.1 also
  allows, so that byte is the one difference compared. The trace's server
  certificate has a 1024-bit RSA key, which is refused (checked); its
  CertificateVerify signature is therefore not verified here.
- TLS13-KDF out of scope (9): mode EXTRACT_AND_EXPAND (OpenSSL itself refuses
  it) and 8 FIPS-provider-only checks (SHAKE-256/SHA-512/256 digests, short
  keys, approval indicators).
- BearSSL, different verdict (`tests/x509/bearssl/POLICY.txt`): goodName3
  (no common-name fallback), hashSHA1 and secp256r1-sha1 (SHA-1 refused),
  rsa1017 (RSA below 2048 bits). Not expressible (5): directTrust,
  ignoredSignature1/2 (end-entity anchors), hashSHA256Unsupported
  (configurable hash set), secp521r1 (P-521).
- OpenSSL verify, different verdict (`tests/x509/openssl/POLICY.txt`, 37):
  anchors are Name and key, so a trusted certificate's CA flag and EKU are not
  checked (5 accept); a leaf cannot be its own anchor (2 reject); RSA below
  2048 bits, MD5, SHA-1 and SHA-3 signatures, Ed25519, RSASSA-PSS-only keys,
  name constraints, a critical OCSP no-check extension and pathLen without cA
  are refused; the 2048-bit floor applies at every OpenSSL auth level (1
  accept). Out of scope (93, `SKIPPED.txt`): OpenSSL auxiliary trust settings
  on certificates (53), client, code-signing and timestamp purposes (31), and
  the -check_ss_sig, -policy_check, -verify_depth and -x509_strict options (9).
