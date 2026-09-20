# luce-tls

Native Luce Base TLS 1.3. MIT OR Apache-2.0.

Client and server handshakes for one profile: `TLS_CHACHA20_POLY1305_SHA256`,
X25519, and ECDSA-P256 CertificateVerify. `session.connect` / `session.accept`
plus `x509.mint_self_signed` retain direct P-256 issuer pinning for private
servers.

`session.connect_public` validates the bounded public HTTPS path used by the
Lucia OS Caddy edge. It pins the official ISRG Root X2 P-384 public key and
validates the complete TLS certificate list below that anchor: strict DER and
algorithm agreement, ECDSA P-384/SHA-384 signatures, issuer/subject chaining,
validity against the wall clock, CA basic constraints and path length, key
usage, TLS server EKU, DNS SAN matching, duplicate rejection, and rejection of
unknown critical extensions. A caller with another explicit P-384 root can use
`session.connect_p384_chain`.

This is deliberately not a general system CA store or path builder. The public
profile supports P-256 leaves and P-384 issuers, does not fetch missing
intermediates, and does not yet perform OCSP/CRL revocation checks. There is no
resumption, client certificate support, or alternate cipher suite.

Experimental, not security-reviewed.

```sh
python3 tools/bootstrap.py
python3 tests/run.py
python3 tests/sanitize.py
```

Bootstrap verifies the sibling compiler/crypto revisions in `bootstrap/` and
builds tools inside this package. Both test runners accept `--base PATH` for an
existing compiler. Caches default to `build/cache` (`LUCE_CACHE` may override).
The matrix exercises native optimization levels 0–3 and C debug/release,
including a real loopback client/server exchange, the captured Lucia OS
Caddy/Let's Encrypt chain both with and without its anchor certificate, and
negative chain, trust, hostname, time, extension, ordering and tamper cases.
Sanitizer checks cover generated C and the runtime. The public path has also
been exercised against the independent live Caddy endpoint, but CI remains
deterministic and does not depend on that network service. These checks do not
establish complete RFC 5280 policy processing, revocation coverage, leak freedom
or side-channel safety.
