# luce-tls

Native Luce Base TLS 1.3. MIT OR Apache-2.0.

Client and server handshakes for one profile: `TLS_CHACHA20_POLY1305_SHA256`,
X25519, ECDSA-P256. Trust is a pinned issuer public key, not a system CA store.
`session.connect` / `session.accept` plus `x509.mint_self_signed` for private
servers. No resumption, client certificates, or other cipher suites.

Experimental, not security-reviewed.

```sh
python3 tools/bootstrap.py
python3 tests/run.py
python3 tests/sanitize.py
```

Bootstrap verifies the sibling compiler/crypto revisions in `bootstrap/` and
builds tools inside this package. Both test runners accept `--base PATH` for an
existing compiler. Caches default to `build/cache` (`LUCE_CACHE` may override).
The matrix exercises native optimization levels 0–3 and C debug/release, including
a real loopback client/server exchange; sanitizer checks cover generated C and
the runtime. These checks do not establish external TLS interoperability,
certificate-policy completeness, leak freedom or side-channel safety.
