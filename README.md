# luce-tls

Native Luce Base TLS helpers for the future HTTPS client. MIT OR Apache-2.0.
First slice: TLS 1.3 HKDF-Expand-Label, record-header parsing and DNS-ID
hostname matching. Not a handshake, certificate path builder or production
HTTPS stack.

```sh
python3 tools/bootstrap.py
python3 tests/run.py
python3 tests/sanitize.py
```
