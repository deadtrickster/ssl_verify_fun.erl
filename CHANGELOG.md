# Changelog

## 1.1.8

### Security

- Partial-label wildcards (`a*.example.com`, `*o.example.com`, `b*z.example.com`) no longer
  match across label boundaries, e.g. `a*.example.com` no longer matches `a.evil.example.com`
  (RFC 6125 Section 6.4.3).
- Wildcard identifiers no longer match IP address literals, e.g. `*.168.1.1` no longer
  matches `192.168.1.1` (RFC 6125 Section 1.7.2, RFC 9110 Section 4.3.4).

### Maintenance

- CI moved to `erlef/setup-beam` and tests OTP 25-28.
- Removed the vendored `rebar3` and `elvis` escripts, which no longer run on supported
  OTP releases, and the obsolete Travis CI config. `make` now uses `rebar3` from `PATH`.
