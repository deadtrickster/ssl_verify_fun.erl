# Changelog

## 1.1.9

### Security

- A `dNSName` that is not valid ASCII is never handed to the matcher undecoded. Such an
  identifier does not match (RFC 5280 Section 4.2.1.6, IA5String) and no longer raises
  `function_clause` in `ssl_verify_string:strip_right/2` (#7).

### Maintenance

- Unit tests for `ssl_verify_fun_encodings`, including a regression test for undecodable
  `dNSName` entries (#10).
- An undecodable `utf8String` is reported as `{error, invalid}` instead of
  `{ok, {error, invalid}}`.
- Docs build and publish from `mix.exs` now, so hexdocs.pm/ssl_verify_fun/ resolves.
  The README is the main page; module pages return once `src` carries edoc annotations.

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
