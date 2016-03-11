# SSL verification for Erlang [![Build Status](https://travis-ci.org/deadtrickster/ssl_verify_fun.erl.svg?branch=master)](https://travis-ci.org/deadtrickster/ssl_verify_fun.erl)

## Certificate fingerprint validation

```erlang
1> ssl:connect("github.com", 443, [{verify_fun,
				 {fun ssl_verify_fingerprint:verify_fun/3,
				  [{check_fingerprint, {sha, "D79F076110B39293E349AC89845B0380C19E2F8B"} }]}},
				{verify, verify_none}]).   
{ok,{sslsocket,{gen_tcp,#Port<0.1499>,tls_connection,
                        undefined},
               <0.53.0>}}
               
2> ssl:connect("google.com", 443, [{verify_fun,
				 {fun ssl_verify_fingerprint:verify_fun/3,
				  [{check_fingerprint, {sha, "D79F076110B39293E349AC89845B0380C19E2F8B"} }]}},
				{verify, verify_none}]).
=ERROR REPORT==== 10-Mar-2016::16:13:54 ===
SSL: certify: ssl_handshake.erl:1492:Fatal error: handshake failure
{error,{tls_alert,"handshake failure"}}

```

## Hostname validation

Excerpt from RFC (http://tools.ietf.org/html/rfc6125)


```

6.4.3.  Checking of Wildcard Certificates

   1.  The client SHOULD NOT attempt to match a presented identifier in
   which the wildcard character comprises a label other than the
   left-most label (e.g., do not match bar.*.example.net).

   2.  If the wildcard character is the only character of the left-most
   label in the presented identifier, the client SHOULD NOT compare
   against anything but the left-most label of the reference
   identifier (e.g., *.example.com would match foo.example.com but
   not bar.foo.example.com or example.com).

   3.  The client MAY match a presented identifier in which the wildcard
   character is not the only character of the label (e.g.,
   baz*.example.net and *baz.example.net and b*z.example.net would
   be taken to match baz1.example.net and foobaz.example.net and
   buzz.example.net, respectively).  However, the client SHOULD NOT
   attempt to match a presented identifier where the wildcard
   character is embedded within an A-label or U-label [IDNA-DEFS] of
   an internationalized domain name [IDNA-PROTO].

6.4.4.  Checking of Common Names

   As noted, a client MUST NOT seek a match for a reference identifier
   of CN-ID if the presented identifiers include a DNS-ID, SRV-ID,
   URI-ID, or any application-specific identifier types supported by the
   client.

   Therefore, if and only if the presented identifiers do not include a
   DNS-ID, SRV-ID, URI-ID, or any application-specific identifier types
   supported by the client, then the client MAY as a last resort check
   for a string whose form matches that of a fully qualified DNS domain
   name in a Common Name field of the subject field (i.e., a CN-ID).  If
   the client chooses to compare a reference identifier of type CN-ID
   against that string, it MUST follow the comparison rules for the DNS
   domain name portion of an identifier of type DNS-ID, SRV-ID, or
   URI-ID, as described under Section 6.4.1, Section 6.4.2, and
   Section 6.4.3.
   
```

###Usage###

* With SSL lib or HTTP client you can use provided verify_fun/3, do not forget to add `check_hostname` key to user state:

``` erlang

CACertFile = "..../my-ca.pem".
ssl:connect("tv.eurosport.com", 443, [{verify_fun, {fun ssl_verify_hostname:verify_fun/3, [{check_hostname, "tv.eurosport.com"}]}}, {cacertfile, CACertFile }, {server_name_indication, "tv.eurosport.com"}, {verify, verify_peer}, {depth, 99}]).

=ERROR REPORT==== 9-Oct-2014::03:34:41 ===
SSL: certify: ..../ssl_handshake.erl:1403:Fatal error: handshake failure
{error,{tls_alert,"handshake failure"}}

ssl:connect("tv.eurosport.com", 443, [{verify_fun, {fun ssl_verify_hostname:verify_fun/3, []}}, {cacertfile, CACertFile }, {server_name_indication, "tv.eurosport.com"}, {verify, verify_peer}, {depth, 99}]).

{ok,{sslsocket,{gen_tcp,#Port<0.1565>,tls_connection,
                        undefined},
                        <0.53.0>}}
                        
```

Unfortunately as you can see OTP SSL error reporting not so informative (in fact it ignores everything user-provided verify_fun returns as failure reason (8 October 2014))

``` erlang 
path_validation_alert(Reason) ->
    ?ALERT_REC(?FATAL, ?HANDSHAKE_FAILURE).
```

* With custom verify_fun:
Call `verify_cert_hostname/2` with Certificate and Hostname.
