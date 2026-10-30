%%% -*- erlang -*-
%%%
%%% MIT License
%%%
%%% Copyright (c) 2014-2016 Ilya Khaprov <ilya.khaprov@publitechs.com>

-module(ssl_verify_hostname_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

verify_hostname_success_test_ () ->
  %% presented identifier, reference identifier, validation and parsing result
  Tests = [
           {"www.example.com", "WWW.eXamPle.CoM", false}, %% case insensitive match
           {"www.example.com.", "www.example.com", false}, %% ignore trailing dots (prevenet *.com. matches)
           {"www.example.com", "www.example.com.", false},
           {"*.example.com", "www.example.com", {[], ".example.com", true}},         %% always matching wildcards
           {"b*z.example.com", "buzz.example.com", {"b", "z.example.com", false}},
           {"*baz.example.com", "foobaz.example.com", {[], "baz.example.com", false}},
           {"baz*.example.com", "baz1.example.com", {"baz", ".example.com", false}},
           {"192.168.1.1", "192.168.1.1", false} %% exact IP literal match still works
          ],
  [{lists:append(join(" : ", [I, R])),
    fun() ->
            ?assertMatch(V, ssl_verify_hostname:parse_and_validate_wildcard_identifier(I, R)),
            ?assert(ssl_verify_hostname:try_match_hostname(I, R))
    end} || {I, R, V} <- Tests].


verify_hostname_fail_test_ () ->
  %% presented identifier, reference identifier
  Tests = [
           {"*.com", "eXamPle.CoM"},
           {".com.", "example.com."},
           {"*.www.example.com", "www.example.com."},
           {"foo.*.example.com", "foo.bar.example.com."},
           {"xn--*.example.com", "xn-foobar.example.com"},
           {"*fooxn--bar.example.com", "bazfooxn--bar.example.com"},
           {"*.akamaized.net", "tv.eurosport.com"},
           {"a*c.example.com", "abcd.example.com"},
           {"*baz.example.com", "foobuzz.example.com"},
           %% partial-label wildcard must not match across label boundaries (RFC 6125 6.4.3)
           {"a*.example.com", "a.evil.example.com"},
           {"a*.example.com", "a.b.c.example.com"},
           {"*o.example.com", "bar.foo.example.com"},
           {"b*z.example.com", "b.z.example.com"},
           {"b*z.example.com", "bu.zz.example.com"},
           %% wildcards must not match IP address literals
           {"*.168.1.1", "192.168.1.1"},
           {"1*.168.1.1", "192.168.1.1"},
           {"*2.168.1.1", "192.168.1.1"},
           {"*.0.0.1", "127.0.0.1"},
           {"*.168.1.1", "::ffff:192.168.1.1"}
          ],
  [{lists:append(join(" : ", [I, R])),
    fun() -> ?assertNot(ssl_verify_hostname:try_match_hostname(I, R)) end} || {I, R} <- Tests].

undecodable_dns_name_never_matches_test() ->
  %% <<128>> is not valid UTF-8, so decoding it yields an error tuple that used
  %% to reach the matcher and raise function_clause in ssl_verify_string.
  Undecodable = ssl_verify_fun_encodings:decode_dns_name(<<128>>),
  ?assertNot(ssl_verify_hostname:try_match_hostname(Undecodable, "www.example.com")),
  ?assertEqual({error, invalid}, Undecodable),
  %% a well formed but non-ASCII dNSName is not IA5 either (RFC 5280 4.2.1.6)
  NonAscii = ssl_verify_fun_encodings:decode_dns_name(<<16#C3, 16#A9, "xample.com">>),
  ?assertNot(ssl_verify_hostname:try_match_hostname(NonAscii, "www.example.com")),
  ?assertEqual({error, invalid}, NonAscii).

%% A malformed dNSName stays in the altname list, so the certificate cannot
%% fall back to a subject CN that does match (RFC 6125 Section 6.4.4).
verify_cert_malformed_dns_name_no_cn_fallback_test() ->
  Cert = cert_with(cn("www.example.com"), [{dNSName, <<128>>}]),
  ?assertEqual({fail, unable_to_match_altnames},
               ssl_verify_hostname:verify_cert_hostname(Cert, "www.example.com")).

%% A valid dNSName still matches when the SAN also holds an undecodable one,
%% and it is the altname that matches, not the CN.
verify_cert_mixed_dns_names_test() ->
  Cert = cert_with(cn("www.example.com"),
                   [{dNSName, <<128>>}, {dNSName, <<"other.example.com">>}]),
  ?assertEqual({valid, "other.example.com"},
               ssl_verify_hostname:verify_cert_hostname(Cert, "other.example.com")).

%% A non-ASCII dNSName given as a list is rejected the same way, and still
%% blocks CN fallback.
verify_cert_non_ascii_list_dns_name_test() ->
  Cert = cert_with(cn("www.example.com"),
                   [{dNSName, <<"other.example.com">>}, {dNSName, [16#E9]}]),
  ?assertEqual({fail, unable_to_match_altnames},
               ssl_verify_hostname:verify_cert_hostname(Cert, "www.example.com")).

%% Only the fields the hostname check reads; nothing here is signed.
cert_with(RdnSequence, AltNames) ->
  #'OTPCertificate'{
     tbsCertificate = #'OTPTBSCertificate'{
                         subject = {rdnSequence, RdnSequence},
                         extensions = [#'Extension'{extnID = ?'id-ce-subjectAltName',
                                                    extnValue = AltNames}]}}.

cn(Name) ->
  [[#'AttributeTypeAndValue'{type = ?'id-at-commonName', value = {utf8String, Name}}]].

%% Certs generated via:
%% actual cert content dumped via:
%% ssl:connect("google.co.uk", 443, [{verify_fun, {fun(C, E, State) -> io:format(user, "C: ~p~n", [C]), {valid, state} end, state}}])
%% then we write them to der via:
%% C = {..}.
%% B = public_key:pkix_encode('OTPCertificate', C, 'otp').
%% file:write_file("google_teletex.der", B).


google_cert() ->
  load_cert("google.der").

load_cert(Cert) ->
  {ok, Bin} = file:read_file("test/certs/" ++ Cert),
  public_key:pkix_decode_cert(Bin, otp).

google_cert_dns_wildcard() ->
  load_cert("google_wildcard.der").


google_cert_without_dns() ->
  load_cert("google_nodns.der").


google_cert_printable_string() ->
  load_cert("google_printable.der").


google_cert_teletex_string() ->
  load_cert("google_teletex.der").

google_cert_bmp_string() ->
  load_cert("google_bmp.der").

google_cert_universal_string() ->
  load_cert("google_universal.der").

verify_google_cert_test () ->
  ?assertEqual({valid, "google.co.uk"}, ssl_verify_hostname:verify_fun(google_cert(), valid_peer, [{check_hostname, "google.co.uk"}])).

verify_google_cert_dns_wildcard_test () ->
  ?assertEqual({valid, "www.google.co.uk"}, ssl_verify_hostname:verify_fun(google_cert_dns_wildcard(), valid_peer, [{check_hostname, "www.google.co.uk"}])).

verify_google_cert_without_dns_test () ->
  ?assertEqual({valid, "www.google.co.uk"}, ssl_verify_hostname:verify_fun(google_cert_without_dns(), valid_peer, [{check_hostname, "www.google.co.uk"}])).

verify_google_cert_printable_string_test() ->
  ?assertEqual({valid, "www.google.co.uk"}, ssl_verify_hostname:verify_fun(google_cert_printable_string(), valid_peer, [{check_hostname, "www.google.co.uk"}])).

verify_google_cert_teletex_string_test() ->
  ?assertEqual({valid, "www.google.co.uk"}, ssl_verify_hostname:verify_fun(google_cert_teletex_string(), valid_peer, [{check_hostname, "www.google.co.uk"}])).

verify_google_cert_bmp_string_test() ->
  ?assertEqual({valid, "google.co.uk"}, ssl_verify_hostname:verify_fun(google_cert_bmp_string(), valid_peer, [{check_hostname, "google.co.uk"}])).

verify_google_cert_universal_string_test() ->
  ?assertEqual({valid, "google.co.uk"}, ssl_verify_hostname:verify_fun(google_cert_universal_string(), valid_peer, [{check_hostname, "google.co.uk"}])).

%% Copyright Ericsson AB 1996-2016. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
-spec join(Sep, List1) -> List2 when
      Sep :: T,
      List1 :: [T],
      List2 :: [T],
      T :: term().

join(Sep, [H|T]) -> [H|join_prepend(Sep, T)].

join_prepend(_Sep, []) -> [];
join_prepend(Sep, [H|T]) -> [Sep, H|join_prepend(Sep, T)].
