%%% -*- erlang -*-
%%%
%%% MIT License
%%%
%%% Copyright (c) 2014, Ilya Khaprov <ilya.khaprov@publitechs.com>

-module(ssl_verify_hostname_tests).

-include_lib("eunit/include/eunit.hrl").

verify_hostname_success_test_ () ->
           %% presented identifier, reference identifier, validation and parsing result
  Tests = [
           {"www.example.com", "WWW.eXamPle.CoM", false}, %% case insensitive match
           {"www.example.com.", "www.example.com", false}, %% ignore trailing dots (prevenet *.com. matches)
           {"www.example.com", "www.example.com.", false},
           {"*.example.com", "www.example.com", {[], ".example.com", true}},         %% always matching wildcards
           {"b*z.example.com", "buzz.example.com", {"b", "z.example.com", false}},
           {"*baz.example.com", "foobaz.example.com", {[], "baz.example.com", false}},
           {"baz*.example.com", "baz1.example.com", {"baz", ".example.com", false}}
          ],
  [{string:join([I, R]," : "), fun() ->
                                   ?assertMatch(V, ssl_verify_hostname:validate_and_parse_wildcard_identifier(I, R)),
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
           {"*baz.example.com", "foobuzz.example.com"}
          ],
  [{string:join([I, R]," : "), fun() -> ?assertNot(ssl_verify_hostname:try_match_hostname(I, R)) end} || {I, R} <- Tests].


%%TODO: add certificate tests
