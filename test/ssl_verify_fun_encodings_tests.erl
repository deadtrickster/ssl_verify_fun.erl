%%% -*- erlang -*-
%%%
%%% MIT License
%%%
%%% Copyright (c) 2014-2016 Ilya Khaprov <ilya.khaprov@publitechs.com>

-module(ssl_verify_fun_encodings_tests).

-include_lib("eunit/include/eunit.hrl").

decode_dns_name_test_ () ->
  Tests = [
           {"binary ascii name", <<"www.example.com">>, "www.example.com"},
           {"list ascii name", "www.example.com", "www.example.com"},
           {"binary wildcard", <<"*.example.com">>, "*.example.com"},
           %% a dNSName is an IA5String: anything outside ASCII is not an identifier
           {"utf8 encoded name", <<16#C3, 16#A9, "xample.com">>, {error, invalid}},
           {"lone continuation byte", <<128>>, {error, invalid}},
           {"truncated utf8 sequence", <<16#C3>>, {error, invalid}},
           {"list with non-ascii char", [16#E9 | "xample.com"], {error, invalid}},
           {"nul byte", <<"www.example.com", 0>>, {error, invalid}}
          ],
  [{Name, ?_assertEqual(Expected, ssl_verify_fun_encodings:decode_dns_name(In))}
   || {Name, In, Expected} <- Tests].

get_string_test_ () ->
  Tests = [
           {"printable", {printableString, "www.example.com"}, {ok, "www.example.com"}},
           {"printable wildcard", {printableString, "*.example.com"}, {ok, "*.example.com"}},
           {"printable non-printable char", {printableString, "www.example.com" ++ [16#E9]},
            {error, invalid}},
           {"utf8", {utf8String, <<"www.example.com">>}, {ok, "www.example.com"}},
           {"utf8 non-ascii", {utf8String, <<16#C3, 16#A9>>}, {ok, [16#E9]}},
           {"utf8 invalid bytes", {utf8String, <<16#C3>>}, {error, invalid}},
           {"teletex", {teletexString, "www.example.com"}, {ok, "www.example.com"}},
           {"teletex non-ascii", {teletexString, [16#E9]}, {error, invalid}},
           {"bmp", {bmpString, "www.example.com"}, {ok, "www.example.com"}},
           {"universal", {universalString, "www.example.com"}, {ok, "www.example.com"}},
           {"unknown type", {unknownString, "www.example.com"}, {error, invalid}}
          ],
  [{Name, ?_assertEqual(Expected, ssl_verify_fun_encodings:get_string(In))}
   || {Name, In, Expected} <- Tests].
