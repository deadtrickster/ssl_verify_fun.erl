%%% -*- erlang -*-
%%%
%%% MIT License
%%%
%%% Copyright (c) 2014-2016 Ilya Khaprov <ilya.khaprov@publitechs.com>

-module(ssl_verify_hostname).

-export([verify_fun/3,
         verify_cert_hostname/2]).

-ifdef(TEST).
-export([parse_and_validate_wildcard_identifier/2, try_match_hostname/2]).
-endif.

-include_lib("public_key/include/public_key.hrl").

-export_type([hostname/0,
              user_state/0]).

-type hostname() :: nonempty_string() | binary().
-type user_state() :: [{check_hostname, Hostname :: hostname()}] | [].

%%====================================================================
%% Public API
%%====================================================================

-spec verify_fun(Cert :: #'OTPCertificate'{},
                 Event :: {bad_cert, Reason :: atom() | {revoked, atom()}} |
                          {extension, #'Extension'{}} |
                          valid | valid_peer,
                 InitialUserState :: term()) ->
                    {valid, UserState :: term()} | {valid_peer, UserState :: user_state()} |
                    {fail, Reason :: term()} | {unknown, UserState :: term()}.
verify_fun(_, {bad_cert, _} = Reason, _) ->
  {fail, Reason};
verify_fun(_, {extension, _}, UserState) ->
  {unknown, UserState};
verify_fun(_, valid, UserState) ->
  {valid, UserState};
verify_fun(Cert, valid_peer, UserState) ->
  CheckHostname = proplists:get_value(check_hostname, UserState),
  case CheckHostname of
    undefined -> {valid, UserState};
    _ -> verify_cert_hostname(Cert, CheckHostname)
  end.

-spec verify_cert_hostname(Cert :: #'OTPCertificate'{}, Hostname :: hostname()) ->
                              {valid, hostname()} | {fail, term()}.
verify_cert_hostname(Cert, Hostname) ->
  %% first try match dns altnames if any
  DNSNames = ssl_verify_fun_cert_helpers:extract_dns_names(Cert),
  DNSNameMatched = try_match_hostnames(DNSNames, Hostname),
  case maybe_check_subject_cn(DNSNames, DNSNameMatched, Cert, Hostname) of
    true ->
      {valid, Hostname};
    Reason ->
      {fail, Reason}
  end.

%%====================================================================
%% Private Parts
%%====================================================================

-spec try_match_hostnames([string()], Hostname :: string()) -> boolean().
try_match_hostnames([DNSName| REST], Hostname) ->
  case try_match_hostname(DNSName, Hostname) of
    true ->
      true;
    _ ->
      try_match_hostnames(REST, Hostname)
  end;
try_match_hostnames([], _Hostname) ->
  false.

-spec maybe_check_subject_cn(DNSNames :: [string()],
                             DNSNameMatched :: boolean(),
                             Cert :: #'OTPCertificate'{},
                             Hostname :: string()) -> true | unable_to_match_altnames | unable_to_match_common_name | unable_to_decode_common_name.
maybe_check_subject_cn(DNSNames, DNSNameMatched, Cert, Hostname) ->
  case DNSNameMatched of
    true -> true;
    false ->
      case DNSNames of
        [_|_] ->
          unable_to_match_altnames;
        [] ->
          try_match_common_name(Cert, Hostname)
      end
  end.

try_match_common_name(Cert, Hostname) ->
  case ssl_verify_fun_cert_helpers:extract_cn(Cert) of
    {ok, String} ->
      case try_match_hostname(String, Hostname) of
        true -> true;
        false -> unable_to_match_common_name
      end;
    _ ->
      unable_to_decode_common_name
  end.

case_insensitive_match(Str1, Str2) ->
  ssl_verify_string:to_lower(Str1) == ssl_verify_string:to_lower(Str2).

wildcard_not_in_a_label(BeforeW, AfterWString) ->
  AfterDotPos = ssl_verify_string:chr(AfterWString, $.),
  (ssl_verify_string:str(BeforeW, "xn--") == 0)
    andalso
      (0 == (ssl_verify_string:str(
               ssl_verify_string:substr(AfterWString, 1, AfterDotPos), "xn--")
            )).

try_match_wildcard(BeforeW, AfterW, SingleCharW, Pattern) ->
  %% Compare AfterW part with end of pattern with length (length AfterW)
  %% was Wildcard the only character in left-most label in identifier
  %% doesn't matter since parts after Wildcard should match unconditionally.
  %% However if Wildcard was the only character in left-most label we can't
  %% match this *.example.com and bar.foo.example.com
  %% Likewise, a partial-label wildcard such as *o.example.com must not match
  %% bar.foo.example.com: RFC 6125 Section 6.4.3 only allows the wildcard to
  %% match within the left-most label, so the characters it consumes in the
  %% presented hostname must not contain a dot.
  FirstPatternDotPos = ssl_verify_string:chr(Pattern, $.),
  case SingleCharW of
    true ->
      %% only compare against whole left-most label in pattern
      case_insensitive_match(AfterW, ssl_verify_string:substr(Pattern, FirstPatternDotPos));
    false ->
      case wildcard_not_in_a_label(BeforeW, AfterW) of
        true ->
          %% baz*.example.net and *baz.example.net and b*z.example.net would
          %% be taken to match baz1.example.net and foobaz.example.net and
          %% buzz.example.net, respectively
          BeforeWLen = length(BeforeW),
          AfterWLen = length(AfterW),
          %% the part of the pattern consumed by the wildcard
          WildcardSpan = ssl_verify_string:substr(Pattern,
                                                  BeforeWLen + 1,
                                                  length(Pattern) - BeforeWLen - AfterWLen),
          case_insensitive_match(AfterW,
                                 ssl_verify_string:substr(Pattern,
                                                          (length(Pattern) - AfterWLen + 1),
                                                          AfterWLen))
            andalso
            case_insensitive_match(BeforeW, ssl_verify_string:substr(Pattern, 1, BeforeWLen))
            andalso
            ssl_verify_string:chr(WildcardSpan, $.) == 0;
        false -> false
      end
  end.

check_two_labels_after_wildcard(String) ->
  %% at least two dots(in fact labels since we remove trailing dot first) after wildcard
  case ssl_verify_string:chr(String, $.) of
    0 ->
      false;
    FirstDotAfterWildcardPos ->
      case ssl_verify_string:chr(ssl_verify_string:substr(String, 1 + FirstDotAfterWildcardPos), $.) of
        0 ->
          false;
        _ ->
          FirstDotAfterWildcardPos
      end
  end.

check_wildcard_in_leftmost_label(Identifier, WildcardPos) ->
  %% only allow *.example.com, not foo.*.example.com
  case ssl_verify_string:chr(Identifier, $.) of
    0 ->
      false;
    DotPos ->
      case DotPos < WildcardPos of
        true -> false;
        false -> true
      end
  end.

parse_and_validate_wildcard_identifier(Identifier, Hostname) ->
  %% try wildcard match
  case ssl_verify_string:chr(Identifier, $*) of
    0 -> %% no wildcard, return false
      false;
    WildcardPos ->
      validate_wildcard_identifier(Identifier, Hostname, WildcardPos)
  end.

validate_wildcard_identifier(Identifier, Hostname, WildcardPos) ->
  case length(Hostname) < length(Identifier) of
    true -> false; %% wildcard should constiute at least one character
    _ ->
      case check_wildcard_in_leftmost_label(Identifier, WildcardPos) of
        true ->
          AfterWString = ssl_verify_string:substr(Identifier, WildcardPos + 1),
          BeforeWString = ssl_verify_string:substr(Identifier, 1,  WildcardPos - 1),
          %% only one wildcard allowed
          case ssl_verify_string:chr(AfterWString, $*) of
            0 ->
              case check_two_labels_after_wildcard(AfterWString) of %% at least two labels after wildcard
                false -> false;
                FirstDotAfterWildcardPos ->
                  SingleCharW = (FirstDotAfterWildcardPos == WildcardPos andalso length(BeforeWString) == 0),
                  {BeforeWString, AfterWString, SingleCharW}
              end;
            _ ->
              false
          end;
        _ ->
          false
      end
  end.

try_match_hostname(Identifier0, Hostname0) ->
  Identifier = ssl_verify_string:strip(Identifier0, right, $.), %% what about *.com.??
  Hostname = ssl_verify_string:strip(Hostname0, right, $.),
  case case_insensitive_match(Identifier, Hostname) of
    true ->
      true;
    false ->
      %% a literal IP address is an IP-ID, not a DNS-ID, and must never be
      %% matched by a wildcard (RFC 6125 Section 1.7.2, RFC 9110 Section 4.3.4)
      case is_ip_address(Hostname) of
        true -> false;
        false ->
          case parse_and_validate_wildcard_identifier(Identifier, Hostname) of
            {BeforeWString, AfterWString, SingleCharW} ->
              try_match_wildcard(BeforeWString, AfterWString, SingleCharW, Hostname);
            _ -> false
          end
      end
  end.

is_ip_address(Hostname) ->
  case inet:parse_address(Hostname) of
    {ok, _} -> true;
    {error, _} -> false
  end.
