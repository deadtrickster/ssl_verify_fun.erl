%%% -*- erlang -*-
%%%
%%% MIT License
%%%
%%% Copyright (c) 2014, Ilya Khaprov <ilya.khaprov@publitechs.com>

-module(ssl_verify_hostname).
-include_lib("public_key/include/public_key.hrl").


-export([verify_fun/3, verify_cert_hostname/2]).
-ifdef(TEST).
-export([validate_and_parse_wildcard_identifier/2, try_match_hostname/2]).
-endif.

%% extract cn from subject
extract_cn({rdnSequence, List}) ->
  extract_cn2(List).
extract_cn2([[#'AttributeTypeAndValue'{type={2,5,4,3},
                                       value=CN}]|_]) ->
  CN;
extract_cn2([_|Rest]) ->
  extract_cn2(Rest);
extract_cn2([]) ->
  [].

extract_dns_names(TBSCert)->
  Extensions = pubkey_cert:extensions_list(TBSCert#'OTPTBSCertificate'.extensions),
  AltSubject = pubkey_cert:select_extension(?'id-ce-subjectAltName', Extensions),
  case AltSubject of
    undefined ->
      [];
    _ ->
      extract_dns_names_from_alt_names(AltSubject#'Extension'.extnValue, [])
  end.

extract_dns_names_from_alt_names([ExtValue | Rest], Acc) ->
  Acc1 = case ExtValue of
           {dNSName, DNSName} ->
             [unicode:characters_to_list(DNSName) | Acc];
           _ ->
             Acc
         end,
  extract_dns_names_from_alt_names(Rest, Acc1);
extract_dns_names_from_alt_names([], Acc) ->
  Acc.

case_insensitive_match(Str1, Str2) ->
  string:to_lower(Str1) == string:to_lower(Str2).

wildcard_not_in_a_label(BeforeW, AfterWString) ->
  AfterDotPos = string:chr(AfterWString, $.),
  (string:str(BeforeW, "xn--") == 0) andalso (0 == (string:str(string:substr(AfterWString, 1, AfterDotPos), "xn--"))).

try_match_wildcard(BeforeW, AfterW, SingleCharW, Pattern) ->
  %% Compare AfterW part with end of pattern with length (length AfterW)
  %% was Wildcard the only character in left-most label in identifier
  %% doesn't matter since parts after Wildcard should match unconditionally.
  %% However if Wildcard was the only character in left-most label we can't match this *.example.com and bar.foo.example.com
  %% if i'm correct if it wasn't the only character
  %% we can match like this: *o.example.com = bar.foo.example.com
  %% but this is prohibited anyway thanks to check_wildcard_in_leftmost_label
  FirstPatternDotPos = string:chr(Pattern, $.),
  case SingleCharW of
    true ->
      %% only compare againts whole left-most label in pattern
      case_insensitive_match(AfterW, string:substr(Pattern, FirstPatternDotPos));
    false ->
      case wildcard_not_in_a_label(BeforeW, AfterW) of
        true ->
          %% baz*.example.net and *baz.example.net and b*z.example.net would
          %% be taken to match baz1.example.net and foobaz.example.net and
          %% buzz.example.net, respectively
          case_insensitive_match(AfterW, string:substr(Pattern, (length(Pattern) - length(AfterW) + 1), length(AfterW))) andalso
          case_insensitive_match(BeforeW, string:substr(Pattern, 1, length(BeforeW)));
        false -> false
      end
  end.

check_two_labels_after_wildcard(String) ->
  %% at least two dots(in fact labels since we remove trailing dot first) after wildcard
  case string:chr(String, $.) of
    0 ->
      false;
    FirstDotAfterWildcardPos ->
      case string:chr(string:substr(String, 1 + FirstDotAfterWildcardPos), $.) of
        0 ->
          false;
        _ ->
          FirstDotAfterWildcardPos
      end
  end.

check_wildcard_in_leftmost_label(Identifier, WildcardPos) ->
  %% only allow *.example.com, not foo.*.example.com
  case string:chr(Identifier, $.) of
    0 ->
      false;
    DotPos ->
      if
        DotPos < WildcardPos ->
          false;
        true -> true
      end
  end.

validate_and_parse_wildcard_identifier(Identifier, Hostname) ->
  %% try wildcard match
  case string:chr(Identifier, $*) of
    0 -> %% no wildcard, return false
      false;
    WildcardPos ->
      if length(Hostname) < length(Identifier) -> false; %% wildcard should constiute at least one character
         true ->
          case check_wildcard_in_leftmost_label(Identifier, WildcardPos) of
            true ->
              AfterWString = string:substr(Identifier, WildcardPos + 1),
              BeforeWString = string:substr(Identifier, 1,  WildcardPos - 1),
              %% only one wildcard allowed
              case string:chr(AfterWString, $*) of
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
      end
  end.

try_match_hostname(Identifier0, Hostname0) ->
  Identifier = string:strip(Identifier0, right, $.), %% what about *.com.??
  Hostname = string:strip(Hostname0, right, $.),
  case case_insensitive_match(Identifier, Hostname) of
    true ->
      true;
    false ->
      case validate_and_parse_wildcard_identifier(Identifier, Hostname) of
        {BeforeWString, AfterWString, SingleCharW} ->
          try_match_wildcard(BeforeWString, AfterWString, SingleCharW, Hostname);
        _ -> false
      end
  end.

try_match_hostnames([DNSName| REST], Hostname) ->
  case try_match_hostname(DNSName, Hostname) of
    true ->
      true;
    _ ->
      try_match_hostnames(REST, Hostname)
  end;
try_match_hostnames([], _Hostname) ->
  false.

maybe_check_subject_cn(DNSNames, DNSNameMatched, TBSCert, Hostname) ->
  case DNSNameMatched of
    true -> true;
    false ->
      case DNSNames of
        [_|_] ->
          {fail, unable_to_match_altnames};
        [] ->
          try_match_hostname(extract_cn(TBSCert#'OTPTBSCertificate'.subject), Hostname)
      end
  end.

verify_cert_hostname(Cert, Hostname) ->
  TBSCert = Cert#'OTPCertificate'.tbsCertificate,
  %% first try match dns altnames if any
  DNSNames = extract_dns_names(TBSCert),
  DNSNameMatched = try_match_hostnames(DNSNames, Hostname),
  case maybe_check_subject_cn(DNSNames, DNSNameMatched, TBSCert, Hostname) of
    true ->
      {valid, Hostname};
    Reason ->
      {fail, Reason}
  end.

verify_fun(_,{bad_cert, _} = Reason, _) ->
  {fail, Reason};
verify_fun(_,{extension, _}, UserState) ->
  {unknown, UserState};
verify_fun(_, valid, UserState) ->
  {valid, UserState};
verify_fun(Cert, valid_peer, UserState) ->
  CheckHostname = proplists:get_value(check_hostname, UserState),
  if
    CheckHostname /= undefined ->
      verify_cert_hostname(Cert, CheckHostname);
    true -> {valid, UserState}
  end.
