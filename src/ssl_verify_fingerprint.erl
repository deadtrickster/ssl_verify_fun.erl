-module(ssl_verify_fingerprint).
-export([verify_fun/3]).

-ifdef(TEST).
-export([verify_cert_fingerprint/2]).
-endif.

bin_to_hexstr(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) ||
    X <- binary_to_list(Bin)]).


hexstr_to_bin(S) when is_list(S) and (length(S) rem 2 =:= 0) ->
  hexstr_to_bin(S, []);
hexstr_to_bin(_) ->
  invalid.
hexstr_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hexstr_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hexstr_to_bin(T, [V | Acc]).

verify_cert_fingerprint(Cert, Fingerprint, FingerprintAlgorithm) ->
  CertBinary = public_key:pkix_encode('OTPCertificate', Cert, 'otp'),
  Hash = crypto:hash(FingerprintAlgorithm, CertBinary),
  case Hash of
    Fingerprint ->
      {valid, bin_to_hexstr(Fingerprint)};
    _ ->
      {fail, bin_to_hexstr(Hash)}
  end.

verify_cert_fingerprint(Cert, CheckFingerprint) ->
  {FingerprintAlgorithm, Fingerprint} = CheckFingerprint,
  case hexstr_to_bin(Fingerprint) of
    invalid -> {fail, invalid_fingerprint};
    FingerprintB -> verify_cert_fingerprint(Cert, FingerprintB, FingerprintAlgorithm)
  end.
  

verify_fun(_,{bad_cert, _}, UserState) ->
  {valid, UserState};
verify_fun(_,{extension, _}, UserState) ->
  {unknown, UserState};
verify_fun(_, valid, UserState) ->
  {valid, UserState};
verify_fun(Cert, valid_peer, UserState) ->
  CheckFingerprint = proplists:get_value(check_fingerprint, UserState),
  if 
    CheckFingerprint /= undefined ->
      verify_cert_fingerprint(Cert, CheckFingerprint);
    true -> {valid, UserState}
  end.
