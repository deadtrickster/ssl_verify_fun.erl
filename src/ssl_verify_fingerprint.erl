-module(ssl_verify_fingerprint).
-export([verify_fun/3, verify_cert_fingerprint/2]).

bin_to_hexstr(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) ||
    X <- binary_to_list(Bin)]).

hexstr_to_bin(S) ->
  hexstr_to_bin(S, []).
hexstr_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hexstr_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hexstr_to_bin(T, [V | Acc]).

verify_cert_fingerprint(Cert, CheckFingerprint) ->
  {FingerprintAlgorithm, Fingerprint} = CheckFingerprint,
  BinFingerprint = hexstr_to_bin(Fingerprint),
  CertBinary = public_key:pkix_encode('OTPCertificate', Cert, 'otp'),
  Hash = crypto:hash(FingerprintAlgorithm, CertBinary),
  case Hash of
    BinFingerprint ->
      {valid, Fingerprint};
    _ ->
      {fail, "Fingerprint doesn't match"}
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
