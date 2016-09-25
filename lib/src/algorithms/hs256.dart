/// Provides an factories for HS256 signers and verifiers.
library just_jwt.algorithms.hs256;

import 'dart:convert';

import 'package:crypto/crypto.dart' show sha256, Hmac;

import 'package:just_jwt/src/signatures.dart';

/// Returns the new HS256 signer with secret [key].
Signer createHS256Signer(String key) {
  var hmac = new Hmac(sha256, key.codeUnits);

  return (String message) {
    var hash = hmac.convert(message.codeUnits);
    return BASE64URL.encode(hash.bytes);
  };
}

/// Returns the new HS256 verifier with secret [key].
Verifier createHS256Verifier(String key) {
  var signer = createHS256Signer(key);

  return (String message, String signature) => signer(message) == signature;
}
