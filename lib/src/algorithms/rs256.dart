/// Provides an factories for RS256 signers and verifiers.
library just_jwt.algorithms.rs256;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart' as pointy;
import 'package:pointycastle/src/impl/secure_random_base.dart';
import 'package:pointycastle/src/registry/registry.dart';
import 'package:pointycastle/src/ufixnum.dart';
import 'package:rsa_pkcs/rsa_pkcs.dart';

import 'package:just_jwt/src/signatures.dart';

/// Returns the new RS256 signer with the private key obtained from [pem].
///
/// [pem] should contains at least a private key in a following format:
/// -----BEGIN RSA PRIVATE KEY-----\n
/// ...............................\n
/// -----END RSA PRIVATE KEY-----
Signer createRS256Signer(String pem) {
  RSAKeyPair pair = _parsePEM(pem);
  var rawKey = pair.private;
  if (rawKey == null)
    throw new ArgumentError.value(
        pem, 'privatePem', 'Private PEM is not valid!');

  var privateKey = new pointy.RSAPrivateKey(
      rawKey.modulus, rawKey.privateExponent, rawKey.prime1, rawKey.prime2);
  var privateKeyParams = new pointy.PrivateKeyParameter(privateKey);

  var signer = _createSigner(privateKeyParams, true);

  return (String toSign) {
    var message = new Uint8List.fromList(toSign.codeUnits);
    pointy.RSASignature sig = signer.generateSignature(message);
    return sig.bytes;
  };
}

/// Returns the new RS256 verifier with a public key obtained from [pem].
///
/// [pem] should contains at least a public key in a following format:
/// -----BEGIN PUBLIC KEY-----\n
/// ..........................\n
/// -----END PUBLIC KEY-----
Verifier createRS256Verifier(String pem) {
  RSAKeyPair pair = _parsePEM(pem);
  var rawKey = pair.public;
  if (rawKey == null)
    throw new ArgumentError.value(pem, 'publicPem', 'Public PEM is not valid!');

  var publicKey = new pointy.RSAPublicKey(
      rawKey.modulus, new BigInt.from(rawKey.publicExponent));
  return _createVerifier(publicKey);
}

/// Returns the new RS256 verifier with a public key defined by [encodedModulus] and [encodedExponent].
///
/// Parameters are Base64urlUInt-encoded values as described in:
/// RFC 7518 - JSON WEB Algorithms (https://tools.ietf.org/html/rfc7518#section-6.3)
Verifier createJwaRS256Verifier(String encodedModulus, String encodedExponent) {
  var n =
      new BigInt.from(base64.decode(encodedModulus).buffer.asUint8List()[0]);
  var e =
      new BigInt.from(base64.decode(encodedExponent).buffer.asUint8List()[0]);
  var publicKey = new pointy.RSAPublicKey(n, e);

  return _createVerifier(publicKey);
}

Verifier _createVerifier(pointy.RSAPublicKey publicKey) {
  var publicKeyParams = new pointy.PublicKeyParameter(publicKey);

  var signer = _createSigner(publicKeyParams, false);

  return (String message, List<int> signature) {
    var rsaSignature =
        new pointy.RSASignature(new Uint8List.fromList(signature));
    return signer.verifySignature(
        new Uint8List.fromList(message.codeUnits), rsaSignature);
  };
}

RSAKeyPair _parsePEM(String pem) {
  RSAPKCSParser parser = new RSAPKCSParser();
  return parser.parsePEM(pem);
}

pointy.Signer _createSigner(
    pointy.CipherParameters parameters, bool forSigning) {
  var signer = new pointy.Signer('SHA-256/RSA');
  signer.init(forSigning, parameters);

  return signer;
}

class _NullSecureRandom extends SecureRandomBase {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(pointy.SecureRandom, "Null", null);

  var _nextValue = 0;

  String get algorithmName => "Null";

  void seed(pointy.CipherParameters params) {}

  int nextUint8() => clip8(_nextValue++);
}
