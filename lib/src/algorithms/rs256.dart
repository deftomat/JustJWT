/// Provides an factories for RS256 signers and verifiers.
library just_jwt.algorithms.rs256;

import 'dart:convert';
import 'dart:typed_data';

import 'package:bignum/bignum.dart';
import 'package:pointycastle/pointycastle.dart' as pointy;
import 'package:pointycastle/src/impl/secure_random_base.dart';
import 'package:pointycastle/src/registry/factory_config.dart';
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
  var signer = new pointy.Signer('SHA-256/RSA');

  RSAPKCSParser parser = new RSAPKCSParser();
  RSAKeyPair pair = parser.parsePEM(pem);
  var rawPrivate = pair.private;
  if (rawPrivate == null) throw new ArgumentError.value(pem, 'privatePem', 'Private PEM is not valid!');

  var modulus = rawPrivate.modulus;
  var privateExponent = rawPrivate.privateExponent;
  var p = rawPrivate.prime1;
  var q = rawPrivate.prime2;

  var privateKey = new pointy.RSAPrivateKey(modulus, privateExponent, p, q);
  var privateKeyParams = new pointy.PrivateKeyParameter(privateKey);

  var params = () => new pointy.ParametersWithRandom(privateKeyParams, new _NullSecureRandom());

  signer.init(true, params());

  return (String toSign) => BASE64URL.encode(signer.generateSignature(new Uint8List.fromList(toSign.codeUnits)).bytes);
}

/// Returns the new RS256 verifier with the public key obtained from [pem].
///
/// [pem] should contains at least a public key in a following format:
/// -----BEGIN PUBLIC KEY-----\n
/// ..........................\n
/// -----END PUBLIC KEY-----
Verifier createRS256Verifier(String pem) {
  var signer = new pointy.Signer('SHA-256/RSA');

  RSAPKCSParser parser = new RSAPKCSParser();
  RSAKeyPair pair = parser.parsePEM(pem);
  var rawPublic = pair.public;
  if (rawPublic == null) throw new ArgumentError.value(pem, 'publicPem', 'Public PEM is not valid!');

  var modulus = rawPublic.modulus;
  var publicExponent = new BigInteger(rawPublic.publicExponent);

  var publicKey = new pointy.RSAPublicKey(modulus, publicExponent);
  var publicKeyParams = new pointy.PublicKeyParameter(publicKey);

  var params = () => new pointy.ParametersWithRandom(publicKeyParams, new _NullSecureRandom());

  signer.init(false, params());

  return (String message, String signature) {
    var rsaSignature = new pointy.RSASignature(new Uint8List.fromList(BASE64URL.decode(signature)));
    return signer.verifySignature(new Uint8List.fromList(message.codeUnits), rsaSignature);
  };
}



class _NullSecureRandom extends SecureRandomBase {
  static final FactoryConfig FACTORY_CONFIG = new StaticFactoryConfig(pointy.SecureRandom, "Null");

  var _nextValue = 0;

  String get algorithmName => "Null";

  void seed(pointy.CipherParameters params) {}

  int nextUint8() => clip8(_nextValue++);
}
