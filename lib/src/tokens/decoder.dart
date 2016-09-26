part of just_jwt.tokens;

/// Converter capable of decode the encoded JWT.
///
/// Decoding process involves the signature verification by one of the supported verifier.
class Decoder extends Converter<EncodedJwt, Jwt> {
  final Map<String, Verifier> _verifiers;

  Decoder(this._verifiers);

  /// Converts the instance of [EncodedJwt] to the instance of [JWT].
  /// Also, verifies the JWT's signature.
  Jwt convert(EncodedJwt encodedJwt) {
    var header = _decodeMap(encodedJwt.header);
    var payload = _decodeMap(encodedJwt.payload);
    var jwt = new _Jwt.from(header, payload);

    _checkSignature(encodedJwt, jwt.alg);

    return jwt;
  }

  Map<String, dynamic> _decodeMap(String encoded) {
    var bytes = _decodeBytes(encoded);
    var json = new String.fromCharCodes(bytes);
    return JSON.decode(json);
  }

  List<int> _decodeBytes(String encoded) => BASE64URL.decode(encoded);

  void _checkSignature(EncodedJwt encodedJwt, String alg) {
    var verifier = _tryFindVerifier(encodedJwt, alg);
    var toVerify = '${encodedJwt.header}.${encodedJwt.payload}';
    var signature = _decodeBytes(encodedJwt.signature);

    if (verifier(toVerify, signature) == false)
      throw new InvalidJwtSignatureError(encodedJwt);
  }

  Verifier _tryFindVerifier(EncodedJwt encodedJwt, String alg) {
    return _verifiers[alg] ?? (throw new UnsupportedVerificationAlgError(alg, encodedJwt));
  }
}

/// Occurs when the JWT's alg is not supported by any verifier in decoder.
class UnsupportedVerificationAlgError extends JwtDecodingError {
  UnsupportedVerificationAlgError(String alg, EncodedJwt jwt)
      : super('Unsupported algorithm: Cannot verify JWT due to unsupported [$alg] algorithm!', jwt);
}

/// Occurs when the JWT's signature is not valid.
class InvalidJwtSignatureError extends JwtDecodingError {
  InvalidJwtSignatureError(EncodedJwt jwt)
      : super('Invalid JWT signature: [${jwt.signature}] is not a valid signature!', jwt);
}

/// Occurs when JWT decoding fails.
abstract class JwtDecodingError extends JwtError {
  final EncodedJwt jwt;

  JwtDecodingError(String message, this.jwt) : super(message);
}
