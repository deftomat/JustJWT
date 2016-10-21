part of just_jwt.tokens;

/// Converter capable of decode the encoded JWT.
///
/// Decoding process involves the signature verification by one of the supported verifier.
class Decoder extends Converter<EncodedJwt, Jwt> {
  final TokenVerifier _verifier;

  Decoder(this._verifier);

  /// Converts the instance of [EncodedJwt] to the instance of [JWT].
  /// Also, verifies the JWT's signature.
  Jwt convert(EncodedJwt encodedJwt) {
    var header = _decodeMap(encodedJwt.header);
    var payload = _decodeMap(encodedJwt.payload);
    var jwt = new _Jwt.from(header, payload);

    _checkSignature(jwt, encodedJwt);

    return jwt;
  }

  Map<String, dynamic> _decodeMap(String encoded) {
    var bytes = _decodeBytes(encoded);
    var json = new String.fromCharCodes(bytes);
    return JSON.decode(json);
  }

  List<int> _decodeBytes(String encoded) {
    var normalized = _normalizeBASE64(encoded);
    return BASE64URL.decode(normalized);
  }

  String _normalizeBASE64(String encoded) {
    var reminder = encoded.length % 4;
    var normalizedLength = encoded.length + (reminder == 0 ? 0 : 4 - reminder);

    return encoded.padRight(normalizedLength, '=');
  }

  void _checkSignature(Jwt jwt, EncodedJwt encodedJwt) {
    var signature = _decodeBytes(encodedJwt.signature);
    var toVerify = new ToVerify(jwt, encodedJwt, signature);

    if (_verifier(toVerify) == false) throw new InvalidJwtSignatureError(encodedJwt);
  }
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
