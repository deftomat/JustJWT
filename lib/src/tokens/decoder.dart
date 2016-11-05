part of just_jwt.tokens;

/// Converter capable of decode the encoded JWT.
///
/// Decoding process involves the signature verification by one of the supported verifier.
class Decoder extends Converter<EncodedJwt, Future<Jwt>> {
  final TokenVerifier _verifier;

  Decoder(this._verifier);

  /// Converts the instance of [EncodedJwt] to the instance of [JWT].
  /// Also, verifies the JWT's signature.
  Future<Jwt> convert(EncodedJwt encodedJwt) async {
    var header = _decodeMap(encodedJwt.header);
    var payload = _decodeMap(encodedJwt.payload);
    var jwt = new _Jwt.from(header, payload);

    await _verify(jwt, encodedJwt);

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

  Future _verify(Jwt jwt, EncodedJwt encodedJwt) async {
    var signature = _decodeBytes(encodedJwt.signature);
    var toVerify = new ToVerify(jwt, encodedJwt, signature);

    if ((await _verifier(toVerify)) == false) throw new JwtVerificationError(toVerify);
  }
}

/// Occurs when the JWT's signature is not valid.
class JwtVerificationError extends JwtDecodingError {
  final ToVerify toVerify;

  EncodedJwt get encodedJwt => toVerify.encodedJwt;

  JwtVerificationError(this.toVerify) : super('JWT verification failed!');
}

/// Occurs when JWT decoding fails.
abstract class JwtDecodingError extends JwtError {
  EncodedJwt get encodedJwt;

  JwtDecodingError(String message) : super(message);
}
