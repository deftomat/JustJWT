part of just_jwt.tokens;

/// Converter capable of encode the JWT.
///
/// Encoding involves the signing of the JWT.
class Encoder extends Converter<Jwt, EncodedJwt> {
  final Map<String, Signer> _signers;

  Encoder(this._signers);

  /// Converts the instance of [Jwt] to the instance of [EncodedJwt].
  /// Also, signs the JWT.
  EncodedJwt convert(Jwt jwt) {
    var signer = _tryFindSigner(jwt);

    var encodedHeader = _encodeMap(jwt.header);
    var encodedPayload = _encodeMap(jwt.payload);

    var signature = signer('$encodedHeader.$encodedPayload');
    var encodedSignature = _encodeBytes(signature);

    return new _EncodedJwt(encodedHeader, encodedPayload, encodedSignature);
  }

  Signer _tryFindSigner(Jwt jwt) {
    return _signers[jwt.alg] ?? (throw new UnsupportedSigningAlgError(jwt));
  }

  String _encodeMap(Map map) => _encodeBytes(JSON.encode(map).codeUnits);
  String _encodeBytes(List<int> bytes) => BASE64URL.encode(bytes);
}

/// Occurs when the JWT's alg is not supported by any signer in encoder.
class UnsupportedSigningAlgError extends JwtEncodingError {
  UnsupportedSigningAlgError(Jwt jwt)
      : super('Unsupported algorithm: Cannot sign JWT due to unsupported [${jwt.alg}] algorithm!', jwt);
}

/// Occurs when JWT encoding fails.
abstract class JwtEncodingError extends JwtError {
  final Jwt jwt;

  JwtEncodingError(String message, this.jwt) : super(message);
}
