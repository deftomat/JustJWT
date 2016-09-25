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

    var encodedHeader = _encode(jwt.header);
    var encodedPayload = _encode(jwt.payload);
    var signature = signer('$encodedHeader.$encodedPayload');

    return new _EncodedJwt(encodedHeader, encodedPayload, signature);
  }

  Signer _tryFindSigner(Jwt jwt) {
    var signer = _signers[jwt.alg];
    if (signer == null) throw new UnsupportedSigningAlgError(jwt);

    return signer;
  }

  String _encode(Map map) => BASE64URL.encode(JSON.encode(map).codeUnits);
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
