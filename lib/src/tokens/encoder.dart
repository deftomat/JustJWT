part of just_jwt.tokens;

/// Converter capable of encode the JWT.
///
/// Encoding involves the signing of the JWT.
class Encoder extends Converter<Jwt, Future<EncodedJwt>> {
  final TokenSigner _signer;

  Encoder(this._signer);

  /// Converts the instance of [Jwt] to the instance of [EncodedJwt].
  /// Also, signs the JWT.
  Future<EncodedJwt> convert(Jwt jwt) async {
    var encodedHeader = _encodeMap(jwt.header);
    var encodedPayload = _encodeMap(jwt.payload);
    var toSign = new ToSign(jwt, encodedHeader, encodedPayload);

    var signature = await _signer(toSign);
    var encodedSignature = _encodeBytes(signature);

    return new _EncodedJwt(encodedHeader, encodedPayload, encodedSignature);
  }

  String _encodeMap(Map map) => _encodeBytes(JSON.encode(map).codeUnits);
  String _encodeBytes(List<int> bytes) => BASE64URL.encode(bytes);
}

/// Occurs when JWT encoding fails.
abstract class JwtEncodingError extends JwtError {
  Jwt get jwt;

  JwtEncodingError(String message) : super(message);
}
