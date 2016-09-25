part of just_jwt.tokens;

/// Represents an encoded JSON Web Token.
abstract class EncodedJwt {
  String get header;
  String get payload;
  String get signature;

  /// Constructs an EncodedJwt from a raw encoded JWT string.
  factory EncodedJwt(String jwt) = _EncodedJwt.from;

  /// Returns an encoded JWT as a one string.
  ///
  /// Format: $header.$payload.$signature
  String toString();
}

class _EncodedJwt implements EncodedJwt {
  final String header;
  final String payload;
  final String signature;

  factory _EncodedJwt.from(String jwt) {
    var parts = jwt.split('.');

    if (parts.length != 3) throw new CannotParseRawJwtError(jwt);

    return new _EncodedJwt(parts[0], parts[1], parts[2]);
  }

  _EncodedJwt(this.header, this.payload, this.signature);

  String toString() => '$header.$payload.$signature';
}

/// Occurs when an raw JWT string cannot be parsed due to its invalid format.
class CannotParseRawJwtError extends JwtError {
  CannotParseRawJwtError(String rawJwt) : super('Cannot parse raw JWT string [$rawJwt]!');
}
