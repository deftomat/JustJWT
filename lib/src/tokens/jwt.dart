part of just_jwt.tokens;

/// Represents a JSON Web Token.
abstract class Jwt {
  Map<String, dynamic> get header;
  Map<String, dynamic> get payload;
  String get alg;

  /// Creates a JWT with the specified HS256 algorithm.
  factory Jwt.HS256(Map<String, dynamic> payload) = _Jwt.HS256;

  /// Creates a JWT with the specified RS256 algorithm.
  factory Jwt.RS256(Map<String, dynamic> payload) = _Jwt.RS256;
}

class _Jwt implements Jwt {
  final Map<String, dynamic> header;
  final Map<String, dynamic> payload;

  factory _Jwt.HS256(Map<String, dynamic> payload) =>
      new _Jwt('HS256', payload);
  factory _Jwt.RS256(Map<String, dynamic> payload) =>
      new _Jwt('RS256', payload);

  _Jwt(String alg, this.payload)
      : header = new Map.unmodifiable({'alg': alg, 'typ': 'JWT'});

  _Jwt.from(this.header, this.payload);

  String get alg => header['alg'];
}
