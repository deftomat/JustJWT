library just_jwt.errors;

/// Occurs when [just_jwt] library throws a custom error.
///
/// All [just_jwt] errors implement this error class.
abstract class JwtError implements Exception {
  final String message;

  JwtError(this.message);

  String toString() => message;
}
