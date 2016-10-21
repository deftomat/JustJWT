part of just_jwt.tokens;

/// Verifies the [toVerify] structure.
typedef bool TokenVerifier(ToVerify toVerify);

/// Contains context for [TokenVerifier].
class ToVerify {
  final Jwt jwt;
  final EncodedJwt encodedJwt;
  final List<int> signature;

  ToVerify(this.jwt, this.encodedJwt, this.signature);
}

/// Transforms an instance of [Verifier] into an instance of [TokenVerifier].
TokenVerifier toTokenVerifier(Verifier verifier) {
  return (ToVerify toVerify) {
    var message = '${toVerify.encodedJwt.header}.${toVerify.encodedJwt.payload}';
    return verifier(message, toVerify.signature);
  };
}

/// Combines multiple [verifiers] into one [TokenVerifier].
///
/// For example, combines a signature verifier with a custom claim verifiers.
TokenVerifier combineTokenVerifiers(Iterable<TokenVerifier> verifiers) {
  return (ToVerify toVerify) {
    return !verifiers.any((verifier) => !verifier(toVerify));
  };
}

/// Composes multiple [verifiers] into one [TokenVerifier].
///
/// The resulting verifier will choose an underlining sub-verifier according to the JWT's algorithm.
TokenVerifier composeTokenVerifiers(Map<String, TokenVerifier> verifiers) {
  return (ToVerify toVerify) {
    var alg = toVerify.jwt.alg;
    var verifier = verifiers[alg] ?? (throw new UnsupportedVerificationAlgError(alg, toVerify.encodedJwt));
    return verifier(toVerify);
  };
}

/// Occurs when the JWT's alg is not supported by any verifier.
class UnsupportedVerificationAlgError extends JwtDecodingError {
  UnsupportedVerificationAlgError(String alg, EncodedJwt jwt)
      : super('Unsupported algorithm: Cannot verify JWT due to unsupported [$alg] algorithm!', jwt);
}
