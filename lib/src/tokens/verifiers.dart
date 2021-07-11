part of just_jwt.tokens;

/// Verifies the [toVerify] structure.
typedef Future<bool> TokenVerifier(ToVerify toVerify);

/// Contains context for [TokenVerifier].
class ToVerify {
  final Jwt jwt;
  final EncodedJwt encodedJwt;
  final List<int> signature;

  ToVerify(this.jwt, this.encodedJwt, this.signature);
}

/// Transforms an instance of [Verifier] into an instance of [TokenVerifier].
TokenVerifier toTokenVerifier(Verifier verifier) {
  return (ToVerify toVerify) async {
    var message =
        '${toVerify.encodedJwt.header}.${toVerify.encodedJwt.payload}';
    return verifier(message, toVerify.signature);
  };
}

/// Combines multiple [verifiers] into one [TokenVerifier].
///
/// For example, combines a signature verifier with a custom claim verifiers.
TokenVerifier combineTokenVerifiers(Iterable<TokenVerifier> verifiers) {
  return (ToVerify toVerify) async {
    var computations = verifiers.map((verifier) => verifier(toVerify));

    for (var computation in computations) {
      if ((await computation) == false) return false;
    }
    return true;
  };
}

/// Composes multiple [verifiers] into one [TokenVerifier].
///
/// The resulting verifier will choose an underlining sub-verifier according to the JWT's algorithm.
TokenVerifier composeTokenVerifiers(Map<String, TokenVerifier> verifiers) {
  return (ToVerify toVerify) {
    var alg = toVerify.jwt.alg;
    var verifier =
        verifiers[alg] ?? (throw new UnsupportedVerificationAlgError(toVerify));
    return verifier(toVerify);
  };
}

/// Occurs when the JWT's alg is not supported by any verifier.
class UnsupportedVerificationAlgError extends JwtDecodingError {
  final ToVerify toVerify;

  EncodedJwt get encodedJwt => toVerify.encodedJwt;

  UnsupportedVerificationAlgError(this.toVerify)
      : super(
            'Unsupported algorithm: Cannot verify JWT due to unsupported algorithm!');
}
