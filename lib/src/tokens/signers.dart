part of just_jwt.tokens;

/// Returns a signature of the [toSign] structure.
typedef Future<List<int>> TokenSigner(ToSign toSign);

/// Contains context for [TokenSigner].
class ToSign {
  final Jwt jwt;
  final String encodedHeader;
  final String encodedPayload;

  ToSign(this.jwt, this.encodedHeader, this.encodedPayload);
}

/// Transforms an instance of [Signer] into an instance of [TokenSigner].
TokenSigner toTokenSigner(Signer signer) {
  return (ToSign toSign) async {
    var message = '${toSign.encodedHeader}.${toSign.encodedPayload}';
    return signer(message);
  };
}

/// Merges multiple [signers] into one [TokenSigner].
///
/// The resulting signer will choose an underlining sub-signer according to the JWT's algorithm.
TokenSigner composeTokenSigners(Map<String, TokenSigner> signers) {
  return (ToSign toSign) {
    var alg = toSign.jwt.alg;
    var signer = signers[alg] ?? (throw new UnsupportedSigningAlgError(toSign));
    return signer(toSign);
  };
}

/// Occurs when the JWT's alg is not supported by any signer.
class UnsupportedSigningAlgError extends JwtEncodingError {
  final ToSign toSign;

  Jwt get jwt => toSign.jwt;

  UnsupportedSigningAlgError(this.toSign)
      : super('Unsupported algorithm: Cannot sign JWT due to unsupported algorithm!');
}
