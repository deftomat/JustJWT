library just_jwt.signatures;

/// Verifies the [signature] of the [message].
typedef bool Verifier(String message, List<int> signature);

/// Returns a signature of the [message].
typedef Signature Signer(String message);
