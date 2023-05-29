library just_jwt.signatures;

/// Returns a signature of the [message].
typedef List<int> Signer(String message);

/// Verifies the [signature] of the [message].
typedef bool Verifier(String message, List<int> signature);
