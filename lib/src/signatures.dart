library just_jwt.signatures;

/// Verifiers the [signature] of the [message].
typedef bool Verifier(String message, List<int> signature);

/// Returns a signature of the [message].
typedef List<int> Signer(String message);
