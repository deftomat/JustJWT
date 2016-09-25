library just_jwt.signatures;

/// Verifiers the [signature] of the [message].
typedef bool Verifier(String message, String signature);

/// Returns a signature of the [message].
typedef String Signer(String message);
