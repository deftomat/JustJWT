# Changelog

## 1.0.0

- Initial version

# 1.1.0

- Signer/Verifier works with List\<int> instead of String.

# 1.1.1

- Works with non-padded BASE64 strings.

# 1.2.1

- Improved Signers/Verifiers composition.
- New ```createJwaRS256Verifier``` function which creates a RSA256 verifier from encoded modulus and encoded exponent as described in RFC 7518.
