import 'package:test/test.dart';
import 'package:just_jwt/src/algorithms/hs256.dart';
import 'package:just_jwt/src/signatures.dart';

void main() {
  final String key = 'secret';
  final String message = 'message';
  final String corruptedMessage = 'corrupted_message';
  final String expectedSignature = 'i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=';

  group('The HS256 signer ', () {
    Signer signer;

    setUp(() {
      signer = createHS256Signer(key);
    });

    test('should generates an expected signature.', () {
      expect(signer(message), equals(expectedSignature));
    });

    test('should generates an unexpected signature.', () {
      expect(signer(corruptedMessage), isNot(equals(expectedSignature)));
    });
  });

  group('The HS256 verifier ', () {
    Verifier verifier;

    setUp(() {
      verifier = createHS256Verifier(key);
    });

    test('should succesfully verifies a signature.', () {
      expect(verifier(message, expectedSignature), isTrue);
    });

    test('should rejects the corrupted message.', () {
      expect(verifier(corruptedMessage, expectedSignature), isFalse);
    });
  });
}
