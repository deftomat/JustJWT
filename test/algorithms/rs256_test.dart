import 'package:test/test.dart';
import 'package:just_jwt/src/algorithms/rs256.dart';
import 'package:just_jwt/src/signatures.dart';

void main() {
  final String privateKey = '-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n-----END RSA PRIVATE KEY-----';
  final String publicKey = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n-----END PUBLIC KEY-----';
  final String message = 'message';
  final String corruptedMessage = 'corrupted_message';
  final String expectedSignature = 'xlkFbDN1BEqngjC0HKrmJh9k9KANzvpwdRf8xJuRLpF5zdMG0F7Ln6bx2Dr6tzWejGXGEokub8JW-yzolLbrgABHHQPIP4Vd81eWTE-r8DXvjWcOc_i27RD0py8v6moGKsssYnJrgEFtYksyG4_MS5k-LO8vHI2l34eTaWxLEss=';

  group('The RS256 signer ', () {
    Signer signer;

    setUp(() {
      signer = createRS256Signer(privateKey);
    });

    test('should generates an expected signature.', () {
      expect(signer(message), equals(expectedSignature));
    });

    test('should generates an unexpected signature', () {
      expect(signer(corruptedMessage), isNot(equals(expectedSignature)));
    });
  });

  group('The RS256 verifier ', () {
    Verifier verifier;

    setUp(() {
      verifier = createRS256Verifier(publicKey);
    });

    test('should succesfully verifies a signature.', () {
      expect(verifier(message, expectedSignature), isTrue);
    });

    test('should rejects the corrupted message.', () {
      expect(verifier(corruptedMessage, expectedSignature), isFalse);
    });
  });
}
