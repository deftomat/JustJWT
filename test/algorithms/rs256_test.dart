import 'package:test/test.dart';
import 'package:just_jwt/src/algorithms/rs256.dart';
import 'package:just_jwt/src/signatures.dart';

void main() {
  final String privateKey =
      '-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n-----END RSA PRIVATE KEY-----';
  final String publicKey =
      '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n-----END PUBLIC KEY-----';
  final encodedModulus =
      '3ZWrUY0Y6IKN1qI4BhxR2C7oHVFgGPYkd38uGq1jQNSqEvJFcN93CYm16/G78FAFKWqwsJb3Wx+nbxDn6LtP4AhULB1H0K0g7/jLklDAHvI8yhOKlvoyvsUFPWtNxlJyh5JJXvkNKV/4Oo12e69f8QCuQ6NpEPl+cSvXIqUYBCs=';
  final encodedExponent = 'AQAB';

  final String message = 'message';
  final String corruptedMessage = 'corrupted_message';
  final List<int> expectedSignature = [
    198,
    89,
    5,
    108,
    51,
    117,
    4,
    74,
    167,
    130,
    48,
    180,
    28,
    170,
    230,
    38,
    31,
    100,
    244,
    160,
    13,
    206,
    250,
    112,
    117,
    23,
    252,
    196,
    155,
    145,
    46,
    145,
    121,
    205,
    211,
    6,
    208,
    94,
    203,
    159,
    166,
    241,
    216,
    58,
    250,
    183,
    53,
    158,
    140,
    101,
    198,
    18,
    137,
    46,
    111,
    194,
    86,
    251,
    44,
    232,
    148,
    182,
    235,
    128,
    0,
    71,
    29,
    3,
    200,
    63,
    133,
    93,
    243,
    87,
    150,
    76,
    79,
    171,
    240,
    53,
    239,
    141,
    103,
    14,
    115,
    248,
    182,
    237,
    16,
    244,
    167,
    47,
    47,
    234,
    106,
    6,
    42,
    203,
    44,
    98,
    114,
    107,
    128,
    65,
    109,
    98,
    75,
    50,
    27,
    143,
    204,
    75,
    153,
    62,
    44,
    239,
    47,
    28,
    141,
    165,
    223,
    135,
    147,
    105,
    108,
    75,
    18,
    203
  ];

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

  group('The JWA RS256 verifier ', () {
    Verifier verifier;

    setUp(() {
      verifier = createJwaRS256Verifier(encodedModulus, encodedExponent);
    });

    test('should succesfully verifies a signature.', () {
      expect(verifier(message, expectedSignature), isTrue);
    });

    test('should rejects the corrupted message.', () {
      expect(verifier(corruptedMessage, expectedSignature), isFalse);
    });
  });
}
