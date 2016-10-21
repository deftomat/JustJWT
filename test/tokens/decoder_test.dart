import 'package:test/test.dart';
import 'package:just_jwt/src/tokens.dart';

void main() {
  final EncodedJwt encodedJwt = new _EncodedJwt();
  Decoder decoder;

  group('Decoding of a valid EncodedJwt ', () {
    Jwt jwt;

    setUp(() {
      var verifiers = {'HS256': (message, signature) => true};
      decoder = new Decoder(verifiers);
    });

    setUp(() {
      jwt = decoder.convert(encodedJwt);
    });

    test('should create a Jwt with an expected header.', () {
      expect(jwt.header, equals({'alg': 'HS256', 'typ': 'JWT'}));
    });

    test('should create a Jwt with an expected payload.', () {
      expect(jwt.payload, equals({'claim': 'value'}));
    });

    test('should create a Jwt with an expected algorithm.', () {
      expect(jwt.alg, equals('HS256'));
    });
  });

  group('Decoding of an EncodedJwt with an unsupported algorithm ', () {
    setUp(() {
      var verifiers = {'another': (message, signature) => true};
      decoder = new Decoder(verifiers);
    });

    test('should throws an UnsupportedVerificationAlgError.', () {
      var expectedError = new isInstanceOf<UnsupportedVerificationAlgError>();
      expect(() => decoder.convert(encodedJwt), throwsA(expectedError));
    });
  });

  group('Decoding of an EncodedJwt with an invalid signature ', () {
    setUp(() {
      var verifiers = {'HS256': (message, signature) => false};
      decoder = new Decoder(verifiers);
    });

    test('should throws an InvalidJwtSignatureError.', () {
      var expectedError = new isInstanceOf<InvalidJwtSignatureError>();
      expect(() => decoder.convert(encodedJwt), throwsA(expectedError));
    });
  });
}

class _EncodedJwt implements EncodedJwt {
  @override
  String get header => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

  @override
  String get payload => 'eyJjbGFpbSI6InZhbHVlIn0';

  @override
  String get signature => 'DWYUYxNvKDWUU5ILY3qive7eXYgUeZb9mUzuaGW6tT8';
}
