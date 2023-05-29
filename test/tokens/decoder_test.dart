import 'package:test/test.dart';
import 'package:just_jwt/src/tokens.dart';

void main() {
  final EncodedJwt encodedJwt = new _EncodedJwt();
  late Decoder decoder;

  group('Decoding of a valid EncodedJwt ', () {
    late Jwt jwt;

    setUp(() {
      var verifier = (ToVerify toVerify) async => true;
      decoder = new Decoder(verifier);
    });

    setUp(() async {
      jwt = await decoder.convert(encodedJwt);
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

  group('Decoding of an EncodedJwt with an invalid signature ', () {
    setUp(() {
      var verifier = (ToVerify toVerify) async => false;
      decoder = new Decoder(verifier);
    });

    test('should throws an InvalidJwtSignatureError.', () async {
      var expectedError = const TypeMatcher<JwtVerificationError>();
      expect(decoder.convert(encodedJwt), throwsA(expectedError));
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
