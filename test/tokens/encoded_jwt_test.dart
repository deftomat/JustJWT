import 'package:test/test.dart';
import 'package:just_jwt/src/tokens.dart';

void main() {
  group('The EncodedJwt ', () {
    String header, payload, signature, stringifiedJwt;
    EncodedJwt encodedJwt;

    setUp(() {
      header = 'HEADER';
      payload = 'PAYLOAD';
      signature = 'SIGNATURE';
      stringifiedJwt = '$header.$payload.$signature';
      encodedJwt = new EncodedJwt(stringifiedJwt);
    });

    test('should has a properly parsed header string.', () {
      expect(encodedJwt.header, equals(header));
    });

    test('should has a properly parsed payload string.', () {
      expect(encodedJwt.payload, equals(payload));
    });

    test('should has a properly parsed signature string.', () {
      expect(encodedJwt.signature, equals(signature));
    });

    test('should be stringifiable.', () {
      expect(encodedJwt.toString(), equals(stringifiedJwt));
    });
  });

  test('Construction of EncodedJwt should throws an error when string is invalid.', () {
    var malformedJwt = 'header.payload';
    var expectedError = const TypeMatcher<CannotParseRawJwtError>();

    expect(() => new EncodedJwt(malformedJwt), throwsA(expectedError));
  });
}
