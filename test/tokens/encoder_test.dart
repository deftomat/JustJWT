import 'package:test/test.dart';
import 'package:just_jwt/src/tokens.dart';

void main() {
  final Jwt jwt = new _Jwt();
  Encoder encoder;

  group('Encoding of a Jwt', () {
    final List<int> signature = [0, 1, 2];
    EncodedJwt encodedJwt;

    setUp(() {
      var signers = {'HS256': (message) => signature};
      encoder = new Encoder(signers);
    });

    setUp(() {
      encodedJwt = encoder.convert(jwt);
    });

    test('should create an EncodedJwt with an expected header.', () {
      expect(encodedJwt.header, equals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
    });

    test('should create an EncodedJwt with an expected payload.', () {
      expect(encodedJwt.payload, equals('eyJjbGFpbSI6InZhbHVlIn0='));
    });

    test('should create an EncodedJwt with an expected signature.', () {
      expect(encodedJwt.signature, equals('AAEC'));
    });
  });

  group('Encoding of an Jwt with an unsupported algorithm ', () {
    setUp(() {
      var signers = {'another': (message) => 'signature'};
      encoder = new Encoder(signers);
    });

    test('should throws an UnsupportedSigningAlgError.', () {
      var expectedError = new isInstanceOf<UnsupportedSigningAlgError>();
      expect(() => encoder.convert(jwt), throwsA(expectedError));
    });
  });
}

class _Jwt implements Jwt {
  @override
  String get alg => 'HS256';

  @override
  Map<String, String> get header => {'alg': 'HS256', 'typ': 'JWT'};

  @override
  Map<String, dynamic> get payload => {'claim': 'value'};
}
