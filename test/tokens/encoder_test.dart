import 'package:test/test.dart';
import 'package:just_jwt/src/tokens.dart';

void main() {
  final Jwt jwt = new _Jwt();
  late Encoder encoder;

  group('Encoding of a Jwt', () {
    final List<int> signature = [0, 1, 2];
    late EncodedJwt encodedJwt;

    setUp(() {
      var signer = (ToSign toSign) async => signature;
      encoder = new Encoder(signer);
    });

    setUp(() async {
      encodedJwt = await encoder.convert(jwt);
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
}

class _Jwt implements Jwt {
  @override
  String get alg => 'HS256';

  @override
  Map<String, String> get header => {'alg': 'HS256', 'typ': 'JWT'};

  @override
  Map<String, dynamic> get payload => {'claim': 'value'};
}
