import 'package:test/test.dart';
import 'package:just_jwt/src/tokens.dart';

void main() {
  group('The HS256 JWT ', () {
    testJwt((Map<String, dynamic> payload) => new Jwt.HS256(payload), 'HS256');
  });

  group('The RS256 JWT ', () {
    testJwt((Map<String, dynamic> payload) => new Jwt.RS256(payload), 'RS256');
  });
}

testJwt(jwtFactory(Map<String, dynamic> payload), String expectedAlgorithm) {
  late Jwt jwt;
  late Map<String, dynamic> payload;

  setUp(() {
    payload = <String, dynamic>{'claim': 'value'};
    jwt = jwtFactory(payload);
  });

  test('should has a valid header.', () {
    var expectedHeader = {'alg': expectedAlgorithm, 'typ': 'JWT'};
    expect(jwt.header, equals(expectedHeader));
  });

  test('should has a given payload.', () {
    expect(jwt.payload, equals(payload));
  });

  test('should has an expected algorithm.', () {
    expect(jwt.alg, equals(expectedAlgorithm));
  });
}
