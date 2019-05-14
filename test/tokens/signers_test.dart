import 'package:test/test.dart';
import 'package:just_jwt/src/tokens.dart';
void main() {
  final Jwt jwt = new _Jwt();
  final toSign = new ToSign(jwt, 'a', 'b');

  test('Should transform Signer into TokenSigner.', () async {
    var signer = (String message) => message.codeUnits;
    var tokenSigner = toTokenSigner(signer);

    expect(await tokenSigner(toSign), equals('a.b'.codeUnits));
  });

  group('A multiple signers composition', () {
    var signers;

    setUp(() {
      signers = <String, TokenSigner>{
        'alg2': (ToSign toSign) async => [2],
        'alg3': (ToSign toSign) async => [3],
      };
    });

    test('should create signer without support for required algorithm.', () {
      var signer = composeTokenSigners(signers);
      var expectedError = const TypeMatcher<UnsupportedSigningAlgError>();

      expect(() => signer(toSign), throwsA(expectedError));
    });

    test('should create signer with support for required algorithm.', () {
      signers['alg1'] = (ToSign toSign) => [1];
      var signer = composeTokenSigners(signers);

      expect(signer(toSign), equals([1]));
    });
  });
}

class _Jwt implements Jwt {
  @override
  String get alg => 'alg1';

  @override
  Map<String, String> get header => null;

  @override
  Map<String, dynamic> get payload => null;
}
