import 'package:test/test.dart';
import 'package:just_jwt/src/tokens.dart';

void main() {
  final Jwt jwt = new _Jwt();
  final EncodedJwt encodedJwt = new _EncodedJwt();
  final toVerify = new ToVerify(jwt, encodedJwt, [0, 1, 2]);

  test('Should transform SignatureVerifier into TokenVerifier.', () async {
    var verifier = (String message, List<int> signature) {
      return message == 'h.p' && signature == toVerify.signature;
    };
    var tokenVerifier = toTokenVerifier(verifier);

    expect(await tokenVerifier(toVerify), isTrue);
  });

  test('Should combine multiple verifiers.', () async {
    var verifiers = [
      (ToVerify toVerify) async => true,
      (ToVerify toVerify) async => false
    ];
    var verifier = combineTokenVerifiers(verifiers);

    expect(await verifier(toVerify), isFalse);
  });

  group('A multiple verifiers composition', () {
    var verifiers;

    setUp(() {
      verifiers = {
        'alg2': (ToVerify toVerify) => [2],
        'alg3': (ToVerify toVerify) => [3],
      };
    });

    test('should create signer without support for required algorithm.', () {
      var verifier = composeTokenVerifiers(verifiers);
      var expectedError = const TypeMatcher<UnsupportedVerificationAlgError>();

      expect(() => verifier(toVerify), throwsA(expectedError));
    });

    test('should create signer with support for required algorithm.', () {
      verifiers['alg1'] = (ToVerify toVerify) => [1];
      var verifier = composeTokenVerifiers(verifiers);

      expect(verifier(toVerify), equals([1]));
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

class _EncodedJwt implements EncodedJwt {
  @override
  String get header => 'h';

  @override
  String get payload => 'p';

  @override
  String get signature => 's';
}
