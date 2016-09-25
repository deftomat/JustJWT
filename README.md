# JustJWT

[![Build Status](https://travis-ci.org/deftomat/JustJWT.svg?branch=master)](https://travis-ci.org/deftomat/JustJWT)

A simple JWT library for Dart with support for custom signature algorithms.

Library already supports HS256 and RS256 algorithms.

## Usage

A simple encoding example:

    import 'package:just_jwt/just_jwt.dart';

    main() {
      var signers = {
        'HS256': createHS256Signer('secret')
        'RS256': createRS256Signer('<private key>'),
        // additional supported algorithms
      };
      
      // Creates JWT encoder which supports ONLY tokens with HS256 or RS256 alg.
      var encoder = new Encoder(signers);
      
      var jwt = new Jwt.HS256({'some': 'value'});
      // or var jwt = new Jwt.RS256({'some': 'value'});
      
      // Encodes JWT
      var encodedJwt = encoder.convert(jwt);
      print(encodedJwt);
    }
    
A simple decoding example:

    import 'package:just_jwt/just_jwt.dart';

    main() {
      var verifiers = {
        'HS256': createHS256Verifier('secret'),
        'RS256': createRS256Verifier('<public key>'),
        // additional supported algorithms
      };
      
      // Creates decoder which support ONLY tokens with HS256 or RS256 alg.
      // Unsupported algorithm will cause an UnsupportedVerificationAlgError.
      var decoder = new Decoder(verifiers);
      
      var encodedJwt = new EncodedJwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoidmFsdWUifQ==.ZHaHisAt9O9fcGFAFanEvsRjlSqAELN7NdXvue-E1PQ=');
      
      var jwt = decoder.convert(encodedJwt);
    }

## Custom algorithm

Algorithm name is always stored in JWT. Encoders/Decoders tries to find a Signer/Verifier by its name in signers/verifiers map.

To support custom algorithm, just implement a [JWT interface](https://github.com/deftomat/JustJWT/blob/master/lib/src/tokens/jwt.dart) and create your own [Verifier/Signer](https://github.com/deftomat/JustJWT/blob/master/lib/src/signatures.dart).

