#!/bin/bash

# Fast fail the script on failures.
set -e

# Run the tests.
pub run test -p vm,content-shell

# Install dart_coveralls; gather and send coverage data.
if [ "$COVERALLS_TOKEN" ] && [ "$TRAVIS_DART_VERSION" = "stable" ]; then
  pub global activate dart_coveralls
  pub global run dart_coveralls report \
    --retry 2 \
    --exclude-test-files \
    test/test_all.dart
fi
