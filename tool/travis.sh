#!/bin/bash

# Fast fail the script on failures.
set -e

# Run the tests.
pub run test -p vm,content-shell
