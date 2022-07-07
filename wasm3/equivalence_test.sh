#!/bin/bash
#
#  Copyright 2022 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Run both the cc_binary and wasm_cc_binary using the wasm3 interpreter to see
# if the print the same thing to stdout.

source testing/shbase/googletest.sh

set -x

if [[ $# != 4 ]]; then
  die "Wrong number of arguments: $#.  Expected <executable> <bytecode.wasm> <bin_result_code> <wasm_result_code>"
fi

binary="$1"
wasm_bytecode="$2"
bin_result_code="$3"
wasm_result_code="$4"
shift 4

if [[ ! -x "$binary" ]]; then
  die "$binary either does not exist, or is not executable"
fi
if [[ ! -e "$wasm_bytecode" ]]; then
  die "$wasm_bytecode does not exist"
fi

$binary > "${TEST_TMPDIR}/bin_result"
result_code=$?
if [[ "$result_code" != "$bin_result_code" ]]; then
  die "Execution of $binary returned $result_code, expected $bin_result_code"
fi
third_party/sealedcomputing/wasm3/enforcer/enforcer "$wasm_bytecode" > "${TEST_TMPDIR}/enforcer_result"
result_code=$?
if [[ "$result_code" != "$wasm_result_code" ]]; then
  die "Execution of enforcer returned $result_code, expected $wasm_result_code"
fi
cat "${TEST_TMPDIR}/bin_result"
cat "${TEST_TMPDIR}/enforcer_result"
# They should not be expected to behave the same if they return different errors.
if [[ "$bin_result_code" == "$wasm_result_code" ]]; then
  cmp "${TEST_TMPDIR}/bin_result" "${TEST_TMPDIR}/enforcer_result" || die "Equivalence test failed: different outputs"
fi

echo "PASS"
