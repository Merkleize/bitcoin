#!/bin/bash

dir=$(
./build/test/functional/test_runner.py --nocleanup test/functional/feature_checkcontractverify.py 2>&1 \
| tee /dev/stderr \
| sed -n 's/^Temporary test directory at //p'
)

echo "Extracted path: $dir"

echo "Combining logs"

./build/test/functional/combine_logs.py "$dir/feature_checkcontractverify_0" >ccv_logs.txt

echo "Filtering logs"

grep -E 'OP_CHECKCONTRACTVERIFY|Broadcast txid=' ccv_logs.txt >ccv_logs_filtered.txt

echo "Generating test vectors"

python parse_ccv_logs.py
