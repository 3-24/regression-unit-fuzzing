#!/bin/bash

set -e
set -o xtrace

AFL_FUZZ=$HOME/regression-unit-framework/tools/AFLplusplus/afl-fuzz

export AFL_NO_UI=1

for i in {0..15}; do
	( timeout 43200 $AFL_FUZZ -b $i -i ./seed -o ./out_$i -- $1 @@ ) &
done

wait
