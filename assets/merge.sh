#!/bin/bash

set -e

for i in {0..15};
do
	for f in ./out_$i/default/queue/* ;
	do
		filename=$(basename $f)
		cp $f ./integrated/${i}_${filename}
	done
done

fdupes -I ./integrated
