#! /bin/bash

# Recompile many selected P4 source programs using the current version
# of p4c-bm2-ss in your path.  Useful if a new version of p4c-bm2-ss
# fixes a bug in the way it generates JSON for bmv2.


ls -l `which p4c-bm2-ss`

for j in examples/*.p4
do
    k=x/`basename $j .p4`.json
    echo "+ p4c-bm2-ss ${j} -o ${k}"
    p4c-bm2-ss ${j} -o ${k}
done
