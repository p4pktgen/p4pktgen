#! /bin/bash

# Recompile many selected P4 source programs using the current version
# of p4c-bm2-ss in your path.  Useful if a new version of p4c-bm2-ss
# fixes a bug in the way it generates JSON for bmv2.


ls -l `which p4c-bm2-ss`

for j in demo1-action-names-uniquified.p4_16 demo1.p4_16 demo2.p4_16 demo8 demo9b demo9 demo10b demo10 demo11 demo14 demo15 demo16 tcp-options-parser2
do
    echo "+ p4c-bm2-ss p4_programs/${j}.p4 -o compiled_p4_programs/${j}.json"
    p4c-bm2-ss p4_programs/${j}.p4 -o compiled_p4_programs/${j}.json
done
