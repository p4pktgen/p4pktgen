#! /bin/bash

for p in *.p4
do
    j=`basename $p .p4`.json
    p4c-bm2-ss $* "$p" -o "$j" >& /dev/null
    exit_status=$?
#    if [ $exit_status != 0 ]
#    then
#	echo "---------- $p ----------"
#	echo "p4c-bm2-ss exit status:" $exit_status
#    fi

    if [ -e "$j" ]
    then
	echo "---------- $p ----------"
	~/p4pktgen/tools/bmv2-json-check.py "$j"
	
	# Run simple_switch only for purposes of running its built-in
	# checks to see if there are known problems with the bmv2 JSON
	# file contents.
	simple_switch --use-files 0 -i 0@0 "$j"
    fi
done
