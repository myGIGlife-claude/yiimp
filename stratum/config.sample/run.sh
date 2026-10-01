#!/bin/bash

ulimit -n 10240
ulimit -u 10240

cd /var/stratum || exit 1
while true; do
        ./stratum "/var/yaamp/config/$1"
	sleep 2
done
exec bash

