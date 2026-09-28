#!/bin/bash
# strat.sh algo port [extra STRATUM lines]
K=/tmp/claude-0/-home-user/940fe17f-d697-51b7-8fd2-02f52b656791/scratchpad/kp
cd $K/strat
a=$1 p=$2; shift 2
sed -e "s/port = 9501/port = $p/; s/algo = kawpow/algo = $a/" kawpow.conf > $a.conf
for l in "$@"; do sed -i "s/^diff_max = 1000/diff_max = 1000\n$l/" $a.conf; done
(./stratum2 $a > $a.out 2>&1 &)
