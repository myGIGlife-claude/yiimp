#!/bin/bash
# start a 2 node regtest pair: pair.sh name daemon conffile rpcport p2pport section(0/1) [extra conf lines...]
K=/tmp/claude-0/-home-user/940fe17f-d697-51b7-8fd2-02f52b656791/scratchpad/kp
name=$1 daemon=$2 conf=$3 rpc=$4 p2p=$5 sect=$6; shift 6
for n in 1 2; do
  d=$K/$name$n; mkdir -p "$d"
  {
    echo regtest=1; echo server=1; echo rpcuser=kp; echo rpcpassword=kppass; echo rpcallowip=127.0.0.1
    [ "$sect" = 1 ] && echo "[regtest]"
    echo "rpcport=$((rpc + n - 1))"; echo "port=$((p2p + n - 1))"; echo bind=127.0.0.1
    if [ "$n" = 2 ]; then echo "connect=127.0.0.1:$p2p"; else echo listen=1; for l in "$@"; do echo "$l"; done; fi
  } > "$d/$conf"
  "$daemon" -datadir="$d" -daemon
  sleep 3
done
