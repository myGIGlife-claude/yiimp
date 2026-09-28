#!/bin/bash
# addcoin.sh name symbol algo wallet rpcport usesegwit
mysql -uroot yiimp_kawpow -e "insert into coins (name,symbol,algo,master_wallet,deposit_minimum,dontsell,difficulty,reward,reward_mul,enable,auto_ready,visible,no_explorer,created,conf_folder,program,rpcuser,rpcpasswd,rpchost,rpcport,rpccurl,rpcssl,rpcencoding,account,hasgetinfo,hassubmitblock,hasmasternodes,usesegwit,multialgos,installed,watch,usefaucet) values ('$1','$2','$3','$4',1,1,1,1,1,1,1,1,0,unix_timestamp(),'x','d','kp','kppass','127.0.0.1',$5,0,0,'POW','',0,1,0,$6,0,1,0,0)"
mysql -uroot -N yiimp_kawpow -e "select id from coins where symbol='$2'"
