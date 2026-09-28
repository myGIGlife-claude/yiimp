### Welcome to the cryptopool.builders github!
### This fork of YiiMP is designed to work with our Ultimate Crypto-Server Installer program.
Trying to install this on a server not built by our installer will cause headaches, frustrations, and screaming loudly at your monitor.

#### Please go to https://github.com/mygiglifeinc-glitch/Multi-Pool-Installer for our installer.

## Requirements

- Ubuntu 22.04, 24.04 or 26.04 LTS (x86_64)
- PHP 8.1 or newer (the installer uses PHP 8.3); the bundled Yii framework is 1.1.32
- MariaDB 10.6 or newer
- Stratum build: `build-essential pkg-config libmysqlclient-dev libcurl4-openssl-dev libssl-dev libgmp-dev`
  (`make -C stratum`, then `make -C stratum hashtest && stratum/hashtest` to check the hash functions)

### KawPoW family stratums

`kawpow` (RVN and forks), `evrprogpow` (EVR), `meowpow` (MEWC), `firopow` (FIRO), `sccpow` (SCC)
and `meraki` (TLS) use the KawPoW pool protocol (kawpowminer, T-Rex, NBMiner, TeamRedMiner...),
ports 9501-9506 in `stratum/config.sample`. No extra build dependency. Every stratum keeps the
light cache of the current and next epoch of each coin in memory (16 MB + 128 KB per epoch each: ~95 MB
for RVN or FIRO today, ~145 MB for MEWC) and verifies each share from it (~20 ms of CPU).
Share difficulty 1 is ~2^32 hashes, like a sha256 share: the algos need no web hashrate factor.

### Zcash family stratums

`equihash` (200,9: ZEC, KMD, ARRR...), `equihash144` (144,5: BTG, BTCZ, GLINK...) and
`equihash192` (192,7: YEC, ZCL, ZER...) use the ZIP-301 stratum of the Equihash miners (lolMiner,
GMiner, miniZ...), ports 9600-9602; `yespowerRES` (Resistance) uses the Bitcoin stratum of its
miner with a 140 byte header, port 9650. No extra build dependency. The Zcash daemons build the
coinbase (founders reward, funding streams...) and pay their `mineraddress` (zcashd) or a wallet
key; Bitcoin Gold needs segwit enabled on the coin. The Equihash parameters and the BLAKE2b
personalization can be set per stratum and per coin in the .conf (`equihash_n`, `equihash_k`,
`equihash_personalization`, `[EQUIHASH]` section), e.g. 48,5 for the zcashd regtest. Share
difficulty 1 is 8192 solutions (target 0x0007ffff..): the web hashrate constant of the equihash
algos is 2^23 (Sol/s) instead of 2^42.
Daemon blocknotify: `blocknotify=/path/blocknotify 127.0.0.1:<stratum port> <coin id> %s` (the
TCP port of the stratum of the coin's algo, e.g. 9600 for equihash). The daemons log
`runCommand error: system(... blocknotify ...) returned 256` when that stratum is not listening
(e.g. blocks made by `generate` before the stratum starts): harmless, blocknotify exits 1 then.

Coins can be given their own stratum port with the *Dedicated Port* setting on the coin page;
the old `multi-port` branch is no longer needed.

## Changes to this fork include but not limited to:

```
- File structure -
$STORAGE_ROOT/yiimp/site/web
$STORAGE_ROOT/yiimp/site/stratum (Only on single server installs)
$STORAGE_ROOT/yiimp/site/configuration
$STORAGE_ROOT/yiimp/site/crons
$STORAGE_ROOT/yiimp/site/log
$STORAGE_ROOT/yiimp/starts

- Site Files-
Updated various files to work with new file structure
```


## Donations for continued support of this script are welcomed at:
* BTC 3DvcaPT3Kio8Hgyw4ZA9y1feNnKZjH7Y21
* BCH qrf2fhk2pfka5k649826z4683tuqehaq2sc65nfz3e
* ETH 0x6A047e5410f433FDBF32D7fb118B6246E3b7C136
* LTC MLS5pfgb7QMqBm3pmBvuJ7eRCRgwLV25Nz

## Credits:

* Thanks to tpruvot for the yiimp release
* Thanks to mailinabox for the installer idea
