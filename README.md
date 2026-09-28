### Welcome to the cryptopool.builders github!
### This fork of YiiMP is designed to work with our Ultimate Crypto-Server Installer program.
Trying to install this on a server not built by our installer will cause headaches, frustrations, and screaming loudly at your monitor.

#### Please go to https://github.com/mygiglifeinc-glitch/Multi-Pool-Installer for our installer.

## Requirements

- Ubuntu 22.04, 24.04 or 26.04 LTS (x86_64)
- PHP 8.1 or newer (the installer uses PHP 8.3); the bundled Yii framework is 1.1.32
- MariaDB 10.6 or newer
- Stratum build: `build-essential pkg-config libmysqlclient-dev libcurl4-openssl-dev libssl-dev libgmp-dev`
  (`make -C stratum`, then `make -C stratum hashtest && stratum/hashtest` to check the hash functions
  against known test vectors)
- The stratum is built for `x86-64-v2` CPUs by default. Use `make MARCH=native` to tune it for
  the build machine, but then the binary only runs on that type of CPU.

## Algos added in this fork

- **Bitcoin stratum:** argon2d-uis, blake3 (raw BLAKE3-256, port 9661), flex, ghostrider, groestl, mike, minotaurx, phi1612,
  sha512256d, skein2, verthash, whirlcoin, whirlpoolx, x17r, zr5, and the yespower algos
  yespowerARWN, yespowerLITB, yespowerLTNCG, yespowerMGPC, yespowerSUGAR, yespowerTIDE,
  yespowerurx and yespowerRES.
- **Their own stratum protocols** (each described below):
  - KawPoW family: kawpow, evrprogpow, meowpow, firopow, sccpow, meraki.
  - Zcash family: equihash, equihash144, equihash192.
  - Decred: `decred`, updated for BLAKE3.
  - Monero: randomx.
- **Litecoin MWEB:** the stratum mines MWEB blocks, using the `mweb` getblocktemplate rule.
- **verthash:** needs `verthash.dat`. Build the generator with `make -C stratum verthash_gen`,
  then run `./verthash_gen verthash.dat` (1.2 GB) in the stratum directory.
- **Build fix:** the stratum is now built with `-fno-strict-aliasing`. Without it, gcc
  miscompiled BMW-256, which broke the bmw, lyra2v2, lyra2v3 and lbk3 hashes.

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

### Decred stratum

`decred` (port 3252) mines Decred, whose proof of work has been BLAKE3 since block 794,368.
- **Work:** comes from dcrd's getwork. dcrd must run with `--miningaddr=<pool wallet>`.
- **Blocks:** confirmed by `blocknotify-dcr` (Go 1.21+):
  `make -C blocknotify-dcr install`, then
  `blocknotify-dcr -stratum 127.0.0.1:3252 -coinid <id> -rpcuser <user> -rpcpass <pass> -rpccert <rpc.cert>`.

### Monero (RandomX) stratum

`randomx` (port 9701) mines Monero with the xmrig protocol (xmrig, XMRig-proxy).
- **Work and blocks:** templates come from monerod `get_block_template`, and blocks go out with
  `submit_block`.
- **Shares:** each miner gets its own job blob. Shares are checked with RandomX light mode, using
  up to about 800 MB of caches and about 20-40 ms of CPU per share.
- **Vendored code:** RandomX comes from tevador/RandomX (BSD-3) and supports v1 and v2. Set
  `randomx_v2` in the .conf to use v2 after a network fork.
- **monerod:** run it with `--rpc-login` and
  `--block-notify '<path>/blocknotify 127.0.0.1:9701 <coin id> %s'`.
- **Coin and payouts:**
  - Set the coin's *RPC Type* to `XMR`.
  - Payouts go through monero-wallet-rpc with `transfer_split`. Set its location with
    `$configWalletRPC['XMR'] = 'host:port:user:pass';` in serverconfig.php. The default is the
    daemon host at RPC port + 1.
  - The pool wallet must be the coin's master wallet.
- **Testing:** payouts have been tested only once, on a private test network.

### Other stratum engines

If an algo can't be added to this stratum, a separate stratum program can feed YiiMP instead. It
has to write the same database tables and implement the same wallet calls. See
[docs/BRIDGE.md](docs/BRIDGE.md) for that contract, with randomx as the worked example.

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
