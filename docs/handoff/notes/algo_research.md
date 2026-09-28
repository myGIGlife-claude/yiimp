# Algorithms missing from this YiiMP fork: research (2026-09-25)

## Method and data sources

- **Activity data.** I pulled a live snapshot of miningpoolstats.stream (MPS) on 2026-09-25. It has 534 coins with per-coin pool counts and market caps. I aggregated it by algorithm. Link: https://miningpoolstats.stream/ (data feed `data.miningpoolstats.stream/data/coins_data.js`).
- **What yiimp-style pools actually run.**
  - Live zpool.ca API (`/api/status`, `/api/currencies`): 73 algos, with ports, `mbtc_mh_factor` and live workers per coin. zpool runs a yiimp-derived stack. https://www.zpool.ca/api/status
  - rplant.xyz API: https://pool.rplant.xyz/api/currencies
  - mining-dutch.nl API: https://www.mining-dutch.nl/api/status/
  - zergpool.com returned Cloudflare 522 (origin down) the whole session, so it could not be checked.
- **Miner algo lists.**
  - cpuminer-opt README: https://raw.githubusercontent.com/JayDDee/cpuminer-opt/master/README.md
  - SRBMiner-MULTI README: https://raw.githubusercontent.com/doktor83/SRBMiner-Multi/master/README.md
  - RainbowMiner miner config tables, which carry the yespower `--param-n/r/key` strings: https://raw.githubusercontent.com/RainbowMiner/RainbowMiner/refs/heads/master/Miners/CpuminerJayddee.ps1 and `.../CpuminerRplant.ps1`
- **Local check.** I confirmed the supported list against `stratum/stratum.cpp` in `/home/user/yiimp`. It matches the brief exactly.
  - Existing argon2d entries: `argon2d-crds` = 250 KiB / 4 lanes / t=1, `argon2d-dyn` = 500 KiB / 8 lanes / t=2, `argon2d-uis` = 4096 KiB / 4 lanes / t=1. So zpool's `argon2d500` and `argon2d4096` are already covered. `argon2d1000` and `argon2d16000` are not.
  - `scryptn` is fixed at N=2048. That covers MPS "ScryptN11" (FujiCoin) but not `scryptn2` (N=1048576).
  - **`yescrypt` (all variants) is NOT in the list.** It is missing, even though tpruvot-era pools often had it.

"Activity" below uses MPS pool count (p), MPS market cap and live zpool/rplant worker counts (w). Many small coins show $0 market cap on MPS only because it has no price feed.

---

## 1. Missing algorithms with actively mined coins

### Category A: Bitcoin-derived daemon, getblocktemplate + stratum v1, 80-byte header, new hash only

| algo (pool name) | notable coins | approx. activity (Sep 2026) | HW | cat | reference implementation / license | special notes |
|---|---|---|---|---|---|---|
| `ghostrider` (a.k.a. `gr`) | RTM (Raptoreum), FBIT, YERB, BBC, MTBC, GPRX, FUEC, BTRM, TAFT, ~32 clones | 32 coins / 117 pools on MPS. RTM 23p. zpool: 7,199 workers (largest CPU algo there). rplant: 75 w. | CPU | A | Raptoreum Core (MIT, Dash-derived). Also xmrig (GPL-3) and cpuminer-gr. | Dash-style coinbase: **smartnode payments + "founder" payment** + DIP3/DIP4 CbTx `coinbase_payload`. Hash order is chosen from prevhash (header bytes 4–36). High CPU cost per hash, so verify shares sparingly. |
| `mike` | VKAX, FTB (FortuneBlock) | 2 coins / 2p. zpool 17 w. | CPU | A | GhostRider variant (xmrig PR #3131, xmrigCC-vkax, GPL-3) | Same caveats as ghostrider (Dash-like coinbase). |
| `minotaurx` | MAZA, LCC (Litecoin Cash), CAS, AVN, OBD, PLSR, PLHV | 7 coins / 31p. zpool MAZA ~4,468 w. rplant CAS/OBD. | CPU | A | AvianNetwork `minotaurx_hash` (MIT/X11) | **Multi-algo chains**: LCC (sha256d+minotaurx+Hive), AVN (x16rt+minotaurx) and PLSR (curvehash+minotaurx) select the algo by header version bits. The pool must send and verify the right version. |
| `flex` | KCN (Kylacoin), LCN (Lyncoin) | 2 coins / 5p. zpool KCN 58 w, LCN 47 w. | CPU | A | Flex Labs cores; cpuminer-opt (tpfuemp fork) / SRBMiner (closed) | **LCN is merge-mined with KCN via AuxPoW** (lyncoin.com/about). 60 s blocks. Exact hash chain is **unverified** (see §3). |
| `yespowerR16` | YTN (Yenten), RMC | 1 coin / 10p on MPS. zpool 115 w. rplant YTN 51 + RMC 19 w. | CPU | A | openwall yespower 1.0 (BSD-2) | Same code as existing `yespower`, only parameters change. |
| `yespowerTIDE` | TDC (Tidecoin) | 6p. zpool **1,243 w**. rplant **2,015 w**. | CPU | A | yespower 1.0 (BSD-2) | Post-quantum signatures (Falcon). Tx/script sizes are larger but the header is still 80 bytes. |
| `yespowerSUGAR` | SUGAR (Sugarchain) | 3p. zpool 60 w. | CPU | A | yespower 1.0 | 5 s blocks. Needs fast job refresh. |
| `yespowerADVC` | ADVC (AdventureCoin) | 5p. zpool 200 w. rplant 14 w. | CPU | A | yespower 1.0 | **10% of reward to dev/community/charity/council outputs** (bitcointalk ANN). The coinbase must add these outputs. Yenten fork. |
| `yespowerLTNCG` | CRNC | 2p. zpool 10 w. | CPU | A | yespower 1.0 | – |
| `yespowerMGPC` | MGPC (Magpiecoin) | 3p. zpool 5 w. | CPU | A | yespower 1.0 | – |
| `yespowerEQPAY` | EQPAY (EquityPay) | zpool 27 w | CPU | A? | yespower 1.0 | EquityPay is an EVM/UTXO, **Qtum-style chain** (github.com/equitypay/eqpay). A Qtum-style header is larger than 80 bytes (state roots, prevoutStake, block signature). **Header layout unverified.** Parameters unverified. |
| `power2b` (`yespower-b2b`) | MBC (MicroBitcoin) | 3p. zpool 34 w. rplant **533 w**. | CPU | A | yespower 1.0 with BLAKE2b in place of SHA-256 (volbil/yespower, BSD-2) | – |
| `cpupower` | CPU (CPUchain) | 2p | CPU | A | yespower 1.0 | Small. |
| `yespowerARWN`, `yespowerRES`, `yespowerIC`, `yespowerLITB`, `yespowerMWC`, `interchained` | ARWN, RES, IC, LITB, (MWC on rplant), ITC | rplant `yespowermwc` 10 w. The rest are not on MPS/zpool. | CPU | A | yespower 1.0 | Mostly dead or tiny. They come nearly free once yespower is parameterized. |
| `yescrypt` | BSTY (GlobalBoost-Y), XMY (Myriad), ZNY | 6 coins / 10p. zpool **1,780 w** (BSTY). | CPU | A | yescrypt 0.5 (BSD-2, openwall) / cpuminer-opt | XMY is multi-algo (version bits). |
| `yescryptR8` | MTBC, ZNY | zpool 32 w | CPU | A | yescrypt 0.5 | – |
| `yescryptR16` | FNNC, GOLD, QOGE | 3 coins / 11p. zpool 289 w. | CPU | A | yescrypt 0.5 | – |
| `yescryptR32` | LPEPE, DMS | 2 coins / 8p. zpool 336 w. rplant 389 w. | CPU | A | yescrypt 0.5 | – |
| `sha512256d` | RXD (Radiant) | 13p, ~$0.9M. zpool 6 w. | ASIC (GPU legacy) | A | SHA-512/256 (FIPS 180-4), in OpenSSL / radiant-node (MIT) | BCH-derived (radiant-node). No segwit. Large blocks. zpool factor 1e6 (ASIC-scale hashrate). |
| `verthash` | VTC (Vertcoin) | 15p, ~$3.2M. zpool **474 w**. | GPU | A | Vertcoin Core / VerthashMiner (GPL-3) | Needs the **~1.2 GB `verthash.dat`** loaded in stratum RAM (generated deterministically from the genesis block). Segwit and standard GBT. |
| `sha3-256t` (`sha3t`) | BC3 (BitcoinIII), FJAR (Fjarcode) | BC3 20p. zpool 4 w. rplant BC3 14 w. | GPU/FPGA | A | SHA3-256 ×3 (Keccak FIPS-202). BitcoinIII-Core is Bitcoin Core v29.1 with only the PoW hash changed. | Trivial to add. |
| `heavyhash` (OBTC variant, not kHeavyHash) | OBTC (Optical Bitcoin), URSA | 2p. zpool 24 w. | GPU | A | obtc-core (MIT) | Matrix derived from prevhash via xoshiro, regenerated every block. Not the Kaspa one. |
| `skydoge` | SKYDOGE | 7p, ~$1.1M. zpool 34 w. rplant 59 w. | GPU | A | skydogenet/mainchain (Bitcoin/Drivechain fork, MIT) | "SHAndwich256" = sha256 → sha512 → sha256. **BIP300/301 drivechain**: the coinbase may carry optional BMM/M-message outputs. |
| `hoohash-pepew` | PEPEW (PepePow) | 4p. zpool 12 w. | GPU/CPU | A | PePe-core (Dash-derived). HooHash v1.1.0 (Hoosat, float matrix). | Algo changed at height 4,354,200 (memehash, then XelisV2, then HooHash V110). Floating-point: the reference implementation must be bit-exact. Dash-style masternode coinbase. |
| `rinhash` | RIN (Rincoin) | 3p. zpool 57 w. | CPU/GPU | A | Rin-coin/rincoin (Litecoin fork, MIT). BLAKE3 → Argon2d → SHA3-256. | Argon2d "64 KB, 2 iterations" per search snippet. Lanes/salt **unverified**. RainbowMiner lists a `rinhash2`, so a revision may exist (**unverified**). 60 s blocks. |
| `argon2d16000` | ADOT (Alterdot) | 2p. zpool 2 w. | CPU/GPU | A | Argon2 reference (CC0/Apache-2) | Dash-derived with masternodes. Memory is 16000 KiB. t_cost/lanes **unverified**. |
| `argon2d1000` | 0DYNC (Zero Dynamics Cash, rebranded Dynamic) | zpool 7 w | CPU/GPU | A | Argon2 reference | PoW+PoS hybrid with masternodes. Memory is 1000 KiB. t/lanes **unverified**. |
| `megabtx` | BTX (Bitcore) | 4p, ~$0.8M. zpool 22 w. | CPU/GPU | A | Bitcore (MIT) | Hash composition **unverified**. Replaced timetravel10 in 2020. |
| `megamec` | MEC (Megacoin) | zpool 14 w | CPU/GPU | A | Megacoin | Variant of Mega-BTX. **Unverified.** |
| `anime` | ANI (Animecoin) | 3p. zpool 10 w. | CPU/GPU | A | Quark-style chain (cpuminer-opt `anime`) | Old algo, revived. |
| `curvehash` | PLSR (Pulsar) | 1p. zpool 2 w. | CPU | A | Curvehash (secp256k1-based). **Details unverified.** | PLSR is multi-algo (curvehash + minotaurx) + PoS. |
| `soterg` | SOTER (Soteria) | zpool 1 w | GPU | A | Soteria (RVN/BTC-based). "12 dynamically rotated hashes, timestamped". | Likely x16rt-like. **Details unverified.** 10 s blocks. |
| `odocrypt` | DGB (DigiByte) | 7p. zpool 0 w. | FPGA | A | DigiByte Core (MIT) | Program is re-keyed every 10 days from nTime. DGB multi-algo (version bits). |
| `scryptn2` | XBTX | 2p. zpool 8 w. | CPU | A | scrypt N=1048576, r=1, p=1 | 128 MiB per hash. Verifying shares is expensive. Existing `scryptn` code can take N as a parameter. |
| `qhash` | QTC (Qubitcoin) | 6p. rplant 158 w. | GPU | A? | super-quantum/qubitcoin (Bitcoin-based "quBitcoin demo"). SHA256/SHA3 + 16-qubit circuit simulation (cuStateVec), fixed-point output. | CPU verification needs an exact state-vector simulator reimplementation. Floating-point determinism risk. **Header/stratum unverified.** |
| `sha256dt`, `sha256d_csd`, `sha256dv` | minor (NOVO?, CSD?, VEIL) | ≤1p | – | A | – | Tiny. Skip unless requested. |

### Category B: Bitcoin-derived daemon but different job/submit format

| algo | notable coins | activity | HW | cat | reference implementation / license | special notes |
|---|---|---|---|---|---|---|
| `kawpow` | RVN, XNA (Neurai), GAEL, KRGN, NEOX, SATOX, FREN, CMS, ARL, ABRS | 13 coins / **126 pools**. RVN 45p ~$40M. zpool 73 w. rplant 160 w. | GPU | B | RavenCommunity cpp-kawpow / ethash lib (Apache-2.0) | Header = 80-byte "header hash" part (sha256d of version..nHeight) + nNonce64 + mixHash (120 bytes). notify = `[job, header_hash, seed_hash, target, clean, height, bits]`. submit = `[worker, job, nonce64, header_hash, mix_hash]`. Needs an epoch light cache per 7,500 blocks. Share target is sent directly, not as diff. RVN has segwit-less assets. |
| `evrprogpow` | EVR (Evrmore) | 2p. zpool 27 w. | GPU | B | Evrmore fork of kawpow (different period/constants) | Same framework as kawpow. |
| `meowpow` | MEWC (Meowcoin) | 7p. zpool 11 w. rplant 17 w. | GPU | B | kawpow variant | Same framework. |
| `firopow` | FIRO, KIIRO, (SCC) | 7p. FIRO ~$25M. | GPU | B | Firo (MIT) | ProgPoW with Firo epoch/DAG params. Coinbase: **LLMQ masternode payments + dev fund**. |
| `sccpow` | SCC (StakeCubeCoin) | zpool 6 w | GPU | B | FiroPoW with small change, epoch 3240 | Dash-based, masternodes. |
| `phihash` | PHI (Phicoin) | 4p. zpool 0 w. | GPU | B | ProgPoW-like with FP32 ops, PCG, 25% DAG growth (arXiv 2412.17979) | FP32 determinism in the verifier. |
| `meraki` | TLS (Telestai) | 2p. zpool 1 w. rplant 14 w. | GPU | B | kawpowminer fork (tele-meraki-miner) | Kawpow-family job format. |
| `equihash` (200,9) | ZEC (ASIC), ARRR, KMD, KMDCL, KRGN | ZEC 28p (ASIC-dominated). ARRR 6p. | ASIC | B | zcashd / librustzcash (MIT/Apache) | Zcash header is 140 bytes + 1344-byte solution. ZIP-301 stratum (`mining.set_target`, notify with finalsaplingroot, submit `nTime, nonce2, solution`). Funding streams / lockbox outputs. ZEC GBT returns the coinbase itself (`coinbasetxn`). |
| `equihash144` (144,5) | BTCZ, BTG, GLINK, LTZ, EXCC | 21p total. zpool 77 w. | GPU | B | as above. Personalization per coin ("BgoldPoW", "BitcoinZ", …). | 100-byte solution. |
| `equihash192` (192,7) | YEC, ZCL, ZER, KRGN | 24p. zpool **537 w**. | GPU | B | as above | 400-byte solution. |
| `verushash` | VRSC (Verus) | 21p, ~$17.6M. zpool 99 w. | CPU | B | VerusCoin (MIT) | Zcash-style 140-byte header + variable solution carrying PBaaS data. Verus-specific stratum (solution prefix in notify). Merge-mined PBaaS chains. |
| `randomscash` | SCASH (Satoshi Cash) | 10p. rplant **948 w**. | CPU | B | RandomX 1.2.1 (BSD-3) with Argon2 salt "RandomX-Scash" | **112-byte header** (nonce at byte 76, `hashRandomX` commitment). RandomX key = SHA256d("Scash/RandomX/Epoch/"+floor(time/7 days)). Miners use the xmrig-style `rx/scash` protocol (login/job/submit). |
| Stella (Riecoin) | RIC | 2p, ~$1M | CPU | B | Riecoin Core (MIT) / rieMiner | Prime-constellation PoW. nOffset is 256-bit. Riecoin-specific stratum. |
| BLAKE3 Decred | DCR | 3p, ~$320M | GPU/ASIC | B | dcrd (ISC) | **This fork's `decred` (blake256r14) has been obsolete since 2023-08-29.** DCP-0011 switched PoW to BLAKE3 + ASERT at block 794,368. The existing 180-byte-header getwork path could be reused with a BLAKE3 hash. |
| `neoscrypt-xaya` | CHI (Xaya), ROD (SpaceXpanse) | zpool 3 w | GPU | B? | Xaya Core | Standalone neoscrypt mining uses a separate "powdata"/fake header (Xaya also merge-mines on SHA-256d). **Unverified.** |
| NexaPow | NEXA | 16p, ~$13M | GPU | B/C | Nexa (BCH-derived, MIT) | Uses `getminingcandidate`/`submitminingsolution`, header commitment + variable nonce. Not GBT/80-byte. |

### Category C: non-Bitcoin protocol (would need a separate stratum module; listed for completeness)

| algo | coins | activity | HW | notes |
|---|---|---|---|---|
| RandomX (+ RandomARQ, RandomC64, Panthera, RandomY, RandomVirel, …) | XMR, QRL, ZEPH, XDAG, GNTL/ARQ/MRL, C64, XLA, XCB | XMR 55p ~$10.6B. RandomX family 126p. | CPU | CryptoNote `login/job/submit` + `get_block_template` RPC. XDAG and QRL have their own protocols. |
| kHeavyHash | KAS | 37p ~$1.1B | ASIC | gRPC, GHOSTDAG. Kaspa-fork algos (KarlsenHashV2, Hoohash HTN, WalaHash, Cryptix OX8) also fall here. |
| Blake3 (Alephium) | ALPH | 16p | GPU/ASIC | Sharded, custom protocol. |
| Etchash / Ethash | ETC, ETHW, OCTA, QKC | ETC 43p | ASIC/GPU | eth_getWork / EthereumStratum. |
| Autolykos2 | ERG | 12p | GPU | Ergo node API. |
| Octopus | CFX | 7p | GPU | Conflux. |
| Cuckatoo31/32, Cuckoo | MWC, GRIN, AE, EPIC | – | GPU | Grin-style stratum. |
| ProgPowZ / ProgPow (Epic) | ZANO, EPIC | ZANO 12p | GPU | CryptoNote-based. |
| Tari (SHA-3X, Cuckaroo, merge RandomX) | XTM | 4–6p each | – | Tari gRPC. |
| XelisHashV3 | XEL | 14p | GPU/CPU | Xelis getwork WS. |
| FishHash, PoBW, DynexSolve, BeamHash, Abelhash, K12, NexusHash | IRON, WART, DNX, BEAM, ABEL, AEON, NXS | small | GPU | All custom. |
| PearlHash (PoUW, matmul) | PRL (mainnet 2026-04-27), merge with MDL | **28p, ~$328M** (largest new coin) | NVIDIA GPU | ZK-verified matrix multiplication. Entirely different architecture. |
| OggPoW / XHash | OGG, LAX | 3p / 5p. rplant 54 / 51 w. | GPU | EVM chains (Go ProgPoW / Ethash-derived). |
| Eaglesong, Blake2B (Sia), Blake2B+SHA3 (HNS), zkSNARK (Aleo), UPoW (Qubic), PoC/PoST (Signa, Chia, AR) | CKB, SC, HNS, ALEO, QUBIC, … | – | ASIC/other | Not relevant to yiimp. |
| CryptoNight variants, AstroBWT, X16RS (Hacash) | CCX, RYO, DERO, HAC, … | small | – | Non-Bitcoin. |

---

## 2. Category summary

- **A (easy):** ghostrider, mike, minotaurx, flex, yespowerR16/TIDE/SUGAR/ADVC/LTNCG/MGPC(/EQPAY?), power2b, cpupower, yescrypt/R8/R16/R32, sha512256d, verthash, sha3-256t, heavyhash (OBTC), skydoge, hoohash-pepew, rinhash, argon2d1000/16000, megabtx/megamec, anime, curvehash, soterg, odocrypt, scryptn2, (qhash).
  - Some of these need coinbase work beyond the hash: Dash-style smartnode/founder/CbTx for GhostRider coins, dev/charity outputs for ADVC, AuxPoW for LCN, drivechain outputs for Skydoge.
  - Some need algo-by-version-bits multi-algo handling: LCC, AVN, PLSR, DGB, XMY.
- **B (stratum changes):**
  - kawpow family: kawpow, evrprogpow, meowpow, firopow, sccpow, phihash, meraki. One framework unlocks all seven.
  - Other B items: equihash (200,9 / 144,5 / 192,7), verushash, randomscash, Riecoin, Decred-BLAKE3, neoscrypt-xaya, NexaPow.
- **C (separate pool architecture):** RandomX, kHeavyHash and Kaspa forks, Alephium, Etchash/Ethash, Autolykos2, Octopus, Cuckatoo, ProgPowZ, Tari, Xelis, Pearl, OGG/LAX, FishHash, Warthog, Dynex, Beam, and the rest.

---

## 3. Exact parameters for category A items

### yespower family

All use openwall yespower 1.0 `yespower_tls(header, 80, &params, out)`. The existing yiimp `yespower` is N=2048, r=32, pers=NULL. The existing `yespowerurx` is N=2048, r=32, pers="UraniumX".

| algo | N | r | personalization (exact bytes; length = strlen) | source |
|---|---|---|---|---|
| yespowerR16 (YTN) | 4096 | 16 | NULL (len 0) | Yenten 3.1.0 release notes / search. RainbowMiner. |
| yespowerTIDE (TDC) | 2048 | 8 | NULL | RainbowMiner CpuminerJayddee.ps1 (`--param-n 2048 --param-r 8`) + search |
| yespowerSUGAR | 2048 | 32 | `Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote` | cpuminer-opt README |
| yespowerLTNCG | 2048 | 32 | `LTNCGYES` | cpuminer-opt README |
| yespowerMGPC | 2048 | 32 | `Magpies are birds of the Corvidae family.` | RainbowMiner + magpiecoin.org how-to |
| yespowerADVC | 2048 | 32 | `Let the quest begin` | RainbowMiner. **Unverified:** the ADVC ANN says "based on YespowerR16", which would suggest N=4096/r=16. Test against a real block. |
| yespowerARWN | 2048 | 32 | `ARWN` | RainbowMiner |
| yespowerIC | 2048 | 32 | `IsotopeC` | cpuminer-opt README |
| yespowerLITB | 2048 | 32 | `LITBpower: The number of LITB working or available for proof-of-work mini` (truncated as published) | cpuminer-opt README |
| yespowerIOTS | 2048 | 32 (default) | `Iots is committed to the development of IOT` | cpuminer-opt README |
| cpupower | 2048 | 32 | `CPUpower: The number of CPU working or available for proof-of-work mining` | cpuminer-opt README |
| power2b (MBC) | 2048 | 32 | `Now I am become Death, the destroyer of worlds` | cpuminer-opt README. **Uses the BLAKE2b-based yespower** (`yespower-b2b`: HMAC/PBKDF2-BLAKE2b replaces SHA-256), not plain yespower. |
| interchained (ITC) | 1024 | 8 | NULL | RainbowMiner (**unverified**) |
| yespowerRES, yespowerMWC, yespowerEQPAY | ? | ? | ? | **Unverified.** Not published in docs I could reach. |

**Implementation tip.** Make one `yespower_generic(N, r, pers)` entry and derive every variant from a table. yiimp's existing `yespower` uses difficulty factor 0x10000. cpuminer-opt uses the same 65536 target factor for the yespower and yescrypt families, so keep 0x10000.

### yescrypt family

yescrypt 0.5 in cpuminer-opt style: password = salt = 80-byte header, p=1, output 32 bytes. Parameters are from cpuminer-opt and ccminer conventions.

| algo | N | r | client key | status |
|---|---|---|---|---|
| yescrypt (BSTY, XMY) | 2048 | 8 | none (plain yescrypt, len 0) | cpuminer-opt: "yescrypt Globalboost-Y". Parameters from common knowledge, **unverified** in public docs. |
| yescryptR8 (ZNY, MTBC) | 2048 | 8 | `Client Key` | **Unverified** |
| yescryptR16 | 4096 | 16 | `Client Key` | Partly confirmed (search hit shows 4096/16/"Client Key") |
| yescryptR32 (WAVI, LPEPE) | 4096 | 32 | `WaviBanana` | Confirmed via search snippet of the y-chan ccminer yescrypt.cu |
| yescryptR8g (KOTO) | – | – | – | KOTO is a Zcash-derived header, so it is **not** category A. Skip. |

### Other category A items

- **sha512256d (RXD):** `SHA-512/256( SHA-512/256( header80 ) )`. SHA-512/256 is FIPS 180-4, with its own IV (not truncated SHA-512 with the standard IV). OpenSSL exposes it as `EVP_sha512_256()`. Output byte order as for sha256d. zpool uses port 3342 and factor 1e6. Source: radiant-node README ("SHA512/256 Proof-of-Work"), https://github.com/RadiantBlockchain/radiant-node
- **sha3-256t (BC3/FJAR):** `SHA3-256(SHA3-256(SHA3-256(header80)))`, FIPS-202 SHA3 padding (not Keccak-256). Everything else is identical to Bitcoin Core v29.1. Source: https://github.com/PinkStarrySky/BitcoinIII-Core. Note that SHA3 vs Keccak padding should be checked against a real block.
- **skydoge:** SHAndwich256 = `SHA256( SHA512( SHA256(header80) ) )`, per the MPS/blockspot description "sha256 + sha512 + sha256 instead of sha256 + sha256". Exact byte widths (full 64-byte SHA512 output fed to the final SHA256) are **unverified**. Sources: https://blockspot.io/coin/skydogenet-skydoge/ and https://github.com/skydogenet/mainchain
- **rinhash (RIN):** `SHA3-256( Argon2d( BLAKE3(header80) ) )`. Argon2d is memory-hard, "64 KB, 2 iterations". Lanes, salt and output length are **unverified**. Sources: https://github.com/Rin-coin/rincoin/blob/master/README.md and https://github.com/Rin-coin/RinHash-cuda
- **ghostrider (RTM):**
  - Three rounds. Each round runs 5 "core" hashes from the 15 x15-family functions (blake512, bmw512, groestl512, jh512, keccak512, skein512, luffa512, cubehash512, shavite512, simd512, echo512, hamsi512, fugue512, shabal512, whirlpool), then 1 CryptoNight variant.
  - The CryptoNight variant comes from {cn/dark 512 KB, cn/dark-lite 256 KB, cn/fast 2 MB, cn/lite 1 MB, cn/turtle 256 KB, cn/turtle-lite 128 KB}.
  - No core or CN variant repeats. The order comes from the nibbles of header bytes 4–36 (prevblockhash).
  - Sources: https://blog.raptoreum.com/ghostrider-the-mix-of-algorithms-that-revolutionizes-the-proof-of-work/ and https://deepwiki.com/xmrig/xmrig/7.3-ghostrider-algorithm
  - The exact hash list and selection code should be taken from Raptoreum Core (MIT).
- **mike (VKAX):** a GhostRider variant with a different/extended core set. Exact list **unverified** (see xmrig PR #3131).
- **minotaurx:**
  - Minotaur graph traversal over 16 base functions: BLAKE, BMW, CubeHash, Echo, Fugue, Grøstl, Hamsi, JH, Keccak, Luffa, Shabal, SHAvite, SIMD, Skein, Whirlpool, SHA-2.
  - The path is chosen by intermediate hashes. Yespower is used at the leaf nodes.
  - Input is exactly 80 bytes; output is the final 32 bytes. MIT licence.
  - Leaf yespower parameters are **unverified**.
  - Source: https://libraries.io/pypi/avian-minotaurx-hash (AvianNetwork/minotaurx_hash)
- **flex (KCN/LCN):** Kylacoin describes it as deriving "a deterministic computation path from the input" across ~20 hash families (Blake, Keccak, Skein, Groestl, …). It is commonly described as GhostRider-like (x-cores + CN variants) seeded by a Keccak-512 of the header. **Exact chain unverified.** Sources: https://kylacoin.com/ and https://x.com/kylacoin/status/1832528313723617479
- **verthash (VTC):**
  - Needs verthash.dat (~1.2 GB), generated deterministically. VerthashMiner can create it with `--gen-verthash-data`.
  - The hash reads 32-byte chunks from the file, addressed by SHA3-derived seeds of the 80-byte header.
  - Keep the file mmapped once per stratum process.
  - Source: https://github.com/CryptoGraphics/VerthashMiner
- **heavyhash (OBTC):**
  - Keccak/cSHAKE-based HeavyHash. A 64×64 4-bit matrix is generated with xoshiro256++ seeded from the previous block hash, and regenerated until it is full rank.
  - A matrix-vector product is XORed with the pre-hash, then hashed again.
  - The matrix changes every block; cache it per job.
  - Sources: https://arxiv.org/pdf/1911.05193 and https://github.com/PoWx-Org/obtc-core
- **argon2d16000 / argon2d1000:** memory 16000 KiB and 1000 KiB respectively; salt = password = header, 32-byte output, Argon2 version 0x13. **t_cost and lanes unverified.** By analogy with existing entries (dyn: t=2 / 8 lanes, uis: t=1 / 4 lanes), check against the a.multiminer / cpuminer-opt `argon2d1000` implementations before release.
- **scryptn2:** `scrypt(N=1048576, r=1, p=1)`, per the cpuminer-opt README. Reuse `scrypt_N_R_1_256(input, output, 1048576, 1, 80)`.
- **odocrypt (DGB):** key = `nTime - nTime % (10*24*3600)` (10-day epochs) seeds a generated cipher program. **Unverified** beyond DigiByte docs. FPGA-dominated. zpool has 0 workers, so low value.
- **hoohash-pepew, megabtx, megamec, anime, curvehash, soterg, qhash:** no authoritative public spec found. **Unverified.** Implementations would need to be ported from coin cores or miners.

---

## 4. Recommendation

**Tier 1: add first (high demand, category A, mostly table/param work)**

1. **Generic yespower with a parameter table.** Covers yespowerR16, TIDE, SUGAR, ADVC, LTNCG, MGPC, ARWN, IC, cpupower, plus power2b via a BLAKE2b build.
   - TDC alone has about 3,200 live workers across zpool and rplant. YTN, MBC and ADVC are also active.
   - Coinbase quirk: ADVC's 10% extra outputs.
2. **yescrypt / R8 / R16 / R32.** BSTY has 1.7k workers on zpool, LPEPE and FNNC several hundred. Same shared code base.
3. **ghostrider (+ mike).** Largest CPU algo on zpool (~7.2k workers), 32 coins, 117 pools.
   - The hash is available under MIT.
   - The real work is Dash-style coinbase: smartnode array, founder payment, CbTx `coinbase_payload`. The fork already parses `coinbase_payload` and a `founder` object; check smartnode handling.
4. **minotaurx.** MAZA ~4.5k workers, plus LCC and others. Easy hash (MIT). Multi-algo version-bit coins need care.
5. **flex.** KCN and LCN are active; LCN needs AuxPoW.
6. **verthash** (VTC, 474 workers on zpool). **sha512256d** (RXD, 13 pools). **sha3-256t** (BC3, 20 pools). All are simple ports.

**Tier 2: cheap to add, but coins are small or niche.** skydoge, rinhash, hoohash-pepew, heavyhash (OBTC), argon2d1000/16000, megabtx/megamec, anime, scryptn2, curvehash, soterg. Add on request.

**Tier 3: worth it only if you commit to a KawPoW/ProgPoW job framework (category B).** One implementation (light-cache verification, header-hash/mixhash submit, target-based notify) unlocks kawpow, evrprogpow, meowpow, firopow, sccpow, meraki and phihash: roughly 150+ pools of demand and the main GPU segment yiimp pools still serve. That makes this the best B item.

**Tier 4: B items that are probably not worth it.**
- Equihash: ZEC is ASIC and pool-saturated. 192,7 (YEC/ZCL) still has ~500 workers on zpool if you want GPU Equihash.
- VerusHash: 21 pools, but a Verus-specific stratum.
- RandomSCASH: popular (~950 workers on rplant), but a 112-byte header and the xmrig protocol.
- Riecoin, NexaPow and neoscrypt-xaya: each needs its own protocol variant.

**Skip: category C.** Monero/RandomX, Kaspa and forks, ETC, ERG, ALPH, CFX, Grin/MWC, Zano, Tari, Xelis, Pearl, OGG/LAX and the others need a different pool architecture. They are better served by purpose-built pools (e.g. MiningCore, cryptonote-nodejs-pool). Also skip dead coins: yespowerIOTS/LITB/RES, lyra2z330 GXX, x25x HTH, x21s PGN (zpool shows 0 hashrate).

**Side findings on the existing code** (not requested, but they affect "supported" algos):
- **`decred` is obsolete.** Decred switched PoW to BLAKE3 at block 794,368 (2023-08-29, DCP-0011). Blake256r14 shares will never produce valid DCR blocks. Sources: https://medium.com/decred/decred-journal-august-2023-6b539b82057b and https://github.com/decred/dcps/blob/master/dcp-0011/dcp-0011.mediawiki
- **No MWEB support.** `coind_template.cpp` requests GBT with only `{"rules":["segwit"]}` and nothing references `mweb`.
  - Litecoin Core ≥0.21.2 requires `["segwit","mweb"]` and the MWEB extension block in every block. A block without it is rejected as mweb-missing.
  - LTC under `scrypt` therefore likely cannot be pool-mined correctly as-is. The same applies to other MWEB-enabled Litecoin forks.
  - Source: https://github.com/litecoin-project/litecoin/issues/789

## Sources

- https://miningpoolstats.stream/ (live data feed, 2026-09-25)
- https://www.zpool.ca/api/status and https://www.zpool.ca/api/currencies
- https://pool.rplant.xyz/api/currencies
- https://www.mining-dutch.nl/api/status/
- https://raw.githubusercontent.com/JayDDee/cpuminer-opt/master/README.md
- https://raw.githubusercontent.com/doktor83/SRBMiner-Multi/master/README.md
- https://raw.githubusercontent.com/RainbowMiner/RainbowMiner/refs/heads/master/Miners/CpuminerJayddee.ps1 and `.../CpuminerRplant.ps1`
- https://github.com/yentencoin/yenten/releases/tag/3.1.0 (yespowerR16 N=4096 r=16)
- https://magpiecoin.org/how-to-mine.html
- https://bitcointalk.org/index.php?topic=5536697.0 (ADVC)
- https://blog.raptoreum.com/ghostrider-the-mix-of-algorithms-that-revolutionizes-the-proof-of-work/
- https://deepwiki.com/xmrig/xmrig/7.3-ghostrider-algorithm
- https://libraries.io/pypi/avian-minotaurx-hash
- https://kylacoin.com/ and https://lyncoin.com/about/
- https://github.com/RadiantBlockchain/radiant-node
- https://github.com/PinkStarrySky/BitcoinIII-Core
- https://blockspot.io/coin/skydogenet-skydoge/
- https://github.com/Rin-coin/rincoin/blob/master/README.md
- https://github.com/CryptoGraphics/VerthashMiner
- https://arxiv.org/pdf/1911.05193 (HeavyHash / oPoW)
- https://pepepow.org/announcements/ and https://miningpoolstats.stream/pepepow
- https://github.com/Soteria-Network/Soteria/blob/master/README.md
- https://www.cryptoprofi.info/?p=17745 (0DYNC argon2d1000)
- https://github.com/Alterdot/a.multiminer (argon2d16000)
- https://www.coincarp.com/events/stakecubecoin-scc-pow-algorithm-change/ and https://github.com/stakecube/StakeCubeCoin
- https://arxiv.org/pdf/2412.17979 (Phihash)
- https://github.com/Telestai-Project/tele-meraki-miner
- https://superquantum.medium.com/boost-quantum-simulators-with-your-hashpower-c8142ad73894 (qhash)
- https://github.com/newsmoneymaker/scash-nodejs-pool (SCASH 112-byte header, RandomX key)
- https://hashrateindex.com/blog/pearl-prl-ai-compute-cryptocurrency/ (Pearl)
- https://docs.parallaxprotocol.org/guides/mining/introduction (XHash)
- https://github.com/Oggchain (OggPoW)
