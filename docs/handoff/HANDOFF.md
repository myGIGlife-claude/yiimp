# MultiPool / YiiMP modernization: handoff for the next Claude Code session

Last updated: 2026-09-30. **Phases 1-3 are all merged** into `next` (yiimp) and `master`
(installers); sections 4-6a below are kept as the record but their "PR open" wording is
history.

## 0. Start here (continuing on the owner's own server)

The owner is moving this work from a Claude Code cloud session to their own server, which
has more plugins installed. The cloud session's container and its scratch files are gone;
everything that matters is in the repos.

1. Clone the five repos (default branches are up to date):
   ```
   for r in Multi-Pool-Installer multipool_setup multipool_yiimp_single multipool_yiimp_multi yiimp; do
     git clone https://github.com/myGIGlife-claude/$r
   done
   ```
   yiimp's default branch is `next`; the installers use `master`.

   **Repositories to add to the session.** All five belong to the MultiPool installer
   chain and are all needed, with push access. In a Claude Code cloud session, add them
   to the session's repositories. On a server, make sure `git`/`gh` can push to them.

   | Repo | Role | Branch |
   |---|---|---|
   | `myGIGlife-claude/Multi-Pool-Installer` | Entry point: `bootstrap.sh` clones multipool_setup | `master` |
   | `myGIGlife-claude/multipool_setup` | User setup, `/etc/multipool.conf`, the menu; clones single or multi | `master` |
   | `myGIGlife-claude/multipool_yiimp_single` | YiiMP single-server installer; clones yiimp | `master` |
   | `myGIGlife-claude/multipool_yiimp_multi` | YiiMP multi-server installer; clones yiimp | `master` |
   | `myGIGlife-claude/yiimp` | The YiiMP fork (web + stratum); this handoff lives here | `next` |

   The menu's legacy options (Daemon Builder, NOMP, YiiMP Stratum Upgrade) still clone the
   old `cryptopool-builders/multipool_coin_builder`, `multipool_nomp` and
   `multipool_yiimp_upgrade` at their last release. They haven't been forked or updated.
   Add them only if the owner asks to modernize those too.
2. Read this whole file, then `docs/BRIDGE.md`. Test tools are in `docs/handoff/tools`,
   notes in `docs/handoff/notes`.
3. State on 2026-09-30:
   - Merged: yiimp #3-#8, single/multi #3-#5, Multi-Pool-Installer #4-#5, multipool_setup #2.
   - Nothing else open from this work.
4. Work queue, in order:
   1. Fix the BIP34 height bug for blocks 1-16 (below). Small, with KATs.
   2. Payout test for each algo family (below), with the owner.
   3. Later: installer support for monerod/monero-wallet-rpc.
5. The owner's rules (also in section 1a):
   - Give a plan or list before large changes, and check in after each phase.
   - Merge only when the owner says so. Plain pushes only, never force-push or rewrite.
   - Kill only processes you started, by PID (not `pkill -x stratum`).
   - The owner watches their usage; keep work focused.
   - Commits end with the owner's attribution trailer if their setup uses one; don't put
     model names in commits or PRs.
6. Build and check: `make -C stratum -j$(nproc)` (add `MARCH=native` only for a local
   binary), then `make -C stratum hashtest && stratum/hashtest` (52 KATs pass). PHP:
   `find web -name '*.php' -print0 | xargs -0 -n1 php -l`. Installers: ShellCheck in CI.
7. Section 7 explains how to rebuild the regtest environment (daemons, DB, web test site).

> **Next session, first task: a payout test for each algo family**, with the owner.
> Payouts were the weak spot of the old YiiMP admin. So far only Monero has run
> block -> confirmed -> earnings -> payout, once on regtest, with `earnings.mature_time`
> backdated in SQL. For each coin below, on regtest, run the real web cron with no SQL
> shortcuts: mine blocks through the stratum, let them mature, let the payout run send,
> and check the miner's wallet got the right amount, `payouts` has the txid, and the
> admin pages (coin, user, payouts) show it correctly.
>
> | Family | Test coin | What to watch |
> |---|---|---|
> | Bitcoin stratum (Phase 1 algos) | one Group A coin, e.g. RTM (ghostrider) or VTC (verthash) | normal `sendmany`; masternode coinbase on RTM |
> | KawPoW | RVN | normal `sendmany`; FIRO masternode payouts are still untested (`protx register` failed on regtest) |
> | Equihash | ZEC (zcashd 6.x), then BTG | check which wallet RPCs zcashd 6 still allows for transparent payouts (`sendmany` may be deprecated or disabled); reward read by `zcash_coinbase_miner_value` |
> | Decred | DCR (dcrd + dcrwallet) | payouts go through dcrwallet `sendmany`; blocks confirmed by `blocknotify-dcr` |
> | Monero | XMR | `transfer_split` through monero-wallet-rpc; locked-funds errors while rewards are still locked |
>
> Fix whatever breaks, as its own PR, and ask the owner before merging.
> Also still untested: merge mining (Lyncoin), PoS coins (Pulsar), live mainnet.
> See `docs/BRIDGE.md` and the Phase 3 notes below.
>
> - **BIP34 height bug (fixed in #11):** the block height in the coinbase is wrong
>   for blocks 1-16. `ser_number()` (`stratum/util.cpp`, used by `coinbase.cpp`) writes a
>   one-byte push (`01 01` for height 1), but BIP34 nodes expect what `CScript() << nHeight`
>   makes: `OP_1`..`OP_16` (`0x51`..`0x60`) for heights 1-16. The node rejects those
>   blocks (the upstream miner had the same bug). Only matters for a new chain's
>   first 16 blocks, which is when a new coin launched on this pool needs it. Add a KAT
>   for heights 0, 1, 16, 17, 127, 128, 255, 256 and 65536.
>
> Merge order: PRs #3, then #4, then the Phase 3 PR, and only when the owner says so. Written by the Claude Code session that did this
work, so another session can continue where it stopped. Read it all before
changing anything.

## 1. The owner and what they asked for

- The owner (GitHub `mygiglifeinc-glitch`) is the original author of the
  MultiPool installer (formerly github.com/cryptopool-builders) and of this
  YiiMP fork. The code had not been updated in years.
- The original request: update everything to work on the latest Ubuntu
  releases, and apply current best coding practices and server security.
  That part is done and merged (see section 3).
- Follow-up requests, in order:
  1. Add their fork of YiiMP (`myGIGlife-claude/yiimp`) to the project,
     copy its missing branches, make it PHP 8 compatible, move build fixes
     into it, and modernize it. Done and merged.
  2. "Research all of the minable coins' stratum protocols that YiiMP doesn't
     have, give a list before adding them, then fully add them." The list was
     given, then the owner said: "For the algos the stratum can't handle,
     create a way to integrate them into YiiMP", and approved three phases:
     - **Phase 1**: Bitcoin-style algos (only the hash is new) plus fixes.
       Done; PRs open (section 4).
     - **Phase 2**: a protocol layer in the stratum, then the KawPoW family,
       Equihash and Decred BLAKE3. Mostly done; not in a PR yet (section 5).
     - **Phase 3**: a "bridge" for completely different daemons, with
       RandomX/Monero as the first engine. Not started (section 6).
  3. The owner then said "Pause this for now" and asked for this document.
     The owner has since asked the session to continue (Equihash first); check in with them before starting Phase 3.
- Preferences learned:
  - PHP version: the owner chose **PHP 8.3** as the default.
  - They want a list or plan before large additions, and a check-in after each phase.
  - Merge only when the owner says so. They have said "Merge" / "Yes"
    for earlier rounds, but ask again for new PRs.
  - Obscurity was discussed (rewriting in another language); the advice
    given was not to, for security and trust reasons. Nothing was changed.

## 1a. Standing rules from the owner (2026-09-28)

- **Don't force-push or rewrite `claude/multipool-installer-update-s3rama`**
  (in any repo). Adding commits on top is fine.

## 2. Repositories and how the installer chain works

| Repo | Role | Default branch |
|---|---|---|
| `myGIGlife-claude/Multi-Pool-Installer` | `bootstrap.sh`, the `curl … \| bash` entry point | master |
| `myGIGlife-claude/multipool_setup` | user setup, preflight, menu, `functions.sh` | master |
| `myGIGlife-claude/multipool_yiimp_single` | YiiMP on one server | master |
| `myGIGlife-claude/multipool_yiimp_multi` | YiiMP on several servers over SSH | master |
| `myGIGlife-claude/yiimp` | YiiMP itself: PHP web (Yii 1.1) + C++ stratum | **next** |

Chain: `bootstrap.sh` → clones `multipool_setup` (master, override with `TAG`)
→ `start.sh`/menu → `bootstrap_single.sh` or `bootstrap_multi.sh` → clones
`multipool_yiimp_single`/`_multi` (master, override with `YIIMP_SINGLE_REF` or
`YIIMP_MULTI_REF`). These then clone YiiMP from `${MULTIPOOL_GITHUB}/yiimp.git`
(default branch; `YIIMP_REPO`/`YIIMP_BRANCH` override).

- `MULTIPOOL_GITHUB` defaults to `https://github.com/myGIGlife-claude` (in `functions.sh`).
- Stratum Upgrade, NOMP and Daemon Builder are "legacy": they still come
  from their last cryptopool-builders release, and the menu asks before running them.
- The designated working branch in the four installer repos is
  `claude/multipool-installer-update-s3rama`. In yiimp, work was done on
  several `claude/*` branches (section 5).
- Commit trailer used on every commit:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01PuCJWisqxCymEgkURmDpuA
  ```
  Use your own session's attribution lines if your system prompt gives
  different ones. Never put model names anywhere else in the repos.
- PR bodies end with the "Generated with Claude Code" line plus the session URL.
- GitHub comments you post must end with the Claude Code footer your system prompt specifies.

## 3. Already merged (done)

- **Installers PR round 1** (merged, all four repos):
  - Supported releases: Ubuntu 22.04, 24.04 and 26.04.
  - Distro packages: MariaDB, nginx, certbot and WireGuard now come from Ubuntu; PHP comes from ppa:ondrej/php (`PHP_VERSION`, default 8.3).
  - Setup and error handling:
    - `hide_output` detects failures now.
    - `write_conf_file` writes shell-quoted config files.
    - Users and passwords are validated.
    - sudoers entries are checked with visudo.
  - Security hardening: ufw deny by default; an sshd drop-in; fail2ban; unattended upgrades; MariaDB locked down, with users restricted to specific hosts.
  - The multi-server installer uses SSH with `accept-new` host key checking and a control master (no passwords on disk).
  - ShellCheck CI in every installer repo.
- **Installers round 2** (merged):
  - YiiMP is installed from the fork.
  - `bcmath` is installed.
  - The blake2 build workaround was dropped.
  - nginx denies `/framework/`, `/yaamp/` except `ui/css|js`, and `run.php`/`runconsole.php`.
- **yiimp PR #1** (merged into `next`):
  - Yii 1.1.18 → 1.1.32, with the yaamp framework patches re-applied: autoload from the modules, controller lookup through `GetSSModulePath`, `dumperror`, and the 404 IP.
  - PHP 8 fixes; `E_DEPRECATED` excluded in the entry points.
  - Security fixes:
    - The cron controller only runs from the CLI; it was web-reachable.
    - SQLi, XSS, CSRF (Sec-Fetch-Site/Origin), session cookie flags, bcrypt renter passwords, and open-redirect fixes.
    - The mysqldump password is no longer on the command line.
  - Stratum:
    - Builds with GCC 11–15 and OpenSSL 3.
    - Network input hardening: malformed JSON segfault, SQLi, overflows, a PROXY-header race.
    - blake2 alignment fix and hash-collision fixes.
    - `make hashtest`.
  - CI: PHP lint on 8.1/8.3/8.4, plus a stratum build + hashtest job.
  - The `dedicatedport` coin setting (the multi-port feature) was ported to `next`.
- **yiimp PR #2**: `multi-port` was made identical to `next`.
- The fork's missing branches `multi-port` and `stratum-development` were
  copied from cryptopool-builders/yiimp.

## 4. Phase 1: open PRs, CI green, waiting for the owner

- yiimp **#3** (`claude/multipool-installer-update-s3rama` → `next`)
- multipool_yiimp_single **#3** and multipool_yiimp_multi **#3**
  (`claude/multipool-installer-update-s3rama` → `master`)

All three had passing CI and no review comments at the last check. On
wake-up: check CI/conflicts/comments, and never merge without the owner.

What Phase 1 contains (yiimp):

- **New algos (22):**
  - yespowerR16, TIDE, SUGAR, ADVC, LTNCG, MGPC, ARWN, IC, LITB; cpupower, power2b.
  - yescrypt, R8, R16, R32; sha512256d (RXD), sha3-256t (BC3), verthash (VTC).
  - ghostrider, mike, minotaurx, flex.
  - Ports: 91xx/92xx/93xx; see `stratum/config.sample`.
- **Coinbase and version handling:**
  - Raptoreum-style coinbase: smartnode, founder and superblock outputs, plus the type-5 CbTx payload. It is keyed on template fields.
  - Per-algo block version rules (`powalgo`, `version_mask`/`version_bits` in the .conf) for multi-algo chains (LCC/MAZA/AVN/PLSR).
  - Kylacoin/Lyncoin version-8 coinbase, `coinbasedevreward`, and a sha3d merkle root.
- **Litecoin MWEB:** getblocktemplate retries with the `mweb` rule and appends `01`+mweb after the HogEx transaction. Tested on regtest with litecoind 0.21.4; the block was accepted.
- **BMW-256 miscompiled under strict aliasing:** everything is now built with `-fno-strict-aliasing`.
  - lyra2v3 and lyra2vc0ban had given random hashes; bmw, lbk3 and lyra2v2 had given wrong ones.
  - KATs: Vertcoin blocks 500000 and 1100000.
- **Portable build:** `MARCH ?= x86-64-v2` (`make MARCH=native` to tune). `-march=native` binaries crash with "Illegal instruction" when a VM moves to another CPU; that happened in this container.
- **Web algo tables** in `web/yaamp/core/functions/yaamp.php` (list, colors, ports) are generated by `docs/handoff/tools/sync_algos.py` from `g_algos[]` + `config.sample`.
  - Run: `python3 sync_algos.py <repo> algo=#color ...`
  - Then add mBTC factors by hand in `yaamp_algo_mBTC_factor`: 1000 for GH/s algos, 0.001 for ghostrider/mike/flex.
- **config.sample fixes:** duplicate ports removed, bcd.conf fixed, missing configs added, configs for algos the stratum doesn't have removed.
- **Installers:**
  - The single-server boot list (`server_cleanup.sh` → `stratum.start.sh`) was refreshed to 81 algos; verthash only starts if `verthash.dat` exists.
  - The `stratum` helper accepts any algo that has a config.
  - `verthash_gen` is built and installed.
- **Not tested:** VKAX masternode payouts, Lyncoin merge mining, Pulsar (PoS), live mainnet mining, and a full install on a fresh VM.
  flex has no mainnet KAT: its explorers are on ports the proxy blocked, so it was checked against Kylacoin's own code instead.

## 5. Phase 2: finished, PRs open (waiting for the owner)

**Status update (2026-09-28, later):** Equihash was finished and verified
end to end (blocks accepted and confirmed in the DB):
- zcashd 6.20 NU6 25/25, zcashd Sapling 25/25, BTG 12/12, Resistance 5/5.
- The blocknotify errors only happened while no stratum was running; that is not a bug.

`claude/phase2-equihash` was fast-forwarded into `claude/phase2`, and web changes were added:
- the Equihash tables;
- hashrate constant 2^23 (Sol/s);
- Zcash-family reward and difficulty in `backend/coins.php`;
- the LTC `mweb` retry in `coins.php`;
- NULL coin fields treated as 0 (`db_coins::afterFind`).

49 KATs pass; the page crawl and cron jobs are clean.

PRs:
- yiimp **#4** (`claude/phase2` → `next`)
- multipool_yiimp_single **#4** and multipool_yiimp_multi **#4** (`claude/phase2` → `master`): READMEs, and the Equihash stratums added to the single-server boot list.

All three sit on top of the Phase 1 PRs (#3), so merge #3 first. **Next: check in with the owner before starting Phase 3.**

The rest of this section is the history of how Phase 2 was built.


Branches in `myGIGlife-claude/yiimp`, all pushed:

| Branch | Content | State |
|---|---|---|
| `claude/phase2-kawpow` | protocol layer + KawPoW family | done, merged into `claude/phase2` |
| `claude/phase2-decred` | Decred BLAKE3 | done, merged into `claude/phase2` |
| `claude/phase2` | Phase 1 + the two above + web tables for them | pushed, no PR |
| `claude/phase2-equihash` | `claude/phase2` + Equihash + yespowerRES + this handoff | **in progress** |

Also on GitHub (can be deleted once the owner agrees): `claude/algos-cpu`,
`claude/algos-hash`, `claude/stratum-modernize` (all merged), and
`claude/multi-port-update` (merged via PR #2).

### 5.1 Protocol layer (done)

- Files: `stratum/protocol.h`, `protocol.cpp`, `protocol_kawpow.cpp`,
  `protocol_equihash.cpp`.
- `g_algo_protocols[]` maps an algo to a `YAAMP_PROTOCOL`. Bitcoin algos have no
  entry (`g_protocol == NULL`), so the existing code path is untouched.
- Hooks: `subscribe`, `send_difficulty`, `template_prepare`, `job_notify`
  (with `notify_per_client`), `submit`, `method`, `init`, `config`.
- Helpers:
  - 256-bit target math;
  - `protocol_submit_block(client, job, header_hex, coinbase_hex, blockid, powhash, diff_user)`;
  - share accept/reject accounting;
  - `proto_*` fields in `YAAMP_JOB_TEMPLATE`.
- Renting is turned off for non-Bitcoin families.
- `ser_compactsize()` was fixed: it wrote 253+ sizes in big endian.

### 5.2 KawPoW family (done)

kawpow 9501, evrprogpow 9502, meowpow 9503, firopow 9504, sccpow 9505,
meraki 9506. Hash library: `stratum/algos/progpow/`, with ethash keccak/kiss99
from Ravencoin (Apache-2.0).

Protocol (MiningCore Progpow-compatible):
- `mining.notify` = `[job, header_hash, seed_hash, target, true, height, bits]`
- `mining.submit` = `[worker, job, 0xnonce16, 0xheaderhash, 0xmix]`
- 2-byte nonce prefix per miner.

Light caches: about 95–136 MB per epoch per coin, kept for the current and next epoch.

Share difficulty: diff 1 = target `0x00000000ff…` (`0xffff…` for firopow and sccpow).
Web factor 1. Configs use `difficulty = 0.1`, `diff_min = 0.01`, `diff_max = 100`.

Verified:
- KATs: RVN 3000000 and 4553000, FIRO 1000000 and 1383000, TLS 1119000, plus the official test vectors.
- Regtest end to end:
  - RVN: 10 blocks accepted.
  - FIRO: 6 blocks, with the dev-fund output computed by the pool.
  - MEWC: 5 blocks.
  - SCC: 1 block.

Not tested end to end:
- EVR: its regtest mines SHA256.
- TLS: its regtest uses a different "AltProgPow".
- Firo masternode payouts (`protx register` failed on regtest).
- Real GPU miners.
- The MEWC DAG change at epoch 110+.

Web colors: kawpow `#80c0e0`, evrprogpow `#a0d0f0`, meowpow `#f0c080`,
firopow `#e08080`, sccpow `#80e0c0`, meraki `#c0a0f0`; these are already in `claude/phase2`.
Not added to the boot list, because of memory use.

### 5.3 Decred (done)

- `decred` now uses BLAKE3 over the 180-byte header (DCP-0011). The block id is still BLAKE-256r14.
- Work comes from `getwork` (dcrd has no getblocktemplate).
- Stratum format follows gominer/dcrpool:
  - extranonce1 at header offset 144, extranonce2 at 148;
  - ntime may roll forward.
- DCR RPC is forced through curl.
- A separate raw `blake3` algo (port 9661) exists but has no coin yet.
- Code: official BLAKE3 1.8.7 C code (portable) in `stratum/algos/blake3/`.
- KATs: DCR 794368, 800000 and 1000000.
- End to end: 33 blocks accepted on simnet (dcrd 2.1.6).
- `blocknotify-dcr/` was rewritten with Go modules (dcrd rpcclient v8); needs Go 1.21+.
- Deployment notes, not yet in the installers:
  - dcrd needs `--miningaddr=<pool wallet>`.
  - Run `blocknotify-dcr -stratum 127.0.0.1:3252 -coinid <id> -rpcuser … -rpcpass …`.
  - Stratum difficulty must be ≥ 1.
  - Only mainnet powLimit lines up exactly with the pool's diff 1.

### 5.4 Equihash + yespowerRES (in progress: this is where to resume)

Branch `claude/phase2-equihash` contains:

- `9e0b28ac`: the compactsize endianness fix.
- `65cc837a`: `stratum/algos/equihash` verifier (any n,k; 8-byte BLAKE2b personalization) and the yespowerRES hash, with KATs:
  - ZEC genesis, 1000000 and 3000000;
  - KMD 4000000; ARRR 4100000;
  - ZCL 3260000 (192,7);
  - BTG 800000 and 960000 (144,5);
  - the zcashd regtest genesis (48,5);
  - the RES genesis.
- `21159acf`: `protocol_equihash.cpp`:
  - ZIP-301 stratum: subscribe `[session, nonce1]`, `mining.set_target`, notify `[job, version, prevhash, merkleroot, reserved, time, bits, clean]`, submit `[worker, job, time, nonce2, solution]`.
  - Share difficulty 1 = `0x0007ffff…`.
  - Uses the daemon's `coinbasetxn` + `defaultroots` when present. Otherwise (BTG) it builds its own coinbase, and uses a Sapling v4 coinbase for Zcash forks without coinbasetxn.
  - Config keys: `equihash_n`/`equihash_k` (48,5 for zcashd regtest), `equihash_personalization`, `equihash_header`, and a `[EQUIHASH] SYMBOL = personalization` section. Built-ins: BTG BgoldPoW, BTCZ BitcoinZ, GLINK sngemPoW, BTH BethdPoW, ZER ZERO_PoW, else ZcashPoW.
  - yespowerRES speaks the Bitcoin stratum with hashFinalSaplingRoot as a 10th notify parameter.
- `14e4254c`: configs — equihash 9600, equihash144 9601, equihash192 9602, yespowerRES 9650.

What the stopped agent had done but not reported (from its logs):
- Test miners (now in `docs/handoff/tools/equihash`) submitted shares through the real stratum:
  - Zcash regtest: 40/40 accepted;
  - Bitcoin Gold regtest: 10/10 and 3/3;
  - Komodo: several runs, with correct rejects for low difficulty, invalid solution and duplicate shares.
- The zcashd regtest chains reached heights 138 and 143 and BTG regtest reached 2014, and the daemons ran blocknotify. **Blocks were very likely accepted, but this is unverified.** Part of that height came from the daemons' own `generate`.
- The daemons logged `runCommand error: system(.../blocknotify ...)` for every block, so blocknotify is failing (wrong password/port/format?). Investigate.

**Next steps to finish Equihash:**
1. Set up the test environment (section 7), then rebuild and run `hashtest`. Expect all KATs OK; about 40 were passing plus the Equihash ones.
2. Re-run the end-to-end tests with zcashd (regtest 48,5, both the Sapling and NU6 configs the agent used) and BTG. Check that blocks mined through the stratum are accepted: `getblock` on the stratum-reported hash, and the `blocks` table rows after blocknotify.
3. Fix the blocknotify failure seen with these daemons.
4. Web: run `sync_algos.py` with colors for equihash, equihash144, equihash192 and yespowerRES. Hashrate is in Sol/s — check that the web's hashrate formula (`yaamp_hashrate_constant`, the algo factor) displays sensibly for share diff 1 = 0x0007ffff…, and set the mBTC factor. Nothing has been decided here yet.
5. Merge `claude/phase2-equihash` into `claude/phase2`.
6. Installer notes and changes for Phase 2:
   - Decred: dcrd `--miningaddr`; blocknotify-dcr needs Go 1.21+.
   - KawPoW: memory use; manual `stratum start kawpow`.
   - Equihash: daemon settings.
   - Consider whether a boot list is needed.
7. Open the Phase 2 PR (yiimp `claude/phase2` → `next`), plus installer PRs if you changed the installers. Check in with the owner before starting Phase 3.

Other Phase 2 items from the research that were **not** done: VerusHash,
RandomSCASH, Riecoin, NexaPow, neoscrypt-xaya, phihash, and NiceHash
EthereumStratum.

## 6. Phase 3 (not started): bridge for non-Bitcoin daemons

Approved design, as proposed to the owner:

- **A documented DB contract.** Everything YiiMP needs (hashrate, blocks, payouts) comes from the tables `accounts`, `workers`, `shares` (aggregated per worker per flush), `blocks` (category new→immature→generate/orphan via the web cron) and `stratums`. See `stratum/share.cpp`, `db.cpp` and `web/yaamp/core/backend/blocks.php`. An external stratum engine that writes these tables the same way plugs into stats and payouts.
- **The web wallet RPC adapter layer** (`web/yaamp/core/rpc/wallet-rpc.php`, class `WalletRPC`) already translates Bitcoin-style calls for `GETH` (Ethereum) and `XMR` (CryptoNote, `xmr-rpc.php`). New daemon families need an adapter there (rpcencoding value on the coin).
- **Installer hooks** to run the external engine as a screen/systemd service, like the stratums.
- **First engine: RandomX/Monero.**
  - It needs RandomX (BSD-3) share validation with a dataset/cache per seed hash.
  - Block template from monerod `get_block_template` (reserved offset for the extranonce), submission with `submit_block`.
  - The xmrig `login`/`job`/`submit` protocol.
- The research list of Category C coins is in `docs/handoff/notes/algo_research.md`.

## 6a. Phase 3 status (2026-09-28): randomx done on `claude/phase3`

- Stratum: `protocol_randomx.cpp` (monerod get_block_template/submit_block, xmrig
  protocol, RandomX light mode from `algos/randomx`, tevador/RandomX 7607fb2 BSD-3),
  `algos/cryptonote_block.c`, new optional protocol hooks (create_template, request,
  send_error, coind_config, coind_init), curl url path + digest auth. Port 9701.
- KATs: official RandomX vectors (v1 and v2), XMR mainnet block 3772000 (block id + PoW).
  hashtest otherwise identical to claude/phase2 (gcc 13 and 14).
- Web: XMR adapter rewritten for monerod/monero-wallet-rpc 0.18 (`$configWalletRPC` in
  serverconfig), coins.php XMR branch, randomx tables (factor 0.001, constant 2^10).
- Contract doc: `docs/BRIDGE.md`. Protocol test client: `tools/randomx/rxclient.py`.
- Tested (monerod/wallet-rpc 0.18.5.1 regtest, xmrig 6.26.0): ~52 blocks accepted and
  confirmed, new -> immature -> generate, 2 orphans after pop_blocks detected, one
  transfer_split payout received by the miner wallet (earnings mature_time backdated).
- Not done: RandomX variants (RandomWOW, rx/arq: compile-time RandomX configs), full-memory
  (dataset) verification mode, installer changes, live mainnet mining.

## 7. Recreating the test environment (the container is ephemeral)

Machine used: Ubuntu 24.04, x86_64, root. Packages that were installed:
```
mariadb-server memcached nginx (for the nginx rule test only)
php8.3-cli php8.3-mysql php8.3-memcache php8.3-curl php8.3-gmp php8.3-mbstring php8.3-gd
php8.4 (+ memcache, gmp, curl) for extra checks
build-essential pkg-config libmysqlclient-dev libcurl4-openssl-dev libssl-dev libgmp-dev gcc-14 g++-14
```
Services have no systemd here. Start them by hand:
```
mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld && (setsid mysqld_safe >/dev/null 2>&1 &)
memcached -u memcache -d -p 11211 -l 127.0.0.1
```

Build and hash tests (in a yiimp checkout):
```
make -C blocknotify && make -C stratum -j8 && make -C stratum hashtest && ./stratum/hashtest
```
If you see "Illegal instruction", run `git clean -fdX stratum` and rebuild
(stale objects from another CPU). `VERTHASH_DATAFILE=/path ./stratum/hashtest`
runs the verthash KAT; create the file with
`make -C stratum verthash_gen && stratum/verthash_gen <file>` (1.2 GB, about 1.3 GB RAM).

Web test site (see `docs/handoff/tools/site`):
- Copy `web/` to a directory and create `serverconfig.php` from `web/serverconfig.sample.php` (LOGS/HTDOCS/BIN paths, DB credentials, `YAAMP_ADMIN_IP` 127.0.0.1).
- Create a test DB from `sql/2019-11-10-yiimp.sql.gz` + `sql/2018-09-22-workers.sql`, and `/etc/yiimp/keys.php` from `web/keys.sample.php`.
- Serve it with `php8.3 -S 127.0.0.1:8083 -t <dir> <dir>/router.php` (start it with run_in_background; background `&` processes die when the shell call ends).
- `crawl.sh` requests every controller action (routes list: `grep "function action" web/yaamp/modules/*/*Controller.php`). Get an admin cookie first with `curl -c jar http://127.0.0.1:8083/site/adminRights`.
- `req.php` runs one request from the CLI.
- Yii errors go to `web/yaamp/runtime/application.log`.

End-to-end stratum tests:
- Run the coin daemon on regtest/simnet (release binaries from GitHub releases, verify checksums) with a second node connected: many daemons refuse getblocktemplate without a peer.
- Point the stratum at a test DB with an `installed`, `enable`, `auto_ready` coin row, then mine with the test miners in `docs/handoff/tools`:
  - `miner.py`: Bitcoin-style scrypt/sha256d.
  - `bitcoin/cpuminer.py`: loads a `libpow.so` built from the stratum hash objects.
  - `kawpow/kpminer.py`: needs a `libkp.so` built from `stratum/algos/progpow`.
  - `equihash/zipminer.py` + `eqsolve.c`, and `equihash/resminer.py` (+ a `libyesres.so` built from the yespower code).
  - `decred/miner_main.go`: Go, lukechampine BLAKE3.
- These scripts have paths from the old scratchpad hard-coded (`/tmp/claude-0/...`); adjust them.
- The compiled `.so` helpers were not saved: rebuild them with gcc `-shared -fPIC` from the stratum sources they wrap.
- Rules the agents followed: use your own database name per task; never
  `pkill -x stratum` (kill by PID); commit early (usage limits interrupted two
  agents mid-task; their uncommitted work survived in the worktree).

Public GitHub repos can be cloned read-only through this environment's git
proxy for reference code, even when they are not in the session's repo scope.

## 8. Known issues and loose ends

Security round 3 and the coin loose ends are merged (yiimp #18 to #24, installers #7 and #8). Nothing below was run against a daemon, database or regtest yet; the first real test is still open.

- Done in round 3:
  - Payouts: a per-coin MySQL lock, the payout row and balance debit claimed in one transaction before the wallet call, refund only on a clean wallet refusal, claim kept and admin alerted on an unclear failure. Automatic resend of tx-less payouts was removed. Balance credits and debits are atomic UPDATEs.
  - Stratum: client lifetime races (only a client's own thread marks it deleted), job locking, per-IP cap `STRATUM:max_cons_per_ip` (default 0 = off), strict login-address check, `coind.cpp` no longer mines to `"1.0"` (an invalid wallet with no backup address stops that coin with an ERROR line).
  - Web: state-changing admin actions are POST-only with the session token (`$postActions`, `yaampPost()`), shared `isValidAddress()`, escaped usernames in admin lists.
  - Coins: ADVC dev output through the template `developer` field; the Lyncoin aux target now falls back to `_target` and the aux tree is capped at MAX_AUXS; KCN and LCN put the segwit commitment output last. IsotopeC ticker is ISO.
  - Installers: the two dead sed anchors are gone; the multi-server installer starts per-algo stratums at boot (`stratum boot`, one per second, stops below 256 MB free; newer algos such as the yespower family and ghostrider still need `stratum start <algo>`).
  - Wallet sends: every send path (payment run, bookmark, sellto, sell cron, renting withdraw, redotx, shift send) takes the per-coin lock and claims before sending through `BackendWalletSend` / `BackendWalletSendOnce` in `payment.php`. A refusal releases the claim; a timeout keeps it until an admin clicks "clear". Renter balances are atomic updates. A required charity/dev/founder output with an empty or invalid address now drops the template (one ERROR per coin per hour). Renting create is POST-only; the external rental API stays GET behind one shared key check and rate limit.
  - Review fixes: the MBL chain-id `&`/`==` precedence bug in `coind_template.cpp` (the fix never ran) and an always-true array-address test were corrected.
- Still open:
  - Rental job charges floor at 0 (hash power was already delivered); the symbol2 transfer has no claim (the amount is read from the wallet each run); the old-style masternode payee is unchanged.
  - `yespower` already uses the Sugarchain personalization, so it equals `yespowerSUGAR`; merging them would change algo names, ports and DB rows, so it was left.
  - The per-login `validateaddress` check stays off (removed upstream in 2020; it would lock out users whose account points at a coin on another algo).
  - PROXY headers are not parsed for IPv6 (`workers.ip` is `varchar(32)`).
  - Accounts whose username is not alphanumeric cannot be blocked from the wallet link (BAN by id works).
  - The manual admin tools (`redotx`, bookmark and market sends) were not changed.
  - Memory: the single-server boot list starts 81 stratums at about 14 MB each.
  - The Resistance chain only works in `claude/phase2-equihash`, via the Equihash protocol family.
